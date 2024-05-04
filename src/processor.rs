use cyphernet::addr::{InetHost, NetAddr};
use std::collections::HashMap;
use std::net::TcpStream;
use std::os::fd::{AsRawFd, RawFd};
use std::process::Stdio;
use std::str::FromStr;
use std::time::Duration;
use std::{io, process};

use cyphernet::{ed25519, Cert, Digest, Sha256};
use netservices::Direction;
use reactor::ResourceId;

use crate::command::{Command, LocalCommand};
use crate::server::{Action, Delegate};
use crate::{Session, Transport};

#[derive(Debug)]
pub struct Processor {
    cert: Cert<ed25519::Signature>,
    signer: ed25519::PrivateKey,
    proxy_addr: NetAddr<InetHost>,
    force_proxy: bool,
    timeout: Duration,
    queue: HashMap<RawFd, LocalCommand>,
}

impl Processor {
    pub fn with(
        cert: Cert<ed25519::Signature>,
        signer: ed25519::PrivateKey,
        proxy_addr: NetAddr<InetHost>,
        force_proxy: bool,
        timeout: Duration,
    ) -> Self {
        Self {
            cert,
            signer,
            proxy_addr,
            force_proxy,
            timeout,
            queue: none!(),
        }
    }
}

impl Delegate for Processor {
    fn accept(&self, connection: TcpStream) -> io::Result<Session> {
        Session::accept::<{ Sha256::OUTPUT_LEN }>(
            connection,
            self.cert.clone(),
            vec![],
            self.signer.clone(),
        )
    }

    fn new_client(&mut self, fd: RawFd, id: ResourceId, key: ed25519::PublicKey) -> Vec<Action> {
        log::debug!(target: "nsh", "Remote {key} (fd={fd}) is connected and assigned id {id}");
        if let Some(command) = self.queue.remove(&fd) {
            log::debug!(target: "nsh", "Sending queued `{command}` to {id}");
            vec![Action::Send(id, command.to_string().as_bytes().to_vec())]
        } else {
            return vec![];
        }
    }

    fn input(&mut self, id: ResourceId, data: Vec<u8>) -> Vec<Action> {
        let mut action_queue = vec![];

        let cmd = match String::from_utf8(data) {
            Ok(cmd) => cmd,
            Err(err) => {
                log::warn!(target: "nsh", "Non-UTF8 command from {id}: {err}");
                action_queue.push(Action::Send(id, b"NON_UTF8_COMMAND".to_vec()));
                action_queue.push(Action::UnregisterTransport(id));
                return action_queue;
            }
        };

        let Ok(cmd) = Command::from_str(&cmd) else {
            action_queue.push(Action::Send(id, b"INVALID_COMMAND".to_vec()));
            action_queue.push(Action::UnregisterTransport(id));
            return action_queue;
        };

        log::info!(target: "nsh", "Executing '{cmd}' for {id}");
        match cmd {
            Command::ECHO => {
                match process::Command::new("sh")
                    .arg("-c")
                    .arg("echo")
                    .stdout(Stdio::piped())
                    .output()
                {
                    Ok(output) => {
                        log::debug!(target: "nsh", "Command executed successfully; {} bytes of output collected", output.stdout.len());
                        action_queue.push(Action::Send(id, output.stdout));
                    }
                    Err(err) => {
                        log::error!(target: "nsh", "Error executing command: {err}");
                        action_queue.push(Action::Send(id, err.to_string().as_bytes().to_vec()));
                        action_queue.push(Action::UnregisterTransport(id));
                    }
                }
            }
            Command::Forward { hop, command } => {
                // TODO: Ensure that the host key equals the key provided during authentication
                let session = match Session::connect_nonblocking::<{ Sha256::OUTPUT_LEN }>(
                    hop.addr,
                    self.cert,
                    vec![hop.id],
                    self.signer.clone(),
                    self.proxy_addr.clone(),
                    self.force_proxy,
                    self.timeout,
                ) {
                    Ok(session) => session,
                    Err(err) => {
                        action_queue.push(Action::Send(
                            id,
                            format!("Failure: {err}").as_bytes().to_vec(),
                        ));
                        return action_queue;
                    }
                };
                match Transport::with_session(session, Direction::Outbound) {
                    Ok(transport) => {
                        self.queue.insert(transport.as_raw_fd(), command);
                        action_queue.push(Action::RegisterTransport(transport));
                    }
                    Err(err) => {
                        action_queue.push(Action::Send(
                            id,
                            format!("Failure: {err}").as_bytes().to_vec(),
                        ));
                        action_queue.push(Action::UnregisterTransport(id));
                    }
                }
            }
        };

        action_queue
    }
}
