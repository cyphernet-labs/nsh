use cyphernet::{ed25519, x25519};
use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{TcpStream, ToSocketAddrs};
use std::os::fd::RawFd;

use netservices::{ListenerEvent, SessionEvent};
use reactor::{Error, Resource, ResourceId, ResourceType, Timestamp};

use crate::{Session, Transport};

pub type Accept = netservices::NetAccept<Session, socket2::Socket>;
pub type Action = reactor::Action<Accept, Transport>;

pub type Ecdh = x25519::PrivateKey;
pub type Auth = ed25519::PrivateKey;

pub trait Delegate: Send {
    fn accept(&self, connection: TcpStream) -> io::Result<Session>;
    fn new_client(&mut self, fd: RawFd, id: ResourceId, key: ed25519::PublicKey) -> Vec<Action>;
    fn input(&mut self, id: ResourceId, data: Vec<u8>) -> Vec<Action>;
}

pub struct Server<D: Delegate> {
    outbox: HashMap<RawFd, VecDeque<Vec<u8>>>,
    action_queue: VecDeque<Action>,
    delegate: D,
}

impl<D: Delegate> Server<D> {
    pub fn with(listen: &impl ToSocketAddrs, delegate: D) -> io::Result<Self> {
        let mut action_queue = VecDeque::new();
        let listener = Accept::bind(listen)?;
        action_queue.push_back(Action::RegisterListener(listener));
        Ok(Self {
            outbox: empty!(),
            action_queue,
            delegate,
        })
    }
}

impl<D: Delegate> reactor::Handler for Server<D> {
    type Listener = Accept;
    type Transport = Transport;
    type Command = ();

    fn tick(&mut self, time: Timestamp) {
        log::trace!(target: "server", "reactor ticks at {time:?}");
    }

    fn handle_timer(&mut self) {
        log::trace!(target: "server", "Reactor receives a timer event");
    }

    fn handle_listener_event(
        &mut self,
        id: ResourceId,
        event: <Self::Listener as Resource>::Event,
        time: Timestamp,
    ) {
        log::trace!(target: "server", "Listener event on {id} at {time:?}");
        match event {
            ListenerEvent::Accepted(connection) => {
                let peer_addr = connection
                    .peer_addr()
                    .expect("unknown peer address on accepted connection");
                let local_addr = connection
                    .local_addr()
                    .expect("unknown local address on accepted connection");
                log::info!(target: "server", "Incoming connection from {peer_addr} on {local_addr}");
                let transport = self.delegate.accept(connection).and_then(Transport::accept);
                match transport {
                    Ok(transport) => {
                        log::info!(target: "server", "Connection accepted, registering transport with reactor");
                        self.action_queue
                            .push_back(Action::RegisterTransport(transport));
                    }
                    Err(err) => {
                        log::info!(target: "server", "Error accepting incoming connection: {err}");
                    }
                }
            }
            ListenerEvent::Failure(err) => {
                log::error!(target: "server", "Error on listener {id}: {err}")
            }
        }
    }

    fn handle_transport_event(
        &mut self,
        id: ResourceId,
        event: <Self::Transport as Resource>::Event,
        time: Timestamp,
    ) {
        log::trace!(target: "server", "I/O on {id} at {time:?}");
        match event {
            SessionEvent::Established(fd, artifact) => {
                let key = artifact.state.pk;
                let queue = self.outbox.remove(&fd).unwrap_or_default();
                log::debug!(target: "server", "Connection with remote peer {key}@{id} successfully established; processing {} items from outbox", queue.len());
                self.action_queue
                    .extend(self.delegate.new_client(fd, id, key));
                self.action_queue
                    .extend(queue.into_iter().map(|msg| Action::Send(id, msg)))
            }
            SessionEvent::Data(data) => {
                log::trace!(target: "server", "Incoming data {data:?}");
                self.action_queue.extend(self.delegate.input(id, data));
            }
            SessionEvent::Terminated(err) => {
                log::error!(target: "server", "Connection with {id} is terminated due to an error: {err}");
                self.action_queue.push_back(Action::UnregisterTransport(id));
            }
        }
    }

    fn handle_registered(&mut self, fd: RawFd, id: ResourceId, ty: ResourceType) {
        log::debug!(target: "server", "{ty:?} having file descriptor {fd} was registered in the reactor with id {id}");
    }

    fn handle_command(&mut self, cmd: Self::Command) {
        log::debug!(target: "server", "Command {cmd:?} received");
    }

    fn handle_error(&mut self, err: Error<Self::Listener, Self::Transport>) {
        match err {
            Error::TransportDisconnect(id, transport) => {
                log::warn!(target: "server", "Remote peer {transport} with id={id} disconnected");
                return;
            }
            // All others are errors:
            ref err @ Error::Poll(_) => {
                log::error!(target: "server", "Error: {err}");
            }
            ref err @ Error::ListenerDisconnect(id, _) => {
                log::error!(target: "server", "Error: {err}");
                self.action_queue.push_back(Action::UnregisterListener(id));
            }
        }
    }

    fn handover_listener(&mut self, id: ResourceId, _listener: Self::Listener) {
        log::error!(target: "server", "Disconnected listener socket {id}");
        panic!("Disconnected listener socket {id}")
    }

    fn handover_transport(&mut self, id: ResourceId, transport: Self::Transport) {
        log::warn!(target: "server", "Remote peer {transport} with id={id} disconnected");
    }
}

impl<D: Delegate> Iterator for Server<D> {
    type Item = Action;

    fn next(&mut self) -> Option<Self::Item> {
        self.action_queue.pop_front()
    }
}
