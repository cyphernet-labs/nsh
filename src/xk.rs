use std::{io, net};
use cyphernet::addr::{HostName, InetHost, NetAddr};
use cyphernet::{Ecdh, EcSk, Sha256};
use cyphernet::encrypt::noise::{HandshakePattern, Keyset, NoiseState};
use cyphernet::proxy::socks5;
use netservices::{LinkDirection, NetConnection};
use netservices::session::{NoiseSession, Socks5Session};

pub type NshSession<G> = NoiseSession<G, Sha256, Socks5Session<net::TcpStream>>;

pub fn connect_nonblocking<G: Ecdh>(
    remote_addr: NetAddr<HostName>,
    remote_id: <G as EcSk>::Pk,
    signer: G,
    proxy_addr: NetAddr<InetHost>,
    force_proxy: bool,
) -> io::Result<NshSession<G>> {
    let connection = if force_proxy {
        net::TcpStream::connect_nonblocking(proxy_addr)?
    } else {
        net::TcpStream::connect_nonblocking(remote_addr.connection_addr(proxy_addr))?
    };
    Ok(session::<G>(
        remote_addr,
        Some(remote_id),
        connection,
        LinkDirection::Outbound,
        signer,
        force_proxy,
    ))
}

pub fn accept<G: Ecdh>(
    connection: net::TcpStream,
    signer: G,
) -> NshSession<G> {
    session::<G>(
        connection.remote_addr().into(),
        None,
        connection,
        LinkDirection::Inbound,
        signer,
        false,
    )
}

fn session<G: Ecdh>(
    remote_addr: NetAddr<HostName>,
    remote_id: Option<G::Pk>,
    connection: net::TcpStream,
    direction: LinkDirection,
    signer: G,
    force_proxy: bool,
) -> NshSession<G> {
    let socks5 = socks5::Socks5::with(remote_addr, force_proxy);
    let proxy = Socks5Session::with(connection, socks5);

    let pair = G::generate_keypair();
    let keyset = if direction.is_outbound() {
        debug_assert!(remote_id.is_some());
        Keyset {
            e: pair.0,
            s: Some(signer.clone()),
            re: None,
            rs: remote_id,
        }
    } else {
        Keyset {
            e: pair.0,
            s: Some(signer.clone()),
            re: None,
            rs: None,
        }
    };

    let noise = NoiseState::initialize::<32>(
        HandshakePattern {
            initiator: cyphernet::encrypt::noise::InitiatorPattern::Xmitted,
            responder: cyphernet::encrypt::noise::OneWayPattern::Known,
        },
        direction.is_outbound(),
        &[],
        keyset,
    );

    NoiseSession::with(proxy, noise)
}
