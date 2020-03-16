#[macro_use]
extern crate log;
extern crate env_logger;
// extern crate clap;
extern crate getopts;
extern crate tokio;
extern crate tokio_rustls;


pub mod boot;
pub mod tls;

use crate::boot::Config;
use crate::tls::TlsConfig;
use crate::tls::TlsStream;
use crate::tls::TlsListener;

use tokio::io::{ AsyncWrite, AsyncRead, };

use std::io;
use std::sync::Arc;
use std::net::SocketAddr;



#[derive(Debug, Clone)]
struct State {
    upstream: Arc<Vec<(String, SocketAddr)>>,
    default_upstream: Arc<Vec<SocketAddr>>,
}

fn is_h1(p: &str) -> bool {
    match p {
        "http/1.1" | "http/1.0" | "http/0.9" => true,
        _ => false,
    }
}

async fn handle(state: State, tls_stream: TlsStream, peer_addr: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
    // TODO: 负载均衡？
    let mut upstream: Option<SocketAddr> = None;
    if let Some(alpn) = tls_stream.alpn() {
        for (proto, addr) in state.upstream.iter() {
            if is_h1(alpn) && (is_h1(proto) || proto == "h1" ) {
                upstream = Some(*addr);
                break;
            }
            if alpn == proto {
                upstream = Some(*addr);
                break;
            }
        }
    } else {
        warn!("[ALPN] Peer={} next protocol not found.", peer_addr);
    }

    let upstrea_addr: SocketAddr = match upstream {
        Some(addr) => addr,
        None => {
            if state.default_upstream.is_empty() {
                warn!("[ALPN] Peer={} service unavailable.", peer_addr);
                return Ok(());
            } else {
                state.default_upstream[0]
            }
        }
    };

    let mut output = tokio::net::TcpStream::connect(upstrea_addr).await?;
    let mut input = tls_stream.inner;

    tokio::io::copy(&mut input, &mut output).await?;
    
    Ok(())
}

async fn run_forever(config: Config) -> Result<(), Box<dyn std::error::Error>> {
    let tls_config = TlsConfig {
        certs: config.certs,
        pkey: config.pkey,
        hostnames: config.hostnames,
        alpns: config.alpns,
    };

    let state = State {
        upstream: Arc::new(config.upstream),
        default_upstream: Arc::new(config.default_upstream),
    };

    let mut listener = TlsListener::bind(&config.bind, tls_config).await?;

    loop {
        let (tcp_stream, peer_addr) = listener.inner.accept().await?;
        let state = state.clone();
        let acceptor = listener.acceptor.clone();
        let hostnames = listener.hostnames.clone();
        tokio::spawn(async move {
            match acceptor.accept(tcp_stream).await {
                Ok(tls_stream) => {
                    let tls_stream = TlsStream { inner: tls_stream, hostnames: hostnames };
                    if let Err(e) = handle(state, tls_stream, peer_addr).await {
                        error!("Peer={} TLS Handshake Error: {:?}", peer_addr, e);
                    }
                },
                Err(e) => {
                    debug!("Peer={} TLS Handshake Error: {:?}", peer_addr, e);
                }
            }
        });
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = boot::boot()?;
    env_logger::init();

    debug!("{:?}", config);

    let mut rt = tokio::runtime::Runtime::new()?;

    rt.block_on(run_forever(config))?;

    Ok(())
}
