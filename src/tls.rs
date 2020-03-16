use tokio::io::{ AsyncWriteExt, };

pub use tokio_rustls::rustls::Certificate;
pub use tokio_rustls::rustls::PrivateKey;
use tokio_rustls::rustls::internal::pemfile;



use std::io;
use std::fs;
use std::sync::Arc;
use std::path::Path;
use std::net::SocketAddr;


#[derive(Debug)]
pub struct TlsConfig {
    pub certs: Vec<Certificate>,
    pub pkey: PrivateKey,
    pub hostnames: Vec<String>,
    pub alpns: Vec<String>,
}

pub fn load_certs<P: AsRef<Path>>(path: P) -> Result<Vec<Certificate>, io::Error> {
    pemfile::certs(&mut io::BufReader::new(fs::File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert"))
}

pub fn load_private_key<P: AsRef<Path>>(path: P) -> Result<PrivateKey, io::Error> {
    let mut pkeys = pemfile::rsa_private_keys(&mut io::BufReader::new(fs::File::open(path)?))
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid key"))?;
    
    if let Some(pkey) = pkeys.pop() {
        Ok(pkey)
    } else {
        Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid key"))
    }
}


pub struct TlsListener {
    pub(crate) inner: tokio::net::TcpListener,
    pub(crate) acceptor: tokio_rustls::TlsAcceptor,
    pub(crate) hostnames: std::sync::Arc<Vec<String>>,
}


impl TlsListener {
    pub async fn bind<A: tokio::net::ToSocketAddrs>(addr: A, tls_config: TlsConfig) -> Result<Self, io::Error> {
        let auth_client = tokio_rustls::rustls::NoClientAuth::new();
        let mut config = tokio_rustls::rustls::ServerConfig::new(auth_client);

        if !tls_config.alpns.is_empty() {
            let alpns = tls_config.alpns.into_iter().map(|s| s.into_bytes()).collect::<Vec<Vec<u8>>>();
            config.set_protocols(&alpns);
        }

        config.set_single_cert(tls_config.certs, tls_config.pkey)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        let inner = tokio::net::TcpListener::bind(addr).await?;
        let config = std::sync::Arc::new(config);
        let acceptor = tokio_rustls::TlsAcceptor::from(config);
        let hostnames = std::sync::Arc::new(tls_config.hostnames);

        Ok(Self { inner, acceptor, hostnames, })
    }

    pub async fn accept(&mut self) -> Result<(TlsStream, SocketAddr), io::Error> {
        loop {
            let (tcp_stream, peer_addr) = self.inner.accept().await?;
            match self.acceptor.accept(tcp_stream).await {
                Ok(tls_stream) => {
                    let tls_stream = TlsStream { inner: tls_stream, hostnames: self.hostnames.clone() };
                    return Ok((tls_stream, peer_addr));
                },
                Err(e) => {
                    trace!("Peer={} TLS Handshake Error: {:?}", peer_addr, e);
                }
            }
        }
    }

    #[inline]
    pub fn tcp_listener(&self) -> &tokio::net::TcpListener {
        &self.inner
    }

    #[inline]
    pub fn acceptor(&self) -> &tokio_rustls::TlsAcceptor {
        &self.acceptor
    }

    #[inline]
    pub fn hostnames(&self) -> &[String] {
        &self.hostnames
    }

    #[inline]
    pub fn local_addr(&self) -> Result<SocketAddr, io::Error> {
        self.inner.local_addr()
    }

    #[inline]
    pub fn ttl(&self) -> Result<u32, io::Error> {
        self.inner.ttl()
    }

    #[inline]
    pub fn set_ttl(&self, ttl: u32) -> Result<(), io::Error> {
        self.inner.set_ttl(ttl)
    }
}


#[derive(Debug)]
pub struct TlsStream {
    pub(crate) inner: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    pub(crate) hostnames: std::sync::Arc<Vec<String>>,
}

impl TlsStream {
    #[inline]
    pub fn local_addr(&self) -> Result<SocketAddr, io::Error> {
        let (io, _) = self.inner.get_ref();
        io.local_addr()
    }

    #[inline]
    pub fn peer_addr(&self) -> Result<SocketAddr, io::Error> {
        let (io, _) = self.inner.get_ref();
        io.peer_addr()
    }

    #[inline]
    pub fn ttl(&self) -> Result<u32, io::Error> {
        let (io, _) = self.inner.get_ref();
        io.ttl()
    }

    #[inline]
    pub fn set_ttl(&self, ttl: u32) -> Result<(), io::Error> {
        let (io, _) = self.inner.get_ref();
        io.set_ttl(ttl)
    }

    pub fn alpn(&self) -> Option<&str> {
        let (_, session) = self.inner.get_ref();
        match tokio_rustls::rustls::Session::get_alpn_protocol(session) {
            Some(bytes) => {
                match std::str::from_utf8(bytes) {
                    Ok(s) => Some(s),
                    Err(e) => {
                        warn!("ALPN string is not a valid UTF-8 seq.");
                        error!("{:?}", e);
                        None
                    }
                }
            },
            None => None,
        }
    }

    #[inline]
    pub fn protocol_version(&self) -> Option<tokio_rustls::rustls::ProtocolVersion> {
        let (_, session) = self.inner.get_ref();
        tokio_rustls::rustls::Session::get_protocol_version(session)
    }

    #[inline]
    pub fn negotiated_ciphersuite(&self) -> Option<&'static tokio_rustls::rustls::SupportedCipherSuite> {
        let (_, session) = self.inner.get_ref();
        tokio_rustls::rustls::Session::get_negotiated_ciphersuite(session)
    }

    #[inline]
    pub fn peer_certificates(&self) -> Option<Vec<Certificate>> {
        let (_, session) = self.inner.get_ref();
        tokio_rustls::rustls::Session::get_peer_certificates(session)
    }

    #[inline]
    pub fn hostnames(&self) -> &[String] {
        &self.hostnames
    }

    #[inline]
    pub fn hostname(&self) -> Option<&str> {
        let (_, session) = self.inner.get_ref();
        session.get_sni_hostname()
    }

    #[inline]
    pub fn into_inner(self) -> tokio_rustls::server::TlsStream<tokio::net::TcpStream> {
        self.inner
    }
}



