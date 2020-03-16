use crate::tls::PrivateKey;
use crate::tls::Certificate;
use crate::tls::load_certs;
use crate::tls::load_private_key;


#[derive(Debug)]
pub struct Config {
    pub hostnames: Vec<String>,
    pub alpns: Vec<String>,
    pub certs: Vec<Certificate>,
    pub pkey: PrivateKey,
    pub upstream: Vec<(String, std::net::SocketAddr)>,
    pub default_upstream: Vec<std::net::SocketAddr>,
    pub bind: std::net::SocketAddr,
}

// TLS-Proxy 0.1.0
// luozijun <luozijun.assistant@gmail.com>
// TLS-Proxy
// $ tlsproxy \
//      --sni-hostnames "localhost,www.baidu.com" \
//      --cert "./keys/ca.crt" --cert "./keys/root.crt" \
//      --pkey "./keys/server.key" \
//      --alpns "h2,http/1.1," \
//      --upstream "h2://192.168.199.1:8000" \
//      --upstream "h1://192.168.199.1:8000" \
//      --upstream "dot://192.168.199.1:8000" \
//      --upstream "webrtc://192.168.199.1:8000" \
//      --upstream "*://192.168.199.1:8000" \
//      --bind "127.0.0.1:8000"
// 
// cargo run -- --tls-pkey "./keys/server.key" --tls-cert "./keys/server.crt" 127.0.0.1:80



fn print_usage(opts: getopts::Options) {
    let name = env!("CARGO_PKG_NAME");
    let version = env!("CARGO_PKG_VERSION");
    let authors = env!("CARGO_PKG_AUTHORS");
    let descp = env!("CARGO_PKG_DESCRIPTION");
    
    println!();
    println!("{} {}", name, version);
    println!("{}", authors);
    println!();
    println!("{}", descp);

    println!();
    let brief = format!("Usage: {} [Options] <BIND>", name);
    print!("{}", opts.usage(&brief));
    println!();
    println!("
Example: 
    
    $ tlsproxy --cert ./keys/server.crt \\
            --cert ./keys/root.crt \\
            --pkey ./keys/server.key \\
            --hostnames 'localhost,www.example.com' \\
            --alpn 'h2,http/1.1,dot,http/1.0'\\
            --upstream dot://192.168.1.1:53 \\
            --upstream h1://192.168.10.1:8000 \\
            --upstream h2://192.168.10.1:9000 \\
            --upstream *://192.168.10.1:3000 \\
            --bind 127.0.0.1:443", );
}


fn parse_config() -> Result<Config, &'static str> {
    todo!()
}

pub fn boot() -> Result<Config, Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let args_len = args.len();

    let mut opts = getopts::Options::new();
    opts.optflag ("h", "help", "");
    opts.optflag ("v", "version", "");
    opts.optopt  ("k", "pkey", "TLS Server Private Key (PEM Format)", "");
    opts.optmulti("c", "cert", "TLS Certificate (PEM Format)", "");
    opts.optopt  ("", "hostnames", "TLS Server SNI Host Names", "");
    opts.optopt  ("", "alpn", "TLS ALPN", "");
    opts.optmulti("", "upstream", "upstream server", "");
    opts.optopt  ("", "verbose", "Sets the level of verbosity. default: info [ info, warn, error, debug, trace]", "");
    opts.opt     ("", "bind", "tls server socket addr", "", getopts::HasArg::Yes, getopts::Occur::Optional);

    let matches = match opts.parse(&args[1..args_len]) {
        Ok(m) => m,
        Err(e) => {
            println!("ParseArgs Error: {:?}", e);
            std::process::exit(0);
        }
    };

    if matches.opt_present("help") {
        print_usage(opts);
        std::process::exit(0);
    }

    if matches.opt_present("version") {
        println!("v{}", env!("CARGO_PKG_VERSION"));
        std::process::exit(0);
    }

    match matches.opt_str("verbose") {
        Some(verbose) => {
            match verbose.to_lowercase().as_str() {
                "info" | "warn" | "error" | "debug" | "trace" => {
                    let s = format!("{}={}", env!("CARGO_PKG_NAME"), verbose);
                    std::env::set_var("RUST_LOG", s);
                },
                _ => {
                    let log_level = ["info", "warn", "error", "debug", "trace"];
                    println!("[ERROR] Log level: {:?}", log_level);
                    std::process::exit(1);
                }
            }
        },
        None => { }
    }
    
    // ---------- Parse Config ------------
    let pkey = match matches.opt_str("pkey") {
        Some(key_path) => load_private_key(key_path)?,
        None => {
            println!("[ERROR] Missing arg pkey.");
            std::process::exit(1);
        }
    };
    let bind = match matches.opt_str("bind") {
        Some(bind_val) => {
            let mut iter = std::net::ToSocketAddrs::to_socket_addrs(&bind_val)?;
            match iter.next() {
                Some(addr) => addr,
                None => {
                    println!("[ERROR] Missing bind addr.");
                    std::process::exit(1);
                }
            }
        },
        None => {
            println!("[ERROR] Missing arg pkey.");
            std::process::exit(1);
        }
    };

    let mut certs = Vec::new();
    for cert_path in matches.opt_strs("cert").iter() {
        let mut tmp = load_certs(cert_path)?;
        certs.append(&mut tmp);
    }

    let hostnames = match matches.opt_str("hostnames") {
        Some(hosts) => hosts.split(',').map(|s| s.to_string()).collect::<Vec<String>>(),
        None => Vec::new(),
    };
    let alpns = match matches.opt_str("alpn") {
        Some(alpn) => alpn.split(',').map(|s| s.to_string()).collect::<Vec<String>>(),
        None => Vec::new(),
    };


    let mut default_upstream = Vec::new();
    let mut upstream = Vec::new();
    for url in matches.opt_strs("upstream").iter() {
        let uri = url.parse::<http::uri::Uri>()?;
        match uri.scheme_str() {
            Some(scheme) => {
                let host = uri.host();
                let port = uri.port_u16();
                if host.is_none() {
                    println!("[ERROR] URI Missing host param.");
                    std::process::exit(1);
                }
                if port.is_none() {
                    println!("[ERROR] URI Missing port param.");
                    std::process::exit(1);
                }
                let host = host.unwrap();
                let port = port.unwrap();
                let domain = format!("{}:{}", host, port);
                let mut iter = std::net::ToSocketAddrs::to_socket_addrs(&domain)?;
                let socket_addr = match iter.next() {
                    Some(addr) => addr,
                    None => {
                        println!("[ERROR] Missing bind addr.");
                        std::process::exit(1);
                    }
                };

                upstream.push((scheme.to_string(), socket_addr));
            },
            None => {
                // *
                let host = uri.host();
                let port = uri.port_u16();
                if host.is_none() {
                    println!("[ERROR] URI Missing host param.");
                    std::process::exit(1);
                }
                if port.is_none() {
                    println!("[ERROR] URI Missing port param.");
                    std::process::exit(1);
                }
                let host = host.unwrap();
                let port = port.unwrap();
                let domain = format!("{}:{}", host, port);
                let mut iter = std::net::ToSocketAddrs::to_socket_addrs(&domain)?;
                let socket_addr = match iter.next() {
                    Some(addr) => addr,
                    None => {
                        println!("[ERROR] Missing bind addr.");
                        std::process::exit(1);
                    }
                };

                default_upstream.push(socket_addr);
            }
        }
    }

    if default_upstream.is_empty() && upstream.is_empty() {
        println!("[ERROR] Missing upstream.");
        std::process::exit(1);
    }

    return Ok(Config {
        hostnames,
        alpns,
        certs,
        pkey,
        upstream,
        default_upstream,
        bind,
    });
}

