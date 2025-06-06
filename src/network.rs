use crate::server::packet_handler;
use crate::{build_private_key, MAX_PACKET_LENGTH};
use std::io::{Error, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::time::Duration;

pub trait QHandler {
    fn handle(&self, data: &[u8]) -> Result<Option<Vec<u8>>, Error>;
}

pub fn qsend_to(
    socket: UdpSocket,
    addr: SocketAddr,
    data: Vec<u8>,
    read_timeout: u64,
    retries: usize,
) -> Result<Vec<u8>, Error> {
    let mut err = None;
    let mut buffer = [0u8; MAX_PACKET_LENGTH];
    socket.set_read_timeout(Some(Duration::new(read_timeout, 0)))?;
    for _i in 0..retries {
        socket.send_to(data.as_slice(), addr)?;
        match socket.recv_from(&mut buffer) {
            Ok((amt, _src)) => return Ok(buffer[0..amt].to_vec()),
            Err(e) => err = Some(e),
        }
    }
    Err(err.unwrap())
}

pub fn qserver(
    private_key: &str,
    port: u16,
    handler: Box<dyn QHandler>,
) -> Result<(), Error> {
    let key = build_private_key(private_key)?;
    let socket = UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], port)))?;
    println!("UDP server started on port {}", port);
    let mut buf = [0; MAX_PACKET_LENGTH];
    loop {
        let (n, src) = socket.recv_from(&mut buf)?;
        println!("Incoming packet with size {} from {}", n, src);
        let data_to_send = packet_handler(&key, &buf[0..n], &handler)?;
        if let Some(data) = data_to_send {
            if let Err(e) = socket.send_to(data.as_slice(), src) {
                println!("send error {}", e.to_string());
            } else {
                println!("response sent.");
            }
        }
    }
}

pub fn qserver_tcp(
    private_key: &str,
    port: u16,
    handler: Box<dyn QHandler>,
) -> Result<(), Error> {
    let key = build_private_key(private_key)?;
    let listener = TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], port)))?;
    println!("TCP server started on port {}", port);
    let mut buf = [0; MAX_PACKET_LENGTH];
    for stream in listener.incoming() {
        match stream {
            Ok(mut istream) => {
                if let Ok(a) = istream.peer_addr() {
                    println!("Connected to {}", a);
                }
                match istream.read(&mut buf) {
                    Ok(n) => {
                        if n == 0 {
                            println!("Connection closed.");
                            continue;
                        }
                        println!("Incoming packet with size {}", n);
                        let data_to_send = packet_handler(&key, &buf[0..n], &handler)?;
                        if let Some(data) = data_to_send {
                            if let Err(e) = istream.write(data.as_slice()) {
                                println!("send error {}", e.to_string());
                            } else {
                                println!("response sent.");
                            }
                        }
                    }
                    Err(_e) => {
                        continue;
                    }
                }
            }
            Err(e) => return Err(e)
        }
    }
    Err(Error::new(ErrorKind::ConnectionAborted, "no more incoming streams"))
}
