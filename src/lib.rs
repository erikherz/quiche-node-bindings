use napi_derive::napi;
use napi::bindgen_prelude::*;
use std::net::UdpSocket;
use quiche::{self, Config, RecvInfo};
use std::collections::HashMap;

const MAX_DATAGRAM_SIZE: usize = 1350;
const HELLO_MESSAGE: &[u8] = b"Hello, World!";
const QUIC_V1: u32 = 0x00000001; // Manually specify QUIC v1

// Helper function to convert io::Error to napi::Error
fn io_err_to_napi(err: std::io::Error) -> napi::Error {
    napi::Error::from_reason(format!("IO Error: {:?}", err))
}

// Helper function to convert quiche::Error to napi::Error
fn quiche_err_to_napi(err: quiche::Error) -> napi::Error {
    napi::Error::from_reason(format!("QUIC Error: {:?}", err))
}

struct Client {
    conn: quiche::Connection,
}

type ClientMap = HashMap<quiche::ConnectionId<'static>, Client>;

#[napi]
pub fn setup_quic_server(cert_path: String, key_path: String) -> Result<String> {
    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];

    let mut clients = ClientMap::new();
    let socket = UdpSocket::bind("0.0.0.0:443").map_err(io_err_to_napi)?;

    let protocol_version = quiche::PROTOCOL_VERSION;
    println!("Using QUIC protocol version: {}", protocol_version);

    let mut config = Config::new(protocol_version).map_err(quiche_err_to_napi)?;

    config.load_cert_chain_from_pem_file(&cert_path).map_err(quiche_err_to_napi)?;
    println!("Certificate loaded successfully from {}", cert_path);

    config.load_priv_key_from_pem_file(&key_path).map_err(quiche_err_to_napi)?;
    println!("Private key loaded successfully from {}", key_path);

    // Set ALPN to advertise HTTP/3 support (necessary for WebTransport)
    config.set_application_protos(&[b"h3"]).map_err(|e| {
        napi::Error::from_reason(format!("Failed to set ALPN protocols: {:?}", e))
    })?;

    config.set_max_idle_timeout(5000);
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_stream_data_uni(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.set_disable_active_migration(true);
    config.enable_early_data();

    let _h3_config = quiche::h3::Config::new().map_err(|e: quiche::h3::Error| {
        napi::Error::from_reason(format!("QUIC HTTP/3 Error: {:?}", e))
    })?;
    println!("HTTP/3 config initialized.");

    loop {
        let (len, from) = socket.recv_from(&mut buf).map_err(io_err_to_napi)?;
        let pkt_buf = &mut buf[..len];

        let hdr = match quiche::Header::from_slice(pkt_buf, quiche::MAX_CONN_ID_LEN) {
            Ok(hdr) => hdr,
            Err(e) => {
                eprintln!("Failed to parse header: {:?}", e);
                continue;
            }
        };

        // Ensure the client is using QUIC v1 (check the version field manually against 0x00000001)
        if hdr.version != QUIC_V1 {
            println!("Unsupported QUIC version from client: {:?}. Only QUIC v1 is supported.", hdr.version);
            let len = quiche::negotiate_version(&hdr.scid, &hdr.dcid, &mut out).unwrap();
            println!("Sending version negotiation packet: {} bytes", len);
            
            if let Err(e) = socket.send_to(&out[..len], from) {
                eprintln!("Failed to send version negotiation packet: {:?}", e);
            } else {
                println!("Version negotiation packet sent successfully.");
            }
            continue;
        }

        let conn_id = hdr.dcid.to_vec();
        let client = clients.entry(conn_id.clone().into()).or_insert_with(|| {
            let scid = quiche::ConnectionId::from_ref(&conn_id);
            println!("Accepting new connection with scid: {:?}", scid);

            let local_addr = socket.local_addr().unwrap();
            match quiche::accept(&scid, None, local_addr, from, &mut config) {
                Ok(conn) => {
                    println!("Connection accepted from {:?}", from);
                    Client { conn }
                }
                Err(e) => {
                    eprintln!("QUIC accept error: {:?}", e);
                    panic!("Failed to accept connection");
                }
            }
        });

        let recv_info = RecvInfo { from, to: socket.local_addr().unwrap() };

        match client.conn.recv(pkt_buf, recv_info) {
            Ok(read) => {
                println!("Received {} bytes", read);
            }
            Err(e) => {
                eprintln!("QUIC recv error: {:?}", e);
                continue;
            }
        }

        if client.conn.is_established() {
            if client.conn.stream_finished(0) {
                eprintln!("Stream 0 is already finished");
            } else {
                match client.conn.stream_send(0, HELLO_MESSAGE, true) {
                    Ok(stream_id) => {
                        println!("Sent 'Hello, World!' on stream {}", stream_id);
                    }
                    Err(e) => {
                        eprintln!("Failed to send stream: {:?}", e);
                    }
                }
            }
        }

        match client.conn.send(&mut out) {
            Ok((write, send_info)) => {
                if let Err(e) = socket.send_to(&out[..write], send_info.to) {
                    eprintln!("Failed to send packet: {:?}", e);
                } else {
                    println!("Sent {} bytes", write);
                }
            }
            Err(quiche::Error::Done) => {
                println!("No more packets to send for this client.");
            }
            Err(e) => {
                eprintln!("Error sending QUIC data: {:?}", e);
            }
        }
    }
}

