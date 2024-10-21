#[macro_use]
extern crate napi_derive;

use napi::bindgen_prelude::*;
use std::net::UdpSocket;
use std::io::Error as IoError;
use quiche::{self, Config};

// Helper function to convert io::Error to napi::Error
fn io_err_to_napi(err: IoError) -> napi::Error {
    napi::Error::from_reason(format!("IO Error: {:?}", err))
}

// Main function for setting up the QUIC server
#[napi]
pub fn setup_quic_server(cert_path: String, key_path: String) -> Result<String> {
    let mut config = Config::new(quiche::PROTOCOL_VERSION).map_err(|e| {
        napi::Error::from_reason(format!("Failed to initialize QUIC config: {:?}", e))
    })?;

    // Load certificate and key
    config.load_cert_chain_from_pem_file(&cert_path).map_err(|e| {
        napi::Error::from_reason(format!("Failed to load certificate: {:?}", e))
    })?;

    config.load_priv_key_from_pem_file(&key_path).map_err(|e| {
        napi::Error::from_reason(format!("Failed to load private key: {:?}", e))
    })?;

    // Bind to a UDP socket
    let socket = UdpSocket::bind("0.0.0.0:443").map_err(io_err_to_napi)?;

    let mut buf = [0; 65535];

    loop {
        let (len, src) = socket.recv_from(&mut buf).map_err(io_err_to_napi)?;

        // Process incoming QUIC packets
        let hdr = quiche::Header::from_slice(&mut buf[..len], quiche::MAX_CONN_ID_LEN)
            .map_err(|e| napi::Error::from_reason(format!("Failed to parse QUIC header: {:?}", e)))?;

        let conn_id = hdr.dcid.to_vec();
        let mut conn = quiche::accept(
            &quiche::ConnectionId::from_ref(&conn_id),
            None,
            src,
            src, // In real scenario, the source and destination should be set properly
            &mut config,
        ).map_err(|e| napi::Error::from_reason(format!("Failed to accept QUIC connection: {:?}", e)))?;

        let recv_info = quiche::RecvInfo { from: src, to: src };
        conn.recv(&mut buf[..len], recv_info).map_err(|e| {
            napi::Error::from_reason(format!("Failed to process QUIC packet: {:?}", e))
        })?;
    }

    Ok("QUIC server setup complete.".to_string())
}

