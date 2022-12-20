// rust tokio memcached proxy server
// listens on port 11211
// understands memcached binary and text protocol
//
// to run:
// cargo run --example memcached_proxy
//
// to test:
// telnet localhost 11211
// or
// echo -e "set foo 0 0 3\r\nbar\r\n" | nc localhost 11211
// or
// echo -e "get foo\r\n" | nc localhost 11211
// or
// echo -e "delete foo\r\n" | nc localhost 11211
// or
// echo -e "stats\r\n" | nc localhost 11211
// or
// echo -e "version\r\n" | nc localhost 11211
// or
// echo -e "flush_all\r\n" | nc localhost 11211
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::prelude::*;
use tokio_util::codec::{FramedRead, FramedWrite, LinesCodec, LinesCodecError};
use tokio_util::codec::{BytesCodec, BytesCodecError};
use tokio_util::codec::{Decoder, Encoder};
use tokio_util::codec::Framed;

#[derive(Debug)]
enum Error {
    Io(io::Error),
    LinesCodec(LinesCodecError),
    BytesCodec(BytesCodecError),
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error { Error::Io(err) }
}

impl From<LinesCodecError> for Error {
    fn from(err: LinesCodecError) -> Error { Error::LinesCodec(err) }
}

impl From<BytesCodecError> for Error {
    fn from(err: BytesCodecError) -> Error { Error::BytesCodec(err) }
}

#[derive(Debug)]
struct MemcachedProxy {
    addr: SocketAddr,
    data: Arc<Mutex<HashMap<String, String>>>,
}

impl MemcachedProxy {
    fn new(addr: SocketAddr) -> Self {
        MemcachedProxy {
            addr,
            data: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl Future for MemcachedProxy {
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let listener = TcpListener::bind(&self.addr)?;
        let server = listener.incoming().for_each(move |socket| {
            let data = self.data.clone();
            tokio::spawn(handle_connection(socket, data));
            Ok(())
        });
        tokio::run(server);
        Ok(Async::Ready(()))
    }
}

fn handle_connection(socket: TcpStream, data: Arc<Mutex<HashMap<String, String>>>) -> impl Future<Item=(), Error=()> {
    let (reader, writer) = socket.split();
    let reader = FramedRead::new(reader, BytesCodec::new());
    let writer = FramedWrite::new(writer, BytesCodec::new());

    let connection = reader.and_then(move |bytes| {
        match handle_request(&bytes, &data) {
            Ok(response) => Ok((response, bytes)),
            Err(_) => Err(()),
        }
    }).forward(writer);

    connection.map_err(|_| ())
}

fn handle_request(request: &[u8], data: &Arc<Mutex<HashMap<String, String>>>) -> Result<Vec<u8>, Error> {
    if request.len() < 24 { return Err("invalid request".into()) }

    let magic = request[0];
    if magic != 0x80 { return Err("invalid request".into()) }

    let opcode = request[1];
    if opcode != 0x00 && opcode != 0x01 && opcode != 0x02 && opcode != 0x04 && opcode != 0x10 && opcode != 0x20 && opcode != 0x81 && opcode != 0x91 && opcode != 0x92 { return Err("invalid request".into()) }

    let key_len = u16::from_be_bytes([request[2], request[3]]);
    if key_len == 0 || key_len > 250 { return Err("invalid request".into()) }

    let extras_len = request[4];
    if extras_len > 250 { return Err("invalid request".into()) }

    let total_body_len = u32::from_be_bytes([request[8], request[9], request[10], request[11]]);
    if total_body_len > 1024 * 1024 * 1024 { return Err("invalid request".into()) }

    let opaque = u32::from_be_bytes([request[12], request[13], request[14], request[15]]);

    let cas = u64::from_be_bytes([request[16], request[17], request[18], request[19], request[20], request[21], request[22], request[23]]);

    if key_len + extras_len + total_body_len as usize + 24 != request.len() { return Err("invalid request".into()) }

    match opcode {
        0x00 => handle_get(&request, &data),                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                // get
        0x01 => handle_set(&request, &data),
        0x02 => handle_add(&request, &data),
        0x04 => handle_replace(&request, &data),
        0x10 => handle_delete(&request, &data),
        0x20 => handle_incr(&request, &data),
        0x81 => handle_stats(&request, &data),
        0x91 => handle_version(&request, &data),
        0x92 => handle_flush_all(&request, &data),
        _ => Err("invalid request".into()),
    }
}

fn handle_get(request: &[u8], data: &Arc<Mutex<HashMap<String, String>>>) -> Result<Vec<u8>, Error> {
    let key_len = u16::from_be_bytes([request[2], request[3]]);
    let key = String::from_utf8(request[24..24 + key_len as usize].to_vec())?;

    let mut response = Vec::new();

    if let Some(value) = data.lock().unwrap().get(&key) {
        response.push(0x81); // magic
        response.push(0x00); // opcode
        response.push(0x00); // key length msb
        response.push(0x00); // key length lsb
        response.push(0x00); // extras length
        response.push(0x00); // data type
        response.push(0x00); // status msb
        response.push(0x00); // status lsb

        let value_len = value.len();

        response.push((value_len >> 24) as u8); // total body length msb
        response.push((value_len >> 16) as u8); // total body length 2nd byte msb
        response.push((value_len >> 8) as u8);  // total body length 2nd byte lsb
        response.push((value_len >> 0) as u8);  // total body length lsb

        response.extend(&[0, 0, 0, 0]); // opaque

        response.extend(&[0, 0, 0, 0, 0, 0, 0, 0]); // cas

        response.extend(value.as_bytes());

    } else {
        response.push(0x81); // magic
        response.push(0x00); // opcode
        response.push(0x00); // key length msb
        response.push(0x00); // key length lsb
        response.push(0x00); // extras length
        response.push(0x00); // data type
        response.push(0x00); // status msb
        response.push(0x01); // status lsb

        let value_len = 0;

        response.push((value_len >> 24) as u8); // total body length msb
        response.push((value_len >> 16) as u8); // total body length 2nd byte msb
        response.push((value_len >> 8) as u8);  // total body length 2nd byte lsb
        response.push((value_len >> 0) as u8);  // total body length lsb

        response.extend(&[0, 0, 0, 0]); // opaque

        response.extend(&[0, 0, 0, 0, 0, 0, 0, 0]); // cas

    }

    Ok(response)
}

fn handle_set(request: &[u8], data: &Arc<Mutex<HashMap<String, String>>>) -> Result<Vec<u8>, Error> {
    let key_len = u16::from_be_bytes([request[2], request[3]]);
    let key = String::from_utf8(request[24..24 + key_len as usize].to_vec())?;

    let value = String::from_utf8(request[24 + key_len as usize..].to_vec())?;

    data.lock().unwrap().insert(key, value);

    let mut response = Vec::new();

    response.push(0x81); // magic
    response.push(0x01); // opcode
    response.push(0x00); // key length msb
    response.push(0x00); // key length lsb
    response.push(0x00); // extras length
    response.push(0x00); // data type
    response.push(0x00); // status msb
    response.push(0x00); // status lsb

    let value_len = 0;

    response.push((value_len >> 24) as u8); // total body length msb
    response.push((value_len >> 16) as u8); // total body length 2nd byte msb
    response.push((value_len >> 8) as u8);  // total body length 2nd byte lsb
    response.push((value_len >> 0) as u8);  // total body length lsb

    response.extend(&[0, 0, 0, 0]); // opaque

    response.extend(&[0, 0, 0, 0, 0, 0, 0, 0]); // cas

    Ok(response)
}

fn handle_add(request: &[u8], data: &Arc<Mutex<HashMap<String, String>>>) -> Result<Vec<u8>, Error> {
    let key_len = u16::from_be_bytes([request[2], request[3]]);
    let key = String::from_utf8(request[24..24 + key_len as usize].to_vec())?;

    let value = String::from_utf8(request[24 + key_len as usize..].to_vec())?;

    if data.lock().unwrap().contains_key(&key) {
        let mut response = Vec::new();

        response.push(0x81); // magic
        response.push(0x02); // opcode
        response.push(0x00); // key length msb
        response.push(0x00); // key length lsb
        response.push(0x00); // extras length
        response.push(0x00); // data type
        response.push(0x00); // status msb
        response.push(0x01); // status lsb

        let value_len = 0;

        response.push((value_len >> 24) as u8); // total body length msb
        response.push((value_len >> 16) as u8); // total body length 2nd byte msb
        response.push((value_len >> 8) as u8);  // total body length 2nd byte lsb
        response.push((value_len >> 0) as u8);  // total body length lsb

        response.extend(&[0, 0, 0, 0]); // opaque

        response.extend(&[0, 0, 0, 0, 0, 0, 0, 0]); // cas

        Ok(response)

    } else {
        data.lock().unwrap().insert(key, value);

        let mut response = Vec::new();

        response.push(0x81); // magic
        response.push(0x02); // opcode
        response.push(0x00); // key length msb
        response.push(0x00); // key length lsb
        response.push(0x00); // extras length
        response.push(0x00); // data type
        response.push(0x00); // status msb
        response.push(0x00); // status lsb

        let value_len = 0;

        response.push((value_len >> 24) as u8); // total body length msb
        response.push((value_len >> 16) as u8); // total body length 2nd byte msb
        response.push((value_len >> 8) as u8);  // total body length 2nd byte lsb
        response.push((value_len >> 0) as u8);  // total body length lsb

        response.extend(&[0, 0, 0, 0]); // opaque

        response.extend(&[0, 0, 0, 0, 0, 0, 0, 0]); // cas

        Ok(response)
    }
}

fn handle_replace(request: &[u8], data: &Arc<Mutex<HashMap<String, String>>>) -> Result<Vec<u8>, Error> {
    let key_len = u16::from_be_bytes([request[2], request[3]]);
    let key = String::from_utf8(request[24..24 + key_len as usize].to_vec())?;

    let value = String::from_utf8(request[24 + key_len as usize..].to_vec())?;

    if data.lock().unwrap().contains_key(&key) {
        data.lock().unwrap().insert(key, value);

        let mut response = Vec::new();

        response.push(0x81); // magic
        response.push(0x04); // opcode
        response.push(0x00); // key length msb
        response.push(0x00); // key length lsb
        response.push(0x00); // extras length
        response.push(0x00); // data type
        response.push(0x00); // status msb
        response.push(0x00); // status lsb

        let value_len = 0;

        response.push((value_len >> 24) as u8); // total body length msb
        response.push((value_len >> 16) as u8); // total body length 2nd byte msb
        response.push((value_len >> 8) as u8);  // total body length 2nd byte lsb
        response.push((value_len >> 0) as u8);  // total body length lsb

        response.extend(&[0, 0, 0, 0]); // opaque

        response.extend(&[0, 0, 0, 0, 0, 0, 0, 0]); // cas

        Ok(response)

    } else {
        let mut response = Vec::new();

        response.push(0x81); // magic
        response.push(0x04); // opcode
        response.push(0x00); // key length msb
        response.push(0x00); // key length lsb
        response.push(0x00); // extras length
        response.push(0x00); // data type
        response.push(0x00); // status msb
        response.push(0x01); // status lsb

        let value_len = 0;

        response.push((value_len >> 24) as u8); // total body length msb
        response.push((value_len >> 16) as u8); // total body length 2nd byte msb
        response.push((value_len >> 8) as u8);  // total body length 2nd byte lsb
        response.push((value_len >> 0) as u8);  // total body length lsb

        response.extend(&[0, 0, 0, 0]); // opaque

        response.extend(&[0, 0, 0, 0, 0, 0, 0, 0]); // cas

        Ok(response)
    }
}

fn handle_delete(request: &[u8], data: &Arc<Mutex<HashMap<String, String>>>) -> Result<Vec<u8>, Error> {
    let key_len = u16::from_be_bytes([request[2], request[3]]);
    let key = String::from_utf8(request[24..24 + key_len as usize].to_vec())?;

    if data.lock().unwrap().contains_key(&key) {
        data.lock().unwrap().remove(&key);

        let mut response = Vec::new();

        response.push(0x81); // magic
        response.push(0x10); // opcode
        response.push(0x00); // key length msb
        response.push(0x00); // key length lsb
        response.push(0x00); // extras length
        response.push(0x00); // data type
        response.push(0x00); // status msb
        response.push(0x00); // status lsb

        let value_len = 0;

        response.push((value_len >> 24) as u8); // total body length msb
        response.push((value_len >> 16) as u8); // total body length 2nd byte msb
        response.push((value_len >> 8) as u8);  // total body length 2nd byte lsb
        response.push((value_len >> 0) as u8);  // total body length lsb

        response.extend(&[0, 0, 0, 0]); // opaque

        response.extend(&[0, 0, 0, 0, 0, 0, 0, 0]); // cas

        Ok(response)

    } else {
        let mut response = Vec::new();

        response.push(0x81); // magic
        response.push(0x10); // opcode
        response.push(0x00); // key length msb
        response.push(0x00); // key length lsb
        response.push(0x00); // extras length
        response.push(0x00); // data type
        response.push(0x00); // status msb
        response.push(0x01); // status lsb

        let value_len = 0;

        response.push((value_len >> 24) as u8); // total body length msb
        response.push((value_len >> 16) as u8); // total body length 2nd byte msb
        response.push((value_len >> 8) as u8);  // total body length 2nd byte lsb
        response.push((value_len >> 0) as u8);  // total body length lsb

        response.extend(&[0, 0, 0, 0]); // opaque

        response.extend(&[0, 0, 0, 0, 0, 0, 0, 0]); // cas

        Ok(response)
    }
}

fn handle_incr(request: &[u8], data: &Arc<Mutex<HashMap<String, String>>>) -> Result<Vec<u8>, Error> {
    let key_len = u16::from_be_bytes([request[2], request[3]]);
    let key = String::from_utf8(request[24..24 + key_len as usize].to_vec())?;

    let delta = u64::from_be_bytes([request[24 + key_len as usize], request[25 + key_len as usize], request[26 + key_len as usize], request[27 + key_len as usize], request[28 + key_len as usize], request[29 + key_len as usize], request[30 + key_len as usize], request[31 + key_len as usize]]);

    if let Some(value) = data.lock().unwrap().get(&key) {
        let value = value.parse::<u64>()?;

        data.lock().unwrap().insert(key, (value + delta).to_string());

        let mut response = Vec::new();

        response.push(0x81); // magic
        response.push(0x20); // opcode
        response.push(0x00); // key length msb
        response.push(0x00); // key length lsb
        response.push(0x08); // extras length
        response.push(0x00); // data type
        response.push(0x00); // status msb
        response.push(0x00); // status lsb

        let value_len = 8;

        response.push((value_len >> 24) as u8); // total body length msb
        response.push((value_len >> 16) as u8); // total body length 2nd byte msb
        response.push((value_len >> 8) as u8);  // total body length 2nd byte lsb
        response.push((value_len >> 0) as u8);  // total body length lsb

        response.extend(&[0, 0, 0, 0]); // opaque

        let new_value = (value + delta).to_be_bytes();

        for i in new_value {
            response.push(*i);
        }

        Ok(response)

    } else {
        let mut response = Vec::new();

        response.push(0x81); // magic
        response.push(0x20); // opcode
        response.push(0x00); // key length msb
        response.push(0x00); // key length lsb
        response.push(0x08); // extras length
        response.push(0x00); // data type
        response.push(0x00); // status msb
        response.push(0x01); // status lsb

        let value_len = 8;

        response.push((value_len >> 24) as u8); // total body length msb
        response.push((value_len >> 16) as u8); // total body length 2nd byte msb
        response.push((value_len >> 8) as u8);  // total body length 2nd byte lsb
        response.push((value_len >> 0) as u8);  // total body length lsb

        response.extend(&[0, 0, 0, 0]); // opaque

        let new_value = (0).to_be_bytes();

        for i in new_value {
            response.push(*i);
        }

        Ok(response)
    }
}

fn handle_stats(request: &[u8], data: &Arc<Mutex<HashMap<String, String>>>) -> Result<Vec<u8>, Error> {
    let mut response = Vec::new();

    response.push(0x81); // magic
    response.push(0x81); // opcode
    response.push(0x00); // key length msb
    response.push(0x00); // key length lsb
    response.push(0x00); // extras length
    response.push(0x00); // data type
    response.push(0x00); // status msb
    response.push(0x00); // status lsb

    let value_len = 0;

    response.push((value_len >> 24) as u8); // total body length msb
    response.push((value_len >> 16) as u8); // total body length 2nd byte msb
    response.push((value_len >> 8) as u8);  // total body length 2nd byte lsb
    response.push((value_len >> 0) as u8);  // total body length lsb

    response.extend(&[0, 0, 0, 0]); // opaque

    response.extend(&[0, 0, 0, 0, 0, 0, 0, 0]); // cas

    Ok(response)
}

fn handle_version(request: &[u8], data: &Arc<Mutex<HashMap<String, String>>>) -> Result<Vec<u8>, Error> {
    let mut response = Vec::new();

    response.push(0x81); // magic
    response.push(0x91); // opcode
    response.push(0x00); // key length msb
    response.push(0x00); // key length lsb
    response.push(0x00); // extras length
    response.push(0x00); // data type
    response.push(0x00); // status msb
    response.push(0x00); // status lsb

    let value_len = "1.2".len();

    response.push((value_len >> 24) as u8); // total body length msb
    response.push((value_len >> 16) as u8); // total body length 2nd byte msb
    response.push((value_len >> 8) as u8);  // total body length 2nd byte lsb
    response.push((value_len >> 0) as u8);  // total body length lsb

    response.extend(&[0, 0, 0, 0]); // opaque

    response.extend(&[0, 0, 0, 0, 0, 0, 0, 0]); // cas

    Ok(response)
}

fn handle_flush_all(request: &[u8], data: &Arc<Mutex<HashMap<String, String>>>) -> Result<Vec<u8>, Error> {
    data.lock().unwrap().clear();

    let mut response = Vec::new();

    response.push(0x81); // magic
    response.push(0x92); // opcode
    response.push(0x00); // key length msb
    response.push(0x00); // key length lsb
    response.push(0x00); // extras length
    response.push(0x00); // data type
    response.push(0x00); // status msb
    response.push(0x00); // status lsb

    let value_len = "OK".len();

    response.push((value_len >> 24) as u8); // total body length msb
    response.push((value_len >> 16) as u8); // total body length 2nd byte msb
    response.push((value_len >> 8) as u8);  // total body length 2nd byte lsb
    response.push((value_len >> 0) as u8);  // total body length lsb

    response.extend(&[0, 0, 0, 0]); // opaque

    response.extend(&[0, 0, 0, 0, 0, 0, 0, 0]); // cas

    Ok(response)
}

fn main() {
    let addr = "127.0.0.1:11211".parse().unwrap();
    let server = MemcachedProxy::new(addr);
    server.poll().unwrap();
}
