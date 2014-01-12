#[feature(struct_variant)];

use std::io::buffered::BufferedStream;
use std::io::net::ip::SocketAddr;
use std::io::net::tcp::TcpStream;

static PROTO_VERSION: i32 = 196608; // 3 << 16

#[deriving(ToStr)]
enum AuthType {
    AuthUnknown,
    AuthOk,
    AuthKerberosV4,
    AuthKerberosV5,
    AuthClearTextPassword,
    AuthCryptPassword(u16),
    AuthMD5Password(u32),
    AuthSCMCredential 
}

#[deriving(ToStr)]
struct FieldInfo {
    name: ~str,
    oid: i32,
    attr_nr: i16,
    type_oid: i32,
    typlen: i16,
    atttypmod: i32,
    formatcode: i16
}

#[deriving(ToStr)]
enum Message {
    MsgAuthentification(AuthType), // 'R'
    MsgPassword {password: ~str}, // 'p'
    MsgParameterStatus {key: ~str, val: ~str}, // 'S'
    MsgBackendKeyData {process_id: i32, secret_key: i32}, // 'K'
    MsgReadyForQuery {backend_transaction_status_indicator: u8}, // 'Z'
    MsgDataRow {columns: ~[Option<~[u8]>]}, // 'D'
    MsgCommandComplete {cmd_tag: ~str}, // 'C' 
    MsgEmptyQueryResponse, // 'I'
    MsgNoticeResponse {field_type: u8, field_values: ~[~str]}, // 'N' 
    MsgErrorResponse {field_type: u8, field_values: ~[~str]}, // 'E' 
    MsgCopyInResponse, // 'G'
    MsgCopyOutResponse, // 'H'
    MsgParse {query: ~str, stmt_name: ~str, parameter_oids: ~[i32]}, // 'P'
    MsgParseComplete, // '1'
    MsgQuery {query: ~str}, // 'Q'
    MsgRowDescription {fields: ~[FieldInfo]}, // 'T'
    MsgTerminate, // 'X'
    MsgStartup {proto_version: i32, params: ~[(~str, ~str)]},
    MsgSSLRequest {ssl_request_code: i32}
}

fn write_message(io: &mut BufferedStream<TcpStream>, msg: &Message) {
    match *msg {
        MsgStartup {proto_version, ref params} => {
            let mut sz: uint = 8 + 1;

            for &(ref k, ref v) in params.iter() {
              sz += k.len() + 1 + v.len() + 1;
            }

            io.write_be_i32(sz as i32);
            io.write_be_i32(proto_version);

            for &(ref k, ref v) in params.iter() {
                write_cstring(io, *k);
                write_cstring(io, *v);
            }
            io.write_u8(0);
        }
        MsgQuery {ref query} => {
            write_message_header(io, 'Q' as u8, query.len() + 1);
            write_cstring(io, *query);
        }
        _ => {fail!()}
    }
    io.flush();
}

fn write_cstring(io: &mut BufferedStream<TcpStream>, str: &str) {
      io.write_str(str);
      io.write_u8(0);
}

// body_size excludes the typ byte and the size i32
fn write_message_header(io: &mut BufferedStream<TcpStream>, typ: u8, payload: uint) {
    io.write_u8(typ);
    io.write_be_i32((payload + 4) as i32);
}

fn parse_auth_message(io: &mut BufferedStream<TcpStream>, rem_len: i32) -> AuthType {
    assert!(rem_len >= 4);
    let authtype = io.read_be_i32();
    match authtype {
        0 => AuthOk, 
        1 => AuthKerberosV4,
        2 => AuthKerberosV5,
        3 => AuthClearTextPassword,
        4 => {
            assert!(rem_len >= 4 + 2);
            let salt = io.read_be_u16();
            AuthCryptPassword(salt)
        }
        5 => {
            assert!(rem_len >= 4 + 4);
            let salt = io.read_be_u32();
            AuthMD5Password(salt)
        }
        6 => AuthSCMCredential,
        _ => AuthUnknown
    }
}

// XXX: read max number of bytes
fn read_cstring(io: &mut BufferedStream<TcpStream>) -> ~str {
    let mut b = io.read_until(0).unwrap();
    b.pop();
    std::str::from_utf8_owned(b)
}

fn read_message(io: &mut BufferedStream<TcpStream>) -> Message {
    let ty = io.read_u8();
    let sz = io.read_be_i32();
    assert!(sz >= 4);
    match (ty as char) {
        'R' => MsgAuthentification(parse_auth_message(io, sz-4)),
        'p' => MsgPassword {password: read_cstring(io)},
        'S' => {
            let key = read_cstring(io);
            let val = read_cstring(io); 
            MsgParameterStatus {key: key, val: val}
        },
        'K' => {
             let process_id = io.read_be_i32(); 
             let secret_key = io.read_be_i32(); 
             MsgBackendKeyData {process_id: process_id, secret_key: secret_key}
        }
        'Z' => MsgReadyForQuery {backend_transaction_status_indicator: io.read_u8()},
        'D' => fail!(), // MsgDataRow {columns: ~[Option<~[u8]>]},
        'C' => MsgCommandComplete {cmd_tag: read_cstring(io)},
        'I' => MsgEmptyQueryResponse,
        'N' => fail!(), // MsgNoticeResponse {field_type: u8, field_values: ~[~str]},
        'E' => {
            let mut sz = sz - 5;
            let field_type = io.read_u8();
            let mut arr = ~[];
            while sz > 1 {
                let s = read_cstring(io);
                sz -= (s.len() + 1) as i32;
                (&mut arr).push(s);
            }
            let nul = io.read_u8();
            assert!(nul == 0);

            MsgErrorResponse {field_type: field_type, field_values: arr}
        }
        'G' => MsgCopyInResponse,
        'H' => MsgCopyOutResponse,
        'P' => fail!(), // MsgParse {query: ~str, stmt_name: ~str, parameter_oids: ~[i32]},
        '1' => MsgParseComplete,
        'Q' => MsgQuery {query: read_cstring(io)},
        'T' => fail!(), // MsgRowDescription {fields: ~[FieldInfo]},
        'X' => MsgTerminate,
        _ => fail!()
    }
}

fn main() {
    let addr = from_str::<SocketAddr>("127.0.0.1:5432").unwrap();
    let tcp_stream = TcpStream::connect(addr).unwrap();
    let mut io = BufferedStream::new(tcp_stream);

    let msg = MsgStartup {proto_version: PROTO_VERSION,
                          params: ~[(~"user", ~"mneumann"), (~"database", ~"test")]};

    write_message(&mut io, &msg); 


    loop {
        let msg = read_message(&mut io);
        println!("{:?}", msg);

        match msg {
            MsgReadyForQuery {..} => {
                println!("Done");
                break
            }
            _ => {}
        }
    }

    write_message(&mut io, &MsgQuery {query: ~"select * from articles;"});
    write_message(&mut io, &MsgQuery {query: ~"select * from articles;"});

    let msg = read_message(&mut io);
    println!("{:?}", msg);
}
