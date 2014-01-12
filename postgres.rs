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

struct FieldInfo {
    name: ~str,
    oid: i32,
    attr_nr: i16,
    type_oid: i32,
    typlen: i16,
    atttypmod: i32,
    formatcode: i16
}

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
    MsgStartupMessage {proto_version: i32, params: ~[(~str, ~str)]},
    MsgSSLRequest {ssl_request_code: i32}
}

fn write_cstring(io: &mut BufferedStream<TcpStream>, str: &str) {
      io.write_str(str);
      io.write_u8(0);
}

fn write_startup_message(io: &mut BufferedStream<TcpStream>, params: &[(&str, &str)]) {
    let mut sz: uint = 8 + 1;

    for &(k, v) in params.iter() {
      sz += k.len() + 1 + v.len() + 1;
    } 

    io.write_be_i32(sz as i32);
    io.write_be_i32(PROTO_VERSION);

    for &(k, v) in params.iter() {
        write_cstring(io, k);
        write_cstring(io, v);
    }
    io.write_u8(0);
    io.flush();
}

// body_size excludes the typ byte and the size i32
fn write_message_header(io: &mut BufferedStream<TcpStream>, typ: u8, payload: uint) {
    io.write_u8(typ);
    io.write_be_i32((payload + 4) as i32);
}

fn write_query_message(io: &mut BufferedStream<TcpStream>, query: &str) {
    write_message_header(io, 'Q' as u8, query.len() + 1); 
    write_cstring(io, query);
    io.flush();
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

fn parse_message_header(io: &mut BufferedStream<TcpStream>) -> (u8, i32) {
    let typ = io.read_u8();
    let len = io.read_be_i32();
    return (typ, len);
}

fn main() {
    let addr = from_str::<SocketAddr>("127.0.0.1:5432").unwrap();
    let tcp_stream = TcpStream::connect(addr).unwrap();
    let mut io = BufferedStream::new(tcp_stream);
    write_startup_message(&mut io, [("user", "mneumann"), ("database", "test")]);

    let (typ, len) = parse_message_header(&mut io);
    println!("Typ: {:u} / len: {:d}", typ, len);

    if typ == 82 /* 'R' */ {
        let authmsg = parse_auth_message(&mut io, len-4);
        println!("{:?}", authmsg);
    }
    else {
        fail!();
    }

    write_query_message(&mut io, "select * from articles;");
    
    let (typ, len) = parse_message_header(&mut io);
    println!("Typ: {:u} / len: {:d}", typ, len);
}
