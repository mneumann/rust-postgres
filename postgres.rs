#[feature(struct_variant)];

extern mod extra;

use std::io::buffered::BufferedStream;
use std::io::net::ip::SocketAddr;
use std::io::net::tcp::TcpStream;
use extra::serialize;
use extra::serialize::Decodable;

/// A structure to decode a Postgres message from a reader.
pub struct Decoder<'a> {
    priv rd: &'a mut BufferedStream<TcpStream>,
    priv remaining_bytes: uint
}

impl<'a> Decoder<'a> {
    /// Creates a new Postgres decoder for decoding from the
    /// specified reader.
    pub fn new(rd: &'a mut BufferedStream<TcpStream>, remaining_bytes: uint) -> Decoder<'a> {
      Decoder { rd: rd, remaining_bytes: remaining_bytes }
    }

    // XXX: read max number of bytes
    fn read_cstr(&mut self) -> ~str {
        let mut b = self.rd.read_until(0).unwrap();
        b.pop();
        std::str::from_utf8_owned(b)
    }

    fn get_remaining_bytes(&self) -> uint { self.remaining_bytes }
}

impl<'a> serialize::Decoder for Decoder<'a> {
    fn read_nil(&mut self) -> () { fail!() }

    fn read_u64(&mut self) -> u64 { fail!() }

    fn read_uint(&mut self) -> uint { fail!() }

    fn read_u32(&mut self) -> u32 { fail!() }

    fn read_u16(&mut self) -> u16 { fail!() }

    fn read_u8(&mut self) -> u8 { self.rd.read_u8() }

    fn read_i64(&mut self) -> i64 { fail!() }

    fn read_int(&mut self) -> int { fail!() }

    fn read_i32(&mut self) -> i32 { self.rd.read_be_i32() } 

    fn read_i16(&mut self) -> i16 { self.rd.read_be_i16() }

    fn read_i8(&mut self) -> i8 { fail!() }

    fn read_bool(&mut self) -> bool { fail!() }

    fn read_f64(&mut self) -> f64 { fail!() }

    fn read_f32(&mut self) -> f32 { fail!() }

    fn read_char(&mut self) -> char { fail!() }

    fn read_str(&mut self) -> ~str { self.read_cstr() }

    fn read_enum<T>(&mut self, _name: &str, _f: |&mut Decoder<'a>| -> T) -> T { fail!() }
    fn read_enum_variant<T>(&mut self, _names: &[&str], _f: |&mut Decoder<'a>, uint| -> T) -> T { fail!() }
    fn read_enum_variant_arg<T>(&mut self, _idx: uint, _f: |&mut Decoder<'a>| -> T) -> T { fail!() }

    fn read_seq<T>(&mut self, f: |&mut Decoder<'a>, uint| -> T) -> T {
        let len = self.read_i16();
        assert!(len >= 0);
        f(self, len as uint)
    }
    
    fn read_seq_elt<T>(&mut self, _idx: uint, f: |&mut Decoder<'a>| -> T) -> T {
        f(self)
    }

    fn read_struct<T>(&mut self, _name: &str, _len: uint, f: |&mut Decoder<'a>| -> T) -> T {
        f(self)
    }

    fn read_struct_field<T>(&mut self, _name: &str, _idx: uint, f: |&mut Decoder<'a>| -> T) -> T {
        f(self)
    }

    fn read_option<T>(&mut self, _f: |&mut Decoder<'a>, bool| -> T) -> T { fail!() }

    fn read_map<T>(&mut self, _f: |&mut Decoder<'a>, uint| -> T) -> T { fail!() }
    fn read_map_elt_key<T>(&mut self, _idx: uint, f: |&mut Decoder<'a>| -> T) -> T { f(self) }
    fn read_map_elt_val<T>(&mut self, _idx: uint, f: |&mut Decoder<'a>| -> T) -> T { f(self) }


    fn read_enum_struct_variant<T>(&mut self, names: &[&str],
                                   f: |&mut Decoder<'a>, uint| -> T)
                                   -> T { self.read_enum_variant(names, f) } 

    fn read_enum_struct_variant_field<T>(&mut self, _name: &str, idx: uint,
                                         f: |&mut Decoder<'a>| -> T)
                                         -> T { self.read_enum_variant_arg(idx, f) }

    fn read_tuple<T>(&mut self, f: |&mut Decoder<'a>, uint| -> T) -> T {
        self.read_seq(f)
    }

    fn read_tuple_arg<T>(&mut self, idx: uint, f: |&mut Decoder<'a>| -> T) -> T {
        self.read_seq_elt(idx, f)
    }

    fn read_tuple_struct<T>(&mut self, _name: &str,
                            f: |&mut Decoder<'a>, uint| -> T)
                            -> T { self.read_tuple(f) }

    fn read_tuple_struct_arg<T>(&mut self, idx: uint,
                                f: |&mut Decoder<'a>| -> T)
                                -> T { self.read_tuple_arg(idx, f) }
}



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

#[deriving(ToStr,Decodable)]
struct FieldInfo {
    name: ~str,
    oid: i32,
    attr_nr: i16,
    type_oid: i32,
    typlen: i16,
    atttypmod: i32,
    formatcode: i16
}

// 'E'
#[deriving(ToStr)]
struct MResponseStatus {
    field_type: u8,
    field_values: ~[~str]
}

// 'K'
#[deriving(ToStr,Decodable)]
struct MBackendKeyData {
    process_id: i32,
    secret_key: i32
}

// 'S'
#[deriving(ToStr,Decodable)]
struct MParameterStatus {
    key: ~str,
    val: ~str
}

// 'T'
#[deriving(ToStr,Decodable)]
struct MRowDescription {
    fields: ~[FieldInfo]
}

// 'D'
#[deriving(ToStr)]
struct MDataRow {
    columns: ~[Option<~[u8]>]
}

impl<'a> serialize::Decodable<Decoder<'a>> for MDataRow {
    fn decode(d: &mut Decoder<'a>) -> MDataRow {
        let ncols = d.rd.read_be_i16();
        assert!(ncols >= 0);
        let mut arr = ~[];

        for _ in range(0, ncols) {
            let len = d.rd.read_be_i32();
            if len == -1 {
                (&mut arr).push(None);
            } else {
                assert!(len >= 0);
                (&mut arr).push(Some(d.rd.read_bytes(len as uint))); 
            }
        }
        MDataRow {columns: arr}
    }
}


#[deriving(ToStr)]
enum Message {
    MsgAuthentification(AuthType), // 'R'
    MsgPassword {password: ~str}, // 'p'
    MsgParameterStatus(MParameterStatus), // 'S'
    MsgBackendKeyData(MBackendKeyData),
    MsgReadyForQuery {backend_transaction_status_indicator: u8}, // 'Z'
    MsgDataRow(MDataRow), // 'D'
    MsgCommandComplete {cmd_tag: ~str}, // 'C' 
    MsgEmptyQueryResponse, // 'I'
    MsgNoticeResponse(MResponseStatus), // 'N' 
    MsgErrorResponse(MResponseStatus), // 'E'
    MsgCopyInResponse, // 'G'
    MsgCopyOutResponse, // 'H'
    MsgParse {query: ~str, stmt_name: ~str, parameter_oids: ~[i32]}, // 'P'
    MsgParseComplete, // '1'
    MsgQuery {query: ~str}, // 'Q'
    MsgRowDescription(MRowDescription), // 'T'
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

fn parse_auth_message<'a>(d: &mut Decoder<'a>) -> AuthType {
    assert!(d.remaining_bytes >= 4);
    let authtype = d.rd.read_be_i32();
    match authtype {
        0 => AuthOk, 
        1 => AuthKerberosV4,
        2 => AuthKerberosV5,
        3 => AuthClearTextPassword,
        4 => {
            assert!(d.remaining_bytes >= 4 + 2);
            let salt = d.rd.read_be_u16();
            AuthCryptPassword(salt)
        }
        5 => {
            assert!(d.remaining_bytes >= 4 + 4);
            let salt = d.rd.read_be_u32();
            AuthMD5Password(salt)
        }
        6 => AuthSCMCredential,
        _ => AuthUnknown
    }
}

impl<'a> serialize::Decodable<Decoder<'a>> for MResponseStatus {
    fn decode(d: &mut Decoder<'a>) -> MResponseStatus {
        let mut sz = d.get_remaining_bytes() - 1;
        let field_type = d.rd.read_u8();
        let mut arr = ~[];
        while sz > 1 {
            let s = d.read_cstr();
            sz -= (s.len() + 1);
            (&mut arr).push(s);
        }
        let nul = d.rd.read_u8();
        assert!(nul == 0);
        assert!(sz - 1 == 0);
        MResponseStatus {field_type: field_type, field_values: arr}
    }
}

fn read_message(io: &mut BufferedStream<TcpStream>) -> Message {
    let ty = io.read_u8();
    let sz = io.read_be_i32();
    assert!(sz >= 4);

    let mut d = Decoder::new(io, sz as uint - 4);

    match (ty as char) {
        'R' => MsgAuthentification(parse_auth_message(&mut d)),
        'p' => MsgPassword {password: d.read_cstr()},
        'S' => MsgParameterStatus(Decodable::decode(&mut d)),
        'K' => MsgBackendKeyData(Decodable::decode(&mut d)),
        'Z' => MsgReadyForQuery {backend_transaction_status_indicator: d.rd.read_u8()},
        'D' => MsgDataRow(Decodable::decode(&mut d)),
        'C' => MsgCommandComplete {cmd_tag: d.read_cstr()},
        'I' => MsgEmptyQueryResponse,
        'N' => MsgNoticeResponse(Decodable::decode(&mut d)),
        'E' => MsgErrorResponse(Decodable::decode(&mut d)),
        'G' => MsgCopyInResponse,
        'H' => MsgCopyOutResponse,
        'P' => fail!(), // MsgParse {query: ~str, stmt_name: ~str, parameter_oids: ~[i32]},
        '1' => MsgParseComplete,
        'Q' => MsgQuery {query: d.read_cstr()},
        'T' => MsgRowDescription(Decodable::decode(&mut d)),
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
    //write_message(&mut io, &MsgQuery {query: ~"select * from articles;"});

    loop {
      let msg = read_message(&mut io);
      println!("{:?}", msg);
    }
}
