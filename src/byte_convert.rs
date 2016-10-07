use num_bigint::BigInt;
use serialize::base64::{self, ToBase64};
use result::{Result, CrackError};
use std::fs::File;
use std::io::{BufReader, Read};
use ::serialize::base64::FromBase64;

pub fn hex2bigint(hex: &str) -> ::std::result::Result<BigInt, &'static str> {
    return BigInt::parse_bytes(hex.as_bytes(), 16).ok_or("Couldn't parse as hex");
}

pub fn bigint2base64(num: BigInt) -> ::std::result::Result<String, &'static str> {
    let (_, bytes) = num.to_bytes_be();

    return Ok(bytes.to_base64(base64::STANDARD));
}

pub fn hex2bytes(hex: &str) -> ::std::result::Result<Vec<u8>, &'static str> {
    let (_, uint) = try!(hex2bigint(hex)).to_bytes_be();
    Ok(uint)
}

pub fn open_base64_path(path: &str) -> Result<Vec<u8>> {
    let file = try!(File::open(path));
    let mut buf = BufReader::new(file);
    let mut b64bytes = Vec::new();
    try!(buf.read_to_end(&mut b64bytes));
    b64bytes.from_base64().map_err(|e| CrackError::from(e))
}
