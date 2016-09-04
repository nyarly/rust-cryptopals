use num_bigint::BigInt;
use serialize::base64::{self,ToBase64};

pub fn hex2bigint(hex: &str) -> Result<BigInt,&'static str> {
  return BigInt::parse_bytes(hex.as_bytes(), 16).ok_or("Couldn't parse as hex")
}

pub fn bigint2base64(num: BigInt) -> Result<String, &'static str> {
  let (_, bytes) = num.to_bytes_be();

  return Ok(bytes.to_base64(base64::STANDARD))
}

pub fn hex2bytes(hex: &str) -> Result<Vec<u8>, &'static str> {
  let (_, uint) = try!(hex2bigint(hex)).to_bytes_be();
  Ok(uint)
}
