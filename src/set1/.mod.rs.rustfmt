pub mod challenge1;
pub mod challenge2;

use num_bigint::BigInt;
use serialize::base64::{STANDARD,ToBase64};

fn hex2bigint(hex: &str) -> Result<BigInt,&'static str> {
  return BigInt::parse_bytes(hex.as_bytes(), 16).ok_or("Couldn't parse as hex")
}

fn bigint2base64(num: BigInt) -> Result<String, &'static str> {
  let (_, bytes) = num.to_bytes_be();

  return Ok(bytes.to_base64(STANDARD))
}

#[cfg(test)]
mod tests {
  use num_bigint::BigInt;
  use num::cast::ToPrimitive;
  #[test]
  fn can_bigint_from_hex() {
    assert_eq!( BigInt::to_u32(&super::hex2bigint("a7").unwrap()).unwrap(), 167)
  }

}
