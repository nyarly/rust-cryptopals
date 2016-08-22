extern crate num_bigint;
extern crate num;
extern crate rustc_serialize as serialize;

pub mod set1 {
  pub mod challenge1 {

    use num_bigint::BigInt;
    use serialize::base64::{STANDARD,ToBase64};


    fn hex2bigint(hex: &str) -> Result<BigInt,&'static str> {
      return BigInt::parse_bytes(hex.as_bytes(), 16).ok_or("Couldn't parse as hex")
    }

    fn bigint2base64<'a>(num: BigInt) -> Result<&'a str, &'static str> {
      let (_, bytes) = num.to_bytes_be();

      return Ok(&bytes.to_base64(STANDARD))
    }

    pub fn hex2base64(hex: &str) -> Result<&str, &'static str> {
      bigint2base64(hex2bigint(hex))
    }
    #[cfg(test)]
    mod tests {
      use num_bigint::BigInt;
      use num::cast::ToPrimitive;
      #[test]
      fn can_bigint_from_hex() {
        assert_eq!( BigInt::to_u32(&super::hex2bigint("a7").unwrap()).unwrap(), 167)
      }

      #[test]
      fn it_works() {
        assert_eq!(
          super::hex2base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"),
          "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
          )
      }
    }
  }
}
