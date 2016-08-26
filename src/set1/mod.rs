pub mod challenge1;
pub mod challenge2;
pub mod challenge3;
pub mod challenge4;


mod utils {
  use num_bigint::BigInt;
  use serialize::base64::{STANDARD,ToBase64};
  use std::ops::BitXor;
  use std::iter::{FromIterator,IntoIterator};

  pub fn hex2bigint(hex: &str) -> Result<BigInt,&'static str> {
    return BigInt::parse_bytes(hex.as_bytes(), 16).ok_or("Couldn't parse as hex")
  }

  pub fn bigint2base64(num: BigInt) -> Result<String, &'static str> {
    let (_, bytes) = num.to_bytes_be();

    return Ok(bytes.to_base64(STANDARD))
  }

  pub fn hex2bytes(hex: &str) -> Result<Vec<u8>, &'static str> {
    let (_, uint) = try!(hex2bigint(hex)).to_bytes_be();
    Ok(uint)
  }

  pub fn xor_iters<I,J,V>(pvec: I, kvec: J) -> I
    where I: IntoIterator<Item=V>+FromIterator<<V as BitXor>::Output>,
          J: IntoIterator<Item=V>,
          V: BitXor {
            pvec.into_iter()
              .zip(kvec)
              .map(|(p,k)|
                   p ^ k
                  )
              .collect()
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
}
