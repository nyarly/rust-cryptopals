use std::ops::BitXor;
use std::iter::{self, FromIterator, IntoIterator};

pub fn scored_decrypt(crypted: &[u8], key: u8) -> (u32, Vec<u8>) {
  let trial = decrypt(crypted, key);
  let score = super::frequency::english_score(&trial);
  // println!("{:?} {:?}", score, String::from_utf8(trial.clone()).unwrap_or(String::from("no")));
  (score, trial)
}

pub fn xor_iters<I, J, K, V>(pvec: I, kvec: J) -> K
  where I: IntoIterator<Item = V>,
        J: IntoIterator<Item = V>,
        K: FromIterator<<V as BitXor>::Output>,
        V: BitXor
{
  pvec.into_iter()
      .zip(kvec)
      .map(|(p, k)| p ^ k)
      .collect()
}

pub fn decrypt(crypted: &[u8], key: u8) -> Vec<u8> {
  xor_iters(crypted, iter::repeat(&key))
}


#[cfg(test)]
mod tests {
  use super::*;
  use ::byte_convert::*;
  use num_bigint::BigInt;
  use num::cast::ToPrimitive;

  fn make_string(bytes: Vec<u8>) -> String {
    String::from_utf8(bytes).unwrap()
  }

  #[test]
  fn example_xor() {
    assert_eq!(make_string(xor_iters(hex2bytes("1c0111001f010100061a024b53535009181c").unwrap(),
                                     hex2bytes("686974207468652062756c6c277320657965").unwrap())),
               make_string(hex2bytes("746865206b696420646f6e277420706c6179").unwrap()))
  }

  #[test]
  fn can_bigint_from_hex() {
    assert_eq!(BigInt::to_u32(&hex2bigint("a7").unwrap()).unwrap(), 167)
  }

  #[test]
  fn double_decrypt() {
    let orig = String::from("1234").into_bytes();
    let d = decrypt(&orig, 138);
    let p = decrypt(&d, 138);
    assert_eq!(orig, p)
  }
}
