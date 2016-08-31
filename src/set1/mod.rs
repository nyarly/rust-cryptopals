pub mod challenge1;
pub mod challenge2;
pub mod challenge3;
pub mod challenge4;
pub mod challenge5;

// ICK with the pub here
pub mod utils {
  use num_bigint::BigInt;
  use serialize::base64::{STANDARD,ToBase64};
  use std::ops::BitXor;
  use std::iter::{self,FromIterator,IntoIterator};

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

  pub fn full_u8() -> Box<Iterator<Item=u8>> {
    Box::new((0..128).chain((0..128).map(|n| n+128)))
  }

  pub fn scored_decrypt(crypted: &[u8], key: u8) -> (u32, Vec<u8>) {
    let trial = decrypt(crypted, key);
    (english_score(&trial), trial)
  }

  pub fn best_score<I>(mut list: I) -> Option<(u32, Vec<u8>)> where
    I: Iterator<Item=(u32, Vec<u8>)>
    {
      match list.next() {
        None => None,
        Some(v) =>
          Some(list.fold(v, |best, candidate| {
            let (max_score, _) = best;
            let (score, _) = candidate;
            if score > max_score {
              candidate
            } else {
              best
            }}))
      }
    }

  pub fn xor_iters<I,J,K,V>(pvec: I, kvec: J) -> K
    where I: IntoIterator<Item=V>,
          J: IntoIterator<Item=V>,
          K: FromIterator<<V as BitXor>::Output>,
          V: BitXor {
            pvec.into_iter()
              .zip(kvec)
              .map(|(p,k)| p ^ k)
              .collect()
          }

  pub fn decrypt(crypted: &[u8], key: u8) -> Vec<u8> {
    xor_iters(crypted, iter::repeat(&key))
  }

  pub fn english_score(bytes: &[u8]) -> u32 {
    bytes.iter()
      .fold(1, |score, letter|
            if score == 0 {
              0
            } else {
              match *letter {
                b' ' =>  score + 130,
                b'e'|b'E' => score + 127,
                b't'|b'T' => score + 90,
                b'a'|b'A' => score + 81,
                b'o'|b'O'|b'\n'|b'\t'|b'\r' => score + 75,
                b'i'|b'I' => score + 69,
                b'n'|b'N' => score + 67,
                b's'|b'S' => score + 63,
                b'h'|b'H' => score + 60,
                b'r'|b'R' => score + 59,
                b'd'|b'D' => score + 42,
                b'l'|b'L' => score + 40,
                b'c'|b'C' => score + 27,
                b'u'|b'U' => score + 27,
                b' '...b'~' => score,
                _ =>  0,
              }
            }

    )
  }


  #[cfg(test)]
  mod tests {
    use super::*;
    use num_bigint::BigInt;
    use num::cast::ToPrimitive;
    #[test]
    fn can_bigint_from_hex() {
      assert_eq!( BigInt::to_u32(&super::hex2bigint("a7").unwrap()).unwrap(), 167)
    }

    #[test]
    fn full_u8_is_goes_to_255() {
      assert_eq!(full_u8().last().unwrap(), 255u8)
    }

    fn string_score(s: &str) -> u32 {
      let v = String::from(s).into_bytes();
      english_score(&v)
    }

    #[test]
    fn double_decrypt() {
      let orig = String::from("1234").into_bytes();
      let d = decrypt(&orig, 138);
      let p = decrypt(&d, 138);
      assert_eq!(orig, p)
    }

    #[test]
    fn scores_english() {
      assert!(string_score("some words") > 0);
      assert!(string_score("some words") > string_score("zxcvb"));
      assert!(string_score(";;;;;") == 1)
    }

  }
}
