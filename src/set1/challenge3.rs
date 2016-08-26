///The hex encoded string:
///
///1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
///... has been XOR'd against a single character. Find the key, decrypt the message.
///
///You can do this by hand. But don't: write code to do it for you.
///
/// # Examples
///
/// ```
/// # use cryptopals::set1::challenge3::best_decrypt;
///
/// let best = best_decrypt("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
/// assert_eq!(
///   String::from_utf8(best).unwrap(),
///   "Cooking MC's like a pound of bacon"
/// )
/// ```
pub fn best_decrypt(encrypted: &str) -> Vec<u8> {
  let cstr = hex2bytes(encrypted).unwrap();
  let mut max_score = 0;
  let mut best = decrypt(cstr.clone(), b'0');

  for c in 0..255 {
    let (trial, score) = scored_decrypt(cstr.clone(), c);
    if score > max_score {
      best = trial;
      max_score = score
    }
  }
  best
}

pub fn scored_decrypt(crypted: Vec<u8>, key: u8) -> (u32, Vec<u8>) {
    let trial = decrypt(cstr.clone(), c);
    (english_score(&trial), trial)
}

use super::utils::*;
use std::iter;

pub fn decrypt(crypted: Vec<u8>, key: u8) -> Vec<u8> {
  xor_iters(crypted, iter::repeat(key))
}

pub fn english_score(bytes: &Vec<u8>) -> u32 {
  bytes.iter()
    .fold(1, |score, letter|
          if score == 0 {
            0
          } else {
            match *letter {
              b' ' =>  score + 13 ,
              b'e'|b'E' => score + 13,
              b't'|b'T' => score + 12,
              b'a'|b'A' => score + 11,
              b'o'|b'O' => score + 10,
              b'i'|b'I' => score + 9,
              b'n'|b'N' => score + 8,
              b's'|b'S' => score + 7,
              b'h'|b'H' => score + 6,
              b'r'|b'R' => score + 5,
              b'd'|b'D' => score + 4,
              b'l'|b'L' => score + 3,
              b'c'|b'C' => score + 2,
              b'u'|b'U' => score + 1,
              b' '...b'~' => score,
              _ =>  0,
            }
          }

          )
}

#[cfg(test)]
mod test {
  use super::*;

  fn string_score(s: &str) -> u32 {
    let v = String::from(s).into_bytes();
    english_score(&v)
  }

  #[test]
  fn scores_english() {
    assert!(string_score("some words") > 0);
    assert!(string_score("some words") > string_score("zxcvb"));
    assert!(string_score(";;;;;") == 1)
  }

  #[test]
  fn double_decrypt() {
    let orig = String::from("1234").into_bytes();
    let d = decrypt(orig.clone(), 138);
    let p = decrypt(d, 138);
    assert_eq!(orig, p)
  }
}
