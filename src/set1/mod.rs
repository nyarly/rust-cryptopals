pub mod challenge1;
//pub mod challenge2;
//pub mod challenge3;
pub mod challenge4;
pub mod challenge5;
pub mod challenge6;

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
/// # use cryptopals::set1::best_hex_decrypt;
///
/// let best = best_hex_decrypt("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
/// assert_eq!(
///   String::from_utf8(best).unwrap(),
///   "Cooking MC's like a pound of bacon"
/// )
/// ```
use ::byte_convert::*;
pub fn best_hex_decrypt(encrypted: &str) -> Vec<u8> {
  let cstr = hex2bytes(encrypted).unwrap();

  best_decrypt(&cstr)
}

pub fn best_decrypt(cstr: &[u8]) -> Vec<u8> {
  let (_, best) = utils::best_score(utils::full_u8().map(|c| xor::scored_decrypt(&cstr, c)))
    .unwrap_or_else(|| (0, xor::decrypt(&cstr, b'0')));
  best
}

mod frequency {
  use std::collections::btree_map::BTreeMap;
  // lower is better now
  pub fn english_score(bytes: &[u8]) -> u32 {
    let fc = frequency_counts(bytes);

    rmsd(congruent_counts(english_freqs(), fc).values().cloned(), english_freqs().values().cloned())
  }

  pub fn isomorph_score(bytes: &[u8]) -> u32 {
    let fc = frequency_counts(bytes);
    let score = rmsd(sorted_counts(fc), sorted_counts(english_freqs()));
    println!("= {}\n", score);
    score
  }

  fn sorted_counts(unsorted: BTreeMap<u8,u32>) -> Vec<u32> {
    let mut res = unsorted.values().cloned().collect::<Vec<_>>();
    res.sort_by(|l,r| r.cmp(l));
    res
  }

  fn rmsd<I>(left: I, right: I) -> u32 where I: IntoIterator<Item=u32> + Clone {
    println!("{:?} vs \n{:?}", left.clone().into_iter().collect::<Vec<_>>(), right.clone().into_iter().collect::<Vec<_>>());
    let sod = squares_of_differences(left, right);
    (sod.iter().fold(0, |acc, n| acc + n) as f64 / sod.len() as f64).sqrt() as u32
  }

  fn frequency_counts(bytes: &[u8]) -> BTreeMap<u8,u32> {
    let mut fc = BTreeMap::new();
    let mut count = 0;
    for c in bytes {
      let entry = fc.entry(*c).or_insert(0);
      *entry += 1;
      count += 1
    }
    let factor = 1000.0 / count as f64;
    for (_, count) in fc.iter_mut() {
      *count = (*count as f64 * factor) as u32
    }
    fc
  }

  fn congruent_counts(like: BTreeMap<u8,u32>, from: BTreeMap<u8,u32>) -> BTreeMap<u8, u32> {
    let mut res = BTreeMap::new();
    for key in like.keys() {
      res.insert(*key, from.get(key).map(|kr| kr.clone()).unwrap_or(0));
    }
    res
  }

  fn english_freqs() -> BTreeMap<u8,u32> {
    let mut ef = BTreeMap::new();
    ef.insert(b' ', 130);
    ef.insert(b'e', 127);
    ef.insert(b'E', 127);
    ef.insert(b't', 90);
    ef.insert(b'T', 90);
    ef.insert(b'a', 81);
    ef.insert(b'A', 81);
    ef.insert(b'o', 75);
    ef.insert(b'O', 75);
    ef.insert(b'\n', 75);
    ef.insert(b'\t', 75);
    ef.insert(b'\r', 75);
    ef.insert(b'i', 69);
    ef.insert(b'I', 69);
    ef.insert(b'n', 67);
    ef.insert(b'N', 67);
    ef.insert(b's', 63);
    ef.insert(b'S', 63);
    ef.insert(b'h', 60);
    ef.insert(b'H', 60);
    ef.insert(b'r', 59);
    ef.insert(b'R', 59);
    ef.insert(b'd', 42);
    ef.insert(b'D', 42);
    ef.insert(b'l', 40);
    ef.insert(b'L', 40);
    ef.insert(b'c', 27);
    ef.insert(b'C', 27);
    ef.insert(b'u', 27);
    ef.insert(b'U', 27);
    ef
  }

  fn squares_of_differences<I: IntoIterator<Item=u32>>(left: I, right: I) -> Vec<u32> {
    left.into_iter().zip(right.into_iter())
      .map(|(l,r)| (l as i32 - r as i32).pow(2) as u32)
      .collect()
  }

  #[cfg(test)]
  mod tests {
    use super::*;
    fn string_score(s: &str) -> u32 {
      let v = String::from(s).into_bytes();
      english_score(&v)
    }

    #[test]
    fn scores_english() {
      assert!(string_score("some words") > 0,
              "score = {}", string_score("some_words"));
      assert!(string_score("some words") < string_score("zxcvb"),
              "'some words' = {} 'zxcvb' = {}", string_score("some words"), string_score("zxcvb"));
      assert!(string_score(";;;;;") > 71, "';;;;;' = {}", string_score(";;;;;"))
    }

  }
}

mod utils {
  pub fn full_u8() -> Box<Iterator<Item=u8>> {
    Box::new((0..128).chain((0..128).map(|n| n+128)))
  }

  pub fn best_score<I, S, V>(list: I) -> Option<(S, V)>
    where I: Iterator<Item=(S, V)>,
          S: Ord + Clone
    { list.min_by_key(|&(ref score,_)| score.clone()) }

  #[cfg(test)]
  mod tests {
    use super::*;
    #[test]
    fn full_u8_is_goes_to_255() {
      assert_eq!(full_u8().last().unwrap(), 255u8)
    }
  }
}
mod xor {
  use std::ops::BitXor;
  use std::iter::{self,FromIterator,IntoIterator};

  pub fn scored_decrypt(crypted: &[u8], key: u8) -> (u32, Vec<u8>) {
    let trial = decrypt(crypted, key);
    let score =super::frequency::english_score(&trial);
    println!("{:?} {:?}", score, String::from_utf8(trial.clone()).unwrap_or(String::from("no")));
    (score, trial)
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
      assert_eq!(
        make_string(xor_iters(
            hex2bytes("1c0111001f010100061a024b53535009181c").unwrap(),
            hex2bytes("686974207468652062756c6c277320657965").unwrap()
            )),
            make_string(hex2bytes("746865206b696420646f6e277420706c6179").unwrap())
            )
    }

    #[test]
    fn can_bigint_from_hex() {
      assert_eq!( BigInt::to_u32(&hex2bigint("a7").unwrap()).unwrap(), 167)
    }

    #[test]
    fn double_decrypt() {
      let orig = String::from("1234").into_bytes();
      let d = decrypt(&orig, 138);
      let p = decrypt(&d, 138);
      assert_eq!(orig, p)
    }
  }
}
