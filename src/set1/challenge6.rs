use std::fs::File;
use std::io::{BufRead,BufReader};
use super::utils::*;
use ::byte_convert::*;
use super::frequency::Counts;
use super::frequency::ENGLISH_FREQS;
use super::xor;
use ::byte_convert::*;

fn crack_repeating_key_xor() -> Result(String) {
  let file = try!(File::open("s1c6.txt"));
  let buf = BufReader::new(file);
  let crypted = base642bytes(buf);

  let keysize = pick_keysize(crypted);
  let key = (0..keysize).map(|offset| {
    try!(key_for_slice(crypted, offset).ok())
  }).collect();
  (keysize, key, try!(repeating_key_xor(crypted, key)))
}

fn hamming(left: &str, right: &str) -> u32 {
  left.bytes().zip(right.bytes()).fold(0, |dist, (lb, rb)| {
    (lb ^ rb).count_ones() + dist
  })
}

fn pick_keysize(crypted: &[u8]) -> u32 {
  best_score((2..40).iter().map(|a_keysize| {
    chunks = crypted.chunks(a_keysize);
    let a = chunks.next();
    (chunks.take(3).fold(0, |acc, chunk| acc + hamming(a, chunk)) as f64 / a_keysize as f64, keysize)
  }))
}

fn key_for_slice(crypted: &[u8], offset: usize) -> Option<u8> {
    let sliced = crypted
      .enumerate()
      .filter_map(|(i, c)|
                  match i % keysize {
                    offset => Some(c),
                    _ => None
                  });
    Count::new(sliced)
      .most_congruent_item(&(*ENGLISH_FREQS), 0, |a,b| a^b)
      .map(|(sc, key)| key)
}

#[cfg(test)]
mod test {

  #[test]
  fn hamming() {
    assert_eq!(super::hamming("this is a test", "wokka wokka!!!"), 37)
  }

}
