use utils::*;
use frequency;
use result::CrackError;
use byte_convert::open_base64_path;

/// There's a file here. It's been base64'd after being encrypted with repeating-key XOR.
///
/// Decrypt it.
/// Here's how:
/// # Examples
/// ```
/// use ::cryptopals::set1::challenge6::crack_repeating_key_xor;
/// let answer = crack_repeating_key_xor("s1c6.txt").unwrap();
/// let (keysize, key, result) = answer;
/// assert_eq!(keysize, 29);
/// assert_eq!(key, String::from("Terminator X: Bring the noise"));
/// assert!(result.find("Supercalafragilisticexpialidocious").is_some())
pub fn crack_repeating_key_xor(path: &str) -> Result<(usize, String, String), CrackError> {
  let crypted = try!(open_base64_path(path));
  let keysize = try!(pick_keysize(&crypted));
  let key = try!(String::from_utf8((0..keysize)
                                     .map(|offset| {
                                       key_for_slice(&crypted, offset, keysize).unwrap()
                                     })
                                     .collect()));
  let cryptstr = try!(String::from_utf8(crypted));
  Ok((keysize,
      key.clone(),
      try!(super::challenge5::repeating_key_xor(&cryptstr, &key).ok_or("empty crypt"))))
}

fn hamming(left: &str, right: &str) -> u32 {
  left.bytes().zip(right.bytes()).fold(0, |dist, (lb, rb)| (lb ^ rb).count_ones() + dist)
}

fn pick_keysize(crypted: &[u8]) -> Result<usize, CrackError> {
  best_score((2..40).map(|a_keysize| {
    let mut chunks = crypted.chunks(a_keysize);
    let a = chunks.next().unwrap();
    let pair = (((chunks.take(8)
                        .fold(0, |acc, chunk| {
                          acc +
                          hamming(&String::from_utf8(a.to_vec()).unwrap(),
                                  &String::from_utf8(chunk.to_vec()).unwrap())
                        }) as f64 / a_keysize as f64) * 100.0) as u32,
                a_keysize);
    pair
  }))
    .map(|(_sc, ks)| ks)
    .ok_or(CrackError::Str("empty keysize range"))
}

fn get_slice(crypted: &[u8], offset: usize, keysize: usize) -> Vec<u8> {
  crypted.iter()
         .enumerate()
         .filter_map(|(i, c)| {
           if i % keysize == offset {
             Some(*c)
           } else {
             None
           }
         })
         .collect()
}

fn key_for_slice(crypted: &[u8], offset: usize, keysize: usize) -> Option<u8> {
  let slice = get_slice(crypted, offset, keysize);
  frequency::Counts::new(slice)
    .most_congruent_item(&(*frequency::ENGLISH_FREQS),
                         &(*frequency::ENGLISH_PENALTIES),
                         25,
                         |a, b| a ^ b)
    .map(|(_sc, key)| key)
}

#[cfg(test)]
mod test {
  fn munge_string(v: Vec<u8>) -> String {
    v.iter()
     .cloned()
     .map(|b| b as char)
     .collect()
  }

  #[test]
  fn get_slice() {
    let t = "0123456789".as_bytes();
    assert_eq!(munge_string(super::get_slice(t, 0, 2)), "02468");
    assert_eq!(munge_string(super::get_slice(t, 1, 2)), "13579");
    assert_eq!(munge_string(super::get_slice(t, 0, 3)), "0369");
    assert_eq!(munge_string(super::get_slice(t, 1, 3)), "147");
    assert_eq!(munge_string(super::get_slice(t, 2, 3)), "258");
  }


  #[test]
  fn hamming() {
    assert_eq!(super::hamming("this is a test", "wokka wokka!!!"), 37)
  }

}
