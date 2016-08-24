use super::hex2bigint;
use std::str;

fn hex2bytes(hex: &str) -> Result<Vec<u8>, &'static str> {
  let (_, uint) = try!(hex2bigint(hex)).to_bytes_be();
  Ok(uint)
}

pub fn xor_strings<'g>(plain: &'g str, key: &'g str) -> Result<String, &'static str> {
  let pvec = try!(hex2bytes(plain));
  let kvec = try!(hex2bytes(key));

  String::from_utf8(
    pvec.iter()
    .zip(kvec)
    .map(|(p,k)|
         p ^ k
        )
    .collect()
    ).map_err(|_| "problems making a string of result")
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn example_xor() {
    assert_eq!(
      xor_strings("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965").unwrap(),
      "686974207468652062756c6c277320657965"
      )
  }
}
