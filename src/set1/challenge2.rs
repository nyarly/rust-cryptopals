fn hex2bytes(hex: &str) -> Result([u8], &'static str) {
  try!(hex2bigint).to_bytes_be();
}

pub fn xor_strings<'g>(plain: &'g str, _: &'g str) -> Result<&'g str, &'static str> {
  let pbytes = try!(hex2bytes(plain));
  let kbytes = try!(hex2bytes(key));


  Ok(plain)
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
