pub use super::utils::*;

#[cfg(test)]
mod tests {
  use super::*;

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
}
