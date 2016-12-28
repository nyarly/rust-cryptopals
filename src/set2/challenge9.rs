pub fn pkcs7(data: &[u8], block_size: usize) -> Vec<u8> {
  let padding = block_size - (data.len() % block_size);
  data.iter()
    .chain([padding as u8].iter().cycle().take(padding))
    .map(|c| c.clone())
    .collect()
}

#[cfg(test)]
mod test {
  use super::pkcs7;

  #[test]
  fn padding() {
    assert_eq!(pkcs7("YELLOW SUBMARINE".as_bytes(), 20),
               "YELLOW SUBMARINE\x04\x04\x04\x04".as_bytes())
  }
}
