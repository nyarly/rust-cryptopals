fn hamming(left: &str, right: &str) -> u32 {
  left.bytes().zip(right.bytes()).fold(0, |dist, (lb, rb)| {
    (lb ^ rb).count_ones() + dist
  })
}

#[cfg(test)]
mod test {

  #[test]
  fn hamming() {
    assert_eq!(super::hamming("this is a test", "wokka wokka!!!"), 37)
  }

}
