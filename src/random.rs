use rand::{self, Rng};
use rand::distributions::{range, IndependentSample};

pub fn byte_range(start: usize, end: usize) -> Vec<u8> {
  let mut rand = rand::thread_rng();

  let len_range = range::Range::new(start, end);
  let len = len_range.ind_sample(&mut rand);

  bytes(len)
}

pub fn bytes(len: usize) -> Vec<u8> {
  let mut rand = rand::thread_rng();
  let mut bytes = Vec::new();

  for _ in 0..len {
    bytes.push(rand.gen())
  }

  bytes
}


pub fn padding(input: &[u8]) -> Vec<u8> {
  let mut padded = byte_range(5, 10);
  padded.extend_from_slice(input);
  let mut tail = byte_range(5, 10);
  padded.append(&mut tail);
  padded
}
