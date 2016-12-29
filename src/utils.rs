pub fn full_u8() -> Box<Iterator<Item = u8>> {
  Box::new((0..128).chain((0..128).map(|n| n + 128)))
}

use std::fmt::Debug;
pub fn best_score<I, S, V>(list: I) -> Option<(S, V)>
  where I: Iterator<Item = (S, V)>,
        S: Ord + Clone + Debug,
        V: Debug
{
  list.min_by_key(|&(ref score, _)| score.clone())
}

pub fn by_score<I, S, V>(list: I) -> Vec<(S, V)>
  where I: Iterator<Item = (S, V)>,
        S: Ord + Clone,
        V: Clone
{
  let mut v = list.collect::<Vec<_>>();
  v.sort_by_key(|&(ref score, _)| score.clone());
  v
}

#[cfg(test)]
mod tests {
  use super::*;
  #[test]
  fn full_u8_is_goes_to_255() {
    assert_eq!(full_u8().last().unwrap(), 255u8)
  }
}
