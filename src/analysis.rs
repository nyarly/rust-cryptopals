#[derive(Debug,PartialEq,Clone,Copy)]
pub enum Mode {
  ElectronicCodebook,
  CipherBlockChaining,
}

pub mod aes {
  use super::Mode;
  use std::iter::repeat;
  use num_bigint::{BigInt, Sign};
  use frequency;
  use result::Result;

  pub fn detector<F>(blocksize: usize, oracle: F) -> Result<Mode>
    where F: for<'g> Fn(&'g [u8]) -> Result<Vec<u8>>
  {
    let exploit_message: Vec<u8> = repeat(b'a').take(3 * blocksize).collect(); // 6 * 16 = blocksize (should work down to 3)

    let crypt = try!(oracle(&exploit_message));
    let chunks =
      (&crypt.as_slice()).chunks(blocksize).map(|ch| BigInt::from_bytes_be(Sign::Plus, ch));
    let c = frequency::Counts::new(chunks);

    if c.sorted_counts()[0] > 1 {
      Ok(Mode::ElectronicCodebook)
    } else {
      Ok(Mode::CipherBlockChaining)
    }
  }
}
