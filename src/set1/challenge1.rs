use ::byte_convert::*;

pub fn hex2base64(hex: &str) -> Result<String, &'static str> {
    hex2bigint(hex).and_then(|num| bigint2base64(num))
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(
      super::hex2base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d").unwrap(),
      "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
      )
    }
}
