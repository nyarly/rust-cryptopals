use ::byte_convert::open_base64_path;
use ::result::*;
use ::crypto::{aes, blockmodes, buffer};
use std::iter;

/// Examples
///
/// ```
/// let decrypt = cryptopals::set1::challenge7::decrypt_file("s1c7.txt").unwrap();
/// assert!( decrypt.find("Samson to Delilah").is_some())
/// ```
pub fn decrypt_file(path: &str) -> Result<String> {
    let crypted = try!(open_base64_path(path));

    let mut plain: Vec<u8> = iter::repeat(0u8).take(crypted.len()).collect();
    let mut decryptor = aes::ecb_decryptor(aes::KeySize::KeySize128,
                                           "YELLOW SUBMARINE".as_bytes(),
                                           blockmodes::NoPadding);

    println!("{:?}", crypted);
    println!("{:?}", plain);
    {
        let mut cbuf = buffer::RefReadBuffer::new(&crypted);
        let mut pbuf = buffer::RefWriteBuffer::new(plain.as_mut_slice());
        try!(decryptor.decrypt(&mut cbuf, &mut pbuf, false));
    }
    println!("{:?}", plain);
    String::from_utf8(plain.clone()).map_err(CrackError::from)
}
