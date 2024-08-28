use std::io::Read;

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};

use crate::{cli::Base64Format, get_reader};

pub fn process_encode(input: &str, format: Base64Format) -> anyhow::Result<String> {
    let mut reader: Box<dyn Read> = get_reader(input)?;

    let mut buf = Vec::new();
    reader.read_to_end(&mut buf)?;

    let encoded = match format {
        Base64Format::Standard => STANDARD.encode(&buf),
        Base64Format::UrlSafe => URL_SAFE_NO_PAD.encode(&buf),
    };

    Ok(encoded)
}

pub fn process_decode(input: &str, format: Base64Format) -> anyhow::Result<Vec<u8>> {
    let mut reader: Box<dyn Read> = get_reader(input)?;

    let mut buf = String::new();
    reader.read_to_string(&mut buf)?;
    // avoid accidental newlines
    let buf = buf.trim();

    let decoded = match format {
        Base64Format::Standard => STANDARD.decode(buf)?,
        Base64Format::UrlSafe => URL_SAFE_NO_PAD.decode(buf)?,
    };

    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_encode() {
        let input = "Cargo.toml";
        assert!(process_encode(input, Base64Format::Standard).is_ok());
        // assert!(process_encode(input, Base64Format::UrlSafe).is_ok());
    }

    // #[test]
    // fn test_process_decode() {
    //     let input = "fixtures/base64.txt";
    //     assert!(process_decode(input, Base64Format::Standard).is_ok());
    //     // assert!(process_decode(input, Base64Format::UrlSafe).is_ok());
    // }
}
