pub const ENCODING: base64::engine::general_purpose::GeneralPurpose = base64::engine::general_purpose::URL_SAFE;

use crate::error::{self, Error};

use std::convert::TryFrom;

pub fn encode<T: AsRef<[u8]>>(bytes: T) -> String {
    base64::encode(bytes)
}

pub fn decode<T: AsRef<[u8]>>(bytes: T) -> error::Result<Vec<u8>> {
    base64::decode(bytes).map_err(Into::into)
}

pub struct CodedObject {
    pub bytes: Vec<u8>,
    pub scheme: String,
}

impl CodedObject {
    pub fn as_urn(&self) -> String {
        format!("urn:{}:{}", self.scheme, encode(&self.bytes))
    }

    pub fn as_binary(&self) -> error::Result<Vec<u8>> {
        let mut output = Vec::new();
        output.push(u8::try_from(self.scheme.as_bytes().len())?);
        output.extend(self.scheme.as_bytes());
        output.extend(&self.bytes);
        Ok(output)
    }

    pub fn from_urn(urn: &str) -> error::Result<CodedObject> {
        let last_colon = urn.rfind(':');
        match last_colon {
            None => Err(Error::BadScheme("".into())),
            Some(idx) => {
                let first_colon = urn.find(':').unwrap();  // There's definitely SOME colon in this branch
                Ok(CodedObject {
                    scheme: urn[first_colon+1..idx].into(),
                    bytes: decode(urn[idx+1..].as_bytes())?,
                })
            },
        }
    }

    pub fn from_binary(bytes: &[u8]) -> error::Result<CodedObject> {
        let scheme_len = bytes[0];
        if scheme_len as usize >= bytes.len() {
            return Err(Error::InvalidSchemeLength(scheme_len));
        }
        let scheme = std::str::from_utf8(&bytes[1 .. scheme_len as usize + 1])?;
        Ok(CodedObject {
            scheme: scheme.into(),
            bytes: bytes[scheme_len as usize + 1 ..].into(),
        })
    }

    pub fn expect_scheme(&self, scheme: &str) -> error::Result<()> {
        if scheme == self.scheme {
            Ok(())
        } else {
            Err(Error::BadScheme(self.scheme.clone()))
        }
    }
}

pub trait Encodable {
    fn encode(&self) -> CodedObject;
}

pub trait Decodable: Sized {
    fn decode(input: &CodedObject) -> error::Result<Self>;
}
