use bincode::{self, Options};
use serde::{Deserialize, Serialize};

use crate::error::Result;

pub fn serialize<T>(object: &T) -> Result<Vec<u8>>
where
    T: Serialize,
{
    let opts = bincode::DefaultOptions::new()
        .with_little_endian()
        .with_fixint_encoding();
    Ok(opts.serialize(&object)?)
}

pub fn deserialize<'a, T>(buffer: &'a Vec<u8>) -> Result<T>
where
    T: Deserialize<'a>,
{
    let opts = bincode::DefaultOptions::new()
        .with_little_endian()
        .with_fixint_encoding();
    let decoded: T = opts.deserialize(buffer.as_slice())?;

    Ok(decoded)
}

pub fn arr_to_string(arr: &[u8]) -> String {
    let len = arr.iter().position(|&x| x == 0).unwrap_or(arr.len());
    let valid_bytes = &arr[..len];
    String::from_utf8(valid_bytes.to_vec()).expect("utf8 conversion error")
}
