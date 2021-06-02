use crate::error::Error;
use byteorder::{BigEndian, ReadBytesExt};
use std::io::{Cursor, Read};

pub fn read_data(buf: &mut Cursor<Vec<u8>>) -> Result<Vec<u8>, Error> {
    let length = buf.read_u32::<BigEndian>()?;
    let mut data = vec![0; length as usize];
    buf.read_exact(&mut data)?;
    Ok(data)
}

pub fn read_string(buf: &mut Cursor<Vec<u8>>) -> Result<String, Error> {
    let data = read_data(buf)?;
    Ok(std::str::from_utf8(&data).map(|s| s.to_string())?)
}

// #[cfg(unix)]
// pub fn set_user_protected_permissions(path: &str) -> Result<(), Error> {
//     use std::os::unix::fs::PermissionsExt;
//     let mut perms = std::fs::File::open(path)?.metadata()?.permissions();
//     perms.set_mode(0o600);
//     std::fs::set_permissions(path, perms)?;
//     Ok(())
// }

// #[cfg(not(unix))]
// pub fn set_user_protected_permissions(path: &str) -> Result<(), Error> {
//     Ok(())
// }
