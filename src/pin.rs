// Unlock with a pin, like the official clients' "unlock with PIN".
//
// The pin only authorizes reusing what the agent already has: the keys kept
// in memory after a lock, or the master password saved with
// `rbw remember-password` for the first unlock after the agent starts. Only
// an argon2id hash of it is stored. A pin is short, so the hash can be
// brute forced by anyone who can read it, but they could read the saved
// master password just as well; what the pin protects against is someone at
// the keyboard, and the agent forgets the keys after MAX_FAILURES wrong pins.

use crate::prelude::*;

pub const MAX_FAILURES: u8 = 5;

#[derive(serde::Serialize, serde::Deserialize)]
struct Stored {
    salt: String,
    hash: String,
}

fn err(message: impl Into<String>) -> Error {
    Error::Biometric {
        message: message.into(),
    }
}

fn hash(pin: &[u8], salt: &[u8]) -> Result<[u8; 32]> {
    let mut out = [0_u8; 32];
    argon2::Argon2::default()
        .hash_password_into(pin, salt, &mut out)
        .map_err(|e| err(format!("failed to hash the pin: {e}")))?;
    Ok(out)
}

pub fn is_set() -> bool {
    crate::dirs::pin_file().exists()
}

pub fn set(pin: &crate::locked::Password) -> Result<()> {
    if pin.password().is_empty() {
        return Err(err("the pin can't be empty"));
    }
    let salt: [u8; 16] = rand::random();
    let stored = Stored {
        salt: crate::base64::encode(salt),
        hash: crate::base64::encode(hash(pin.password(), &salt)?),
    };
    let file = crate::dirs::pin_file();
    let tmp = file.with_extension("tmp");
    let data = serde_json::to_vec(&stored)
        .map_err(|e| err(format!("failed to save the pin: {e}")))?;
    {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut fh = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| err(format!("failed to save the pin: {e}")))?;
        fh.write_all(&data)
            .map_err(|e| err(format!("failed to save the pin: {e}")))?;
    }
    std::fs::rename(&tmp, &file)
        .map_err(|e| err(format!("failed to save the pin: {e}")))?;
    Ok(())
}

pub fn verify(pin: &crate::locked::Password) -> Result<bool> {
    let data = std::fs::read(crate::dirs::pin_file())
        .map_err(|e| err(format!("no pin set: {e}")))?;
    let stored: Stored = serde_json::from_slice(&data)
        .map_err(|e| err(format!("invalid pin file: {e}")))?;
    let salt = crate::base64::decode(&stored.salt)
        .map_err(|_| err("invalid pin file"))?;
    let expected = crate::base64::decode(&stored.hash)
        .map_err(|_| err("invalid pin file"))?;
    let actual = hash(pin.password(), &salt)?;
    // constant time: no early exit on the first different byte
    Ok(expected.len() == actual.len()
        && expected
            .iter()
            .zip(actual.iter())
            .fold(0_u8, |acc, (a, b)| acc | (a ^ b))
            == 0)
}

pub fn clear() -> Result<()> {
    match std::fs::remove_file(crate::dirs::pin_file()) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(err(format!("failed to remove the pin: {e}"))),
    }
}
