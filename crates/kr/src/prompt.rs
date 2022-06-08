//! GUI password prompt using pinentry
use std::cmp;
use std::io::prelude::*;
use std::io::BufReader;
use std::process::{Command, Stdio};

pub struct PasswordPrompt {
    key_name: String,
}

impl PasswordPrompt {
    pub fn new(key_name: String) -> Self {
        PasswordPrompt { key_name: key_name }
    }

    /// Invokes the password prompt and puts the entered password into `password_buffer`.
    ///
    /// Returns the number of bytes input into the buffer.
    pub fn invoke(&self, password_buffer: &mut [u8]) -> usize {
        #[cfg(target_os = "macos")]
        let commmand_str = "pinentry-mac";

        #[cfg(target_os = "linux")]
        let commmand_str = "pinentry";

        let mut pinentry = Command::new(commmand_str)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("pinentry command failed to start");

        // Configure pinentry
        let pincmd = pinentry.stdin.take();

        match pincmd {
            Some(mut pincmd) => {
                writeln!(pincmd, "SETTITLE Unlock SSH key").expect("failed to write to pinentry");
                writeln!(pincmd, "SETPROMPT Password:").expect("failed to write to pinentry");
                writeln!(
                    pincmd,
                    "SETDESC Enter the password for unlocking the SSH key '{}'",
                    self.key_name
                )
                .expect("failed to write to pinentry");
                writeln!(pincmd, "GETPIN").expect("failed to write to pinentry");

                let message = pinentry.stdout.take();

                match message {
                    Some(message) => {
                        // Read until we get an "ERR" or "D" line
                        let out = BufReader::new(message);
                        for line in out.lines() {
                            let line = line.expect("failed to read line from pinentry");
                            if line.starts_with("ERR ") {
                                pinentry.kill().expect("failed to kill pinentry");
                                return 0; // Abort!
                            } else if line.starts_with("D ") {
                                let bytes = &line.as_bytes()[2..];
                                for (byte, target) in bytes.iter().zip(password_buffer.iter_mut()) {
                                    *target = *byte;
                                }

                                pinentry.kill().expect("failed to kill pinentry");
                                return cmp::min(bytes.len(), password_buffer.len());
                            }
                        }
                    }
                    None => return 0,
                }
            }
            None => return 0,
        }

        pinentry.kill().expect("failed to kill pinentry");
        return 0;
    }
}
