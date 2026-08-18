//! Terminal input for `cfc prompts`.
//!
//! No TTY crate is in the dependency graph (no crossterm / termion /
//! dialoguer), and pulling one in for two termios calls is not worth it, so
//! raw mode is done directly through libc, which is already there.
//!
//! Only ICANON and ECHO are cleared: OPOST stays on so `\n` still works as
//! a newline, and ISIG stays on so Ctrl-C is delivered as SIGINT (caught by
//! the async loop) instead of arriving as a stray 0x03 byte. Termios is
//! restored by `Drop`, including on the Ctrl-C path, because the loop
//! unwinds normally rather than calling `exit` from a signal handler.

use std::io::Read;
use std::os::fd::AsRawFd;

/// True when stdin is a terminal, i.e. when single-key input is possible.
pub fn stdin_is_tty() -> bool {
    // SAFETY: isatty takes an fd and only reads terminal state.
    unsafe { libc::isatty(std::io::stdin().as_raw_fd()) == 1 }
}

/// True when stdout is a terminal, used to decide whether an in-place
/// countdown (`\r`) is meaningful.
pub fn stdout_is_tty() -> bool {
    // SAFETY: as above.
    unsafe { libc::isatty(std::io::stdout().as_raw_fd()) == 1 }
}

/// Restores the terminal mode when dropped.
pub struct RawMode {
    fd: i32,
    saved: libc::termios,
}

impl RawMode {
    /// Enables per-keypress reads. Returns `Ok(None)` when stdin is not a
    /// terminal, which is a normal case (piped stdin) and not an error.
    pub fn enable() -> std::io::Result<Option<Self>> {
        let fd = std::io::stdin().as_raw_fd();
        if !stdin_is_tty() {
            return Ok(None);
        }
        // SAFETY: `saved` is fully initialised by tcgetattr before use; the
        // fd is a live terminal.
        unsafe {
            let mut saved: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(fd, &mut saved) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            let mut raw = saved;
            raw.c_lflag &= !(libc::ICANON | libc::ECHO);
            raw.c_cc[libc::VMIN] = 1;
            raw.c_cc[libc::VTIME] = 0;
            if libc::tcsetattr(fd, libc::TCSANOW, &raw) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(Some(Self { fd, saved }))
        }
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        // SAFETY: restoring the exact termios captured in `enable`.
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSANOW, &self.saved);
        }
    }
}

/// Spawns the single stdin reader for the process.
///
/// One dedicated blocking thread owns stdin for the whole session and
/// forwards bytes over a channel. That keeps the async side cancel-safe:
/// abandoning a `recv()` when a prompt times out cannot swallow a byte the
/// way cancelling a read on `tokio::io::stdin()` can.
pub fn spawn_key_reader() -> tokio::sync::mpsc::UnboundedReceiver<u8> {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    std::thread::spawn(move || {
        let mut stdin = std::io::stdin().lock();
        let mut buf = [0u8; 1];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) => break,
                Ok(_) => {
                    if tx.send(buf[0]).is_err() {
                        break;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
    });
    rx
}

/// Maps a raw byte to the key the prompt loop cares about.
///
/// Uppercase is accepted, and both Enter forms are reported so line-mode
/// (non-TTY) input can be filtered out instead of read as a keypress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    Char(char),
    Enter,
    Escape,
    Other,
}

pub fn classify(byte: u8) -> Key {
    match byte {
        b'\n' | b'\r' => Key::Enter,
        0x1b => Key::Escape,
        b if b.is_ascii_graphic() => Key::Char((b as char).to_ascii_lowercase()),
        _ => Key::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn letters_are_lowercased() {
        assert_eq!(classify(b'a'), Key::Char('a'));
        assert_eq!(classify(b'A'), Key::Char('a'));
        assert_eq!(classify(b'D'), Key::Char('d'));
        assert_eq!(classify(b'1'), Key::Char('1'));
    }

    #[test]
    fn control_bytes_are_not_characters() {
        assert_eq!(classify(b'\n'), Key::Enter);
        assert_eq!(classify(b'\r'), Key::Enter);
        assert_eq!(classify(0x1b), Key::Escape);
        assert_eq!(classify(0x00), Key::Other);
        assert_eq!(classify(b' '), Key::Other);
    }
}
