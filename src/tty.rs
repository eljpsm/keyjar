//! Terminal input: the no-echo secret read and the y/N confirmation.
//! Prompts go to stderr so stdout stays clean for values. The termios guard
//! restores the terminal from Drop, so a panic or early return cannot leave
//! the shell echo-less.

use std::io::{BufRead, IsTerminal, Write};
use std::os::fd::AsRawFd;

use anyhow::Context;

/// Read a secret from stdin. On a terminal the input is not echoed; from a
/// pipe it is read plainly. Single-line mode strips the trailing newline,
/// multiline reads to EOF verbatim.
pub(crate) fn read_secret(name: &str, multiline: bool, quiet: bool) -> anyhow::Result<Vec<u8>> {
    let stdin = std::io::stdin();
    if !stdin.is_terminal() {
        return read_plain(&mut stdin.lock(), multiline);
    }
    if !quiet {
        let hint = if multiline { " (end with ^D)" } else { "" };
        eprint!("value for {name}{hint}: ");
        std::io::stderr().flush()?;
    }
    let guard = NoEcho::engage(stdin.as_raw_fd()).context("disabling echo")?;
    let value = read_plain(&mut stdin.lock(), multiline);
    drop(guard);
    // The terminal swallowed the enter keypress along with the input.
    eprintln!();
    value
}

fn read_plain(input: &mut impl BufRead, multiline: bool) -> anyhow::Result<Vec<u8>> {
    let mut buf = Vec::new();
    if multiline {
        input.read_to_end(&mut buf).context("reading stdin")?;
        Ok(buf)
    } else {
        input.read_until(b'\n', &mut buf).context("reading stdin")?;
        Ok(strip_one_line(buf))
    }
}

/// Drop a trailing `\n` or `\r\n`. The newline ends the entry; it is not
/// part of the secret.
fn strip_one_line(mut line: Vec<u8>) -> Vec<u8> {
    if line.last() == Some(&b'\n') {
        line.pop();
        if line.last() == Some(&b'\r') {
            line.pop();
        }
    }
    line
}

/// Ask on stderr, default No. Only called when stdin is a terminal.
pub(crate) fn confirm(prompt: &str) -> anyhow::Result<bool> {
    eprint!("{prompt}");
    std::io::stderr().flush()?;
    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .context("reading stdin")?;
    let answer = answer.trim();
    Ok(answer.eq_ignore_ascii_case("y") || answer.eq_ignore_ascii_case("yes"))
}

struct NoEcho {
    fd: i32,
    original: libc::termios,
}

impl NoEcho {
    fn engage(fd: i32) -> std::io::Result<Self> {
        let mut original = unsafe { std::mem::zeroed::<libc::termios>() };
        if unsafe { libc::tcgetattr(fd, &mut original) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let hidden = without_echo(original);
        if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &hidden) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(NoEcho { fd, original })
    }
}

impl Drop for NoEcho {
    fn drop(&mut self) {
        unsafe { libc::tcsetattr(self.fd, libc::TCSAFLUSH, &self.original) };
    }
}

/// Clear ECHO only. ICANON stays on so line editing keeps working while the
/// secret is typed.
fn without_echo(mut t: libc::termios) -> libc::termios {
    t.c_lflag &= !libc::ECHO;
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_single_line_read_strips_the_newline_variants() {
        assert_eq!(strip_one_line(b"secret\n".to_vec()), b"secret");
        assert_eq!(strip_one_line(b"secret\r\n".to_vec()), b"secret");
        assert_eq!(strip_one_line(b"secret".to_vec()), b"secret");
        assert_eq!(strip_one_line(b"".to_vec()), b"");
    }

    // A pipe can hold more than one line; single-line mode must take only
    // the first, multiline must take everything.
    #[test]
    fn plain_reads_honor_the_multiline_switch() {
        let input = b"first\nsecond\n";
        assert_eq!(read_plain(&mut &input[..], false).unwrap(), b"first");
        assert_eq!(read_plain(&mut &input[..], true).unwrap(), input);
    }

    #[test]
    fn the_echo_transform_clears_echo_and_nothing_else() {
        let mut t = unsafe { std::mem::zeroed::<libc::termios>() };
        t.c_lflag = libc::ECHO | libc::ICANON | libc::ISIG;
        let hidden = without_echo(t);
        assert_eq!(hidden.c_lflag & libc::ECHO, 0);
        assert_ne!(hidden.c_lflag & libc::ICANON, 0);
        assert_ne!(hidden.c_lflag & libc::ISIG, 0);
    }
}
