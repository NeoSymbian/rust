//! Symbian (NeoSymbian): stdout and stderr go to the kernel's debug port, a line at a time, so `println!` and panic
//! messages reach the serial log; P.I.P.S.'s own fds 0-2 lead nowhere on a phone. Stdin is empty.

use crate::io;
use crate::sync::Mutex;
use crate::sys::pal::symbian::{DEBUG_LINE, debug_print};

pub struct Stdin;
pub struct Stdout;
pub struct Stderr;

/// The unfinished line of each stream (stdout, stderr).
static PENDING: [Mutex<Vec<u8>>; 2] = [Mutex::new(Vec::new()), Mutex::new(Vec::new())];

fn write_lines(stream: usize, buf: &[u8]) -> io::Result<usize> {
    let mut line = PENDING[stream].lock().unwrap_or_else(|e| e.into_inner());
    for &b in buf {
        if b == b'\n' {
            debug_print(&line);
            line.clear();
        } else {
            line.push(b);
            if line.len() == DEBUG_LINE {
                debug_print(&line);
                line.clear();
            }
        }
    }
    Ok(buf.len())
}

fn flush_line(stream: usize) -> io::Result<()> {
    let mut line = PENDING[stream].lock().unwrap_or_else(|e| e.into_inner());
    if !line.is_empty() {
        debug_print(&line);
        line.clear();
    }
    Ok(())
}

impl Stdin {
    pub const fn new() -> Stdin {
        Stdin
    }
}

impl io::Read for Stdin {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        Ok(0)
    }
}

impl Stdout {
    pub const fn new() -> Stdout {
        Stdout
    }
}

impl io::Write for Stdout {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        write_lines(0, buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        flush_line(0)
    }
}

impl Stderr {
    pub const fn new() -> Stderr {
        Stderr
    }
}

impl io::Write for Stderr {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        write_lines(1, buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        flush_line(1)
    }
}

pub fn is_ebadf(_err: &io::Error) -> bool {
    false
}

pub const STDIN_BUF_SIZE: usize = 8;

pub fn panic_output() -> Option<impl io::Write> {
    Some(Stderr::new())
}
