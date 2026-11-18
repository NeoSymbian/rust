//! The process start-up of a Symbian EXE that uses std.
//!
//! A Symbian EXE starts at `E32Main`, not `main`: NeoSymbian's `e32::main!` defines it and calls [`start`], which
//! does what `lang_start` does elsewhere.

#![unstable(feature = "symbian_rt", issue = "none")]

/// Run `main` as a std program: the thread's cleanup stack and argc/argv (the process command line) first, stdout flushed
/// after. Returns `main`'s result for `E32Main` to return (the process exit reason).
pub fn start(main: fn() -> i32) -> i32 {
    crate::sys::symbian_init();
    let r = main();
    crate::rt::cleanup();
    r
}
