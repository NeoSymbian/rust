//! NeoSymbian (EKA2) calls std needs besides P.I.P.S.: the kernel's debug port, its secure RNG and the start-up a
//! P.I.P.S. program expects (a cleanup stack, then `__crt0` for argc/argv/environ). Executive calls are issued as
//! NeoSymbian's `e32-sys` crate issues them (`swi #n`, numbers from the kernel's `execs.txt`).

use crate::ffi::{c_char, c_int, c_void};

// Executive call numbers (NeoSymbian/e32-rs `e32-sys/src/execs.rs`).
const EXEC_DEBUG_PRINT: u32 = 0x56;
const EXEC_MATH_SECURE_RANDOM: u32 = 0x109;
const KERR_NOT_READY: i32 = -18;

#[inline(always)]
unsafe fn exec4<const N: u32>(a0: u32, a1: u32, a2: u32, a3: u32) -> u32 {
    let r: u32;
    // SAFETY: the caller passes what executive call `N` expects.
    unsafe {
        crate::arch::asm!("swi #{n}", n = const N,
            inlateout("r0") a0 => r, in("r1") a1, in("r2") a2, in("r3") a3, clobber_abi("C"));
    }
    r
}

/// `TPtrC8`/`TPtr8` as the kernel reads them: word 0 = `length | type << 28`.
#[repr(C)]
struct PtrC8 {
    len_type: u32,
    ptr: *const u8,
}

#[repr(C)]
struct Ptr8 {
    len_type: u32,
    max: u32,
    ptr: *mut u8,
}

/// The debug port's line limit (`RDebug::Printf`'s `TBuf8<0x100>`; longer output faults the kernel's monitor).
pub const DEBUG_LINE: usize = 0xff;

/// Print `bytes` as one line on the kernel debug port (the kernel ends the line); longer input is split.
pub fn debug_print(bytes: &[u8]) {
    for chunk in bytes.chunks(DEBUG_LINE) {
        let des = PtrC8 { len_type: (1 << 28) | chunk.len() as u32, ptr: chunk.as_ptr() };
        // SAFETY: `des` describes `chunk`, both alive for the call.
        unsafe { exec4::<EXEC_DEBUG_PRINT>(&des as *const PtrC8 as u32, 0, 0, 0) };
    }
}

/// Fill `buf` from the kernel's secure RNG (`Math::RandomL`, seeded at boot: NeoSymbian WB1).
pub fn secure_random(buf: &mut [u8]) {
    for chunk in buf.chunks_mut(1 << 16) {
        loop {
            let mut des = Ptr8 { len_type: 2 << 28, max: chunk.len() as u32, ptr: chunk.as_mut_ptr() };
            // SAFETY: `des` describes `chunk`; the kernel writes at most its maximum length.
            let r = unsafe { exec4::<EXEC_MATH_SECURE_RANDOM>(&mut des as *mut Ptr8 as u32, 0, 0, 0) } as i32;
            match r {
                0 => break,
                // shortcut: spin until the boot-time seed is in; the kernel seeds before any user code runs today
                KERR_NOT_READY => unsafe {
                    libc::sched_yield();
                },
                e => rtabort!("Math::RandomL failed: {e}"),
            }
        }
    }
}

unsafe extern "C" {
    // euser.dll: CTrapCleanup::New()
    #[link_name = "_ZN12CTrapCleanup3NewEv"]
    fn ctrapcleanup_new() -> *mut c_void;
    // libc.dll: __crt0(int& argc, char**& argv, char**& envp), what P.I.P.S.'s C start-up calls
    #[link_name = "_Z6__crt0RiRPPcS2_"]
    fn crt0(argc: *mut c_int, argv: *mut *mut *mut c_char, envp: *mut *mut *mut c_char);
}

/// A cleanup stack for the calling thread: P.I.P.S. uses one (without it `opendir` panics E32USER-CBase 69).
/// Threads created by `pthread_create` get theirs from libpthread.
pub fn cleanup_stack() {
    // SAFETY: plain call; a null result only means P.I.P.S. calls that need one will panic.
    unsafe { ctrapcleanup_new() };
}

/// The process start-up a P.I.P.S. program gets from its crt0: the cleanup stack, then argc/argv for `env::args`.
pub fn init() {
    cleanup_stack();
    let mut argc: c_int = 0;
    let mut argv: *mut *mut c_char = crate::ptr::null_mut();
    let mut envp: *mut *mut c_char = crate::ptr::null_mut();
    // SAFETY: crt0 fills the three outputs.
    unsafe {
        crt0(&mut argc, &mut argv, &mut envp);
        crate::sys::args::init(argc as isize, argv as *const *const u8);
    }
}
