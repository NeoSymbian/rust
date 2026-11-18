//! NeoSymbian (EKA2) calls std needs besides P.I.P.S.: the kernel's debug port, its secure RNG and the start-up a
//! P.I.P.S. program expects (a cleanup stack; argc/argv from the process command line). Executive calls are issued as
//! NeoSymbian's `e32-sys` crate issues them (`swi #n`, numbers from the kernel's `execs.txt`).

use crate::ffi::{c_int, c_void};

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
    // euser.dll: User::CommandLineLength(), User::CommandLine(TDes16&)
    #[link_name = "_ZN4User17CommandLineLengthEv"]
    fn command_line_length() -> c_int;
    #[link_name = "_ZN4User11CommandLineER6TDes16"]
    fn command_line(des: *mut Ptr16);
    // euser.dll: RProcess::FileName() const, a TFileName returned through the hidden result pointer
    #[link_name = "_ZNK8RProcess8FileNameEv"]
    fn process_file_name(out: *mut FileName, this: *const i32);
}

/// `TPtr16`: `{ len | EPtr << 28, max_len, ptr }`.
#[repr(C)]
struct Ptr16 {
    len_type: u32,
    max: u32,
    ptr: *mut u16,
}

/// `TFileName` = `TBuf16<256>`: `{ len | EBuf << 28, max_len, data }`.
#[repr(C)]
struct FileName {
    len_type: u32,
    max: u32,
    data: [u16; 256],
}

const KCURRENT_PROCESS_HANDLE: i32 = 0xffff8000u32 as i32;
const KMASK_DES_LENGTH: u32 = 0x0fff_ffff;

/// A cleanup stack for the calling thread: P.I.P.S. uses one (without it `opendir` panics E32USER-CBase 69).
/// Threads created by `pthread_create` get theirs from libpthread.
pub fn cleanup_stack() {
    // SAFETY: plain call; a null result only means P.I.P.S. calls that need one will panic.
    unsafe { ctrapcleanup_new() };
}

/// The EXE's path and its command line, split at spaces ("double quotes" group words), as `env::args` sees them.
/// (P.I.P.S.'s own `__crt0` is not used: it first asks P.I.P.S.'s IPC server whether `popen`/`posix_spawn` made the
/// process, and blocks when that server is not running.)
fn kernel_args() -> Vec<Vec<u8>> {
    let mut file = FileName { len_type: 3 << 28, max: 256, data: [0; 256] };
    // SAFETY: the callee constructs the TFileName in `file`; `this` is a current-process RProcess.
    unsafe { process_file_name(&mut file, &KCURRENT_PROCESS_HANDLE) };
    let n = ((file.len_type & KMASK_DES_LENGTH) as usize).min(256);
    let mut args = vec![String::from_utf16_lossy(&file.data[..n]).into_bytes()];

    // SAFETY: plain call. One spare character, as P.I.P.S.'s crt0 allocates: a buffer of exactly the reported
    // length hangs the EXE in User::CommandLine (seen on the WB1 kernel).
    let len = unsafe { command_line_length() }.max(0) as usize + 1;
    let mut buf = vec![0u16; len];
    let mut des = Ptr16 { len_type: 2 << 28, max: len as u32, ptr: buf.as_mut_ptr() };
    // SAFETY: `des` describes `buf`; the kernel writes at most `len` characters and the new length.
    unsafe { command_line(&mut des) };
    let got = ((des.len_type & KMASK_DES_LENGTH) as usize).min(len);
    let line = String::from_utf16_lossy(&buf[..got]);
    let (mut word, mut quoted, mut any) = (String::new(), false, false);
    for c in line.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                any = true;
            }
            c if c.is_whitespace() && !quoted => {
                if any {
                    args.push(crate::mem::take(&mut word).into_bytes());
                    any = false;
                }
            }
            c => {
                word.push(c);
                any = true;
            }
        }
    }
    if any {
        args.push(word.into_bytes());
    }
    args
}

/// The process start-up std needs on Symbian: the cleanup stack, then argc/argv for `env::args`.
pub fn init() {
    cleanup_stack();
    // argv lives for the whole process, as a C program's does
    let mut argv: Vec<*const u8> = kernel_args()
        .into_iter()
        .map(|mut a| {
            a.push(0);
            a.leak().as_ptr()
        })
        .collect();
    let argc = argv.len() as isize;
    argv.push(crate::ptr::null());
    // SAFETY: argc/argv describe NUL-terminated strings that are never freed.
    unsafe { crate::sys::args::init(argc, argv.leak().as_ptr()) };
}

// The unwinder entry points std's backtrace code and the unwind crate name: compiled in, never called (Symbian EXEs
// are panic=abort, without backtraces or a personality routine). Defined here so the linker never pulls libgcc's
// unwinder, which needs a C++ runtime Symbian does not export.
macro_rules! no_unwinder {
    ($($name:ident),* $(,)?) => {
        $(
            #[unsafe(no_mangle)]
            pub extern "C" fn $name() -> ! {
                crate::process::abort()
            }
        )*
    };
}
no_unwinder!(
    _Unwind_Backtrace,
    _Unwind_FindEnclosingFunction,
    _Unwind_GetCFA,
    _Unwind_GetIP,
    _Unwind_GetIPInfo,
    _Unwind_GetLanguageSpecificData,
    _Unwind_GetRegionStart,
    _Unwind_GetTextRelBase,
    _Unwind_GetDataRelBase,
    _Unwind_VRS_Get,
    _Unwind_VRS_Set,
    __gnu_unwind_frame,
);
