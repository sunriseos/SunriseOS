//! Test function ensuring divide by zero interruption kills only the current
/// process.

use sunrise_libuser::error::Error;
use sunrise_libuser::twili::IPipeProxy;

/// Help string.
pub static HELP: &'static str = "test_divide_by_zero: Check exception handling by throwing a divide by zero";

/// Test function ensuring divide by zero interruption kills only the current
/// process.
pub fn main(_stdin: IPipeProxy, _stdout: IPipeProxy, _stderr: IPipeProxy, _args: &[&str]) -> Result<(), Error> {
    // don't panic, we want to actually divide by zero
    unsafe {
        asm!("
        mov eax, 42
        mov ecx, 0
        div ecx" :::: "volatile", "intel")
    }
    Ok(())
}
