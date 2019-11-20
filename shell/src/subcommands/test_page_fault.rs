//! Test function ensuring pagefaults kills only the current process.

use alloc::string::String;
use alloc::vec::Vec;

use sunrise_libuser::error::Error;
use sunrise_libuser::twili::IPipeProxy;

/// Help string.
pub static HELP: &str = "test_page_fault: Check exception handling by throwing a page_fault";

/// Test function ensuring pagefaults kills only the current process.
pub fn main(_stdin: IPipeProxy, _stdout: IPipeProxy, _stderr: IPipeProxy, _args: Vec<String>) -> Result<(), Error> {
    // dereference the null pointer.
    // doing this in rust is so UB, it's optimized out, so we do it in asm.
    unsafe {
        asm!("
        mov al, [0]
        " ::: "eax" : "volatile", "intel")
    }
    Ok(())
}