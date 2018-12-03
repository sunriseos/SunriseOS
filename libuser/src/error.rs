pub use kfs_libkern::error::KernelError;
use failure::Backtrace;
use core::fmt;

#[derive(Debug, Fail)]
pub enum Error {
    Kernel(KernelError, Backtrace),
    Sm(SmError, Backtrace),
    //Vi(ViError, Backtrace),
    Libuser(LibuserError, Backtrace),
    Unknown(u32, Backtrace)
}

impl Error {
    pub fn from_code(errcode: u32) -> Error {
        let module = errcode & 0x1F;
        let description = errcode >> 9;
        match Module(module) {
            Module::Kernel => Error::Kernel(KernelError::from_description(description), Backtrace::new()),
            Module::Sm => Error::Sm(SmError(description), Backtrace::new()),
            //Module::Vi => Error::Vi(ViError(description), Backtrace::new()),
            Module::Libuser => Error::Libuser(LibuserError(description), Backtrace::new()),
            _ => Error::Unknown(errcode, Backtrace::new())
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // TODO: Better Display implementation for libuser::Error
        // BODY: Right now, the libuser::Error Display just shims back to the Debug implementation.
        // BODY: It'd be nice if it delegated the display to the underlying Error types.
        write!(f, "Error: {:?}", self)
    }
}

impl From<KernelError> for Error {
    fn from(error: KernelError) -> Self {
        Error::Kernel(error, Backtrace::new())
    }
}

enum_with_val! {
    #[derive(PartialEq, Eq, Clone, Copy)]
    struct Module(u32) {
        Kernel = 1,
        Sm = 21,
        Vi = 114,
        Libuser = 115
    }
}

enum_with_val! {
    #[derive(PartialEq, Eq, Clone, Copy)]
    pub struct LibuserError(u32) {
        AddressSpaceExhausted = 1,
        InvalidMoveHandleCount = 2,
        InvalidCopyHandleCount = 3,
        PidMissing = 4,
    }
}

impl From<LibuserError> for Error {
    fn from(error: LibuserError) -> Self {
        Error::Libuser(error, Backtrace::new())
    }
}


enum_with_val! {
    #[derive(PartialEq, Eq, Clone, Copy)]
    pub struct SmError(u32) {
        OutOfProcesses = 1,
        NotInitialized = 2,
        MaxSessions = 3,
        ServiceAlreadyRegistered = 4,
        OutOfServices = 5,
        InvalidName = 6,
        ServiceNotRegistered = 7,
        PermissionDenied = 8,
        ServiceAccessControlTooBig = 9,
    }
}

impl From<SmError> for Error {
    fn from(error: SmError) -> Self {
        Error::Sm(error, Backtrace::new())
    }
}
