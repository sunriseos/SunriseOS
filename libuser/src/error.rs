//! Error handling
//!
//! Errors in Horizon/NX follow a specific format. They are encoded on a 32-bit
//! integer, where the bottom 9 bits represent the module, while the top bits
//! represent the "description". A Module is usually a sysmodule, with a few
//! additional modules for specific libraries (Module 168 is userland crash, for
//! instance). See the [switchbrew Error Codes page] for more information.
//!
//! Such errors are nice, but have one small problem: they're missing backtraces.
//! In libuser, we opted to use a failure enum. We have a different enum for
//! every module, listing all of their error descriptions, and a big enum
//! over all those module errors. This fine-grained approach makes error handling
//! code nicer. For instance, writing a function returning an Error:
//!
//! ```
//! fn ret_err() -> Result<(), Error> {
//!    // Will automatically be converted to Error, the backtrace filled
//!    let _ = Err(KernelError::InvalidPort)?;
//!    let _ = Err(SmError::PermissionDenied)?;
//!    Ok(())
//! }
//! ```
//!
//! Matching on an error is similarly convenient:
//!
//! ```
//! # let err: Result<(), Error> = Ok(());
//! match err {
//!    Ok(_) => (),
//!    Err(Error::Kernel(KernelError::InvalidPort, _)) => (),
//!    _ => ()
//! }
//! ```
//!
//! [switchbrew Error Codes page]: https://switchbrew.org/w/index.php?title=Error_codes

pub use kfs_libkern::error::KernelError;
use failure::Backtrace;
use core::fmt;

/// The global error type. Every error defined here can be downcasted to this
/// type. A Backtrace will be created when casting an error to this type.
#[derive(Debug, Fail)]
pub enum Error {
    /// A Kernel Error. Usually returned by syscalls.
    Kernel(KernelError, Backtrace),
    /// Service Manager error.
    Sm(SmError, Backtrace),
    //Vi(ViError, Backtrace),
    /// Internal Libuser error.
    Libuser(LibuserError, Backtrace),
    /// An unknown error type. Either someone returned a custom error, or this
    /// version of libuser is outdated.
    Unknown(u32, Backtrace)
}

impl Error {
    /// Create an Error from a packed error code, creating a backtrace at this
    /// point.
    pub fn from_code(errcode: u32) -> Error {
        let module = errcode & 0x1FF;
        let description = errcode >> 9;
        match Module(module) {
            Module::Kernel => Error::Kernel(KernelError::from_description(description), Backtrace::new()),
            Module::Sm => Error::Sm(SmError(description), Backtrace::new()),
            //Module::Vi => Error::Vi(ViError(description), Backtrace::new()),
            Module::Libuser => Error::Libuser(LibuserError(description), Backtrace::new()),
            _ => Error::Unknown(errcode, Backtrace::new())
        }
    }

    /// Pack this error into an error code. Note that the returned error code
    /// won't have any tracing information associated with it. If possible, to
    /// assist in debugging, a way to pass the backtrace should be provided.
    pub fn as_code(&self) -> u32 {
        match *self {
            Error::Kernel(err, ..) => err.description() << 9 | Module::Kernel.0,
            Error::Sm(err, ..) => err.0 << 9 | Module::Sm.0,
            //Error::Vi(err, ..) => err.0 << 9 | Module::Vi.0,
            Error::Libuser(err, ..) => err.0 << 9 | Module::Libuser.0,
            Error::Unknown(err, ..) => err,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
    /// Internal libuser errors.
    #[derive(PartialEq, Eq, Clone, Copy)]
    pub struct LibuserError(u32) {
        /// An attempt to find available space failed.
        AddressSpaceExhausted = 1,
        /// Too many move handles were passed to an IPC message.
        InvalidMoveHandleCount = 2,
        /// Too many copy handles were passed to an IPC message.
        InvalidCopyHandleCount = 3,
        /// Attempted to read PID from an IPC message containing none.
        PidMissing = 4,
    }
}

impl From<LibuserError> for Error {
    fn from(error: LibuserError) -> Self {
        Error::Libuser(error, Backtrace::new())
    }
}


enum_with_val! {
    /// Service Manager errors.
    #[derive(PartialEq, Eq, Clone, Copy)]
    pub struct SmError(u32) {
        /// Too many processes spawned.
        OutOfProcesses = 1,
        /// Attempted to use the service manager without initializing it.
        NotInitialized = 2,
        /// This service already reached the maximum amount of sessions allowed to connect to it.
        MaxSessions = 3,
        /// Attempted to register a service that already exists.
        ServiceAlreadyRegistered = 4,
        /// Too many services have been created.
        OutOfServices = 5,
        /// The name is too long. Make sure it's only 7 characters and ends with
        /// a \0.
        InvalidName = 6,
        /// Attempted to unregister a service that was not previously registered.
        ServiceNotRegistered = 7,
        /// Process SACs do not allow accessing or hosting this service.
        PermissionDenied = 8,
        /// The provided SACs are too big.
        ServiceAccessControlTooBig = 9,
    }
}

impl From<SmError> for Error {
    fn from(error: SmError) -> Self {
        Error::Sm(error, Backtrace::new())
    }
}
