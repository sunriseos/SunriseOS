//! Server wrappers around IPC Buffers
//!
//! IPC Servers may accept different kinds of IPC Buffers, in order to move
//! around large amounts of data efficiently. There exists two kinds of IPC
//! Buffers, the Pointers and the Buffers.
//!
//! Pointers work in a pair of input and output: the Server pushes an InPointer
//! while the Client pushes an OutPointer. The kernel will memcpy the contents of
//! the OutPointer to the appropriate InPointer of the other side.
//!
//! Buffers work by remapping the memory from the sender to the receiver. The in
//! and out simply decide whether the memory is remapped as read-only or write-
//! only (on supported platforms. On platforms that don't have write-only memory,
//! it will be mapped RW instead).
//!
//! Those types are not meant to be used directly. Instead, you should get them
//! as arguments from the [object macro](crate::ipc::macros).
//!
//! The types will auto-deref to their underlying type, allowing the user to
//! manipulate them as if they were normal pointers.

use core::marker::PhantomData;
use crate::ipc::IPCBuffer;
use crate::error::{Error, LibuserError};
use core::mem::{size_of, align_of};

// TODO: Use plain to ensure T is a valid POD type
// BODY: Plain would give us two benefits: it would do the alignment and size
// BODY: checks for us, and it would give a type-system guarantee that our T
// BODY: is valid for any arbitrary type.

/// An incoming Pointer buffer, also known as a Type-X Buffer.
///
/// Note that `T` should be a POD type (in other word, it should be defined for
/// all bit values). This usually means that it should be a repr(C) struct and
/// only contain numeric fields.
pub struct InPointer<'a, T: ?Sized> {
    /// Address of the InBuffer in the current address space.
    addr: u64,
    /// Size of the InPointer. Should match the size of T, or be a multiple of
    /// the size of T::Item if T is a slice.
    size: u64,
    /// Lifetime of the InPointer, should be bound to a [Message](crate::ipc::Message).
    phantom: PhantomData<&'a T>
}

impl<'a, T> InPointer<'a, T> {
    /// Creates a new InPointer from an underlying [IPCBuffer].
    ///
    /// # Panics
    ///
    /// Panics if the passed buffer is not a Type-X buffer.
    ///
    /// # Errors
    ///
    /// Returns an InvalidIpcBuffer error if the size does not match what was
    /// expected.
    ///
    /// Returns an InvalidIpcBuffer error if the address is not properly aligned.
    pub fn new(buf: IPCBuffer) -> Result<InPointer<'_, T>, Error> {
        assert!(buf.buftype().is_type_x());
        if buf.size != size_of::<T>() as u64 ||
           buf.addr % (align_of::<T>() as u64) != 0 {
            Err(LibuserError::InvalidIpcBuffer.into())
        } else {
            Ok(InPointer {
                addr: buf.addr,
                size: buf.size,
                phantom: PhantomData
            })
        }
    }
}

impl<'a, T> core::ops::Deref for InPointer<'a, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe {
            (self.addr as usize as *const T).as_ref().unwrap()
        }
    }
}

impl<'a, T: ?Sized + core::fmt::Debug> core::fmt::Debug for InPointer<'a, T> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_tuple("InPointer")
            .field(&*self)
            .finish()
    }
}

impl<'a, T> InPointer<'a, [T]> {
    /// Creates a new InPointer from an underlying [IPCBuffer].
    ///
    /// # Panics
    ///
    /// Panics if the passed buffer is not a Type-X buffer.
    ///
    /// # Errors
    ///
    /// Returns a InvalidIpcBuffer error if the size does not match what was
    /// expected
    pub fn new(buf: IPCBuffer) -> Result<InPointer<'_, [T]>, Error> {
        assert!(buf.buftype().is_type_x());
        if buf.size % size_of::<T>() as u64 != 0 || buf.size == 0 ||
           buf.addr % (align_of::<T>() as u64) != 0 {
            Err(LibuserError::InvalidIpcBuffer.into())
        } else {
            Ok(InPointer {
                addr: buf.addr,
                size: buf.size,
                phantom: PhantomData
            })
        }
    }
}

impl<'a, T> core::ops::Deref for InPointer<'a, [T]> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        unsafe {
            core::slice::from_raw_parts(self.addr as usize as *const T,
                                        self.size as usize / size_of::<T>())
        }
    }
}

/// An incoming Buffer, also known as a Type-A Buffer.
///
/// Note that `T` should be a POD type (in other word, it should be defined for
/// all bit values). This usually means that it should be a repr(C) struct and
/// only contain numeric fields.
pub struct InBuffer<'a, T: ?Sized> {
    /// Address of the InBuffer in the current address space.
    addr: u64,
    /// Size of the InBuffer. Should match the size of T, or be a multiple of
    /// the size of T::Item if T is a slice.
    size: u64,
    /// Lifetime of the InBuffer, should be bound to a [Message](crate::ipc::Message).
    phantom: PhantomData<&'a T>
}


impl<'a, T> InBuffer<'a, T> {
    /// Creates a new InBuffer from an underlying [IPCBuffer].
    ///
    /// # Panics
    ///
    /// Panics if the passed buffer is not a Type-A buffer.
    ///
    /// # Errors
    ///
    /// Returns a InvalidIpcBuffer error if the size does not match what was
    /// expected
    pub fn new(buf: IPCBuffer) -> Result<InBuffer<'_, T>, Error> {
        assert!(buf.buftype().is_type_a());
        if buf.size != size_of::<T>() as u64 ||
           buf.addr % (align_of::<T>() as u64) != 0 {
            Err(LibuserError::InvalidIpcBuffer.into())
        } else {
            Ok(InBuffer {
                addr: buf.addr,
                size: buf.size,
                phantom: PhantomData
            })
        }
    }
}

impl<'a, T> core::ops::Deref for InBuffer<'a, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe {
            (self.addr as usize as *const T).as_ref().unwrap()
        }
    }
}

impl<'a, T: ?Sized + core::fmt::Debug> core::fmt::Debug for InBuffer<'a, T> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_tuple("InBuffer")
            .field(&*self)
            .finish()
    }
}


impl<'a, T> InBuffer<'a, [T]> {
    /// Creates a new InBuffer from an underlying [IPCBuffer].
    ///
    /// # Panics
    ///
    /// Panics if the passed buffer is not a Type-A buffer.
    ///
    /// # Errors
    ///
    /// Returns a InvalidIpcBuffer error if the size does not match what was
    /// expected
    pub fn new(buf: IPCBuffer) -> Result<InBuffer<'_, [T]>, Error> {
        assert!(buf.buftype().is_type_a());
        if buf.size % size_of::<T>() as u64 != 0 || buf.size == 0 ||
           buf.addr % (align_of::<T>() as u64) != 0 {
            Err(LibuserError::InvalidIpcBuffer.into())
        } else {
            Ok(InBuffer {
                addr: buf.addr,
                size: buf.size,
                phantom: PhantomData
            })
        }
    }
}

impl<'a, T> core::ops::Deref for InBuffer<'a, [T]> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        unsafe {
            core::slice::from_raw_parts(self.addr as usize as *const T,
                                        self.size as usize / size_of::<T>())
        }
    }
}
