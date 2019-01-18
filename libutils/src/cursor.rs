//! Simple cursor
//!
//! This module contains a very simple cursor, similar to std::io's, but without
//! relying on the io module. It also offers additional convenience functions to
//! make writing PODs easy.
//!
//! If std::io is ever ported to core::io, this module can disappear.
//!
//! - https://github.com/rust-lang/rust/issues/48331
//! - https://github.com/rust-lang-nursery/portability-wg/issues/12

use byteorder::ByteOrder;
use core::mem::{self, size_of};
use core::slice;

// TODO: Cursor read_raw/write_raw is totally unsafe.
// BODY: Libutils' Cursor allows creating a structure from a byte array, by doing
// BODY: pointer magic fuckery. We should be using a crate like Plain instead,
// BODY: which properly encapsulates the unsafety.

/// A minimal Cursor for writing, for use in libcore.
///
/// See https://doc.rust-lang.org/std/io/struct.Cursor.html
#[derive(Debug)]
pub struct CursorWrite<'a> {
    /// Data backing this cursor.
    data: &'a mut [u8],
    /// Position of the cursor in the data.
    pos: usize
}

impl<'a> CursorWrite<'a> {
    /// Creates a new cursor wrapping the provided underlying in-memory buffer.
    pub fn new(data: &mut [u8]) -> CursorWrite<'_> {
        CursorWrite {
            data: data,
            pos: 0
        }
    }

    /// Returns the current position of this cursor.
    pub fn pos(&self) -> usize {
        self.pos
    }

    /// Skip the given amount of bytes, returning a mutable slice to it.
    pub fn skip_write(&mut self, bytelen: usize) -> &mut [u8] {
        let ret = &mut self.data[self.pos..self.pos + bytelen];
        self.pos += bytelen;
        ret
    }

    /// Writes an u8 in the given byte ordering.
    pub fn write_u8<BO: ByteOrder>(&mut self, v: u8) {
        self.data[self.pos] = v;
        self.pos += 1;
    }
    /// Writes a u16 in the given byte ordering.
    pub fn write_u16<BO: ByteOrder>(&mut self, v: u16) {
        BO::write_u16(&mut self.data[self.pos..], v);
        self.pos += 2;
    }
    /// Writes a u32 in the given byte ordering.
    pub fn write_u32<BO: ByteOrder>(&mut self, v: u32) {
        BO::write_u32(&mut self.data[self.pos..], v);
        self.pos += 4;
    }
    /// Writes a u64 in the given byte ordering.
    pub fn write_u64<BO: ByteOrder>(&mut self, v: u64) {
        BO::write_u64(&mut self.data[self.pos..], v);
        self.pos += 8;
    }
    /// Writes the given byte slice entirely.
    pub fn write(&mut self, v: &[u8]) {
        self.data[self.pos..self.pos + v.len()].copy_from_slice(v);
        self.pos += v.len();
    }

    /// Writes the given structure.
    pub fn write_raw<T: Copy>(&mut self, v: T) {
        let ptr = &v;
        let arr = unsafe {
            slice::from_raw_parts(ptr as *const T as *const u8, size_of::<T>())
        };
        self.skip_write(size_of::<T>()).copy_from_slice(arr);
    }
}

/// A minimal Cursor for writing, for use in libcore.
///
/// See https://doc.rust-lang.org/std/io/struct.Cursor.html
#[derive(Debug)]
pub struct CursorRead<'a> {
    /// Data backing this cursor.
    data: &'a [u8],
    // Let's cheat
    /// Position of the cursor in the data.
    pos: ::core::cell::Cell<usize>
}

impl<'a> CursorRead<'a> {
    /// Creates a new cursor wrapping the provided underlying in-memory buffer.
    pub fn new(data: &[u8]) -> CursorRead<'_> {
        CursorRead {
            data: data,
            pos: 0.into()
        }
    }

    /// Returns the current position of this cursor.
    pub fn pos(&self) -> usize {
        self.pos.get()
    }

    /// Reads an u8 in the given byteorder.
    pub fn read_u8<BO: ByteOrder>(&self) -> u8 {
        let ret = self.data[self.pos.get()];
        self.pos.set(self.pos.get() + 1);
        ret
    }
    /// Reads an u16 in the given byteorder.
    pub fn read_u16<BO: ByteOrder>(&self) -> u16 {
        let ret = BO::read_u16(&self.data[self.pos.get()..]);
        self.pos.set(self.pos.get() + 2);
        ret
    }
    /// Reads an u32 in the given byteorder.
    pub fn read_u32<BO: ByteOrder>(&self) -> u32 {
        let ret = BO::read_u32(&self.data[self.pos.get()..]);
        self.pos.set(self.pos.get() + 4);
        ret
    }
    /// Reads an u64 in the given byteorder.
    pub fn read_u64<BO: ByteOrder>(&self) -> u64 {
        let ret = BO::read_u64(&self.data[self.pos.get()..]);
        self.pos.set(self.pos.get() + 8);
        ret
    }

    /// Reads `v.len()` bytes from the stream, and asserts that it is equal to
    /// `v`.
    pub fn assert(&self, v: &[u8]) {
        assert_eq!(&self.data[self.pos.get()..self.pos.get() + v.len()], v);
        self.pos.set(self.pos.get() + v.len());
    }

    /// Skips `bytelen` bytes, returning a slice to them for inspection.
    pub fn skip_read(&self, bytelen: usize) -> &[u8] {
        let ret = &self.data[self.pos.get()..self.pos.get() + bytelen];
        self.pos.set(self.pos.get() + bytelen);
        ret
    }

    /// Reads the given structure from the bytestream.
    pub fn read_raw<T: Copy>(&self) -> T {
        unsafe {
            let mut v: T = mem::uninitialized();
            {
                let arr = slice::from_raw_parts_mut(&mut v as *mut T as *mut u8, size_of::<T>());
                arr.copy_from_slice(self.skip_read(size_of::<T>()));
            }
            v
        }
    }
}
