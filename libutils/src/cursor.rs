use byteorder::ByteOrder;
use core::mem::{self, size_of};
use core::slice;

// Minimal cursor implementation
pub struct CursorWrite<'a> {
    data: &'a mut [u8],
    pos: usize
}

#[allow(dead_code)]
impl<'a> CursorWrite<'a> {
    pub fn new(data: &mut [u8]) -> CursorWrite {
        CursorWrite {
            data: data,
            pos: 0
        }
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    // Dissociate the lifetimes
    pub fn skip_write(&mut self, bytelen: usize) -> &mut [u8] {
        let ret = &mut self.data[self.pos..self.pos + bytelen];
        self.pos += bytelen;
        ret
    }
    pub fn write_u8<BO: ByteOrder>(&mut self, v: u8) {
        self.data[self.pos] = v;
        self.pos += 1;
    }
    pub fn write_u16<BO: ByteOrder>(&mut self, v: u16) {
        BO::write_u16(&mut self.data[self.pos..], v);
        self.pos += 2;
    }
    pub fn write_u32<BO: ByteOrder>(&mut self, v: u32) {
        BO::write_u32(&mut self.data[self.pos..], v);
        self.pos += 4;
    }
    pub fn write_u64<BO: ByteOrder>(&mut self, v: u64) {
        BO::write_u64(&mut self.data[self.pos..], v);
        self.pos += 8;
    }
    pub fn write(&mut self, v: &[u8]) {
        self.data[self.pos..self.pos + v.len()].copy_from_slice(v);
        self.pos += v.len();
    }
    pub fn write_raw<T: Copy>(&mut self, v: T) {
        let ptr = &v;
        let arr = unsafe {
            slice::from_raw_parts(ptr as *const T as *const u8, size_of::<T>())
        };
        self.skip_write(size_of::<T>()).copy_from_slice(arr);
    }
}

pub struct CursorRead<'a> {
    data: &'a [u8],
    // Let's cheat
    pos: ::core::cell::Cell<usize>
}

#[allow(dead_code)]
impl<'a> CursorRead<'a> {
    pub fn new(data: &[u8]) -> CursorRead {
        CursorRead {
            data: data,
            pos: 0.into()
        }
    }

    pub fn pos(&self) -> usize {
        self.pos.get()
    }

    // Dissociate the lifetimes
    pub fn read_u8<BO: ByteOrder>(&self) -> u8 {
        let ret = self.data[self.pos.get()];
        self.pos.set(self.pos.get() + 1);
        ret
    }
    pub fn read_u16<BO: ByteOrder>(&self) -> u16 {
        let ret = BO::read_u16(&self.data[self.pos.get()..]);
        self.pos.set(self.pos.get() + 2);
        ret
    }
    pub fn read_u32<BO: ByteOrder>(&self) -> u32 {
        let ret = BO::read_u32(&self.data[self.pos.get()..]);
        self.pos.set(self.pos.get() + 4);
        ret
    }
    pub fn read_u64<BO: ByteOrder>(&self) -> u64 {
        let ret = BO::read_u64(&self.data[self.pos.get()..]);
        self.pos.set(self.pos.get() + 8);
        ret
    }

    pub fn assert(&self, v: &[u8]) {
        assert_eq!(&self.data[self.pos.get()..self.pos.get() + v.len()], v);
        self.pos.set(self.pos.get() + v.len());
    }

    pub fn skip_read(&self, bytelen: usize) -> &[u8] {
        let ret = &self.data[self.pos.get()..self.pos.get() + bytelen];
        self.pos.set(self.pos.get() + bytelen);
        ret
    }

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
