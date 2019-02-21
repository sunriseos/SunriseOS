//! Generic useful functions

use kfs_libutils;
pub use self::kfs_libutils::*;
pub use crate::checks::*;
use crate::error::KernelError;
use crate::scheduler;
use crate::sync::SpinLockIRQ;
use crate::process::ThreadState;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::ops::{RangeBounds, Bound};
use bit_field::BitField;

/// A trait for things that can be splitted in two parts
pub trait Splittable where Self: Sized {
    /// Split the given object in two at a given offset.
    ///
    /// The left side is modified in place, and the new right side is returned.
    ///
    /// If offset >= self.length, the object is untouched, and the right-hand side is None.
    /// If offset == 0, the object is untouched, and the right-hand side is None.
    fn split_at(&mut self, offset: usize) -> Result<Option<Self>, KernelError>;

    /// Splits the given object in two at the given offset.
    ///
    /// The right side is modified in place, and the new left side is returned.
    ///
    /// Note that offset is still the distance from the **start**.
    ///
    /// If offset >= self.length, the object is untouched, and the right-hand side is None.
    /// If offset == 0, the object is untouched, and the right-hand side is None.
    fn right_split(&mut self, offset: usize) -> Result<Option<Self>, KernelError> {
        let right_opt = self.split_at(offset)?;
        match right_opt {
            None => Ok(None), // no split was done
            Some(mut other) => {
                // swap the left and the right parts
                ::core::mem::swap(self, &mut other);
                Ok(Some(other))
            }
        }
    }
}

/// Checks if our thread was killed, in which case unschedule ourselves.
///
/// # Note
///
/// As this function will be the last that will be called by a thread before dying,
/// caller must make sure all of its scope variables are ok to be leaked.
pub fn check_thread_killed() {
    if scheduler::get_current_thread().state.load(Ordering::SeqCst) == ThreadState::Killed {
        let lock = SpinLockIRQ::new(());
        loop { // in case of spurious wakeups
            let _ = scheduler::unschedule(&lock, lock.lock());
        }
    }
}

/// Provides an abstraction over an Atomic bitmap.
pub trait AtomicBitmap {
    /// Returns the number of bits this bitmap contains.
    fn bit_len(&self) -> usize;
    /// Returns an iterator over each bit in the bitmap.
    ///
    /// The bits may change while iterating!
    fn bit_iter(&self) -> BitIterator<Self>;
    /// Obtains the bit at the index `bit`; note that index 0 is the least
    /// significant bit, while index `length() - 1` is the most significant bit.
    ///
    /// `load_bit` takes an [Ordering] argument which describes the memory
    /// ordering of this operation. Possible values are [SeqCst](Ordering::SeqCst),
    /// [Acquire](Ordering::Acquire) and [Relaxed](Ordering::Relaxed).
    ///
    /// # Panics
    ///
    /// Panics if order is [Release](Ordering::Release) or
    /// [AcqRel](Ordering::AcqRel).
    fn load_bit(&self, index: usize, order: Ordering) -> bool;
    /// Sets the bit at the index `bit` to the value `val` (where true means a
    /// value of '1' and false means a value of '0'); note that index 0 is the
    /// least significant bit, while index `length() - 1` is the most significant
    /// bit.
    ///
    /// `store_bit` takes an [Ordering] argument which describes the memory
    /// ordering of this operation. Possible values are [SeqCst](Ordering::SeqCst),
    /// [Release](Ordering::Release) and [Relaxed](Ordering::Relaxed).
    ///
    /// # Panics
    ///
    /// Panics if order is [Acquire](Ordering::Acquire) or
    /// [AcqRel](Ordering::AcqRel).
    fn store_bit(&self, index: usize, val: bool, order: Ordering);
    /// Stores a bit into the atomic bitmap if the current value of that bit is
    /// the same as the `current` value. The other bits are unchanged. Note that
    /// index 0 is the least significant bit, while index `length() - 1` is the
    /// most significant bit.
    ///
    /// The return value is always the previous value. If it is equal to
    /// `current`, then the value was updated.
    ///
    /// `compare_and_swap` also takes an [Ordering] argument which describes the
    /// memory ordering of this operation. Notice that even when using [AcqRel],
    /// the operation might fail and hence just perform an [Acquire] load, but
    /// not have [Release] semantics. Using [Acquire] makes the store part of
    /// this operation [Relaxed] if it happens, and using [Release] makes the
    /// load part [Relaxed].
    ///
    /// [Acquire]: Ordering::Acquire
    /// [Relaxed]: Ordering::Relaxed
    /// [Release]: Ordering::Release
    /// [AcqRel]: Ordering::AcqRel
    fn compare_and_swap(&self, index: usize, current: bool, new: bool, order: Ordering) -> Result<bool, bool>;
    /// Finds `count` consecutive bits in the atomic bitmap that are of value
    /// `!val`, and atomically sets them to `val` (where true means a value of
    /// '1' and false means a value of '0').
    ///
    /// The return value is the index of the least significant bit that changed,
    /// or [None] if the bitmap didn't contain enough bits of the right value.
    fn set_n_bits(&self, count: usize, val: bool) -> Option<usize>;
    /// Sets the bits in `range` in the atomic bitmap to value `val` (where true
    /// means a value of '1' and false means a value of '0'); note that index 0
    /// is the least significant bit, while index `length() - 1` is the most
    /// significant bit.
    ///
    /// # Atomicity
    ///
    /// Those bits are individually set atomically, but they might not all appear
    /// to be set all at once.
    fn store_bits_nonatomic<T: RangeBounds<usize>>(&self, range: T, val: bool);
}

/// A cell in a bitmap array.
pub trait BitmapCell {
    /// The amount of bits this cell contains.
    fn bit_capacity() -> usize;
}

impl BitmapCell for AtomicUsize {
    fn bit_capacity() -> usize {
        core::mem::size_of::<AtomicUsize>() * 8
    }
}

/// An iterator over bits in a Bitmap, returned by [AtomicBitmap::bit_iter].
#[derive(Debug)]
pub struct BitIterator<'a, T: ?Sized + AtomicBitmap>(&'a T, usize);

impl<'a, T: ?Sized + AtomicBitmap> Iterator for BitIterator<'a, T> {
    type Item = bool;
    fn next(&mut self) -> Option<bool> {
        if self.1 < self.0.bit_len() {
            let val = self.0.load_bit(self.1, Ordering::SeqCst);
            self.1 += 1;
            Some(val)
        } else {
            None
        }
    }
}


impl AtomicBitmap for AtomicUsize {
    fn bit_len(&self) -> usize {
        Self::bit_capacity()
    }
    fn load_bit(&self, index: usize, order: Ordering) -> bool {
        assert!(index < 8 * core::mem::size_of::<AtomicUsize>());
        self.load(order).get_bit(index)
    }
    fn store_bit(&self, index: usize, val: bool, order: Ordering) {
        assert!(index < 8 * core::mem::size_of::<AtomicUsize>());
        // We first calculate a mask to use with `fetch_or`/`fetch_and`.
        let mut mask = 0;
        mask.set_bit(index, val);
        if val {
            self.fetch_or(mask, order);
        } else {
            self.fetch_and(!mask, order);
        }
    }
    fn store_bits_nonatomic<T: RangeBounds<usize>>(&self, range: T, val: bool) {
        let start = match range.start_bound() {
            Bound::Unbounded => 0,
            Bound::Included(b) => *b,
            Bound::Excluded(_b) => unreachable!("Excluded in start"),
        };
        let end = match range.end_bound() {
            Bound::Unbounded => 0,
            Bound::Included(b) => *b + 1,
            Bound::Excluded(b) => *b,
        };
        assert!(start < 8 * core::mem::size_of::<AtomicUsize>());
        assert!(end <= 8 * core::mem::size_of::<AtomicUsize>());
        let mut mask = 0;
        mask.set_bits_area(start..end, true);
        if val {
            self.fetch_or(mask, Ordering::SeqCst);
        } else {
            self.fetch_and(!mask, Ordering::SeqCst);
        }
    }
    fn compare_and_swap(&self, index: usize, current: bool, new: bool, order: Ordering) -> Result<bool, bool> {
        assert!(index < 8 * core::mem::size_of::<AtomicUsize>());
        // This cell stores multiple bits, but we can only compare/swap on the whole cell at once,
        // so it's possible for compare/swap to fail because a different bit in the cell has been
        // modified by another thread. In such a case, continue trying to compare/swap until either
        // we are successful or another thread modifies the specified bit before we do.
        let mut cur_cell_val = self.load(Ordering::Acquire);
        loop {
            // Load the current cell value, and stop early if the bit we're trying to set has
            // already been changed on another thread
            let cur_val = cur_cell_val.get_bit(index);
            if cur_val != current {
                return Err(cur_val);
            }

            // Decide what the new cell value should be after setting/unsetting the specified bit
            let mut new_cell_val = cur_cell_val;
            new_cell_val.set_bit(index, new);

            // Try to swap in the new cell value. If successful, we can signal success. Otherwise,
            // check whether the failure was because the targeted bit was flipped by another thread.
            // If so, then stop early and indicate failure. Otherwise, try again.
            match self.compare_exchange(cur_cell_val, new_cell_val, order, Ordering::Acquire) {
                Ok(_current) => return Ok(new),
                Err(oldval) => cur_cell_val = oldval,
            }
        }
    }
    fn set_n_bits(&self, count: usize, val: bool) -> Option<usize> {
        assert!(count < 8 * core::mem::size_of::<AtomicUsize>());
        let mut set_idx = None;

        // Use fetch_update to avoid writing our own CAS loop.
        let res = self.fetch_update(|old| {
            set_idx = None;
            let mut curcount = 0;
            for offset in 0..Self::bit_capacity() {
                if old.get_bit(offset) != val {
                    let firstoff = *set_idx.get_or_insert(offset);
                    curcount += 1;
                    if curcount == count {
                        let mut new = old;
                        new.set_bits_area(firstoff..=offset, val);
                        return Some(new)
                    }
                } else {
                    curcount = 0;
                    set_idx = None;
                }
            }
            None
        }, Ordering::SeqCst, Ordering::SeqCst);

        res
            .ok()
            .map(|_| set_idx.expect("fetch_update cannot succeed without setting set_idx"))
    }

    fn bit_iter(&self) -> BitIterator<Self> {
        BitIterator(self, 0)
    }
}

impl<'a, T: AtomicBitmap + BitmapCell> AtomicBitmap for [T] {
    fn bit_len(&self) -> usize {
        T::bit_capacity() * self.len()
    }
    fn load_bit(&self, index: usize, order: Ordering) -> bool {
        self[index / T::bit_capacity()].load_bit(index % T::bit_capacity(), order)
    }

    fn store_bit(&self, index: usize, val: bool, order: Ordering) {
        self[index / T::bit_capacity()].store_bit(index % T::bit_capacity(), val, order)
    }

    fn compare_and_swap(&self, index: usize, current: bool, new: bool, order: Ordering) -> Result<bool, bool> {
        self[index / T::bit_capacity()].compare_and_swap(index % T::bit_capacity(), current, new, order)
    }

    fn store_bits_nonatomic<U: RangeBounds<usize>>(&self, range: U, val: bool) {
        let start_bit = match range.start_bound() {
            Bound::Unbounded => 0,
            Bound::Included(b) => *b,
            Bound::Excluded(_) => unreachable!("Got excluded bound in start"),
        };

        let start_cell = start_bit / T::bit_capacity();

        let end_bit_included = match range.end_bound() {
            Bound::Unbounded => self.bit_len() - 1,
            Bound::Included(b) => *b,
            // If 0 is excluded, then the range is empty.
            Bound::Excluded(0) => return,
            Bound::Excluded(b) => *b - 1,
        };

        let end_cell_included = end_bit_included / T::bit_capacity();

        for (idx, item) in self.iter().enumerate()
            .skip(start_cell)
            .take_while(|(idx, _)| *idx <= end_cell_included)
        {
            let range_start = if start_cell == idx {
                start_bit % T::bit_capacity()
            } else {
                0
            };
            let range_end = if end_cell_included == idx {
                (end_bit_included % T::bit_capacity()) + 1
            } else {
                T::bit_capacity()
            };
            item.store_bits_nonatomic(range_start..range_end, val);
        }
    }

    fn set_n_bits(&self, count: usize, val: bool) -> Option<usize> {
        for (idx, i) in self.iter().enumerate() {
            if let Some(i_idx) = i.set_n_bits(count, val) {
                return Some(idx * T::bit_capacity() + i_idx)
            }
        }
        None
    }

    fn bit_iter(&self) -> BitIterator<Self> {
        BitIterator(self, 0)
    }
}
