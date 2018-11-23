//! Generic useful functions

extern crate kfs_libutils;
pub use self::kfs_libutils::*;
pub use checks::*;
use error::KernelError;

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
