//! Multiboot Information
//!
//! Gives access to the [multiboot information structure] created by our bootloader (GRUB).
//!
//! Bootloader (GRUB) passed its address in `$ebx` when we started.
//!
//! Our bootstrap had the job of copy-ing it to a PAGE_SIZE aligned address, map it,
//! and passed it to us in `$ebx`.
//!
//! When kernel initializes we store this address in [`BOOT_INFO`], and we can then access
//! it at any moment by calling [`get_boot_information`].
//!
//! [multiboot information structure]: https://www.gnu.org/software/grub/manual/multiboot2/multiboot.html#Boot-information-format
//! [`BOOT_INFO`]: self::BOOT_INFO
//! [`get_boot_information`]: self::get_boot_information

use crate::sync::Once;
use multiboot2::BootInformation;

/// Stores the address of the multiboot.
static BOOT_INFO: Once<BootInformation> = Once::new();

/// Get a pointer to the multiboot information structure.
///
/// # Panics
///
/// Panics if the BootInformation hasn't been inited yet. This normally happens
/// right after paging is enabled.
pub fn get_boot_information() -> &'static BootInformation {
    BOOT_INFO.r#try().expect("BootInformation is not init'd")
}

/// Tries to get a pointer to the multiboot information structure.
///
/// Returns `None` if the BootInformation hasn't been inited yet. This normally happens
/// right after paging is enabled.
pub fn try_get_boot_information() -> Option<&'static BootInformation> {
    BOOT_INFO.r#try()
}

/// Initializes the boot information module, allowing the `get_boot_information`
/// functions to operate properly.
///
/// Should only be called once. Further calls will be ignored silently.
pub fn init(boot_information: BootInformation) {
    BOOT_INFO.call_once(|| {
        boot_information
    });
}
