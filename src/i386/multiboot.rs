//! Multiboot Information

use spin::Once;
use multiboot2::BootInformation;

static BOOT_INFO: Once<BootInformation> = Once::new();

/// Get a pointer to the multiboot information structure.
///
/// # Panics
///
/// Panics if the BootInformation hasn't been inited yet. This normally happens
/// right after paging is enabled.
pub fn get_boot_information() -> &'static BootInformation {
    BOOT_INFO.try().expect("BootInformation is not init'd")
}

pub fn init(boot_information: BootInformation) {
    BOOT_INFO.call_once(|| {
        boot_information
    });
}
