//! Multiboot Information

use sync::Once;
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

/// Tries to get a pointer to the multiboot information structure.
///
/// Returns `None` if the BootInformation hasn't been inited yet. This normally happens
/// right after paging is enabled.
pub fn try_get_boot_information() -> Option<&'static BootInformation> {
    BOOT_INFO.try()
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
