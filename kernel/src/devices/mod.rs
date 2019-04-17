//! Device drivers

pub mod rs232;
pub mod pit;
pub mod pic;
pub mod hpet;

use crate::i386::acpi;

/// Initialize a timer to be used by the OS.
pub fn init_timer() {
    if let Some(hpet_info) = acpi::get_acpi_information().hpet() {
        let hpet_init_res = unsafe { hpet::init(&hpet_info) };
        if !hpet_init_res {
            info!("Initialization of HPET failed, switching to PIT");
            unsafe { pit::init_channel_0() };
            info!("Initialized PIT");
        } else {
            info!("Initialized HPET");
        }

    } else {
        unsafe { pit::init_channel_0() };
        info!("Initialized PIT");
    }
}