//! Device drivers

pub mod hpet;
pub mod pic;
pub mod pit;
pub mod rs232;

pub mod lapic;
pub mod ioapic;

use crate::i386::acpi;

/// Initialize a timer to be used by the OS.
pub fn init_timer() {
    let mut use_pit = false;
    if let Some(acpi_info) = acpi::try_get_acpi_information() {
        if let Some(hpet_info) = acpi_info.hpet() {
            let hpet_init_res = unsafe { hpet::init(&hpet_info) };
            if !hpet_init_res {
                info!("Initialization of HPET failed, switching to PIT");
                use_pit = true;
            } else {
                info!("Initialized HPET");
            }
        }
    } else {
        use_pit = true;
    }

    if use_pit {
        unsafe { pit::init_channel_0() };
        info!("Initialized PIT");
    } else {
        unsafe { pit::disable() };
        info!("Disabled PIT");
    }
}
