//! Arch-generic interrupt handling.
//!
//! This file contains the arch-generic implementation details of interrupt
//! handling. It contains the interrupt initialization routine, and routines to
//! unmask and acknowledge interrupts.

use crate::devices::pic;
use crate::devices::lapic::LocalApic;
use crate::devices::ioapic::IoApic;
use acpi::interrupt::{InterruptModel, InterruptSourceOverride};
use crate::sync::Once;
use alloc::vec::Vec;
use crate::mem::PhysicalAddress;

/// Global state for the interrupt handler.
struct InterruptHandler {
    /// Root CPU's Local APIC.
    root_lapic: LocalApic,
    /// Vector of all the IO-APICs.
    ioapics: Vec<IoApic>,
    /// List of interrupt mappings.
    isa_mappings: Vec<InterruptSourceOverride>
}

/// Global state for the interrupt handler.
static INTERRUPT_HANDLER: Once<InterruptHandler> = Once::new();

/// Initialize the interrupt handler.
pub fn init() {
    // Always initialize the pic to redirect entries (otherwise, we might
    // get spurious interrupts on the CPU exception handler) and mask everything.
    info!("Init pic");
    pic::init();

    info!("Mask all interrupts in PIC");
    let pic = pic::get();
    for i in 0..16 {
        pic.mask(i);
    }

    info!("Acquire INTERRUPT_HANDLER");
    let handler = INTERRUPT_HANDLER.call_once(|| {
        match crate::i386::acpi::try_get_acpi_information().and_then(|v| v.interrupt_model().as_ref()) {
            Some(InterruptModel::Apic { local_apic_address, io_apics, interrupt_source_overrides, .. }) => {
                unsafe {
                    let lapic = LocalApic::new(PhysicalAddress(*local_apic_address as usize));
                    let ioapics: Vec<IoApic> = io_apics.iter().map(|v|
                       IoApic::new(PhysicalAddress(v.address as usize), v.global_system_interrupt_base, lapic.local_apic_id())
                    ).collect();

                    for over_ride in interrupt_source_overrides {
                        let mut entry = ioapics[0].redirection_entry(over_ride.global_system_interrupt as u8);
                        entry.set_interrupt_vector(0x20 + over_ride.isa_source as u64);
                        ioapics[0].set_redirection_entry(over_ride.global_system_interrupt as u8, entry);
                    }

                    InterruptHandler {
                        root_lapic: lapic,
                        ioapics,
                        isa_mappings: interrupt_source_overrides.clone()
                    }
                }
            }
            _ => panic!("ACPI did not find a Local APIC"),
        }
    });

    info!("Enable the APIC");
    handler.root_lapic.enable();

    for mapping in &handler.isa_mappings {
        if mapping.isa_source == 0 {
            // Ignore the PIT, we're using the HPET.
            continue;
        }
        let irq = mapping.global_system_interrupt;
        let ioapic = handler.ioapics.iter().find(|ioapic|
            ioapic.interrupt_base() <= irq &&
            irq < ioapic.interrupt_base() + ioapic.redirection_entry_count()).unwrap();

        let mut redirection_entry = ioapic.redirection_entry((irq - ioapic.interrupt_base()) as u8);
        info!("Mapping ISA interrupt {} (at IOAPIC {})", mapping.isa_source, irq);
        redirection_entry.set_interrupt_vector(u64::from(0x20 + mapping.isa_source));
        let trigger_mode = match mapping.trigger_mode {
            acpi::interrupt::TriggerMode::Level => true,
            _ => false
        };
        redirection_entry.set_trigger_mode(trigger_mode);
        let polarity = match mapping.polarity {
            acpi::interrupt::Polarity::ActiveHigh => false,
            _ => true
        };
        redirection_entry.set_interrupt_input_pin_polarity(polarity);
        ioapic.set_redirection_entry((irq - ioapic.interrupt_base()) as u8, redirection_entry);
    }
}

/// Acknowledge the given IRQ.
///
/// # Panic
///
/// Panics if called before calling `init`.
pub fn acknowledge(_irq: u8) {
    INTERRUPT_HANDLER.r#try().unwrap().root_lapic.acknowledge();
}

/// Unmasks the given IRQ.
///
/// # Panic
///
/// Panics if called before calling `init`.
pub fn unmask(irq: u8) {
    let ioapics = &INTERRUPT_HANDLER.r#try().unwrap().ioapics;

    // First, find the "real" IRQ number:
    let irqisa = irq;
    let irq = isa_to_ioapic_irq(irq);

    debug!("Unmasking IRQ {} (ISA {})", irq, irqisa);

    // Then, unmask it.
    let ioapic = ioapics.iter().find(|ioapic|
                                     ioapic.interrupt_base() <= irq &&
                                     irq < ioapic.interrupt_base() + ioapic.redirection_entry_count()).unwrap();

    let mut redirection_entry = ioapic.redirection_entry((irq - ioapic.interrupt_base()) as u8);
    redirection_entry.set_interrupt_mask(false);
    ioapic.set_redirection_entry((irq - ioapic.interrupt_base()) as u8, redirection_entry);
}

/// Gets the IOAPIC pin associated with an ISA (i8259) IRQ.
///
/// # Panic
///
/// Panics if called before calling `init`.
fn isa_to_ioapic_irq(irq: u8) -> u32 {
    let isa_mappings = &INTERRUPT_HANDLER.r#try().unwrap().isa_mappings;
    isa_mappings.iter()
        .find(|v| v.isa_source == irq).map(|v| v.global_system_interrupt)
        .unwrap_or_else(|| irq.into())
}
