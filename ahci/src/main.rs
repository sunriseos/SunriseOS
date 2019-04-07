//! AHCI driver module
//!
//! This driver discovers HBAs on the PCI, initialize them,
//! and exposes IPC endpoints to read and write sectors from/to a disk.
//!
//! # Features
//!
//! Here's a list of wonderful features this driver does **not** provide:
//!
//! - ATAPI support
//! - NCQ support
//! - hotplug/remove of a device
//! - hotplug/remove of a controller
//! - interrupts notifying command has been completed (WIP)
//! - real error management
//! - Port Multipliers
//! - PCI-to-PCI bridges
//!
//! # Interface
//!
//! This driver exposes two IPC interfaces: [AhciInterface], registered as `"ahci:\0"`,
//! and some [IDisk]s.
//!
//! Basically at initialization the driver will assign an id to every discovered disk.
//! You can then ask the [AhciInterface] to give you a session to any [IDisk] from its id,
//! and finally read/write some sectors.
//!
//! We read and write disk sectors only by DMA, letting the device do all the copying.
//! Our client will provide us a handle to a shared memory, and we will make the device
//! DMA read/write to it.
//!
//! # Parallelism
//!
//! For now this driver is "highly single-threaded" and blocking, this means that only one
//! request can be outstanding at any moment, and the driver will wait for it to be completed
//! before accepting other requests.
//!
//! This is highly unsatisfying, since AHCI supports up to 32 commands being issued
//! simultaneously. Unfortunately we can't take advantage of that until we manage to
//! make command-completion interrupts work.

#![feature(alloc, maybe_uninit, box_syntax, untagged_unions, const_vec_new, underscore_const_names)]
#![no_std]

// rustc warnings
#![warn(unused)]
#![warn(missing_debug_implementations)]
#![allow(unused_unsafe)]
#![allow(unreachable_code)]
#![allow(dead_code)]
#![cfg_attr(test, allow(unused_imports))]

// rustdoc warnings
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(intra_doc_link_resolution_failure)]

#[macro_use]
extern crate alloc;
#[macro_use]
extern crate sunrise_libuser;
#[macro_use]
extern crate log;
#[macro_use]
extern crate bitfield;

mod pci;
mod hba;
mod fis;
mod disk;

use crate::hba::HbaMemoryRegisters;
use crate::disk::{Disk, IDisk};
use alloc::prelude::*;
use alloc::sync::Arc;
use sunrise_libuser::error::{Error, AhciError};
use sunrise_libuser::ipc::server::{WaitableManager, PortHandler, IWaitable};
use spin::Mutex;
use sunrise_libuser::types::Handle;
use sunrise_libuser::syscalls;
use sunrise_libuser::ipc::server::SessionWrapper;

/// Array of discovered disk.
///
/// At startup, the driver will initialize each disk it discovers,
/// and populate this vec.
///
/// As hotplug/remove of a disk is not supported, this array remains
/// unchanged for the rest of the driver's execution.
///
/// A disk id is just the index of a disk in this array.
static DISKS: Mutex<Vec<Arc<Mutex<Disk>>>> = Mutex::new(Vec::new());

/// Ahci driver initialisation.
///
/// 1. Discover HBAs on the PCI.
/// 2. For every found HBA:
///     - Initialize each implemented port if we detect it is connected to a device.
///     - Push the created [Disk]s in [DISKS].
/// 3. Start the event loop.
fn main() {
    debug!("AHCI driver starting up");
    let ahci_controllers = pci::get_ahci_controllers();
    debug!("AHCI controllers : {:#x?}", ahci_controllers);
    for (bar5, _) in ahci_controllers {
        DISKS.lock().extend(
            HbaMemoryRegisters::init(bar5 as _)
                .drain(..).map(|disk| Arc::new(Mutex::new(disk)))
        );
    }
    debug!("AHCI initialised disks : {:#x?}", DISKS);

    // event loop
    let man = WaitableManager::new();
    let handler = Box::new(PortHandler::<AhciInterface>::new("ahci:\0").unwrap());
    man.add_waitable(handler as Box<dyn IWaitable>);
    man.run();
}

/// Main interface to the AHCI driver.
///
/// Registered under the name `"ahci:\0"` to the Service Manager, after the discovery stage.
///
/// Provides an endpoint to get the number of discovered disks,
/// and another one to get a session to a given disk.
///
/// As hotplug/remove of a disk is not supported, a disk id remains valid for the whole
/// lifetime of the ahci driver.
#[derive(Default, Debug)]
struct AhciInterface;

object! {
    impl AhciInterface {
        /// Returns the number of discovered disks.
        ///
        /// Any number in the range `0..disk_count()` is considered a valid disk id.
        #[cmdid(0)]
        fn disk_count(&mut self,) -> Result<(usize,), Error> {
            Ok((DISKS.lock().len(),))
        }

        /// Gets the interface to a disk.
        ///
        /// This creates a session to an [IDisk].
        ///
        /// # Error
        ///
        /// - InvalidArg: `disk_id` is not a valid disk id.
        #[cmdid(1)]
        fn get_disk(&mut self, manager: &WaitableManager, disk_id: u32,) -> Result<(Handle,), Error> {
            let idisk = IDisk::new(Arc::clone(
                DISKS.lock().get(disk_id as usize)
                .ok_or(AhciError::InvalidArg)?
            ));
            let (server, client) = syscalls::create_session(false, 0)?;
            let wrapper = SessionWrapper::new(server, idisk);
            manager.add_waitable(Box::new(wrapper) as Box<dyn IWaitable>);
            Ok((client.into_handle(),))
        }
    }
}

capabilities!(CAPABILITIES = Capabilities {
    svcs: [
        sunrise_libuser::syscalls::nr::SleepThread,
        sunrise_libuser::syscalls::nr::ExitProcess,
        sunrise_libuser::syscalls::nr::CloseHandle,
        sunrise_libuser::syscalls::nr::WaitSynchronization,
        sunrise_libuser::syscalls::nr::OutputDebugString,

        sunrise_libuser::syscalls::nr::SetHeapSize,
        sunrise_libuser::syscalls::nr::QueryMemory,
        sunrise_libuser::syscalls::nr::MapSharedMemory,
        sunrise_libuser::syscalls::nr::UnmapSharedMemory,
        sunrise_libuser::syscalls::nr::ConnectToNamedPort,
        sunrise_libuser::syscalls::nr::CreateInterruptEvent,
        sunrise_libuser::syscalls::nr::QueryPhysicalAddress,
        sunrise_libuser::syscalls::nr::MapMmioRegion,
        sunrise_libuser::syscalls::nr::SendSyncRequestWithUserBuffer,
        sunrise_libuser::syscalls::nr::ReplyAndReceiveWithUserBuffer,
        sunrise_libuser::syscalls::nr::AcceptSession,
        sunrise_libuser::syscalls::nr::CreateSession,
    ],
    raw_caps: [
        // todo: IRQ capabilities at runtime
        // body: Currently IRQ capabilities are declared at compile-time.
        // body:
        // body: However, for PCI, the IRQ line we want to subscribe to
        // body: can only be determined at runtime by reading the `Interrupt Line` register
        // body: that has been set-up during POST.
        // body:
        // body: What would be the proper way to handle such a case ?
        // body:
        // body: - Declaring every IRQ line in our capabilities, but only effectively using one ?
        // body: - Deporting the PIC management to a userspace module, and allow it to accept
        // body:   dynamic irq capabilities in yet undefined way.
        sunrise_libuser::caps::ioport(pci::CONFIG_ADDRESS + 0), sunrise_libuser::caps::ioport(pci::CONFIG_ADDRESS + 1), sunrise_libuser::caps::ioport(pci::CONFIG_ADDRESS + 2), sunrise_libuser::caps::ioport(pci::CONFIG_ADDRESS + 3),
        sunrise_libuser::caps::ioport(pci::CONFIG_DATA    + 0), sunrise_libuser::caps::ioport(pci::CONFIG_DATA    + 1), sunrise_libuser::caps::ioport(pci::CONFIG_DATA    + 2), sunrise_libuser::caps::ioport(pci::CONFIG_DATA    + 3),
    ]
});
