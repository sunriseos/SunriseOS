//! Time Service
//!
//! This service takes care of anything related with time.

#![feature(alloc, alloc_prelude, maybe_uninit, untagged_unions)]
#![no_std]

// rustc warnings
#![warn(unused)]
#![warn(missing_debug_implementations)]
#![allow(unused_unsafe)]
#![allow(unreachable_code)]
#![allow(dead_code)]
#![cfg_attr(test, allow(unused_imports))]

// rustdoc warnings
#![warn(missing_docs)] // hopefully this will soon become deny(missing_docs)
#![deny(intra_doc_link_resolution_failure)]

#[macro_use]
extern crate sunrise_libuser;

#[macro_use]
extern crate alloc;

#[macro_use]
extern crate log;

mod timezone;

use alloc::prelude::v1::*;

use sunrise_libuser::syscalls;
use sunrise_libuser::ipc::server::{WaitableManager, PortHandler, IWaitable, SessionWrapper};
use sunrise_libuser::time::{TimeZoneServiceProxy, StaticService as _, TimeZoneService as _};
use sunrise_libuser::types::*;
use sunrise_libuser::io::{self, Io};
use sunrise_libuser::error::Error;
use sunrise_libutils::initialize_to_zero;
use spin::Mutex;

capabilities!(CAPABILITIES = Capabilities {
    svcs: [
        sunrise_libuser::syscalls::nr::SleepThread,
        sunrise_libuser::syscalls::nr::ExitProcess,
        sunrise_libuser::syscalls::nr::CloseHandle,
        sunrise_libuser::syscalls::nr::WaitSynchronization,
        sunrise_libuser::syscalls::nr::OutputDebugString,

        sunrise_libuser::syscalls::nr::ReplyAndReceiveWithUserBuffer,
        sunrise_libuser::syscalls::nr::AcceptSession,
        sunrise_libuser::syscalls::nr::CreateSession,

        sunrise_libuser::syscalls::nr::ConnectToNamedPort,
        sunrise_libuser::syscalls::nr::SendSyncRequestWithUserBuffer,

        sunrise_libuser::syscalls::nr::SetHeapSize,

        sunrise_libuser::syscalls::nr::QueryMemory,

        sunrise_libuser::syscalls::nr::MapSharedMemory,
        sunrise_libuser::syscalls::nr::UnmapSharedMemory,

        sunrise_libuser::syscalls::nr::MapFramebuffer,
    ],
});

/// Entry point interface.
#[derive(Default, Debug)]
struct StaticService;

impl sunrise_libuser::time::StaticService for StaticService {
    fn get_timezone_service(&mut self, manager: &WaitableManager) -> Result<TimeZoneServiceProxy, Error> {
        let timezone_instance = timezone::TimeZoneService::default();
        let (server, client) = syscalls::create_session(false, 0)?;
        let wrapper = SessionWrapper::new(server, timezone_instance, timezone::TimeZoneService::dispatch);
        manager.add_waitable(Box::new(wrapper) as Box<dyn IWaitable>);
        Ok(TimeZoneServiceProxy::from(client))
    }
}

/// IBM Real Time Clock provides access to the current date and time (at second
/// precision). The Real Time Clock is actually part of the CMOS on
/// usual IBM/PC setups.
///
/// It is comprised of a command register and a data register. To access data
/// store on the CMOS, one should first write the data address in the command
/// register, then either read or write the data register to read/write to that
/// data address. This is implemented and abstracted away by [Rtc::read_reg] and
/// [Rtc::write_reg].
struct Rtc {
    /// Command Register.
    command: io::Pio<u8>,
    /// Data Register.
    data: io::Pio<u8>
}

impl Rtc {
    /// Create a new RTC with the default IBM PC values.
    pub fn new() -> Rtc {
        Rtc {
            command: io::Pio::new(0x70),
            data: io::Pio::new(0x71)
        }
    }

    /// Read from a CMOS register.
    fn read_reg(&mut self, reg: u8) -> u8 {
        self.command.write(reg);
        self.data.read()
    }

    /// Write to the CMOS register.
    fn write_reg(&mut self, reg: u8, val: u8) {
        self.command.write(reg);
        self.data.write(val)
    }

    /// Enable the Update Ended RTC interrupt. This will enable an interruption
    /// on IRQ 8 that will be thrown when the RTC is finished updating its
    /// registers.
    pub fn enable_update_ended_int(&mut self) {
        // Set the rate to be as slow as possible...
        //let oldval = self.read_reg(0xA);
        //self.write_reg(0xA, (oldval & 0xF0) | 0xF);
        let oldval = self.read_reg(0xB);
        self.write_reg(0xB, oldval | (1 << 4));
    }

    /// Acknowledges an interrupt from the RTC. Necessary to receive further
    /// interrupts.
    pub fn read_interrupt_kind(&mut self) -> u8 {
        self.read_reg(0xC)
    }

    /// Checks if the RTC is in 12 hours or 24 hours mode. Depending on the mode,
    /// the date might be encoded in BCD.
    #[allow(clippy::wrong_self_convention)] // More readable this way.
    pub fn is_12hr_clock(&mut self) -> bool {
        self.read_reg(0xB) & (1 << 2) != 0
    }
}

/// Global instance of Rtc
static RTC_INSTANCE: Mutex<Rtc> = Mutex::new(unsafe { initialize_to_zero!(Rtc) });

/// RTC interface.
#[derive(Default, Debug)]
struct RTCManager {
    /// Last RTC time value.
    timestamp: Mutex<u64>
}

impl sunrise_libuser::time::RTCManager for RTCManager {
    fn get_rtc_time(&mut self, _manager: &WaitableManager) -> Result<i64, Error> {
        Ok((*self.timestamp.lock()) as i64)
    }

    fn set_rtc_time(&mut self, _manager: &WaitableManager, rtc_time: i64) -> Result<(), Error> {
        unimplemented!()
    }

    fn get_rtc_event(&mut self, _manager: &WaitableManager) -> Result<HandleRef<'static>, Error> {
        unimplemented!()
    }
}

use generic_array::GenericArray;
use generic_array::typenum::consts::U36;

fn main() {
    // Setup a default device location
    let device_location_name = b"Europe/Paris\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    timezone::TZ_MANAGER.lock().set_device_location_name(*device_location_name).unwrap();

    //let irq = syscalls::create_interrupt_event(0x08, 0).unwrap();
    let man = WaitableManager::new();
    let user_handler = Box::new(PortHandler::new("time:u\0", StaticService::dispatch).unwrap());
    let applet_handler = Box::new(PortHandler::new("time:a\0", StaticService::dispatch).unwrap());
    let system_handler = Box::new(PortHandler::new("time:s\0", StaticService::dispatch).unwrap());

    man.add_waitable(user_handler as Box<dyn IWaitable>);
    man.add_waitable(applet_handler as Box<dyn IWaitable>);
    man.add_waitable(system_handler as Box<dyn IWaitable>);

    man.run();
}