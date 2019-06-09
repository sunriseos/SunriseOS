//! Time Service
//!
//! This service takes care of anything related with time.

#![feature(alloc_prelude, untagged_unions)]
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
use sunrise_libuser::time::{TimeZoneServiceProxy, StaticService as _, TimeZoneService as _, RTCManager as _};
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
        sunrise_libuser::syscalls::nr::CreateInterruptEvent,
        sunrise_libuser::syscalls::nr::SendSyncRequestWithUserBuffer,

        sunrise_libuser::syscalls::nr::SetHeapSize,

        sunrise_libuser::syscalls::nr::QueryMemory,
    ],
    raw_caps: [
        sunrise_libuser::caps::irq_pair(0x08, 0x3FF),
        sunrise_libuser::caps::ioport(0x70),
        sunrise_libuser::caps::ioport(0x71),
    ]
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
#[derive(Debug)]
struct Rtc {
    /// Command Register.
    command: io::Pio<u8>,
    /// Data Register.
    data: io::Pio<u8>,
    
    /// Last RTC time value.
    timestamp: Mutex<i64>,

    /// The RTC event.
    irq_event: Option<ReadableEvent>
}

impl Rtc {
    /// Create a new RTC with the default IBM PC values.
    pub fn new() -> Rtc {
        let irq = syscalls::create_interrupt_event(0x08, 0).expect("IRQ cannot be acquired");

        let mut rtc = Rtc {
            command: io::Pio::new(0x70),
            data: io::Pio::new(0x71),
            timestamp: Mutex::default(),
            irq_event: Some(irq)
        };

        rtc.enable_update_ended_int();
        rtc
    }

    /// Get the last timestamp of the RTC.
    pub fn get_time(&self) -> i64 {
        *self.timestamp.lock()
    }

    /// Get the update event of the RTC.
    /// TODO: Implement get_rtc_event
    /// BODY: We need CreateEvent, SignalEvent and ClearEvent syscalls before being able to implement it
    pub fn get_irq_event_handle(&self) -> HandleRef<'static> {
        unimplemented!()
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
    fn read_interrupt_kind(&mut self) -> u8 {
        self.read_reg(0xC)
    }

    /// Checks if the RTC is in 12 hours or 24 hours mode. Depending on the mode,
    /// the date might be encoded in BCD.
    #[allow(clippy::wrong_self_convention)] // More readable this way.
    pub fn is_12hr_clock(&mut self) -> bool {
        self.read_reg(0xB) & (1 << 2) != 0
    }
}

/// Global instance of Rtc. It's safe to actually access it as it isn't modified concurently
static mut RTC_INSTANCE: Rtc = unsafe { initialize_to_zero!(Rtc) };

/// RTC interface.
#[derive(Default, Debug)]
struct RTCManager;

impl IWaitable for Rtc {
    fn get_handle(&self) -> HandleRef<'_> {
        if let Some(irq_event) = &self.irq_event {
            return irq_event.0.as_ref_static()
        }
        panic!("RTC irq event cannot be uninialized");
    }

    fn handle_signaled(&mut self, _manager: &WaitableManager) -> Result<bool, Error> {
        let intkind = self.read_interrupt_kind();
        if intkind & (1 << 4) != 0 {
            // Time changed. Let's update.
            let mut seconds = i64::from(self.read_reg(0));
            let mut minutes = i64::from(self.read_reg(2));
            let mut hours = i64::from(self.read_reg(4));
            let mut day = i64::from(self.read_reg(7));
            let mut month = i64::from(self.read_reg(8));
            let mut year = i64::from(self.read_reg(9));

            // IBM sometimes uses BCD. Why? God knows.
            if !self.is_12hr_clock() {
                seconds = (seconds & 0x0F) + ((seconds / 16) * 10);
                minutes = (minutes & 0x0F) + ((minutes / 16) * 10);
                hours = ( (hours & 0x0F) + (((hours & 0x70) / 16) * 10) ) | (hours & 0x80);
                day = (day & 0x0F) + ((day / 16) * 10);
                month = (month & 0x0F) + ((month / 16) * 10);
                year = (year & 0x0F) + ((year / 16) * 10);
            }

            // Convert day range
            day -= 1;

            // Taken from https://en.wikipedia.org/wiki/Julian_day
            let a = (14 - month) / 12;
            let y = (year + 2000) + 4800 - a;
            let m = month + (12 * a) - 3;

            let mut julian_day_number = day;
            julian_day_number += (153 * m + 2) / 5;
            julian_day_number += 365 * y;
            julian_day_number += y / 4;
            julian_day_number += -y / 100;
            julian_day_number += y / 400;
            julian_day_number -= 32045;
            julian_day_number -= 2440588; // Unix epoch in julian date
            julian_day_number *= 86400; // days to seconds
            julian_day_number += hours * 3600; // hours to seconds
            julian_day_number += minutes * 60;
            julian_day_number += seconds;

            let mut value = self.timestamp.lock();
            *value = julian_day_number;
        }
        Ok(false)
    }
}

impl sunrise_libuser::time::RTCManager for RTCManager {
    fn get_rtc_time(&mut self, _manager: &WaitableManager) -> Result<i64, Error> {
        Ok(unsafe {RTC_INSTANCE.get_time() })
    }

    fn get_rtc_event(&mut self, _manager: &WaitableManager) -> Result<HandleRef<'static>, Error> {
        Ok(unsafe {RTC_INSTANCE.get_irq_event_handle() })
    }
}

use generic_array::GenericArray;
use generic_array::typenum::consts::U36;

fn main() {
    // Setup a default device location
    let device_location_name = b"Europe/Paris\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    timezone::TZ_MANAGER.lock().set_device_location_name(*device_location_name).unwrap();

    unsafe { RTC_INSTANCE = Rtc::new() };

    let man = WaitableManager::new();
    let user_handler = Box::new(PortHandler::new("time:u\0", StaticService::dispatch).unwrap());
    let applet_handler = Box::new(PortHandler::new("time:a\0", StaticService::dispatch).unwrap());
    let system_handler = Box::new(PortHandler::new("time:s\0", StaticService::dispatch).unwrap());
    let rtc_handler = Box::new(PortHandler::new("rtc\0", RTCManager::dispatch).unwrap());

    let rtc_instance = unsafe { Box::from_raw(&mut RTC_INSTANCE as *mut Rtc) };

    man.add_waitable(user_handler as Box<dyn IWaitable>);
    man.add_waitable(applet_handler as Box<dyn IWaitable>);
    man.add_waitable(system_handler as Box<dyn IWaitable>);
    man.add_waitable(rtc_handler as Box<dyn IWaitable>);
    man.add_waitable(rtc_instance as Box<dyn IWaitable>);

    man.run();
}