//! Time Service
//!
//! This service takes care of anything related with time.

#![feature(alloc_prelude, untagged_unions, async_await)]
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

mod timezone;

use alloc::prelude::v1::*;

use sunrise_libuser::syscalls;
use sunrise_libuser::futures::{WaitableManager, WorkQueue};
use sunrise_libuser::ipc::server::{new_session_wrapper, port_handler};
use futures::future::FutureObj;
use sunrise_libuser::time::{TimeZoneServiceProxy, StaticService as _, TimeZoneService as _, RTCManager as _};
use sunrise_libuser::types::*;
use sunrise_libuser::io::{self, Io};
use sunrise_libuser::error::Error;
use spin::Mutex;
use spin::Once;

capabilities!(CAPABILITIES = Capabilities {
    svcs: [
        sunrise_libuser::syscalls::nr::SleepThread,
        sunrise_libuser::syscalls::nr::ExitProcess,
        sunrise_libuser::syscalls::nr::CloseHandle,
        sunrise_libuser::syscalls::nr::WaitSynchronization,
        sunrise_libuser::syscalls::nr::OutputDebugString,
        sunrise_libuser::syscalls::nr::SetThreadArea,

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
    fn get_timezone_service(&mut self, manager: WorkQueue<'static>) -> Result<TimeZoneServiceProxy, Error> {
        let timezone_instance = timezone::TimeZoneService::default();
        let (server, client) = syscalls::create_session(false, 0)?;
        let wrapper = new_session_wrapper(manager.clone(), server, timezone_instance, timezone::TimeZoneService::dispatch);
        manager.spawn(FutureObj::new(Box::new(wrapper)));
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
    /// Command and Data Register.
    registers: Mutex<(io::Pio<u8>, io::Pio<u8>)>,

    /// Last RTC time value.
    timestamp: Mutex<i64>,

    /// The RTC event.
    irq_event: Option<ReadableEvent>
}

impl Rtc {
    /// Create a new RTC with the default IBM PC values.
    pub fn new() -> Rtc {
        let irq = syscalls::create_interrupt_event(0x08, 0).expect("IRQ cannot be acquired");

        let rtc = Rtc {
            registers: Mutex::new((io::Pio::new(0x70), io::Pio::new(0x71))),
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
    fn read_reg(&self, reg: u8) -> u8 {
        let mut registers = self.registers.lock();
        registers.0.write(reg);
        registers.1.read()
    }

    /// Write to the CMOS register.
    fn write_reg(&self, reg: u8, val: u8) {
        let mut registers = self.registers.lock();
        registers.0.write(reg);
        registers.1.write(val)
    }

    /// Enable the Update Ended RTC interrupt. This will enable an interruption
    /// on IRQ 8 that will be thrown when the RTC is finished updating its
    /// registers.
    pub fn enable_update_ended_int(&self) {
        // Set the rate to be as slow as possible...
        //let oldval = self.read_reg(0xA);
        //self.write_reg(0xA, (oldval & 0xF0) | 0xF);
        let oldval = self.read_reg(0xB);
        self.write_reg(0xB, oldval | (1 << 4));
    }

    /// Acknowledges an interrupt from the RTC. Necessary to receive further
    /// interrupts.
    fn read_interrupt_kind(&self) -> u8 {
        self.read_reg(0xC)
    }

    /// Checks if the RTC is in 12 hours or 24 hours mode. Depending on the mode,
    /// the date might be encoded in BCD.
    #[allow(clippy::wrong_self_convention)] // More readable this way.
    pub fn is_12hr_clock(&self) -> bool {
        self.read_reg(0xB) & (1 << 2) != 0
    }
}

impl Default for Rtc {
    fn default() -> Self {
        Self::new()
    }
}

/// Global instance of Rtc.
static RTC_INSTANCE: Once<Rtc> = Once::new();

/// RTC interface.
#[derive(Default, Debug)]
struct RTCManager;

/// Task responsible for updating the RTC_INSTANCE's current time every second.
// https://github.com/rust-lang/rust-clippy/issues/3988
// Should remove on next toolchain upgrade.
#[allow(clippy::needless_lifetimes)]
async fn update_rtc(work_queue: WorkQueue<'_>) {
    let rtc = RTC_INSTANCE.r#try().expect("RTC_INSTANCE to be initialized.");

    loop {
        if let Some(irq_event) = &rtc.irq_event {
            let _ = irq_event.wait_async(work_queue.clone()).await;
        } else {
            panic!("RTC irq event cannot be uninialized");
        }

        let intkind = rtc.read_interrupt_kind();
        if intkind & (1 << 4) != 0 {
            // Time changed. Let's update.
            let mut seconds = i64::from(rtc.read_reg(0));
            let mut minutes = i64::from(rtc.read_reg(2));
            let mut hours = i64::from(rtc.read_reg(4));
            let mut day = i64::from(rtc.read_reg(7));
            let mut month = i64::from(rtc.read_reg(8));
            let mut year = i64::from(rtc.read_reg(9));

            // IBM sometimes uses BCD. Why? God knows.
            if !rtc.is_12hr_clock() {
                seconds = (seconds & 0x0F) + ((seconds / 16) * 10);
                minutes = (minutes & 0x0F) + ((minutes / 16) * 10);
                hours = ( (hours & 0x0F) + (((hours & 0x70) / 16) * 10) ) | (hours & 0x80);
                day = (day & 0x0F) + ((day / 16) * 10);
                month = (month & 0x0F) + ((month / 16) * 10);
                year = (year & 0x0F) + ((year / 16) * 10);
            }

            // Convert RTC to a more valid date
            year += 2000;

            // Taken from https://en.wikipedia.org/wiki/Julian_day
            let a = (14 - month) / 12;
            let y = year + 4800 - a;
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

            let mut value = rtc.timestamp.lock();
            *value = julian_day_number;
        }
    }
}


impl sunrise_libuser::time::RTCManager for RTCManager {
    fn get_rtc_time(&mut self, _manager: WorkQueue) -> Result<i64, Error> {
        Ok(RTC_INSTANCE.r#try().expect("RTC instance not initialized").get_time())
    }

    fn get_rtc_event(&mut self, _manager: WorkQueue) -> Result<HandleRef<'static>, Error> {
        Ok(RTC_INSTANCE.r#try().expect("RTC instance not initialized").get_irq_event_handle())
    }
}

fn main() {
    // Setup a default device location
    let device_location_name = b"Europe/Paris\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    timezone::TZ_MANAGER.lock().set_device_location_name(*device_location_name).unwrap();

    RTC_INSTANCE.call_once(|| Rtc::default());

    let mut man = WaitableManager::new();
    let user_handler = port_handler(man.work_queue(), "time:u\0", StaticService::dispatch).unwrap();
    let applet_handler = port_handler(man.work_queue(), "time:a\0", StaticService::dispatch).unwrap();
    let system_handler = port_handler(man.work_queue(), "time:s\0", StaticService::dispatch).unwrap();
    let rtc_handler = port_handler(man.work_queue(), "rtc\0", RTCManager::dispatch).unwrap();

    man.work_queue().spawn(FutureObj::new(Box::new(user_handler)));
    man.work_queue().spawn(FutureObj::new(Box::new(applet_handler)));
    man.work_queue().spawn(FutureObj::new(Box::new(system_handler)));
    man.work_queue().spawn(FutureObj::new(Box::new(rtc_handler)));

    let rtc_future = update_rtc(man.work_queue());

    man.work_queue().spawn(FutureObj::new(Box::new(rtc_future)));

    man.run();
}
