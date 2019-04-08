//! Clock applet
//!
//! Show the current time in the bottom left corner of the screen.

#![feature(alloc)]
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

use sunrise_libuser::terminal::{Terminal, WindowSize};
use sunrise_libuser::io::{self, Io};
use sunrise_libuser::syscalls;
use core::fmt::Write;

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

/// Turns a day of week number from RTC into an english string.
fn get_day_of_week(dow: u8) -> &'static str {
    match dow {
        2 => "Monday",
        3 => "Tuesday",
        4 => "Wednesday",
        5 => "Thursday",
        6 => "Friday",
        7 => "Saturday",
        1 => "Sunday",
        _ => unreachable!()
    }
}

/// Turns a month number from RTC into an english string.
fn get_month(month: u8) -> &'static str {
    match month {
        01 => "January",
        02 => "February",
        03 => "March",
        04 => "April",
        05 => "May",
        06 => "June",
        07 => "July",
        08 => "August",
        09 => "September",
        10 => "October",
        11 => "November",
        12 => "December",
        _ => unreachable!()
    }
}

fn main() {
    let mut rtc = Rtc::new();

    let irq = syscalls::create_interrupt_event(0x08, 0).unwrap();

    rtc.enable_update_ended_int();

    let mut logger = Terminal::new(WindowSize::FontLines(1, true)).unwrap();

    loop {
        syscalls::wait_synchronization(&[irq.0.as_ref()], None).unwrap();
        let intkind = rtc.read_interrupt_kind();
        if intkind & (1 << 4) != 0 {
            // Time changed. Let's update.
            let mut seconds = rtc.read_reg(0);
            let mut minutes = rtc.read_reg(2);
            let mut hours = rtc.read_reg(4);
            let mut dayofweek = rtc.read_reg(6);
            let mut day = rtc.read_reg(7);
            let mut month = rtc.read_reg(8);
            let mut year = rtc.read_reg(9);

            // IBM sometimes uses BCD. Why? God knows.
            if !rtc.is_12hr_clock() {
                seconds = (seconds & 0x0F) + ((seconds / 16) * 10);
                minutes = (minutes & 0x0F) + ((minutes / 16) * 10);
                hours = ( (hours & 0x0F) + (((hours & 0x70) / 16) * 10) ) | (hours & 0x80);
                day = (day & 0x0F) + ((day / 16) * 10);
                dayofweek = (dayofweek & 0x0F) + ((dayofweek / 16) * 10);
                month = (month & 0x0F) + ((month / 16) * 10);
                year = (year & 0x0F) + ((year / 16) * 10);
            }

            let _ = syscalls::output_debug_string(&format!("{:02}:{:02}:{:02} {} {:02} {} {}", hours, minutes, seconds, get_day_of_week(dayofweek), day, get_month(month), year));
            let _ = write!(&mut logger, "\n{:02}:{:02}:{:02} {} {:02} {} {}", hours, minutes, seconds, get_day_of_week(dayofweek), day, get_month(month), year);
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

        sunrise_libuser::syscalls::nr::ConnectToNamedPort,
        sunrise_libuser::syscalls::nr::CreateInterruptEvent,
        sunrise_libuser::syscalls::nr::SetHeapSize,
        sunrise_libuser::syscalls::nr::SendSyncRequestWithUserBuffer,
        sunrise_libuser::syscalls::nr::QueryMemory,
        sunrise_libuser::syscalls::nr::CreateSharedMemory,
        sunrise_libuser::syscalls::nr::MapSharedMemory,
        sunrise_libuser::syscalls::nr::UnmapSharedMemory,
    ],
    raw_caps: [
        sunrise_libuser::caps::irq_pair(0x08, 0x3FF),
        sunrise_libuser::caps::ioport(0x70),
        sunrise_libuser::caps::ioport(0x71),
    ]
});
