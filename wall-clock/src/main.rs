//! Clock applet
//!
//! Show the current time in the bottom left corner of the screen.

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

use sunrise_libuser::terminal::{Terminal, WindowSize};
use sunrise_libuser::syscalls;
use core::fmt::Write;
use log::info;

use sunrise_libuser::time::{RTCManager, StaticService};

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

#[allow(clippy::cast_sign_loss)]
fn main() {
    let mut logger = Terminal::new(WindowSize::FontLines(1, true)).unwrap();
    let mut time = StaticService::raw_new_time_u().unwrap();
    let mut rtc = RTCManager::raw_new().unwrap();
    let mut timezone_service = time.get_timezone_service().unwrap();

    //let rtc_event = rtc.get_rtc_event().unwrap();

    loop {
        // TODO: Use get_rtc_event event handle
        // BODY: We need CreateEvent, SignalEvent and ClearEvent syscalls before using this.
        syscalls::sleep_thread(1000000000).unwrap();
        //syscalls::wait_synchronization(&[rtc_event.as_ref()], None).unwrap();

        let timestamp = rtc.get_rtc_time().unwrap();
        let res = timezone_service.to_calendar_time_with_my_rule(timestamp).unwrap();
        let calendar = res.0;

        let hours = calendar.hour;
        let minutes = calendar.minute;
        let seconds = calendar.second;
        let day = calendar.day;
        let dayofweek = res.1.day_of_week as u8 + 1;
        let month = calendar.month as u8 + 1;
        let year = calendar.year;

        let _ = info!("{:02}:{:02}:{:02} {} {:02} {} {}", hours, minutes, seconds, get_day_of_week(dayofweek), day, get_month(month), year);
        let _ = write!(&mut logger, "\n{:02}:{:02}:{:02} {} {:02} {} {}", hours, minutes, seconds, get_day_of_week(dayofweek), day, get_month(month), year);
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
