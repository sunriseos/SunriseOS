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
use log::debug;

use sunrise_libuser::time::{RTCManagerProxy, StaticServiceProxy, TimeZoneRule, CalendarAdditionalInfo, CalendarTime};
use spin::Mutex;

use bstr::BStr;
use bstr::ByteSlice;

/// Turns a day of week number from RTC into an english string.
/// /// 
/// # Panics
///
/// * `dow` isn't valid.
fn get_day_of_week(dow: u8) -> &'static str {
    match dow {
        2 => "Monday",
        3 => "Tuesday",
        4 => "Wednesday",
        5 => "Thursday",
        6 => "Friday",
        7 => "Saturday",
        1 => "Sunday",
        _ => panic!("Invalid day of week value")
    }
}

/// Turns a month number from RTC into an english string.
/// 
/// # Panics
///
/// * `month` isn't valid.
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
        _ => panic!("Invalid month value")
    }
}

/// Wrapper to a TimeZoneRule to enforce alignment requirement
#[repr(C, align(8))]
struct TimeZoneRuleWrapper {
    /// The timezone rule
    pub inner: TimeZoneRule,
}

/// An instance to a custom TimeZoneRule
static TIMEZONE_RULE: Mutex<TimeZoneRuleWrapper> = Mutex::new(TimeZoneRuleWrapper { inner: [0x0; 0x4000]});

/// Write a wall clock time into the terminal.
#[allow(clippy::cast_sign_loss)]
fn write_calendar(logger: &mut Terminal, location: &BStr, input: (CalendarTime, CalendarAdditionalInfo), debug_log: bool) {
    let calendar = input.0;

    let hours = calendar.hour;
    let minutes = calendar.minute;
    let seconds = calendar.second;
    let day = calendar.day;
    let dayofweek = input.1.day_of_week as u8 + 1;
    let month = calendar.month as u8 + 1;
    let year = calendar.year;

    if debug_log {
        debug!("{:02}:{:02}:{:02} {} {} {} {}", hours, minutes, seconds, get_day_of_week(dayofweek), day, get_month(month), year);
    }

    let abbreviation = core::str::from_utf8(&input.1.tz_name[..]).unwrap().trim_matches('\0');
    let _ = write!(logger, "{}: {:02}:{:02}:{:02} {} {} {} {} {}", location, hours, minutes, seconds, get_day_of_week(dayofweek), day, get_month(month), year, abbreviation);
}

fn main() {
    let mut logger = Terminal::new(WindowSize::FontLines(1, true)).unwrap();
    let mut time = StaticServiceProxy::raw_new_time_u().unwrap();
    let mut rtc = RTCManagerProxy::raw_new().unwrap();
    let mut timezone_service = time.get_timezone_service().unwrap();

    // Get default timezone name
    let device_location = timezone_service.get_device_location_name().unwrap();
    let device_location_trimed = device_location.as_bstr().trim_with(|c| c == '\0').as_bstr();

    // Let's get New York time
    let custom_location = b"America/New_York\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    let custom_location_trimed = custom_location.as_bstr().trim_with(|c| c == '\0').as_bstr();

    // Load a custom one
    let mut rule = TIMEZONE_RULE.lock();
    timezone_service.load_timezone_rule(*custom_location, &mut rule.inner).unwrap();

    //let rtc_event = rtc.get_rtc_event().unwrap();

    loop {
        // TODO: Use get_rtc_event event handle
        // BODY: We need CreateEvent, SignalEvent and ClearEvent syscalls before using this.
        syscalls::sleep_thread(1000000000).unwrap();
        //syscalls::wait_synchronization(&[rtc_event.as_ref()], None).unwrap();

        let timestamp = rtc.get_rtc_time().unwrap();
        let res = timezone_service.to_calendar_time_with_my_rule(timestamp).unwrap();
        let res_custom_timezone = timezone_service.to_calendar_time(timestamp, &rule.inner).unwrap();

        let _ = writeln!(&mut logger);

        write_calendar(&mut logger, device_location_trimed, res, true);
        let _ = write!(&mut logger, "                                ");
        write_calendar(&mut logger, custom_location_trimed, res_custom_timezone, false);
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
        sunrise_libuser::syscalls::nr::SetHeapSize,
        sunrise_libuser::syscalls::nr::SendSyncRequestWithUserBuffer,
        sunrise_libuser::syscalls::nr::QueryMemory,
        sunrise_libuser::syscalls::nr::CreateSharedMemory,
        sunrise_libuser::syscalls::nr::MapSharedMemory,
        sunrise_libuser::syscalls::nr::UnmapSharedMemory,
    ]
});
