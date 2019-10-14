//! TimeZone module
//!
//! This module takes care of anything related with timezone.
use spin::Mutex;

use sunrise_libuser::error::Error;
use sunrise_libuser::error::TimeError;

use sunrise_libuser::time::CalendarTime;
use sunrise_libuser::time::CalendarAdditionalInfo;
use sunrise_libuser::time::TimeZoneRule as IpcTimeZoneRule;
use sunrise_libuser::time::PosixTime;
use sunrise_libuser::time::LocationName;

use sunrise_libtimezone::TimeZoneRule;
use sunrise_libtimezone::TimeZoneError;

use sunrise_libuser::futures::WorkQueue;

use sunrise_libutils::initialize_to_zero;

/// A IPC result.
type IpcResult<T> = Result<T, Error>;

// TODO: Move to FileSystem interface after implementation
include!(concat!(env!("OUT_DIR"), "/timezone_data.rs"));

/// Represent the file I/O interface with tzdata.
struct TimeZoneFileSystem;

/// Represent a file inside a TimeZoneFileSystem.
struct TimeZoneFile {
    /// The content of the file.
    data: &'static [u8]
}

impl TimeZoneFile {
    /// Create a TimeZoneFile instance from a raw slice.
    pub fn from_raw(data: &'static [u8]) -> Self {
        TimeZoneFile {
            data
        }
    }

    /// Read the whole file.
    pub fn read_full(&self) -> &[u8] {
        self.data
    }
}

impl TimeZoneFileSystem {
    /// Open a file at the given path in the TimeZone virtual filesystem.
    pub fn open_file(path: &[u8]) -> Option<TimeZoneFile> {
        for (file_path, data) in TIMEZONE_ARCHIVE.iter() {
            if *file_path == path {
                return Some(TimeZoneFile::from_raw(data))
            }
        }

        None
    }

    /// Check for a file existance at the given path in the TimeZone virtual filesystem.
    pub fn file_exist(path: &[u8]) -> bool {
        for (file_path, _) in TIMEZONE_ARCHIVE.iter() {
            if *file_path == path {
                return true;
            }
        }
        false
    }

    /// Return the total amount of files in the TimeZone virtual filesystem.
    pub fn file_count() -> u32 {
        TIMEZONE_ARCHIVE.len() as u32
    }
}


/// Global instance handling I/O and storage of the device rules.
pub struct TimeZoneManager {
    /// The location name of this device.
    location: LocationName,

    /// Rules of this device.
    my_rules: TimeZoneRule,

    /// Temporary rules storage used during timezone conversion.
    temp_rules: TimeZoneRule,
}

impl TimeZoneManager {
    /// Get the time zone name used on this devie.
    pub fn get_device_location_name(&self) -> LocationName {
        self.location
    }

    /// Set the time zone name used on this devie.
    ///
    /// Note:
    ///
    /// This also load the new timezone rule.
    pub fn set_device_location_name(&mut self, location: LocationName) -> IpcResult<()> {
        let location_name = core::str::from_utf8(&location).or(Err(TimeError::TimeZoneNotFound))?;

        let path = format!("zoneinfo/{}", location_name);

        let path_trim = path.trim_matches('\0');
        if !TimeZoneFileSystem::file_exist(path_trim.as_bytes()) {
            return Err(TimeError::TimeZoneNotFound.into());
        }
        self.set_device_location_name_unchecked(location);
        self.load_timezone_rule(location, None)
    }

    /// Set the time zone name used on this devie.
    pub fn set_device_location_name_unchecked(&mut self, location: LocationName) {
        self.location = location;
    }

    /// Get the total count of location name available
    pub fn get_total_location_name_count(&self) -> IpcResult<u32> {
        // FIXME: parse binaryList.txt
        Ok(TimeZoneFileSystem::file_count())
    }

    /// Load a time zone rule.
    pub fn load_timezone_rule(&mut self, location: LocationName, timezone_rule: Option<&mut TimeZoneRule>) -> IpcResult<()> {
        let location_name = core::str::from_utf8(&location).or(Err(TimeError::TimeZoneNotFound))?;
        let path = format!("zoneinfo/{}", location_name);

        let path_trim = path.trim_matches('\0');

        let file = TimeZoneFileSystem::open_file(path_trim.as_bytes());
        if file.is_none() {
            return Err(TimeError::TimeZoneNotFound.into());
        }

        let file = file.unwrap();

        let tzdata = file.read_full();

        let timezone_rule = if timezone_rule.is_some() {
            timezone_rule.unwrap()
        } else {
            &mut self.my_rules
        };

        // Before anything else, clear the buffer

        *timezone_rule = ZEROED_TIME_ZONE_RULE;

        // Try conversion
        let res = timezone_rule.load_rules(tzdata, &mut self.temp_rules);

        if res.is_err() {
            return Err(TimeError::TimeZoneConversionFailed.into());
        }

        Ok(())
    }

    /// Get the device timezone rule.
    pub fn get_my_rules(&self) -> &TimeZoneRule {
        &self.my_rules
    }
}

// https://data.iana.org/time-zones/tzdata-latest.tar.gz

/// Global instance of TimeZoneManager
pub static TZ_MANAGER: Mutex<TimeZoneManager> = Mutex::new(unsafe {
    // Safety: This is a POD. There isn't any invariants so this should totally be safe.
    initialize_to_zero!(TimeZoneManager)
});

/// Global clear instance of TimeZoneRule used to avoid copying 16KB on the stack.
 static ZEROED_TIME_ZONE_RULE: TimeZoneRule = unsafe {
    // Safety: This is a POD. There isn't any invariants so this should totally be safe.
    initialize_to_zero!(TimeZoneRule)
};

/// TimeZone service object.
#[derive(Default, Debug, Clone)]
pub struct TimeZoneService {
    /// A dummy field present to just avoid having a zero sized type.
    pub dummy: u64
}

/// Convert a IPC CalendarTime type to a libtimezone CalendarInfo.
fn calendar_to_tzlib(ipc_calendar: CalendarTime) -> sunrise_libtimezone::CalendarTimeInfo {
    let mut res = sunrise_libtimezone::CalendarTimeInfo::default();

    res.year = i64::from(ipc_calendar.year);
    res.month = ipc_calendar.month;
    res.day = ipc_calendar.day;
    res.hour = ipc_calendar.hour;
    res.minute = ipc_calendar.minute;
    res.second = ipc_calendar.second;

    res
}

/// Convert a libtimezone CalendarInfo to a IPC CalendarTime and CalendarAdditionalInfo type.
fn calendar_to_ipc(tzlib_calendar: sunrise_libtimezone::CalendarTime) -> (CalendarTime, CalendarAdditionalInfo) {
    let calendar_time = CalendarTime {
        year: tzlib_calendar.time.year as i16,
        month: tzlib_calendar.time.month,
        day: tzlib_calendar.time.day,
        hour: tzlib_calendar.time.hour,
        minute: tzlib_calendar.time.minute,
        second: tzlib_calendar.time.second,
    };

    let additional_info = CalendarAdditionalInfo {
        day_of_week: tzlib_calendar.additional_info.day_of_week,
        day_of_year: tzlib_calendar.additional_info.day_of_year,
        tz_name: tzlib_calendar.additional_info.timezone_name,
        is_daylight_saving_time: tzlib_calendar.additional_info.is_dst,
        gmt_offset: tzlib_calendar.additional_info.gmt_offset,
    };

    (calendar_time, additional_info)
}

/// Convert a libtimezone TimeZoneError to a IPC Error type.
fn to_timezone_to_time_error(error: TimeZoneError) -> Error {
    let res = match error {
        TimeZoneError::TimeNotFound | TimeZoneError::InvalidTimeComparison => TimeError::TimeNotFound,
        TimeZoneError::Overflow => TimeError::Overflow,
        TimeZoneError::OutOfRange => TimeError::OutOfRange,
        _ => unimplemented!()
    };

    res.into()
}

impl sunrise_libuser::time::TimeZoneService for TimeZoneService {
    #[inline(never)]
    fn get_device_location_name(&mut self, _manager: WorkQueue) -> Result<LocationName, Error> {
        let res = TZ_MANAGER.lock().get_device_location_name();
        Ok(res)
    }

    #[inline(never)]
    fn set_device_location_name(&mut self, _manager: WorkQueue, location: LocationName,) -> Result<(), Error> {
        TZ_MANAGER.lock().set_device_location_name(location)
    }

    #[inline(never)]
    fn get_total_location_name_count(&mut self, _manager: WorkQueue) -> Result<u32, Error> {
        TZ_MANAGER.lock().get_total_location_name_count()
    }

    fn load_location_name_list(&mut self, _manager: WorkQueue, _unknown: u32, _unknown2: &mut [LocationName]) -> Result<u32, Error> {
        unimplemented!()
    }

    #[inline(never)]
    fn load_timezone_rule(&mut self, _manager: WorkQueue, location: LocationName, rules: &mut IpcTimeZoneRule, ) -> Result<(), Error> {
        let rules = TimeZoneRule::from_mut_bytes(rules);
        TZ_MANAGER.lock().load_timezone_rule(location, Some(rules))
    }

    #[inline(never)]
    fn to_calendar_time(&mut self, _manager: WorkQueue, time: PosixTime, rules: &IpcTimeZoneRule, ) -> Result<(CalendarTime, CalendarAdditionalInfo), Error> {
        let rules = TimeZoneRule::from_bytes(rules);
        let res = rules.to_calendar_time(time);
        if let Err(error) = res {
            return Err(to_timezone_to_time_error(error));
        }

        let (calendar_time, calendar_additional_data) = calendar_to_ipc(res.unwrap());

        Ok((calendar_time, calendar_additional_data, ))
    }

    #[inline(never)]
    fn to_calendar_time_with_my_rule(&mut self, _manager: WorkQueue, time: PosixTime, ) -> Result<(CalendarTime, CalendarAdditionalInfo), Error> {
        let manager = TZ_MANAGER.lock();
        let rules = manager.get_my_rules();

        let res = rules.to_calendar_time(time);
        if let Err(error) = res {
            return Err(to_timezone_to_time_error(error));
        }

        let (calendar_time, calendar_additional_data) = calendar_to_ipc(res.unwrap());

        Ok((calendar_time, calendar_additional_data, ))
    }

    #[inline(never)]
    fn to_posix_time(&mut self, _manager: WorkQueue, calendar_time: CalendarTime, rules: &IpcTimeZoneRule, ) -> Result<PosixTime, Error> {
        let rules = TimeZoneRule::from_bytes(rules);
        let res = rules.to_posix_time(&calendar_to_tzlib(calendar_time));
        if let Err(error) = res {
            return Err(to_timezone_to_time_error(error));
        }

        Ok(res.unwrap())
    }

    #[inline(never)]
    fn to_posix_time_with_my_rule(&mut self, _manager: WorkQueue, calendar_time: CalendarTime, ) -> Result<PosixTime, Error> {
        let manager = TZ_MANAGER.lock();
        let rules = manager.get_my_rules();

        let res = rules.to_posix_time(&calendar_to_tzlib(calendar_time));
        if let Err(error) = res {
            return Err(to_timezone_to_time_error(error));
        }

        Ok(res.unwrap())
    }
}
