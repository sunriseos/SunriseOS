use core::ops::Deref;

use spin::Mutex;

use generic_array::GenericArray;
use generic_array::typenum::consts::U36;

use sunrise_libuser::error::Error;
use sunrise_libuser::ipc::*;

use sunrise_libuser::time::CalendarTime;
use sunrise_libuser::time::CalendarAdditionalInfo;
use sunrise_libuser::time::TimeZoneRule as IpcTimeZoneRule;
use sunrise_libuser::time::PosixTime;
use sunrise_libuser::time::LocationName;

use sunrise_libtimezone::TimeZoneRule;

use sunrise_libuser::ipc::server::WaitableManager;

use sunrise_libutils::initialize_to_zero;

/// Type representing a LocationName.
/// Used to get arround Default requirement of the IPC layer
type IpcResult<T> = Result<T, Error>;


// TODO: Move to FileSystem interface after implementation
include!(concat!(env!("OUT_DIR"), "/timezone_data.rs"));

/// Represent the file I/O interface with tzdata.
struct TimeZoneFileSystem;

/// Represent a file inside a TimeZoneFileSystem.
struct TimeZoneFile {
    data: &'static [u8]
}

impl TimeZoneFile {
    /// Create a TimeZoneFile instance from a raw slice.
    pub fn from_raw(data: &'static [u8]) -> Self {
        TimeZoneFile {
            data
        }
    }

    // Read the whole file.
    pub fn read_full(&self) -> &[u8] {
        self.data
    }
}

impl TimeZoneFileSystem {
    pub fn open_file(path: &[u8]) -> Option<TimeZoneFile> {
        for (file_path, data) in TIMEZONE_ARCHIVE.iter() {
            if *file_path == path {
                return Some(TimeZoneFile::from_raw(data))
            }
        }

        None
    }

    pub fn file_exist(path: &[u8]) -> bool {
        for (file_path, _) in TIMEZONE_ARCHIVE.iter() {
            if *file_path == path {
                return true;
            }
        }
        false
    }

    pub fn file_count() -> u32 {
        TIMEZONE_ARCHIVE.len() as u32
    }
}


/// Global instance handling I/O and storage of the device rules.
pub struct TimeZoneManager {
    location: LocationName,
    /// Rules of this device.
    my_rules: TimeZoneRule,

    /// Temporary rules storage used during timezone conversion.
    temp_rules: TimeZoneRule,
}

impl TimeZoneManager {
    pub fn get_device_location_name(&self) -> LocationName {
        self.location
    }

    pub fn set_device_location_name(&mut self, location: LocationName) -> IpcResult<()> {
        let path = format!("zoneinfo/{}", unsafe { core::str::from_utf8_unchecked(&location) });

        let path_trim = path.trim_matches(char::from(0));
        if !TimeZoneFileSystem::file_exist(path_trim.as_bytes()) {
            // TODO 0x7BA74 - not found
            panic!()
        } 
        self.set_device_location_name_unchecked(location);
        self.load_timezone_rule(location, None)
    }

    pub fn set_device_location_name_unchecked(&mut self, location: LocationName) {
        self.location = location;
    }

    pub fn get_total_location_name_count(&self) -> IpcResult<u32> {
        // FIXME: use binaryList.txt
        Ok(TimeZoneFileSystem::file_count())
    }

    pub fn load_timezone_rule(&mut self, location: LocationName, timezone_rule: Option<&mut TimeZoneRule>) -> IpcResult<()> {
        let path = format!("zoneinfo/{}", unsafe { core::str::from_utf8_unchecked(&location) });

        let path_trim = path.trim_matches(char::from(0));

        // FIXME: use binaryList.txt
        let file = TimeZoneFileSystem::open_file(path_trim.as_bytes());
        if file.is_none() {
            // TODO 0x7BA74 - not found
            panic!()
        }

        let file = file.unwrap();

        let tzdata = file.read_full();

        let timezone_rule = if timezone_rule.is_some() {
            timezone_rule.unwrap()
        } else {
            &mut self.my_rules
        };

        // clear potential uninitialized data just in case
        // FIXME: this make the whole thing crash SOMEHOW
        //*timezone_rule = TimeZoneRule::default();

        // Try conversion
        let res = timezone_rule.load_rules(tzdata, &mut self.temp_rules);

        if res.is_err() {
            // TODO: 0x70E74 - conversion failed
            panic!()
        }

        Ok(())
    }

    pub fn get_my_rules(&self) -> &TimeZoneRule {
        &self.my_rules
    }
}

// https://data.iana.org/time-zones/tzdata-latest.tar.gz

/// Global instance of TimeZoneManager
pub static TZ_MANAGER: Mutex<TimeZoneManager> = Mutex::new(unsafe { initialize_to_zero!(TimeZoneManager) });

/// TimeZone service object.
#[derive(Default, Debug)]
pub struct TimeZoneService {
    pub unknown: u64
}

impl Drop for TimeZoneService {
    fn drop(&mut self) {
        info!("DROP TZ");
    }
}

fn calendar_to_tzlib(ipc_calendar: &CalendarTime) -> sunrise_libtimezone::CalendarTimeInfo {
    let mut res = sunrise_libtimezone::CalendarTimeInfo::default();

    res.year = ipc_calendar.year as i64;
    res.month = ipc_calendar.month;
    res.day = ipc_calendar.day;
    res.hour = ipc_calendar.hour;
    res.minute = ipc_calendar.minute;
    res.second = ipc_calendar.second;

    res
}

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

impl sunrise_libuser::time::TimeZoneService for TimeZoneService {
    #[inline(never)]
    fn get_device_location_name(&mut self, _manager: &WaitableManager) -> Result<LocationName, Error> {
        let res = TZ_MANAGER.lock().get_device_location_name();
        Ok(res)
    }

    #[inline(never)]
    fn set_device_location_name(&mut self, _manager: &WaitableManager, location: LocationName,) -> Result<(), Error> {
        TZ_MANAGER.lock().set_device_location_name(location)
    }

    #[inline(never)]
    fn get_total_location_name_count(&mut self, _manager: &WaitableManager) -> Result<u32, Error> {
        TZ_MANAGER.lock().get_total_location_name_count()
    }

    fn load_location_name_list(&mut self, _manager: &WaitableManager, unknown: u32, unknown2: &mut [LocationName]) -> Result<u32, Error> {
        unimplemented!()
    }

    #[inline(never)]
    fn load_timezone_rule(&mut self, _manager: &WaitableManager, location: LocationName, tz_rules: &mut IpcTimeZoneRule, ) -> Result<(), Error> {
        let mut tz_rules = unsafe {
            // TODO: Use plain
            (tz_rules as *mut _ as *mut TimeZoneRule).as_mut().unwrap()
        };

        TZ_MANAGER.lock().load_timezone_rule(location, Some(&mut tz_rules))
    }

    #[inline(never)]
    fn test(&mut self, _manager: &WaitableManager, test: &mut LocationName, ) -> Result<(), Error> {
        test[0] = b'A';
        Ok(())
    }

    #[inline(never)]
    fn to_calendar_time(&mut self, _manager: &WaitableManager, time: PosixTime, timezone_buffer: &IpcTimeZoneRule, ) -> Result<(CalendarTime, CalendarAdditionalInfo), Error> {
        let timezones = unsafe {
            // TODO: Use plain
            (timezone_buffer as *const _ as *const TimeZoneRule).as_ref().unwrap()
        };
        let res = timezones.to_calendar_time(time);
        if res.is_err() {
            // TODO: error managment here
            panic!()
        }

        let (calendar_time, calendar_additional_data) = calendar_to_ipc(res.unwrap());

        Ok((calendar_time, calendar_additional_data, ))
    }

    #[inline(never)]
    fn to_posix_time(&mut self, _manager: &WaitableManager, calendar_time: CalendarTime, timezone_buffer: &IpcTimeZoneRule, ) -> Result<PosixTime, Error> {
        let timezones = unsafe {
            // TODO: Use plain
            (timezone_buffer as *const _ as *const TimeZoneRule).as_ref().unwrap()
        };
        let res = timezones.to_posix_time(&calendar_to_tzlib(&calendar_time));
        if res.is_err() {
            // TODO: error managment here
            panic!()
        }

        Ok(res.unwrap())
    }

    fn to_calendar_time_with_my_rule(&mut self, _manager: &WaitableManager, time: PosixTime, ) -> Result<(CalendarTime, CalendarAdditionalInfo), Error> {
        let manager = TZ_MANAGER.lock();
        let rules = manager.get_my_rules();
    
        let res = rules.to_calendar_time(time);
        if res.is_err() {
            // TODO: error managment here
            panic!()
        }

        let (calendar_time, calendar_additional_data) = calendar_to_ipc(res.unwrap());

        Ok((calendar_time, calendar_additional_data, ))
    }

    #[inline(never)]
    fn to_posix_time_with_my_rule(&mut self, _manager: &WaitableManager, calendar_time: CalendarTime, ) -> Result<PosixTime, Error> {
        let manager = TZ_MANAGER.lock();
        let rules = manager.get_my_rules();

        let res = rules.to_posix_time(&calendar_to_tzlib(&calendar_time));
        if let Err(error) = res {
            // TODO: error managment here
            panic!()
        }

        Ok(res.unwrap())
    }
}
