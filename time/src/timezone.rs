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

/// Global instance handling I/O and storage of the device rules.
pub struct TimeZoneManager {
    location: LocationName,
    /// Rules of this device.
    my_rules: TimeZoneRule
}

impl TimeZoneManager {
    pub fn get_device_location_name(&self) -> LocationName {
        self.location
    }

    pub fn set_device_location_name(&mut self, location: LocationName) -> IpcResult<()> {
        // TODO: check names
        self.set_device_location_name_unchecked(location);
        Ok(())
    }

    pub fn set_device_location_name_unchecked(&mut self, location: LocationName) {
        self.location = location;
    }

    pub fn get_total_location_name_count(&self) -> IpcResult<u32> {
        unimplemented!()
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

        *tz_rules = TimeZoneRule::default();
        Ok(())
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
    fn to_calendar_time_with_my_rule(&mut self, _manager: &WaitableManager, time: PosixTime, ) -> Result<(CalendarTime, CalendarAdditionalInfo), Error> {
        unimplemented!()
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

    #[inline(never)]
    fn to_posix_time_with_my_rule(&mut self, _manager: &WaitableManager, calendar_time: CalendarTime, ) -> Result<PosixTime, Error> {
        unimplemented!()
    }
}
