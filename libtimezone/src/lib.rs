//! Local Time crate
//!
//! Allows manipulating timezone data.

#![no_std]
#![feature(underscore_const_names)]
#![allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]

#[macro_use]
extern crate static_assertions;

mod conversion;
mod misc;
mod utils;

use conversion::ConversionBuffer;

use core::i64;

/// The type used to express time internally.
pub type Time = i64;

/// The max value of the Time type.
pub(crate) const TIME_T_MAX: Time = Time::max_value();

/// The min value of the Time type.
pub(crate) const TIME_T_MIN: Time = Time::min_value();

/// The type used to express time at the API level.
pub type PosixTime = Time;

/// The max number of time transitions that can be stored in a TimeZoneRule.
pub(crate) const TZ_MAX_TIMES: i32 = 1000;

/// The max number of type time infos that can be stored in a TimeZoneRule.
pub(crate) const TZ_MAX_TYPES: i32 = 128;

/// The max size of a POSIX TimeZone name.
pub(crate) const TZ_NAME_MAX: i32 = 255;

/// The max number of leaps definition in TzIf files.
pub(crate) const TZ_MAX_LEAPS: i32 = 50;

/// The max number of chars that can be stored in a TimeZoneRule.
pub(crate) const TZ_MAX_CHARS: i32 = 50;

/// The year of the UNIX Epoch.
pub(crate) const EPOCH_YEAR: i64 = 1970;

/// The year base of the EPOCH_YEAR.
pub(crate) const YEAR_BASE: i64 = 1900;

/// The week day of the UNIX Epoch.
pub(crate) const EPOCH_WEEK_DAY: i64 = 4;

/// The count of seconds in a minute.
pub(crate) const SECS_PER_MIN: i64 = 60;

/// The count of minutes in an hour.
pub(crate) const MINS_PER_HOUR: i64 = 60;

/// The count of hours in a day.
pub(crate) const HOURS_PER_DAY: i64 = 24;

/// The count of days in a week.
pub(crate) const DAYS_PER_WEEK: i64 = 7;

/// The count of days in a common year.
pub(crate) const DAYS_PER_NYEAR: i64 = 365;

/// The count of days in a leap year.
pub(crate) const DAYS_PER_LYEAR: i64 = 366;

/// The count of months in a year.
pub(crate) const MONS_PER_YEAR: i64 = 12;

/// The count of seconds in an hour.
pub(crate) const SECS_PER_HOUR: i64 = SECS_PER_MIN * MINS_PER_HOUR;

/// The count of seconds in a day.
pub(crate) const SECS_PER_DAY: i64 = SECS_PER_HOUR * HOURS_PER_DAY;

/// The year lengths definition (index 0 is a common year, index 1 is a leap year).
pub(crate) const YEAR_LENGTHS: [i64; 2] = [DAYS_PER_NYEAR, DAYS_PER_LYEAR];

/// The month lengths definition (index 0 is a common year, index 1 is a leap year).
pub(crate) const MON_LENGTHS: [[i64; 12]; 2] = [
    [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31],
    [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31],
];

/// The number of year before a reset of leap years.
pub(crate) const YEARS_PER_REPEAT: i64 = 400;

/// The average count of seconds per year.
pub(crate) const AVERAGE_SECS_PER_YEAR: Time = 31556952;

/// The number of seconds before a reset of leap years.
pub(crate) const SECS_PER_REPEAT: Time = YEARS_PER_REPEAT as Time * AVERAGE_SECS_PER_YEAR;

/// Represent a time zone error.
#[derive(Debug)]
pub enum TimeZoneError {
    /// The time values got out of range internally (usually an overflow was catched)
    OutOfRange,

    /// The given calendar timestamp couldn't be compute.
    TimeNotFound,

    /// The given Tzif file couldn't be stored to a TimeZoneRule because it's too big.
    InvalidSize,

    /// Some data inside the Tzif file are invalid.
    InvalidData,

    /// Some data inside the Tzif file are invalid (type processing failed).
    InvalidTypeCount,

    /// An invalid time comparaison occured (is the time in range of the rules?)
    InvalidTimeComparison,

    /// Signed overflow/underflow appened.
    Overflow,

    /// Unknown.
    Unknown,
}

/// The Result of a time conversion.
pub type TimeZoneResult<T> = core::result::Result<T, TimeZoneError>;

/// Represent a TimeZone type info.
///
/// This is used to store rules information in a time range.
#[repr(C, align(8))]
#[derive(Copy, Clone)]
pub(crate) struct TimeTypeInfo {
    /// The GMT offset of the time type info.
    pub gmt_offset: i32,

    /// True if the time type info represent a Day Saving Time.
    pub is_dst: bool,

    /// The index inside the TimeZoneRule char array of the abbrevation c string representing this time type info.
    pub abbreviation_list_index: i32,

    /// True if this represent a Standard Time Daylight.
    pub is_std: bool,

    /// True if this represent a GMT time.
    pub is_gmt: bool,

    /// Explicit padding.
    padding: [u8; 0x2],
}

impl TimeTypeInfo {
    /// Create a new TimeTypeInfo.
    pub fn new(gmt_offset: i32, is_dst: bool, abbreviation_list_index: i32) -> Self {
        TimeTypeInfo {
            gmt_offset,
            is_dst,
            abbreviation_list_index,
            is_std: false,
            is_gmt: false,
            padding: [0x0; 0x2],
        }
    }
}

impl PartialEq<TimeTypeInfo> for TimeTypeInfo {
    fn eq(&self, other: &TimeTypeInfo) -> bool {
        self.gmt_offset == other.gmt_offset
            && self.is_dst == other.is_dst
            && self.is_std == other.is_std
            && self.is_gmt == other.is_gmt
    }
}

assert_eq_size!(TimeTypeInfo, [u8; 0x10]);

impl Default for TimeTypeInfo {
    fn default() -> Self {
        TimeTypeInfo::new(0, false, 0)
    }
}

/// Represent the rules defining a TimeZone.
#[repr(C, align(8))]
pub struct TimeZoneRule {
    /// The count of time transitions.
    pub(crate) timecnt: i32,

    /// The count of time type infos.
    pub(crate) typecnt: i32,

    /// The count of chars.
    pub(crate) charcnt: i32,

    /// ?
    pub(crate) goback: bool,

    /// ?
    pub(crate) goahead: bool,

    /// Time transition timepoints.
    pub(crate) ats: [Time; TZ_MAX_TIMES as usize],

    /// Time transition types.
    pub(crate) types: [u8; TZ_MAX_TIMES as usize],

    /// Time type infos.
    pub(crate) ttis: [TimeTypeInfo; TZ_MAX_TYPES as usize],

    /// The chars.
    pub(crate) chars: [u8; 2 * (TZ_NAME_MAX as usize + 1)],

    /// The index of the default type (usually zero).
    pub(crate) default_type: i32,

    /// Reserved / Unused space.
    reserved: [u8; 0x12c4],
}

assert_eq_size!(TimeZoneRule, [u8; 0x4000]);

/// Represent the basic informations of a local time.
#[repr(C, align(8))]
#[derive(Copy, Clone, Debug)]
pub struct CalendarTimeInfo {
    /// The year of the local time.
    pub year: i64,

    /// The month of the local time.
    pub month: i8,

    /// The day of the local time.
    pub day: i8,

    /// The hour of the local time.
    pub hour: i8,

    /// The minute of the local time.
    pub minute: i8,

    /// The seconds of the local time.
    pub second: i8,
}

impl Default for CalendarTimeInfo {
    fn default() -> Self {
        CalendarTimeInfo {
            year: 0,
            month: 0,
            day: 0,
            hour: 0,
            minute: 0,
            second: 0,
        }
    }
}

assert_eq_size!(CalendarTimeInfo, [u8; 0x10]);

/// Represnet aditional info of a local time.
#[repr(C, align(8))]
#[derive(Copy, Clone, Debug)]
pub struct CalendarAdditionalInfo {
    /// The day of the week of the local time.
    pub day_of_week: u32,

    /// The day of the year of the local time.
    pub day_of_year: u32,

    /// The name of the timezone of the local time.
    pub timezone_name: [u8; 8],

    /// True if the local time represent a Day Saving Time.
    pub is_dst: bool,

    /// The GMT offset of the timezone used to generate this local time.
    pub gmt_offset: i32,
}

impl Default for CalendarAdditionalInfo {
    fn default() -> Self {
        CalendarAdditionalInfo {
            day_of_week: 0,
            day_of_year: 0,
            timezone_name: [0x0; 8],
            is_dst: false,
            gmt_offset: 0,
        }
    }
}

assert_eq_size!(CalendarAdditionalInfo, [u8; 0x18]);

/// Represent a local time.
#[repr(C, align(8))]
#[derive(Copy, Clone, Default, Debug)]
pub struct CalendarTime {
    /// The local time basic informations.
    pub time: CalendarTimeInfo,

    /// Additional information of the local time.
    pub additional_info: CalendarAdditionalInfo,
}

//assert_eq_size!(calendartime; CalendarTime, [u8; 0x20]);

/// Create a CalendarTime from a timestamp and a GMT offset.
fn create_calendar_time(time: Time, gmt_offset: i32) -> TimeZoneResult<CalendarTime> {
    let mut year = EPOCH_YEAR as Time;
    let mut time_days = time as Time / SECS_PER_DAY as Time;
    let mut remaining_secs = time as i64 % SECS_PER_DAY as i64;

    while time_days < 0 || time_days >= YEAR_LENGTHS[utils::is_leap_year(year) as usize] as Time {
        let time_delta = time_days / DAYS_PER_LYEAR as Time;
        let mut delta = time_delta;
        if delta == 0 {
            delta = if time_days < 0 { -1 } else { 1 };
        }
        let mut new_year = year;

        if utils::increment_overflow(&mut new_year, delta) {
            return Err(TimeZoneError::OutOfRange);
        }

        let leap_days = utils::get_leap_days(new_year - 1) - utils::get_leap_days(year - 1);
        time_days -= (new_year - year as Time) * DAYS_PER_NYEAR as Time;
        time_days -= leap_days as Time;
        year = new_year;
    }

    let mut day_of_year = time_days as i64;
    remaining_secs += i64::from(gmt_offset);
    while remaining_secs < 0 {
        remaining_secs += SECS_PER_DAY as i64;
        day_of_year -= 1;
    }

    while remaining_secs >= SECS_PER_DAY as i64 {
        remaining_secs -= SECS_PER_DAY as i64;
        day_of_year += 1;
    }

    while day_of_year < 0 {
        if utils::increment_overflow(&mut year, -1) {
            return Err(TimeZoneError::OutOfRange);
        }

        day_of_year += YEAR_LENGTHS[utils::is_leap_year(year) as usize];
    }

    while day_of_year >= YEAR_LENGTHS[utils::is_leap_year(year) as usize] {
        day_of_year -= YEAR_LENGTHS[utils::is_leap_year(year) as usize];

        if utils::increment_overflow(&mut year, 1) {
            return Err(TimeZoneError::OutOfRange);
        }
    }

    let mut calendar_time: CalendarTime = CalendarTime::default();

    calendar_time.time.year = year as i64;
    calendar_time.additional_info.day_of_year = day_of_year as u32;

    let mut day_of_week = (EPOCH_WEEK_DAY
        + ((year - EPOCH_YEAR) % DAYS_PER_WEEK) * (DAYS_PER_NYEAR % DAYS_PER_WEEK)
        + utils::get_leap_days(year - 1)
        - utils::get_leap_days(EPOCH_YEAR as i64 - 1)
        + day_of_year)
        % DAYS_PER_WEEK;
    if day_of_week < 0 {
        day_of_week += DAYS_PER_WEEK;
    }
    calendar_time.additional_info.day_of_week = day_of_week as u32;
    calendar_time.time.hour =
        ((remaining_secs / SECS_PER_HOUR as Time) % SECS_PER_HOUR as Time) as i8;

    remaining_secs %= SECS_PER_HOUR as Time;

    calendar_time.time.minute = (remaining_secs / SECS_PER_MIN as Time) as i8;
    calendar_time.time.second = (remaining_secs % SECS_PER_MIN as Time) as i8;

    let ip = &MON_LENGTHS[utils::is_leap_year(year) as usize];

    while day_of_year >= ip[calendar_time.time.month as usize] {
        calendar_time.time.month += 1;
        day_of_year -= ip[calendar_time.time.month as usize];
    }

    calendar_time.time.day = (day_of_year + 1) as i8;
    calendar_time.additional_info.is_dst = false;
    calendar_time.additional_info.gmt_offset = gmt_offset;

    Ok(calendar_time)
}

/// Compare two CalendarTimeInfo and return the difference of two of them.
fn compare_calendar_info(a: &CalendarTimeInfo, b: &CalendarTimeInfo) -> isize {
    if a.year != b.year {
        if a.year < b.year {
            return -1;
        } else {
            return 1;
        }
    }

    if a.month != b.month {
        return (a.month - b.month) as isize;
    }

    if a.day != b.day {
        return (a.day - b.day) as isize;
    }

    if a.hour != b.hour {
        return (a.hour - b.hour) as isize;
    }

    if a.minute != b.minute {
        return (a.minute - b.minute) as isize;
    }

    if a.second != b.second {
        return (a.second - b.second) as isize;
    }

    0
}

impl Default for TimeZoneRule {
    fn default() -> Self {
        TimeZoneRule {
            timecnt: 0,
            typecnt: 0,
            charcnt: 0,
            goback: false,
            goahead: false,
            ats: [0x0; TZ_MAX_TIMES as usize],
            types: [0x0; TZ_MAX_TIMES as usize],
            ttis: [TimeTypeInfo::default(); TZ_MAX_TYPES as usize],
            chars: [0x0; 2 * (TZ_NAME_MAX as usize + 1)],
            default_type: 0,
            reserved: [0x0; 0x12c4],
        }
    }
}

impl TimeZoneRule {
    /// Load the given timezones rules from a given slice containing TzIf2 data and a temporary TimeZoneRule buffer.
    ///
    /// Note:
    ///
    /// ``temp_rules`` is used to store parsed data from the TZ String Extensions. this shouldn't be used as a standard TimeZoneRule!
    pub fn load_rules(
        &mut self,
        input: &[u8],
        temp_rules: &mut TimeZoneRule,
    ) -> TimeZoneResult<()> {
        let mut conversion_buffer = ConversionBuffer {
            work_buffer: &input,
            temp_rules,
        };

        conversion::load_body(self, &mut conversion_buffer)
    }

    /// Convert a PosixTime to a CalendarTime using the current timezone.
    pub fn to_calendar_time(&self, time: PosixTime) -> TimeZoneResult<CalendarTime> {
        let time = time as Time;

        if (self.goahead && time < self.ats[0])
            || (self.goback && time > self.ats[self.timecnt as usize - 1])
        {
            let mut new_time = time;
            let mut seconds;
            let years;

            if time < self.ats[0] {
                seconds = self.ats[0] - time;
            } else {
                seconds = time - self.ats[self.timecnt as usize - 1];
            }

            seconds -= 1;

            years = (seconds / SECS_PER_REPEAT + 1) * YEARS_PER_REPEAT as Time;
            seconds = years * AVERAGE_SECS_PER_YEAR;
            if time < self.ats[0] {
                new_time += seconds;
            } else {
                new_time -= seconds;
            }

            if new_time < self.ats[0] && new_time > self.ats[self.timecnt as usize - 1] {
                return Err(TimeZoneError::InvalidTimeComparison);
            }

            let mut result = self.to_calendar_time(new_time as PosixTime)?;

            let mut new_year = result.time.year;
            if time < self.ats[0] {
                new_year -= years as i64;
            } else {
                new_year += years as i64;
            }

            result.time.year = new_year;
            return Ok(result);
        }

        let tti_index: usize = if self.timecnt == 0 || time < self.ats[0] {
            self.default_type as usize
        } else {
            let mut lo = 1;
            let mut hi = self.timecnt;

            while lo < hi {
                let mid = (lo + hi) >> 1;

                if time < self.ats[mid as usize] {
                    hi = mid;
                } else {
                    lo = mid + 1;
                }
            }

            self.types[lo as usize - 1] as usize
        };

        let tti = &self.ttis[tti_index];
        let mut result = create_calendar_time(time, tti.gmt_offset)?;
        result.additional_info.is_dst = tti.is_dst;

        let tz_name = &self.chars[tti.abbreviation_list_index as usize..];
        let tz_len = core::cmp::min(misc::len_cstr(&self.chars[tti.abbreviation_list_index as usize..]), 8);
        (&mut result.additional_info.timezone_name[0..tz_len]).copy_from_slice(&tz_name[..tz_len]);

        Ok(result)
    }

    /// Convert a CalendarTime to a PosixTime using the current timezone.
    pub fn to_posix_time(&self, calendar_time: &CalendarTimeInfo) -> TimeZoneResult<PosixTime> {
        let mut tmp_calendar = *calendar_time;

        let mut tmp_hour = i32::from(tmp_calendar.hour);
        let mut tmp_minute = i32::from(tmp_calendar.minute);

        if utils::normalize_overflow(&mut tmp_hour, &mut tmp_minute, MINS_PER_HOUR as i32) {
            return Err(TimeZoneError::Overflow);
        }

        tmp_calendar.minute = tmp_minute as i8;

        let mut tmp_day = i32::from(tmp_calendar.day);
        if utils::normalize_overflow(&mut tmp_day, &mut tmp_hour, HOURS_PER_DAY as i32) {
            return Err(TimeZoneError::Overflow);
        }

        tmp_calendar.day = tmp_day as i8;
        tmp_calendar.hour = tmp_hour as i8;

        let mut year = tmp_calendar.year;
        let mut month = i64::from(tmp_calendar.month);

        if utils::normalize_overflow(&mut year, &mut month, MONS_PER_YEAR) {
            return Err(TimeZoneError::Overflow);
        }

        tmp_calendar.month = month as i8;

        if utils::increment_overflow(&mut year, YEAR_BASE) {
            return Err(TimeZoneError::Overflow);
        }

        while tmp_day <= 0 {
            if utils::increment_overflow(&mut year, -1) {
                return Err(TimeZoneError::Overflow);
            }

            let li = if 1 < tmp_calendar.month {
                year + 1
            } else {
                year
            };

            tmp_day += YEAR_LENGTHS[utils::is_leap_year(li) as usize] as i32;
        }

        while tmp_day > DAYS_PER_LYEAR as i32 {
            let li = if 1 < tmp_calendar.month {
                year + 1
            } else {
                year
            };

            tmp_day -= YEAR_LENGTHS[utils::is_leap_year(li) as usize] as i32;
            if utils::increment_overflow(&mut year, 1) {
                return Err(TimeZoneError::Overflow);
            }
        }

        loop {
            let i =
                MON_LENGTHS[utils::is_leap_year(year) as usize][tmp_calendar.month as usize] as i32;
            if tmp_day <= i {
                break;
            }
            tmp_day -= i;
            tmp_calendar.month += 1;
            if tmp_calendar.month >= MONS_PER_YEAR as i8 {
                tmp_calendar.month = 0;
                if utils::increment_overflow(&mut year, 1) {
                    return Err(TimeZoneError::Overflow);
                }
            }
        }
        tmp_calendar.day = tmp_day as i8;

        if utils::increment_overflow(&mut year, -YEAR_BASE) {
            return Err(TimeZoneError::Overflow);
        }

        tmp_calendar.year = year;

        let saved_seconds;
        if tmp_calendar.second >= 0 && tmp_calendar.second < SECS_PER_MIN as i8 {
            saved_seconds = 0;
        } else if year + YEAR_BASE < EPOCH_YEAR {
            if utils::increment_overflow(&mut tmp_calendar.second, 1 - SECS_PER_MIN as i8) {
                return Err(TimeZoneError::Overflow);
            }

            saved_seconds = tmp_calendar.second;
            tmp_calendar.second = 1 - SECS_PER_MIN as i8;
        } else {
            saved_seconds = tmp_calendar.second;
            tmp_calendar.second = 0;
        }

        let mut low = TIME_T_MIN;
        let mut high = TIME_T_MAX;

        loop {
            let mut t = low / 2 + high / 2;
            if t < low {
                t = low;
            } else if t > high {
                t = high;
            }

            let direction;
            let res = self.to_calendar_time(t);
            if res.is_err() {
                if t > 0 {
                    direction = 1;
                } else {
                    direction = -1;
                }
            } else {
                let calendar_time = res.unwrap();
                direction = compare_calendar_info(&calendar_time.time, &tmp_calendar);
            }

            // We have a match
            if direction == 0 {
                let result = t + Time::from(saved_seconds);

                if (result < t) != (saved_seconds < 0) {
                    return Err(TimeZoneError::Overflow);
                }
                return Ok(result);
            } else {
                if t == low {
                    if t == TIME_T_MAX {
                        return Err(TimeZoneError::TimeNotFound);
                    }

                    t += 1;
                    low += 1;
                } else if t == high {
                    if t == TIME_T_MIN {
                        return Err(TimeZoneError::TimeNotFound);
                    }
                    t -= 1;
                    high -= 1;
                }

                if low > high {
                    return Err(TimeZoneError::TimeNotFound);
                }

                if direction > 0 {
                    high = t;
                } else {
                    low = t;
                }
            }
        }
    }
}
