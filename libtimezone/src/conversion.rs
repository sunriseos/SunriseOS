//! Conversion module
//!
//! This module is in charge of converting a Tzif file content to a TimeZoneRule.
#![allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]

use core::convert::TryInto;
use misc::compare_cstr;
use misc::len_cstr;

use utils::increment_overflow;
use utils::is_leap_year;

use super::Time;
use super::TimeTypeInfo;
use super::TimeZoneRule;
use super::*;

/// GMT POSIX Time Zone abreviation.
const GMT_TZ_STRING: &[u8] = b"GMT\0";

/// Default POSIX Time Zone rules.
const TZ_DEFAULT_RULE: &[u8] = b",M4.1.0,M10.5.0\0";

/// Represent a buffer used to convert a TzIf file to a TimeZoneRule struct.
#[repr(C, align(8))]
pub(crate) struct ConversionBuffer<'a, 'b> {
    /// The work buffer containing the TzIf file content.
    pub work_buffer: &'a [u8],

    /// A temporary storage used to store the result of ``parse_timezone_name`` during the conversion.
    pub temp_rules: &'b mut TimeZoneRule,
}

/// Represent the header of a Tzif file.
#[repr(C, align(4))]
struct TzifHeader {
    /// The magic number of a Tzif file ("TZif").
    pub magic: [u8; 4],

    /// The version number of the TzIf file.
    pub version: u8,

    /// Reserved for future usage.
    reserved: [u8; 15],

    /// The count of GMT TimeTypeInfo.
    pub ttis_gmt_count: [u8; 4],

    /// The count of Standard Time Daylight TimeTypeInfo.
    pub ttis_std_count: [u8; 4],

    /// The count of leap definitions.
    pub leap_count: [u8; 4],

    /// The count of time transitions.
    pub time_count: [u8; 4],

    /// The count of time type infos.
    pub type_count: [u8; 4],

    /// The count of chars.
    pub char_count: [u8; 4],
}

assert_eq_size!(tzhead; TzifHeader, [u8; 0x2c]);

/// Represent a rule type of a POSIX TimeZone name.
enum RuleType {
    /// Represent a day in the Julian Calendar.
    JulianDay,

    /// Represent a day of the year.
    DayOfYear,

    /// Represent the month number and the day of the week.
    MonthNthDayOfWeek,

    /// Invalid type.
    Invalid,
}

#[repr(C, align(8))]
/// Represent a rule of a POSIX TimeZone name.
struct Rule {
    /// The type of this rule.
    pub rule_type: RuleType,

    /// The day of this rule.
    pub day: i64,

    /// The day of this rule.
    pub week: i64,

    /// The month of this rule.
    pub month: i64,

    /// The time of this rule.
    pub time: i64,
}

impl Default for Rule {
    fn default() -> Self {
        Rule {
            rule_type: RuleType::Invalid,
            day: 0,
            week: 0,
            month: 0,
            time: 0,
        }
    }
}

/// Return true if t1 - t0 equals to the count of seconds before leap seconds repeat.
#[inline]
fn differ_by_repeat(t1: Time, t0: Time) -> bool {
    t1 - t0 == SECS_PER_REPEAT
}

/// Convert a Tzif 32 bits integer to a platform dependent 32 bits integer.
#[inline]
fn detzcode(codep: [u8; 4]) -> i32 {
    i32::from_be_bytes(codep)
}

/// Convert a Tzif 64 bits integer to a platform dependent 64 bits integer.
#[inline]
fn detzcode64(codep: [u8; 8]) -> i64 {
    i64::from_be_bytes(codep)
}

/// Get as shrinked slice at the given delimiter.
///
/// Used in TZ String Extensions parsing logic.
fn get_qz_name(name: &[u8], delimiter: char) -> &[u8] {
    let mut res = name;

    loop {
        let c = res[0] as char;

        if c == '\0' || c == delimiter {
            break;
        }

        res = &res[1..];
    }

    res
}

/// Get the timezone name from a given slice.
fn get_tz_name(name: &[u8]) -> &[u8] {
    let mut res = name;

    loop {
        let c = res[0] as char;

        if c == '\0' || c.is_digit(10) || c == ',' || c == '-' || c == '+' {
            break;
        }

        res = &res[1..];
    }

    res
}

/// Parse a number and return the rest if the number is in range.
fn get_num<'a>(name: &'a [u8], num: &mut i64, min: i64, max: i64) -> Option<&'a [u8]> {
    if !(name[0] as char).is_digit(10) {
        return None;
    }

    let name_str = unsafe { core::str::from_utf8_unchecked(name) };

    let mut max_size = 0;

    for c in name_str.chars() {
        if !c.is_digit(10) {
            break;
        }
        max_size += 1;
    }

    let num_opt = (&name_str[..max_size]).parse::<i64>();
    if let Ok(parsed_num) = num_opt {
        if parsed_num < min || parsed_num > max {
            return None;
        }

        *num = num_opt.unwrap();
        return Some(&name[max_size..]);
    }
    None
}

/// Parse a time and return the rest while giving the seconds of the given time.
fn get_secs<'a>(name: &'a [u8], secs: &mut i64) -> Option<&'a [u8]> {
    let mut num = 0;

    let opt = get_num(name, &mut num, 0, HOURS_PER_DAY * DAYS_PER_WEEK - 1);
    if let Some(name) = opt {
        *secs = num * SECS_PER_HOUR;
        if name[0] == b':' {
            let name = &name[1..];
            let opt = get_num(name, &mut num, 0, MINS_PER_HOUR - 1);
            if let Some(name) = opt {
                *secs += num * SECS_PER_MIN;
                if name[0] == b':' {
                    let name = &name[1..];
                    let opt = get_num(name, &mut num, 0, SECS_PER_MIN);
                    if opt.is_some() {
                        *secs += num;
                        return opt;
                    } else {
                        return None;
                    }
                }
            } else {
                return None;
            }

            return opt;
        }

        return opt;
    }
    None
}

/// Parse the given rule and return the rest if valid.
fn get_rule<'a>(name: &'a [u8], rule: &mut Rule) -> Option<&'a [u8]> {
    let inital_char = name[0] as char;

    let mut name = &name[1..];

    if inital_char == 'J' {
        rule.rule_type = RuleType::JulianDay;
        name = get_num(name, &mut rule.day, 1, DAYS_PER_NYEAR)?;
    } else if inital_char == 'M' {
        rule.rule_type = RuleType::MonthNthDayOfWeek;

        name = get_num(name, &mut rule.month, 1, MONS_PER_YEAR)?;

        if name[0] != b'.' {
            return None;
        }
        name = &name[1..];
        name = get_num(name, &mut rule.week, 1, 5)?;

        if name[0] != b'.' {
            return None;
        }

        name = &name[1..];
        name = get_num(name, &mut rule.day, 0, DAYS_PER_WEEK)?;
    } else if inital_char.is_digit(10) {
        rule.rule_type = RuleType::DayOfYear;
        name = get_num(name, &mut rule.day, 1, DAYS_PER_LYEAR - 1)?;
    } else {
        return None;
    };

    if name[0] == b'/' {
        name = get_offset(&name[1..], &mut rule.time)?;
    } else {
        // Default to 2:00:00
        rule.time = 2 * SECS_PER_HOUR;
    }

    Some(name)
}

/// Parse the offset of a rule and return the rest if valid.
fn get_offset<'a>(name: &'a [u8], offset: &mut i64) -> Option<&'a [u8]> {
    let mut is_negative = false;

    let mut name = name;

    if name[0] == b'-' {
        is_negative = true;
        name = &name[1..];
    } else if name[0] == b'+' {
        name = &name[1..];
    }

    let res = get_secs(name, offset);

    if res.is_some() && is_negative {
        *offset = -*offset;
    }

    res
}

/// Translate a given rule to a Time.
fn translate_rule_to_time(year: i64, rule: &Rule, offset: i64) -> Time {
    let is_leap = is_leap_year(year);
    let value = match rule.rule_type {
        RuleType::JulianDay => {
            let mut value = (rule.day - 1) * SECS_PER_DAY;
            if is_leap && rule.day >= 60 {
                value += SECS_PER_DAY;
            }

            value as Time
        }
        RuleType::DayOfYear => ((rule.day - 1) * SECS_PER_DAY) as Time,
        RuleType::MonthNthDayOfWeek => {
            let m1 = (rule.month + 9) % 12 + 1;
            let yy0 = if rule.month <= 2 { year - 1 } else { year };

            let yy1 = yy0 / 100;
            let yy2 = yy0 % 100;

            let mut day_of_year = ((26 * m1 - 2) / 10 + 1 + yy2 + yy2 / 4 + yy1 / 4 - 2 * yy1) % 7;
            if day_of_year < 0 {
                day_of_year += DAYS_PER_WEEK;
            }

            let mut day = rule.day - day_of_year;
            if day < 0 {
                day += DAYS_PER_WEEK;
            }

            for _ in 1..rule.week {
                if day + DAYS_PER_WEEK >= MON_LENGTHS[is_leap as usize][rule.month as usize - 1] {
                    break;
                }
                day += DAYS_PER_WEEK;
            }

            let mut value = day * SECS_PER_DAY;
            for i in 0..rule.month as usize - 1 {
                value += MON_LENGTHS[is_leap as usize][i] * SECS_PER_DAY;
            }

            value as Time
        }
        _ => unimplemented!(),
    };

    value + (rule.time + offset) as Time
}

/// Parse a POSIX timezone c string into a TimeZoneRule.
#[allow(clippy::cognitive_complexity)]
fn parse_timezone_name(name: &[u8], timezone_rule: &mut TimeZoneRule, last_ditch: bool) -> bool {
    let std_len;
    let mut std_name;
    let mut std_offset;

    let mut name = name;

    std_name = name;
    if last_ditch {
        std_len = GMT_TZ_STRING.len() - 1;
        name = &name[std_len..];
        std_offset = 0;
    } else {
        if name[0] == b'<' {
            name = &name[1..];
            std_name = name;
            name = get_qz_name(name, '>');
            if name[0] != b'>' {
                return false;
            }

            std_len = std_name.len() - name.len();
            name = &name[1..];
        } else {
            name = get_tz_name(name);
            std_len = std_name.len() - name.len();
        }

        if std_len == 0 {
            return false;
        }

        std_offset = 0;
        let offset_opt = get_offset(name, &mut std_offset);

        if let Some(offset_name) = offset_opt {
            name = offset_name;
        } else {
            return false;
        }
    }

    let mut char_count = std_len + 1;
    if timezone_rule.chars.len() < char_count {
        return false;
    }

    let dst_len;
    let mut dst_name = name;

    if name[0] != b'\0' {
        if name[0] == b'<' {
            name = &name[1..];
            dst_name = name;
            name = get_qz_name(name, '>');
            if name[0] != b'>' {
                return false;
            }

            dst_len = dst_name.len() - name.len();
            name = &name[1..];
        } else {
            name = get_tz_name(name);
            dst_len = dst_name.len() - name.len();
        }

        if dst_len == 0 {
            return false;
        }

        char_count += dst_len + 1;
        if timezone_rule.chars.len() < char_count {
            return false;
        }

        let mut dst_offset: i64;

        if name[0] != b'\0' && name[0] != b',' && name[0] != b';' {
            dst_offset = 0;
            let offset_opt = get_offset(name, &mut dst_offset);

            if let Some(offset_name) = offset_opt {
                name = offset_name;
            } else {
                return false;
            }
        } else {
            dst_offset = std_offset - SECS_PER_HOUR;
        }

        if name[0] == b'\0' {
            name = TZ_DEFAULT_RULE;
        }

        if name[0] == b',' || name[0] == b';' {
            name = &name[1..];
            let mut start_rule = Rule::default();
            let mut end_rule = Rule::default();

            let opt = get_rule(name, &mut start_rule);
            if opt.is_none() {
                return false;
            }

            name = opt.unwrap();

            if name[0] != b',' {
                return false;
            }
            name = &name[1..];

            let opt = get_rule(name, &mut end_rule);
            if opt.is_none() {
                return false;
            }

            name = opt.unwrap();

            if name[0] != b'\0' {
                return false;
            }

            timezone_rule.typecnt = 2;

            timezone_rule.ttis[0] =
                TimeTypeInfo::new(-dst_offset as i32, true, (std_len + 1) as i32);
            timezone_rule.ttis[1] = TimeTypeInfo::new(-std_offset as i32, false, 0);
            timezone_rule.default_type = 0;

            let mut time_count: usize = 0;
            let mut january_first = 0 as Time;
            let mut year_begining = EPOCH_YEAR as i64;
            let mut january_offset = 0;

            while EPOCH_YEAR - YEARS_PER_REPEAT / 2 < year_begining {
                let seconds_per_year =
                    YEAR_LENGTHS[is_leap_year(year_begining - 1) as usize] * SECS_PER_DAY;
                year_begining -= 1;
                if increment_overflow(&mut january_first, -seconds_per_year as Time) {
                    january_offset = -seconds_per_year;
                    break;
                }
            }

            let mut year_limit = year_begining + YEARS_PER_REPEAT + 1;

            let mut year = year_begining;

            while year < year_limit {
                let mut start_time = translate_rule_to_time(year, &start_rule, std_offset);
                let mut end_time = translate_rule_to_time(year, &end_rule, dst_offset);
                let seconds_per_year = YEAR_LENGTHS[is_leap_year(year) as usize] * SECS_PER_DAY;

                let reversed = end_time < start_time;
                if reversed {
                    core::mem::swap(&mut start_time, &mut end_time);
                }

                if reversed
                    || (start_time < end_time
                        && end_time - start_time
                            < (seconds_per_year + (std_offset - dst_offset)) as Time)
                {
                    if TZ_MAX_TIMES as usize - 2 < time_count {
                        break;
                    }

                    timezone_rule.ats[time_count] = january_first;
                    if !increment_overflow(
                        &mut timezone_rule.ats[time_count],
                        january_offset as Time + start_time,
                    ) {
                        timezone_rule.types[time_count] = reversed as u8;
                        time_count += 1;
                    } else if january_offset != 0 {
                        timezone_rule.default_type = reversed as i32;
                    }
                    timezone_rule.ats[time_count] = january_first;

                    if !increment_overflow(
                        &mut timezone_rule.ats[time_count],
                        january_offset as Time + end_time,
                    ) {
                        timezone_rule.types[time_count] = !reversed as u8;
                        time_count += 1;
                        year_limit = year + YEARS_PER_REPEAT + 1;
                    } else if january_offset != 0 {
                        timezone_rule.default_type = !reversed as i32;
                    }
                }

                if increment_overflow(
                    &mut january_first,
                    (january_offset + seconds_per_year) as Time,
                ) {
                    break;
                }
                january_offset = 0;
                year += 1;
            }

            timezone_rule.timecnt = time_count as i32;
            if timezone_rule.timecnt == 0 {
                // Perpetual DST
                timezone_rule.typecnt = 1;
            } else if YEARS_PER_REPEAT < year - year_begining {
                timezone_rule.goahead = true;
                timezone_rule.goback = true;
            }
        } else {
            if name[0] != b'\0' {
                return false;
            }

            let mut their_std_offset: i64 = 0;
            for i in 0..timezone_rule.timecnt as usize {
                let typ = timezone_rule.types[i];
                if !timezone_rule.ttis[typ as usize].is_dst {
                    their_std_offset = i64::from(-timezone_rule.ttis[typ as usize].gmt_offset);
                    break;
                }
            }

            let mut their_dst_offset: i64 = 0;
            for i in 0..timezone_rule.timecnt as usize {
                let typ = timezone_rule.types[i];
                if timezone_rule.ttis[typ as usize].is_dst {
                    their_dst_offset = i64::from(-timezone_rule.ttis[typ as usize].gmt_offset);
                    break;
                }
            }

            // Assume standard time
            let is_dst = false;

            for i in 0..timezone_rule.timecnt as usize {
                let typ = timezone_rule.types[i];
                let ttis = &timezone_rule.ttis[typ as usize];

                timezone_rule.types[i] = ttis.is_dst as u8;

                // If it's not GMT, we need to apply offsets
                if !ttis.is_gmt {
                    if is_dst && !ttis.is_std {
                        timezone_rule.ats[i] += (dst_offset - their_dst_offset) as Time;
                    } else {
                        timezone_rule.ats[i] += (std_offset - their_std_offset) as Time;
                    }
                }

                let their_offset = i64::from(-timezone_rule.ttis[typ as usize].gmt_offset);
                if timezone_rule.ttis[typ as usize].is_dst {
                    their_dst_offset = their_offset;
                } else {
                    their_std_offset = their_offset;
                }
            }
        }
    } else {
        dst_len = 0;
        timezone_rule.typecnt = 1;
        timezone_rule.timecnt = 0;
        timezone_rule.ttis[0] = TimeTypeInfo::new(-(std_offset as i32), false, 0);
        timezone_rule.default_type = 0;
    }

    timezone_rule.charcnt = char_count as i32;
    (&mut timezone_rule.chars[0..std_len]).copy_from_slice(&std_name[..std_len]);
    timezone_rule.chars[std_len] = b'\0';

    if dst_len != 0 {
        (&mut timezone_rule.chars[std_len + 1..std_len + 1 + dst_len])
            .copy_from_slice(&dst_name[..dst_len]);
    }

    true
}

/// Load the given timezones rules from a given ConversionBuffer containing TzIf2 data into the given TimeZoneRule.
#[allow(
    clippy::absurd_extreme_comparisons,
    clippy::cast_ptr_alignment,
    clippy::cognitive_complexity
)]
pub(crate) fn load_body(
    timezone_rule: &mut TimeZoneRule,
    conversion_buffer: &mut ConversionBuffer,
) -> TimeZoneResult<()> {
    if conversion_buffer.work_buffer.len() < core::mem::size_of::<TzifHeader>() {
        return Err(TimeZoneError::InvalidSize);
    }

    let work_buffer = conversion_buffer.work_buffer;

    let tzheader: &TzifHeader = unsafe { &*(work_buffer as *const _ as *const TzifHeader) };

    let ttis_gmt_count = detzcode(tzheader.ttis_gmt_count);
    let ttis_std_count = detzcode(tzheader.ttis_std_count);
    let leap_count = detzcode(tzheader.leap_count);
    let mut time_count = detzcode(tzheader.time_count);
    let type_count = detzcode(tzheader.type_count);
    let mut char_count = detzcode(tzheader.char_count);

    if !(0 <= leap_count
        && leap_count < TZ_MAX_LEAPS
        && 0 < type_count
        && type_count < TZ_MAX_TYPES
        && 0 <= time_count
        && time_count < TZ_MAX_TIMES
        && 0 <= char_count
        && char_count < TZ_MAX_CHARS
        && (ttis_std_count == type_count || ttis_std_count == 0)
        && (ttis_gmt_count == type_count || ttis_gmt_count == 0))
    {
        return Err(TimeZoneError::InvalidSize);
    }

    let needed_size = core::mem::size_of::<TzifHeader>()
        + time_count as usize * core::mem::size_of::<Time>()
        + time_count as usize
        + type_count as usize * core::mem::size_of::<TimeTypeInfo>()
        + char_count as usize
        + leap_count as usize * (core::mem::size_of::<Time>() + 4)
        + ttis_std_count as usize
        + ttis_gmt_count as usize;
    if core::mem::size_of::<TimeZoneRule>() < needed_size {
        return Err(TimeZoneError::InvalidSize);
    }

    timezone_rule.timecnt = time_count;
    timezone_rule.typecnt = type_count;
    timezone_rule.charcnt = char_count;

    let mut position = core::mem::size_of::<TzifHeader>();

    time_count = 0;
    for i in 0usize..timezone_rule.timecnt as usize {
        let at_data = &work_buffer[position..position + 8];
        // Will not fail
        let at = detzcode64(at_data.try_into().unwrap());

        timezone_rule.types[i] = if at <= TIME_T_MAX { 1 } else { 0 };

        // Only accept in range values
        if timezone_rule.types[i] != 0 {
            // make sure we don't underflow
            let at_time = if at < TIME_T_MIN { TIME_T_MIN } else { at };

            if time_count != 0 && at_time <= timezone_rule.ats[time_count as usize - 1] {
                if at_time < timezone_rule.ats[time_count as usize - 1] {
                    return Err(TimeZoneError::InvalidData);
                }

                timezone_rule.types[i - 1] = 0;

                time_count -= 1;
            }

            timezone_rule.ats[time_count as usize] = at_time;
            time_count += 1;
        }

        position += core::mem::size_of::<Time>();
    }

    time_count = 0;

    for i in 0usize..timezone_rule.timecnt as usize {
        let typ = work_buffer[position];
        if timezone_rule.typecnt <= i32::from(typ) {
            return Err(TimeZoneError::InvalidData);
        }

        if timezone_rule.types[i] != 0 {
            timezone_rule.types[time_count as usize] = typ;
            time_count += 1;
        }

        position += 1;
    }

    // Updae actual time count (time count minus invalid ones)
    timezone_rule.timecnt = time_count;

    for i in 0usize..timezone_rule.typecnt as usize {
        let at_data = &work_buffer[position..position + 4];
        // Will not fail
        timezone_rule.ttis[i].gmt_offset = detzcode(at_data.try_into().unwrap());
        position += 4;

        let is_dst = work_buffer[position];
        position += 1;

        // This need to be 0 or 1 as it's a bool.
        if is_dst > 1 {
            return Err(TimeZoneError::InvalidData);
        }
        timezone_rule.ttis[i].is_dst = is_dst == 1;

        let abbreviation_list_index = work_buffer[position];
        position += 1;

        // Is it in range?
        if abbreviation_list_index >= timezone_rule.charcnt as u8 {
            return Err(TimeZoneError::InvalidData);
        }

        timezone_rule.ttis[i].abbreviation_list_index = i32::from(abbreviation_list_index);
    }

    // FIXME: clone_fron_slice doesn't do the same thing as this loop. We need to report that on rustc repo.
    /*for i in 0usize..timezone_rule.charcnt as usize {
        timezone_rule.chars[i] = work_buffer[position + i];
    }*/
    //timezone_rule.chars[0usize..timezone_rule.charcnt as usize].clone_from_slice(&work_buffer[position..(timezone_rule.charcnt as usize + position)]);
    timezone_rule.chars[0usize..timezone_rule.charcnt as usize]
        .copy_from_slice(&work_buffer[position..(timezone_rule.charcnt as usize + position)]);
    timezone_rule.chars[timezone_rule.charcnt as usize] = 0;

    position += timezone_rule.charcnt as usize;

    for i in 0usize..timezone_rule.typecnt as usize {
        if ttis_std_count == 0 {
            timezone_rule.ttis[i].is_std = false;
        } else {
            let value = work_buffer[position];
            if value != 0 && value != 1 {
                return Err(TimeZoneError::InvalidData);
            }

            timezone_rule.ttis[i].is_std = value == 1;
            position += 1;
        }
    }

    for i in 0usize..timezone_rule.typecnt as usize {
        if ttis_gmt_count == 0 {
            timezone_rule.ttis[i].is_gmt = false;
        } else {
            let value = work_buffer[position];
            if value != 0 && value != 1 {
                return Err(TimeZoneError::InvalidData);
            }

            timezone_rule.ttis[i].is_gmt = value == 1;
            position += 1;
        }
    }

    if position > work_buffer.len() {
        return Err(TimeZoneError::InvalidData);
    }

    let max_size = work_buffer.len() - position;

    assert!(
        max_size <= (TZ_NAME_MAX as usize + 1),
        "TZNAME is too big to fit on the stack"
    );

    let mut tz_name: [u8; TZ_NAME_MAX as usize + 1] = [0x0; TZ_NAME_MAX as usize + 1];
    (&mut tz_name[0..max_size]).copy_from_slice(&work_buffer[position..]);

    if max_size > 2
        && tz_name[0] == b'\n'
        && tz_name[max_size - 1] == b'\n'
        && timezone_rule.typecnt + 2 <= TZ_MAX_TYPES as i32
    {
        tz_name[max_size - 1] = b'\0';

        if parse_timezone_name(&tz_name[1..], conversion_buffer.temp_rules, false) {
            let mut got_abbr = 0;

            char_count = timezone_rule.charcnt;
            for i in 0..conversion_buffer.temp_rules.typecnt as usize {
                let tsabbr = &conversion_buffer.temp_rules.chars
                    [conversion_buffer.temp_rules.ttis[i].abbreviation_list_index as usize..];

                let mut tmp: usize = 0;
                for j in 0..char_count as usize {
                    if compare_cstr(&timezone_rule.chars[j..], tsabbr) == 0 {
                        conversion_buffer.temp_rules.ttis[i].abbreviation_list_index = j as i32;
                        got_abbr += 1;
                        break;
                    }

                    tmp += 1;
                }

                if tmp >= char_count as usize {
                    let tsabbr_len = len_cstr(tsabbr);

                    if tmp + tsabbr_len < TZ_MAX_CHARS as usize {
                        (&mut timezone_rule.chars[tmp..=tmp + tsabbr_len])
                            .copy_from_slice(&tsabbr[0..=tsabbr_len]);
                        char_count = tmp as i32 + tsabbr_len as i32 + 1;
                        conversion_buffer.temp_rules.ttis[i].abbreviation_list_index = tmp as i32;
                        got_abbr += 1;
                    }
                }
            }

            if got_abbr == conversion_buffer.temp_rules.typecnt {
                timezone_rule.charcnt = char_count;

                while 1 < timezone_rule.timecnt
                    && timezone_rule.types[timezone_rule.timecnt as usize - 1]
                        == timezone_rule.types[timezone_rule.timecnt as usize - 2]
                {
                    timezone_rule.timecnt -= 1;
                }

                let mut index_opt = None;

                for i in 0..conversion_buffer.temp_rules.timecnt as usize {
                    if timezone_rule.timecnt == 0
                        || timezone_rule.ats[timezone_rule.timecnt as usize - 1]
                            < conversion_buffer.temp_rules.ats[i]
                    {
                        index_opt = Some(i);
                        break;
                    }
                }

                if let Some(index) = index_opt {
                    let mut index = index;
                    while index < conversion_buffer.temp_rules.timecnt as usize
                        && (timezone_rule.timecnt as usize) < TZ_MAX_TIMES as usize
                    {
                        timezone_rule.ats[timezone_rule.timecnt as usize] =
                            conversion_buffer.temp_rules.ats[index];
                        timezone_rule.types[timezone_rule.timecnt as usize] =
                            timezone_rule.typecnt as u8 + conversion_buffer.temp_rules.types[index];
                        timezone_rule.timecnt += 1;
                        index += 1;
                    }
                }

                for i in 0..conversion_buffer.temp_rules.typecnt as usize {
                    timezone_rule.ttis[timezone_rule.typecnt as usize] =
                        conversion_buffer.temp_rules.ttis[i];
                    timezone_rule.typecnt += 1;
                }
            }
        }
    }

    if timezone_rule.typecnt == 0 {
        return Err(TimeZoneError::InvalidTypeCount);
    }

    if timezone_rule.timecnt > 1 {
        let first_ttis = &timezone_rule.ttis[timezone_rule.types[0] as usize];
        for i in 1..timezone_rule.timecnt as usize {
            let tmp_ttis = &timezone_rule.ttis[timezone_rule.types[i] as usize];

            if timezone_rule.types[i] < timezone_rule.typecnt as u8
                && timezone_rule.types[0] < timezone_rule.typecnt as u8
                && tmp_ttis == first_ttis
                && compare_cstr(
                    &timezone_rule.chars[tmp_ttis.abbreviation_list_index as usize..],
                    &timezone_rule.chars[first_ttis.abbreviation_list_index as usize..],
                ) != 0
                && differ_by_repeat(timezone_rule.ats[i], timezone_rule.ats[0])
            {
                timezone_rule.goback = true;
            }
        }

        let last_ttis =
            &timezone_rule.ttis[timezone_rule.types[timezone_rule.timecnt as usize - 1] as usize];
        for i in (0..=((timezone_rule.timecnt - 2) as usize)).rev() {
            let tmp_ttis = &timezone_rule.ttis[timezone_rule.types[i] as usize];

            if timezone_rule.types[i] < timezone_rule.typecnt as u8
                && timezone_rule.types[0] < timezone_rule.typecnt as u8
                && tmp_ttis == last_ttis
                && compare_cstr(
                    &timezone_rule.chars[tmp_ttis.abbreviation_list_index as usize..],
                    &timezone_rule.chars[last_ttis.abbreviation_list_index as usize..],
                ) != 0
                && differ_by_repeat(
                    timezone_rule.ats[i],
                    timezone_rule.ats[timezone_rule.timecnt as usize - 1],
                )
            {
                timezone_rule.goahead = true;
            }
        }

        // default_type determination
        let mut is_type_zero_used = false;

        for i in 0..timezone_rule.timecnt as usize {
            if timezone_rule.types[i] == 0 {
                is_type_zero_used = true;
                break;
            }
        }

        let mut default_type: i64 = -1;

        if is_type_zero_used
            && timezone_rule.timecnt > 0
            && timezone_rule.ttis[timezone_rule.types[0] as usize].is_dst
        {
            for i in (0..=timezone_rule.types[0] as usize).rev() {
                if !timezone_rule.ttis[i].is_dst {
                    default_type = i as i64;
                    break;
                }
            }
        }

        if default_type < 0 {
            default_type = 0;

            while timezone_rule.ttis[default_type as usize].is_dst {
                default_type += 1;
                if default_type >= i64::from(timezone_rule.timecnt) {
                    default_type = 0;
                    break;
                }
            }
        }

        timezone_rule.default_type = default_type as i32;
    }

    Ok(())
}
