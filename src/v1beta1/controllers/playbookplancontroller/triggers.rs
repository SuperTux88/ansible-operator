use std::str::FromStr;

use chrono::{DateTime, Duration, TimeZone};

#[derive(Debug, thiserror::Error)]
pub enum ScheduleError {
    #[error("expected exactly 5 fields (minute hour day-of-month month day-of-week)")]
    FieldCount,

    #[error(
        "day-of-week {0:?} is not valid: expected 0-7 (0 and 7 are Sunday) or a day name, as a \
         single day or a range, optionally with a /step"
    )]
    DayOfWeek(String),

    #[error("{0}")]
    Parse(#[from] cron::error::Error),
}

#[derive(Debug)]
pub struct Schedule(cron::Schedule);

impl Schedule {
    /// Parses a standard 5-field cron expression.
    ///
    /// The `cron` crate wants a seconds field in front, and numbers the day of week from 1 = Sunday
    /// to 7 = Saturday, where standard cron has 0 = Sunday to 6 = Saturday and 7 as Sunday again.
    /// Passed through, every numeric day would run a day early and `0` would be refused, so the
    /// day-of-week field is handed over as the day names it selects, which both read the same.
    pub fn parse(value: &str) -> Result<Self, ScheduleError> {
        let [minute, hour, day_of_month, month, day_of_week] = value
            .split_whitespace()
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| ScheduleError::FieldCount)?;
        let day_of_week = day_of_week_names(day_of_week)?;

        Ok(Self(cron::Schedule::from_str(&format!(
            "0 {minute} {hour} {day_of_month} {month} {day_of_week}"
        ))?))
    }
}

/// Day names indexed by their standard cron number, Sunday first.
const DAY_NAMES: [&str; 7] = ["SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"];

/// A standard cron day-of-week field as the comma-separated day names it selects.
///
/// Accepts what the `cron` crate accepted before this translation existed — lists, ranges, `/step`,
/// `*` and `?`, and its day names — so no expression that used to parse is refused, only read with
/// standard numbering. A bare `N/step` runs from `N` to the end of the week, as in cronie.
fn day_of_week_names(field: &str) -> Result<String, ScheduleError> {
    let invalid = || ScheduleError::DayOfWeek(field.to_string());
    let mut selected = [false; 7];

    for item in field.split(',') {
        let (base, step) = match item.split_once('/') {
            Some((base, step)) => {
                let step = step
                    .parse::<usize>()
                    .ok()
                    .filter(|&step| step > 0)
                    .ok_or_else(invalid)?;
                (base, Some(step))
            }
            None => (item, None),
        };
        let (first, last) = match base {
            "*" | "?" => (0, 7),
            _ => match base.split_once('-') {
                Some((first, last)) => (
                    day_number(first).ok_or_else(invalid)?,
                    day_number(last).ok_or_else(invalid)?,
                ),
                None => {
                    let day = day_number(base).ok_or_else(invalid)?;
                    (day, if step.is_some() { 7 } else { day })
                }
            },
        };
        if first > last {
            return Err(invalid());
        }
        for day in (first..=last).step_by(step.unwrap_or(1)) {
            selected[day % 7] = true;
        }
    }

    Ok(DAY_NAMES
        .iter()
        .zip(selected)
        .filter_map(|(name, selected)| selected.then_some(*name))
        .collect::<Vec<_>>()
        .join(","))
}

/// A day of week by standard cron number (`0`-`7`, both ends Sunday) or by any name the `cron`
/// crate knows, case-insensitively.
fn day_number(value: &str) -> Option<usize> {
    if let Ok(number) = value.parse::<usize>() {
        return (number <= 7).then_some(number);
    }
    let day = match value.to_ascii_lowercase().as_str() {
        "sun" | "sunday" => 0,
        "mon" | "monday" => 1,
        "tue" | "tues" | "tuesday" => 2,
        "wed" | "wednesday" => 3,
        "thu" | "thurs" | "thursday" => 4,
        "fri" | "friday" => 5,
        "sat" | "saturday" => 6,
        _ => return None,
    };
    Some(day)
}

/// Whether a playbook should run now or later
#[derive(PartialEq, Eq, Debug)]
pub enum Timing<Tz: TimeZone> {
    /// The playbook should run _now_ due to some reason. If the inner DateTime is set, the timing
    /// is based on a recurring schedule and the DateTime is the start of the current window.
    Now(Option<DateTime<Tz>>),

    /// The playbook will be delayed until some time in the future
    Delayed(DateTime<Tz>),
}

pub fn evaluate_schedule<Tz: TimeZone>(
    schedule: Option<&Schedule>,
    now: DateTime<Tz>,
    window: Duration,
) -> Option<Timing<Tz>> {
    let Some(schedule) = schedule else {
        return Some(Timing::Now(None));
    };

    let next_run = forecast_next_run(schedule, now.clone(), Some(window))?;

    let offset_now = now - window;
    let diff = next_run.clone() - offset_now;

    if diff <= window {
        return Some(Timing::Now(Some(next_run)));
    }

    Some(Timing::Delayed(next_run))
}

pub fn forecast_next_run<Tz: TimeZone>(
    schedule: &Schedule,
    now: DateTime<Tz>,
    window: Option<Duration>,
) -> Option<DateTime<Tz>> {
    let offset_now = now - window.unwrap_or(Duration::zero());
    schedule.0.after(&offset_now).next()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(value: &str) -> DateTime<chrono::Utc> {
        value.parse::<DateTime<chrono::Utc>>().unwrap()
    }

    #[test]
    fn test_delayed_triggers() {
        // Given
        let schedule = Schedule::parse("0 20 * * *").unwrap();
        let window = Duration::seconds(60);

        // When
        let too_early = evaluate_schedule(Some(&schedule), parse("2025-08-12T19:59:00Z"), window);
        let on_time = evaluate_schedule(Some(&schedule), parse("2025-08-12T20:00:00Z"), window);
        let latest = evaluate_schedule(Some(&schedule), parse("2025-08-12T20:00:59Z"), window);
        let too_late = evaluate_schedule(Some(&schedule), parse("2025-08-12T20:01:00Z"), window);

        // Then
        assert_eq!(
            Some(Timing::Delayed(parse("2025-08-12T20:00:00Z"))),
            too_early
        );
        assert_eq!(
            Some(Timing::Now(Some(parse("2025-08-12T20:00:00Z")))),
            on_time
        );
        assert_eq!(
            Some(Timing::Now(Some(parse("2025-08-12T20:00:00Z")))),
            latest
        );
        assert_eq!(
            Some(Timing::Delayed(parse("2025-08-13T20:00:00Z"))),
            too_late
        );
    }

    #[test]
    fn schedules_are_exactly_five_fields_and_semantically_valid() {
        assert!(Schedule::parse("0 3 * * *").is_ok());
        assert!(Schedule::parse("0 3 * *").is_err());
        assert!(Schedule::parse("0 3 * * * 2030").is_err());
        assert!(Schedule::parse("99 3 * * *").is_err());
    }

    /// The weekdays `0 3 * * {day_of_week}` runs on in one week, Sunday first.
    fn days_of(day_of_week: &str) -> Vec<String> {
        let sunday = parse("2026-01-04T00:00:00Z");
        let schedule = Schedule::parse(&format!("0 3 * * {day_of_week}")).unwrap();
        schedule
            .0
            .after(&sunday)
            .take_while(|tick| *tick < sunday + Duration::days(7))
            .map(|tick| tick.format("%a").to_string())
            .collect()
    }

    #[test]
    fn day_of_week_numbers_are_standard_cron() {
        assert_eq!(days_of("1-5"), ["Mon", "Tue", "Wed", "Thu", "Fri"]);
        assert_eq!(days_of("0"), ["Sun"]);
        assert_eq!(days_of("7"), ["Sun"]);
        assert_eq!(days_of("6"), ["Sat"]);
        assert_eq!(days_of("5-7"), ["Sun", "Fri", "Sat"]);
        assert_eq!(days_of("0,3"), ["Sun", "Wed"]);
    }

    #[test]
    fn day_of_week_steps_count_from_the_start_of_their_range() {
        assert_eq!(days_of("*/2"), ["Sun", "Tue", "Thu", "Sat"]);
        assert_eq!(days_of("1-5/2"), ["Mon", "Wed", "Fri"]);
        // A bare start runs to the end of the week, which includes Sunday as 7.
        assert_eq!(days_of("1/3"), ["Sun", "Mon", "Thu"]);
        assert_eq!(days_of("?/3"), ["Sun", "Wed", "Sat"]);
    }

    #[test]
    fn day_names_select_the_same_days_as_their_numbers() {
        assert_eq!(days_of("MON-FRI"), days_of("1-5"));
        assert_eq!(days_of("sun,Sat"), days_of("0,6"));
        assert_eq!(days_of("tues-thursday"), days_of("2-4"));
        assert_eq!(days_of("*").len(), 7);
    }

    #[test]
    fn a_day_of_week_outside_the_week_is_refused() {
        for day_of_week in ["8", "5-1", "FRI-MON", "*/0", "1-", "x", "1,,2"] {
            assert!(
                matches!(
                    Schedule::parse(&format!("0 3 * * {day_of_week}")),
                    Err(ScheduleError::DayOfWeek(_))
                ),
                "{day_of_week:?} must be refused"
            );
        }
    }

    #[test]
    fn a_valid_expression_with_no_occurrence_is_not_unwrapped() {
        let schedule = Schedule::parse("0 0 31 2 *").unwrap();

        assert_eq!(
            forecast_next_run(&schedule, parse("2025-08-12T20:00:00Z"), None),
            None
        );
    }
}
