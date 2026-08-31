use std::str::FromStr;

use chrono::{DateTime, Duration, TimeZone};

#[derive(Debug, thiserror::Error)]
pub enum ScheduleError {
    #[error("expected exactly 5 fields (minute hour day-of-month month day-of-week)")]
    FieldCount,

    #[error("{0}")]
    Parse(#[from] cron::error::Error),
}

#[derive(Debug)]
pub struct Schedule(cron::Schedule);

impl Schedule {
    pub fn parse(value: &str) -> Result<Self, ScheduleError> {
        if value.split_whitespace().count() != 5 {
            return Err(ScheduleError::FieldCount);
        }

        Ok(Self(cron::Schedule::from_str(&format!("0 {value}"))?))
    }
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

    #[test]
    fn a_valid_expression_with_no_occurrence_is_not_unwrapped() {
        let schedule = Schedule::parse("0 0 31 2 *").unwrap();

        assert_eq!(
            forecast_next_run(&schedule, parse("2025-08-12T20:00:00Z"), None),
            None
        );
    }
}
