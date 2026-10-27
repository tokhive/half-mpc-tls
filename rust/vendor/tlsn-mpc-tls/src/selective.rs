use std::{
    ops::Range,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

type LeaderRanges = Vec<Range<usize>>;
type FollowerRecordPlan = (Vec<u8>, PlannedRecord);
type RawRecordPlan = (Option<Vec<u8>>, PlannedRecord, bool);

/// Encryption mode authorized for one fragment of a selective request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PlannedRecord {
    /// A record containing at least one Provider-owned byte range.
    Selective(LeaderRanges),
    /// A record containing only canonical bytes already known by the Hub.
    Public,
}

/// Provider-side control for one pending selective request.
#[derive(Clone, Default)]
pub struct SelectiveLeaderControl {
    state: Arc<Mutex<Option<Plan>>>,
    required: Arc<AtomicBool>,
    used: Arc<AtomicBool>,
}

impl std::fmt::Debug for SelectiveLeaderControl {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SelectiveLeaderControl")
            .finish_non_exhaustive()
    }
}

impl SelectiveLeaderControl {
    /// Requires one request, fragmented at 16 KiB, with a pending selective plan.
    pub fn require_selective(&self) {
        self.required.store(true, Ordering::Release);
    }

    /// Installs one request length and its Provider-owned byte ranges.
    pub fn prepare(
        &self,
        request_len: usize,
        leader_ranges: Vec<Range<usize>>,
    ) -> Result<(), SelectiveError> {
        validate_ranges(request_len, &leader_ranges)?;
        let mut state = self.state.lock().map_err(|_| SelectiveError::Unavailable)?;
        if state.is_some() {
            return Err(SelectiveError::Pending);
        }
        if self.is_required() && self.used.swap(true, Ordering::AcqRel) {
            return Err(SelectiveError::Consumed);
        }
        *state = Some(Plan {
            request_len,
            leader_ranges,
            offset: 0,
            template: None,
        });
        Ok(())
    }

    pub(crate) fn next_record(
        &self,
        record_len: usize,
    ) -> Result<Option<PlannedRecord>, SelectiveError> {
        let mut state = self.state.lock().map_err(|_| SelectiveError::Unavailable)?;
        let Some(plan) = state.as_mut() else {
            return Ok(None);
        };
        if self.is_required() && record_len != (plan.request_len - plan.offset).min(16384) {
            *state = None;
            return Err(SelectiveError::LengthMismatch);
        }
        let (_, record, complete) = plan.take_record(record_len)?;
        if complete {
            *state = None;
        }
        Ok(Some(record))
    }

    pub(crate) fn is_required(&self) -> bool {
        self.required.load(Ordering::Acquire)
    }
}

/// Hub-side control for the canonical template of one pending selective request.
#[derive(Clone, Default)]
pub struct SelectiveFollowerControl {
    state: Arc<Mutex<Option<Plan>>>,
    required: Arc<AtomicBool>,
    used: Arc<AtomicBool>,
}

impl std::fmt::Debug for SelectiveFollowerControl {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SelectiveFollowerControl")
            .finish_non_exhaustive()
    }
}

impl SelectiveFollowerControl {
    /// Requires one request, fragmented at 16 KiB, with a matching canonical plan.
    pub fn require_selective(&self) {
        self.required.store(true, Ordering::Release);
    }

    /// Installs one canonical template and its Provider-owned byte ranges.
    pub fn prepare(
        &self,
        template: Vec<u8>,
        leader_ranges: Vec<Range<usize>>,
    ) -> Result<(), SelectiveError> {
        validate_ranges(template.len(), &leader_ranges)?;
        let mut state = self.state.lock().map_err(|_| SelectiveError::Unavailable)?;
        if state.is_some() {
            return Err(SelectiveError::Pending);
        }
        if self.is_required() && self.used.swap(true, Ordering::AcqRel) {
            return Err(SelectiveError::Consumed);
        }
        *state = Some(Plan {
            request_len: template.len(),
            leader_ranges,
            offset: 0,
            template: Some(template),
        });
        Ok(())
    }

    pub(crate) fn next_record(
        &self,
        record_len: usize,
    ) -> Result<Option<FollowerRecordPlan>, SelectiveError> {
        let mut state = self.state.lock().map_err(|_| SelectiveError::Unavailable)?;
        let Some(plan) = state.as_mut() else {
            return Ok(None);
        };
        if self.is_required() && record_len != (plan.request_len - plan.offset).min(16384) {
            *state = None;
            return Err(SelectiveError::LengthMismatch);
        }
        let (template, record, complete) = plan.take_record(record_len)?;
        if complete {
            *state = None;
        }
        Ok(Some((
            template.expect("follower plans always contain a template"),
            record,
        )))
    }

    pub(crate) fn is_required(&self) -> bool {
        self.required.load(Ordering::Acquire)
    }
}

struct Plan {
    request_len: usize,
    leader_ranges: Vec<Range<usize>>,
    offset: usize,
    template: Option<Vec<u8>>,
}

impl Plan {
    fn take_record(&mut self, record_len: usize) -> Result<RawRecordPlan, SelectiveError> {
        if record_len == 0 || self.offset + record_len > self.request_len {
            return Err(SelectiveError::LengthMismatch);
        }
        let record_start = self.offset;
        let record_end = record_start + record_len;
        let ranges: LeaderRanges = self
            .leader_ranges
            .iter()
            .filter_map(|range| {
                let start = range.start.max(record_start);
                let end = range.end.min(record_end);
                (start < end).then(|| start - record_start..end - record_start)
            })
            .collect();
        let record = if ranges.is_empty() {
            PlannedRecord::Public
        } else {
            PlannedRecord::Selective(ranges)
        };
        let template = self
            .template
            .as_ref()
            .map(|template| template[record_start..record_end].to_vec());
        self.offset = record_end;
        Ok((template, record, self.offset == self.request_len))
    }
}

fn validate_ranges(request_len: usize, ranges: &[Range<usize>]) -> Result<(), SelectiveError> {
    if request_len == 0 || ranges.is_empty() {
        return Err(SelectiveError::InvalidRanges);
    }
    let mut previous_end = 0;
    for range in ranges {
        if range.start < previous_end || range.start >= range.end || range.end > request_len {
            return Err(SelectiveError::InvalidRanges);
        }
        previous_end = range.end;
    }
    Ok(())
}

/// Selective request control failure.
#[derive(Debug, thiserror::Error)]
pub enum SelectiveError {
    /// Another request is already pending on this TLS connection.
    #[error("a selective request is already pending")]
    Pending,
    /// The one-shot precomputed session has already authorized a request.
    #[error("selective request material has already been consumed")]
    Consumed,
    /// The private byte ranges are malformed or outside the request.
    #[error("selective request ranges are invalid")]
    InvalidRanges,
    /// TLS record fragmentation exceeded the prepared request length.
    #[error("selective request record length does not match the prepared request")]
    LengthMismatch,
    /// Internal control state could not be accessed.
    #[error("selective request control is unavailable")]
    Unavailable,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::single_range_in_vec_init)]

    use super::*;

    #[test]
    fn plans_are_single_use_and_translate_ranges_across_records() {
        let leader = SelectiveLeaderControl::default();
        leader.prepare(20, vec![7..13]).unwrap();
        assert!(matches!(
            leader.prepare(20, vec![7..13]),
            Err(SelectiveError::Pending)
        ));
        assert_eq!(
            leader.next_record(10).unwrap(),
            Some(PlannedRecord::Selective(vec![7..10]))
        );
        assert_eq!(
            leader.next_record(10).unwrap(),
            Some(PlannedRecord::Selective(vec![0..3]))
        );
        assert_eq!(leader.next_record(1).unwrap(), None);

        let follower = SelectiveFollowerControl::default();
        follower.prepare((0..20).collect(), vec![7..13]).unwrap();
        assert_eq!(
            follower.next_record(10).unwrap(),
            Some(((0..10).collect(), PlannedRecord::Selective(vec![7..10])))
        );
        assert_eq!(
            follower.next_record(10).unwrap(),
            Some(((10..20).collect(), PlannedRecord::Selective(vec![0..3])))
        );
    }

    #[test]
    fn records_after_the_private_span_use_the_public_fast_path() {
        let leader = SelectiveLeaderControl::default();
        leader.prepare(30, vec![2..6]).unwrap();
        assert_eq!(
            leader.next_record(10).unwrap(),
            Some(PlannedRecord::Selective(vec![2..6]))
        );
        assert_eq!(leader.next_record(10).unwrap(), Some(PlannedRecord::Public));
        assert_eq!(leader.next_record(10).unwrap(), Some(PlannedRecord::Public));

        let follower = SelectiveFollowerControl::default();
        follower.prepare((0..30).collect(), vec![2..6]).unwrap();
        assert_eq!(
            follower.next_record(10).unwrap(),
            Some(((0..10).collect(), PlannedRecord::Selective(vec![2..6])))
        );
        assert_eq!(
            follower.next_record(10).unwrap(),
            Some(((10..20).collect(), PlannedRecord::Public))
        );
        assert_eq!(
            follower.next_record(10).unwrap(),
            Some(((20..30).collect(), PlannedRecord::Public))
        );
    }

    #[test]
    fn required_plans_enforce_fragmentation_and_single_request() {
        let leader = SelectiveLeaderControl::default();
        let follower = SelectiveFollowerControl::default();
        leader.require_selective();
        follower.require_selective();
        leader.prepare(16401, vec![3..9]).unwrap();
        follower.prepare(vec![0; 16401], vec![3..9]).unwrap();
        leader.next_record(16384).unwrap();
        follower.next_record(16384).unwrap();
        leader.next_record(17).unwrap();
        follower.next_record(17).unwrap();
        assert!(matches!(
            leader.prepare(16, vec![3..9]),
            Err(SelectiveError::Consumed)
        ));
        assert!(matches!(
            follower.prepare(vec![0; 16], vec![3..9]),
            Err(SelectiveError::Consumed)
        ));
    }

    #[test]
    fn unexpected_fragment_invalidates_required_plan() {
        for (first, invalid) in [(false, 8192), (false, 16385), (true, 16)] {
            let leader = SelectiveLeaderControl::default();
            let follower = SelectiveFollowerControl::default();
            leader.require_selective();
            follower.require_selective();
            leader.prepare(16401, vec![3..9]).unwrap();
            follower.prepare(vec![0; 16401], vec![3..9]).unwrap();
            if first {
                leader.next_record(16384).unwrap();
                follower.next_record(16384).unwrap();
            }
            assert!(leader.next_record(invalid).is_err());
            assert!(follower.next_record(invalid).is_err());
            assert!(leader.next_record(17).unwrap().is_none());
            assert!(follower.next_record(17).unwrap().is_none());
            assert!(leader.prepare(16401, vec![3..9]).is_err());
            assert!(follower.prepare(vec![0; 16401], vec![3..9]).is_err());
        }
    }

    #[test]
    fn plans_reject_invalid_ranges_and_record_overrun() {
        let control = SelectiveLeaderControl::default();
        assert!(control.prepare(10, vec![]).is_err());
        assert!(control.prepare(10, vec![5..11]).is_err());
        control.prepare(10, vec![5..8]).unwrap();
        assert!(matches!(
            control.next_record(11),
            Err(SelectiveError::LengthMismatch)
        ));
    }
}
