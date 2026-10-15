//! The synthetic frame clock.
//!
//! RFB and SPICE have no frame rate: a static screen produces no traffic at
//! all. Moonlight asks for one in `x-nv-video[0].maxFPS` and expects frames to
//! keep arriving -- its watchdog fires `ML_ERROR_NO_VIDEO_TRAFFIC` /
//! `ML_ERROR_NO_VIDEO_FRAME` if the stream goes quiet
//! (`Limelight.h:419-424`). So the clock here does two things at once:
//!
//! * **it never goes quiet** -- at the deadline it emits a frame whether or not
//!   anything changed, which the encoder turns into a handful of bytes by
//!   predicting perfectly from the previous frame;
//! * **it does not make damage wait longer than the frame rate allows** -- the
//!   deadline is the only thing a change waits for, and it is rescheduled from
//!   the instant a frame is emitted rather than advanced from the previous
//!   deadline, so a stall does not turn into a burst of catch-up frames. The
//!   remaining wait is up to one frame interval, which is the floor for a
//!   fixed-rate stream (`docs/bridging-design.md` §5).

use std::time::{Duration, Instant};

use solstice_backend::Rect;

/// What the clock says to do now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tick {
    /// The accumulated damaged region, or `None` when nothing changed and this
    /// is a keep-alive frame.
    pub damage: Option<Rect>,
    /// Whether the encoder must produce an IDR.
    pub force_idr: bool,
    /// RTP timestamp, 90 kHz.
    pub timestamp: u32,
    /// Frame counter.
    pub frame_number: u64,
}

impl Tick {
    /// Whether this frame repeats the previous one.
    pub fn is_duplicate(&self) -> bool {
        self.damage.is_none()
    }
}

/// A fixed-rate clock that damage can pull forward.
#[derive(Debug)]
pub struct FrameClock {
    interval: Duration,
    origin: Instant,
    next_deadline: Instant,
    pending_damage: Option<Rect>,
    idr_requested: bool,
    frame_number: u64,
}

impl FrameClock {
    /// Build a clock running at `fps`.
    pub fn new(fps: u32, now: Instant) -> Self {
        let interval = Duration::from_nanos(1_000_000_000 / fps.clamp(1, 1000) as u64);
        Self {
            interval,
            origin: now,
            next_deadline: now,
            pending_damage: None,
            idr_requested: true, // the first frame must be a keyframe
            frame_number: 0,
        }
    }

    /// The frame interval.
    pub fn interval(&self) -> Duration {
        self.interval
    }

    /// Record a damaged region. Regions accumulate into their bounding box
    /// until the next frame is emitted.
    pub fn damage(&mut self, rect: Rect) {
        if rect.is_empty() {
            return;
        }
        self.pending_damage = Some(
            self.pending_damage
                .map_or(rect, |existing| existing.union(&rect)),
        );
    }

    /// Ask for a keyframe. Honoured on the next emitted frame.
    pub fn request_idr(&mut self) {
        self.idr_requested = true;
    }

    /// Whether a keyframe is outstanding.
    pub fn idr_pending(&self) -> bool {
        self.idr_requested
    }

    /// Emit a frame if one is due.
    pub fn poll(&mut self, now: Instant) -> Option<Tick> {
        let due = now >= self.next_deadline;
        if !due {
            return None;
        }
        let tick = Tick {
            damage: self.pending_damage.take(),
            force_idr: std::mem::take(&mut self.idr_requested),
            timestamp: self.timestamp_at(now),
            frame_number: self.frame_number,
        };
        self.frame_number += 1;
        // Schedule from `now` rather than from the old deadline: after a stall
        // (a slow encode, a backend hiccup) advancing the old deadline would
        // emit a burst of catch-up frames, which is exactly the burst the
        // pacing in the packetiser exists to avoid.
        self.next_deadline = now + self.interval;
        Some(tick)
    }

    /// How long to sleep before polling again.
    pub fn time_until_next(&self, now: Instant) -> Duration {
        self.next_deadline.saturating_duration_since(now)
    }

    /// The 90 kHz RTP timestamp for an instant.
    fn timestamp_at(&self, now: Instant) -> u32 {
        let nanos = now.saturating_duration_since(self.origin).as_nanos();
        ((nanos * 90_000 / 1_000_000_000) & 0xFFFF_FFFF) as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RECT: Rect = Rect {
        x: 0,
        y: 0,
        width: 16,
        height: 16,
    };

    #[test]
    fn the_first_frame_is_due_immediately_and_is_a_keyframe() {
        let now = Instant::now();
        let mut clock = FrameClock::new(60, now);
        let tick = clock.poll(now).expect("the first frame is due at once");
        assert!(tick.force_idr);
        assert_eq!(tick.frame_number, 0);
    }

    #[test]
    fn frames_are_emitted_at_the_requested_rate() {
        let start = Instant::now();
        let mut clock = FrameClock::new(60, start);
        clock.poll(start).unwrap();

        // Nothing is due before the interval elapses.
        assert!(clock.poll(start + Duration::from_millis(8)).is_none());
        let tick = clock
            .poll(start + clock.interval())
            .expect("due after one interval");
        assert_eq!(tick.frame_number, 1);
    }

    /// Keep-alive frames: the watchdog is the reason these exist.
    #[test]
    fn a_still_screen_still_produces_frames() {
        let start = Instant::now();
        let mut clock = FrameClock::new(30, start);
        let mut now = start;
        let mut emitted = 0;
        for _ in 0..10 {
            if let Some(tick) = clock.poll(now) {
                emitted += 1;
                assert!(tick.is_duplicate() || tick.frame_number == 0);
            }
            now += clock.interval();
        }
        assert_eq!(emitted, 10);
    }

    #[test]
    fn damage_accumulates_into_a_bounding_box() {
        let start = Instant::now();
        let mut clock = FrameClock::new(60, start);
        clock.poll(start).unwrap();

        clock.damage(Rect {
            x: 0,
            y: 0,
            width: 4,
            height: 4,
        });
        clock.damage(Rect {
            x: 100,
            y: 100,
            width: 4,
            height: 4,
        });
        let tick = clock.poll(start + clock.interval()).unwrap();
        assert_eq!(
            tick.damage,
            Some(Rect {
                x: 0,
                y: 0,
                width: 104,
                height: 104
            })
        );
        assert!(!tick.is_duplicate());
    }

    #[test]
    fn empty_damage_is_ignored() {
        let start = Instant::now();
        let mut clock = FrameClock::new(60, start);
        clock.poll(start).unwrap();
        clock.damage(Rect::default());
        assert!(clock.poll(start + clock.interval()).unwrap().is_duplicate());
    }

    #[test]
    fn damage_is_cleared_once_a_frame_takes_it() {
        let start = Instant::now();
        let mut clock = FrameClock::new(60, start);
        clock.poll(start).unwrap();
        clock.damage(RECT);
        assert!(clock
            .poll(start + clock.interval())
            .unwrap()
            .damage
            .is_some());
        assert!(clock
            .poll(start + clock.interval() * 2)
            .unwrap()
            .is_duplicate());
    }

    #[test]
    fn an_idr_request_is_honoured_on_the_next_frame_only() {
        let start = Instant::now();
        let mut clock = FrameClock::new(60, start);
        clock.poll(start).unwrap();
        clock.request_idr();
        assert!(clock.idr_pending());
        assert!(clock.poll(start + clock.interval()).unwrap().force_idr);
        assert!(!clock.idr_pending());
        assert!(!clock.poll(start + clock.interval() * 2).unwrap().force_idr);
    }

    /// After a stall, advancing the deadline from `now` avoids a catch-up
    /// burst that the pacing downstream would then have to absorb.
    #[test]
    fn a_stall_does_not_produce_a_burst() {
        let start = Instant::now();
        let mut clock = FrameClock::new(60, start);
        clock.poll(start).unwrap();

        // Half a second of nothing, then poll repeatedly.
        let resumed = start + Duration::from_millis(500);
        assert!(clock.poll(resumed).is_some());
        assert!(
            clock.poll(resumed).is_none(),
            "a second frame was due at the same instant"
        );
        assert!(clock.poll(resumed + clock.interval()).is_some());
    }

    #[test]
    fn timestamps_advance_in_90khz_units() {
        let start = Instant::now();
        let mut clock = FrameClock::new(60, start);
        assert_eq!(clock.poll(start).unwrap().timestamp, 0);
        let t = clock
            .poll(start + Duration::from_secs(1))
            .unwrap()
            .timestamp;
        assert_eq!(t, 90_000);
    }

    #[test]
    fn time_until_next_counts_down() {
        let start = Instant::now();
        let mut clock = FrameClock::new(60, start);
        clock.poll(start).unwrap();
        assert_eq!(clock.time_until_next(start), clock.interval());
        assert_eq!(
            clock.time_until_next(start + clock.interval()),
            Duration::ZERO
        );
        assert_eq!(
            clock.time_until_next(start + Duration::from_secs(1)),
            Duration::ZERO
        );
    }

    #[test]
    fn an_absurd_framerate_is_clamped_rather_than_dividing_by_zero() {
        let now = Instant::now();
        assert!(FrameClock::new(0, now).interval() <= Duration::from_secs(1));
        assert!(FrameClock::new(100_000, now).interval() >= Duration::from_micros(1000) / 1000);
    }
}
