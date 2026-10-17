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
//!
//! "Never goes quiet" does not have to mean "full rate". An unchanged frame
//! still costs the encoder a full analysis -- 9.5 ms at 1080p, more than half a
//! core at 60 fps, to produce 13 bytes (`docs/implementation-notes.md` §3) --
//! so once the screen has been still for [`IDLE_AFTER`] the clock drops to a
//! keep-alive rate. That is safe for the client: `moonlight-common-c`'s two
//! watchdogs only run until the first packet and the first whole frame
//! (`VideoStream.c:146-176`), and its loss statistic counts gaps in the frame
//! index, which the packetiser keeps contiguous whatever the rate
//! (`ControlStream.c:471-514`). It is safe for latency because damage and IDR
//! requests pull the deadline back to where full rate would have put it, so a
//! change after a long still waits no longer than it would have anyway.

use std::time::{Duration, Instant};

use solstice_backend::Rect;

/// How long the screen must have been still before the clock backs off.
///
/// Not zero, for two reasons. A decoder that holds one frame before display
/// shows a change only when the next frame arrives, and the client notices a
/// lost frame only when a later frame index does; both want the frames right
/// after a change at full rate. And typing or a blinking cursor changes the
/// screen every few hundred milliseconds, which this keeps from oscillating.
pub const IDLE_AFTER: Duration = Duration::from_millis(500);

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

/// A fixed-rate clock that damage can pull forward, and that slows to a
/// keep-alive rate while nothing changes.
#[derive(Debug)]
pub struct FrameClock {
    interval: Duration,
    idle_interval: Duration,
    origin: Instant,
    next_deadline: Instant,
    /// When the last frame went out, which is what damage measures its
    /// full-rate deadline from.
    last_emitted: Option<Instant>,
    /// When the last frame that was not a pure repeat went out.
    last_change: Instant,
    pending_damage: Option<Rect>,
    idr_requested: bool,
    frame_number: u64,
}

impl FrameClock {
    /// Build a clock running at `fps`, with no keep-alive back-off.
    pub fn new(fps: u32, now: Instant) -> Self {
        let interval = interval_for(fps);
        Self {
            interval,
            idle_interval: interval,
            origin: now,
            next_deadline: now,
            last_emitted: None,
            last_change: now,
            pending_damage: None,
            idr_requested: true, // the first frame must be a keyframe
            frame_number: 0,
        }
    }

    /// Drop to `idle_fps` once the screen has been still for [`IDLE_AFTER`].
    /// A rate at or above the full one leaves the clock fixed-rate.
    pub fn with_idle_rate(mut self, idle_fps: u32) -> Self {
        self.idle_interval = interval_for(idle_fps).max(self.interval);
        self
    }

    /// The frame interval.
    pub fn interval(&self) -> Duration {
        self.interval
    }

    /// The keep-alive interval used while the screen is still.
    pub fn idle_interval(&self) -> Duration {
        self.idle_interval
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
        self.wake();
    }

    /// Ask for a keyframe. Honoured on the next emitted frame.
    pub fn request_idr(&mut self) {
        self.idr_requested = true;
        self.wake();
    }

    /// Something needs sending: bring the deadline back to where full rate
    /// would have put it, so a keep-alive wait never delays a change.
    fn wake(&mut self) {
        if let Some(last) = self.last_emitted {
            self.next_deadline = self.next_deadline.min(last + self.interval);
        }
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
        if !tick.is_duplicate() || tick.force_idr {
            self.last_change = now;
        }
        let still = now.saturating_duration_since(self.last_change) >= IDLE_AFTER;
        // Schedule from the old deadline, not from `now`: every wake-up is a
        // little late, and scheduling from when it happened adds that lateness
        // to every interval -- a real 1080p60 session measured 56 fps, about
        // 1.2 ms of oversleep a frame. But after a stall (a slow encode, a
        // backend hiccup) advancing the old deadline would emit a burst of
        // catch-up frames, which is exactly the burst the pacing in the
        // packetiser exists to avoid; so once a whole interval behind, start
        // again from `now`.
        let interval = if still {
            self.idle_interval
        } else {
            self.interval
        };
        let next = self.next_deadline + interval;
        self.next_deadline = if next > now { next } else { now + interval };
        self.last_emitted = Some(now);
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

fn interval_for(fps: u32) -> Duration {
    Duration::from_nanos(1_000_000_000 / fps.clamp(1, 1000) as u64)
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
    fn late_wake_ups_do_not_lower_the_rate() {
        // Every poll lands 1.2 ms after its deadline, as a sleeping thread's
        // do. Sixty frames must still take one second, not 1.07.
        let start = Instant::now();
        let mut clock = FrameClock::new(60, start);
        let late = Duration::from_micros(1200);
        let mut now = start;
        let mut emitted = 0;
        let mut last = start;
        while emitted < 61 {
            if clock.poll(now).is_some() {
                emitted += 1;
                last = now;
            }
            now += clock.time_until_next(now) + late;
        }
        let took = last - start;
        assert!(
            took <= Duration::from_millis(1005),
            "61 frames at 60 fps took {took:?}"
        );
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

    /// Poll at every deadline from `start` until `until`, returning when each
    /// frame went out.
    fn run_still(clock: &mut FrameClock, start: Instant, until: Instant) -> Vec<Instant> {
        let mut now = start;
        let mut emitted = Vec::new();
        while now < until {
            if clock.poll(now).is_some() {
                emitted.push(now);
            }
            now += clock.time_until_next(now).max(Duration::from_micros(1));
        }
        emitted
    }

    #[test]
    fn a_still_screen_drops_to_the_idle_rate_after_the_tail() {
        let start = Instant::now();
        let mut clock = FrameClock::new(60, start).with_idle_rate(5);
        let emitted = run_still(&mut clock, start, start + Duration::from_secs(3));

        let gaps: Vec<Duration> = emitted.windows(2).map(|w| w[1] - w[0]).collect();
        // Full rate until the screen has been still for IDLE_AFTER...
        let full = emitted
            .iter()
            .take_while(|&&t| t - start < IDLE_AFTER)
            .count();
        assert!(
            gaps[..full - 1].iter().all(|&g| g == clock.interval()),
            "{gaps:?}"
        );
        // ...then the keep-alive rate, and never silence.
        let idle = &gaps[full..];
        assert!(!idle.is_empty());
        assert!(
            idle.iter().all(|&g| g == Duration::from_millis(200)),
            "{idle:?}"
        );
        // Three seconds is 180 frames at full rate; backing off leaves the
        // half-second tail plus five a second.
        assert!(emitted.len() < 45, "{} frames in 3 s", emitted.len());
    }

    /// The latency guarantee: a change during a keep-alive wait goes out at
    /// the full-rate deadline, not the keep-alive one.
    #[test]
    fn damage_during_the_idle_wait_is_not_delayed_by_it() {
        let start = Instant::now();
        let mut clock = FrameClock::new(60, start).with_idle_rate(1);
        let emitted = run_still(&mut clock, start, start + Duration::from_secs(2));
        let last = *emitted.last().unwrap();
        assert_eq!(clock.time_until_next(last), Duration::from_secs(1));

        // Damage arrives a moment after a keep-alive went out: it waits only
        // until a full-rate interval has passed since that frame.
        clock.damage(RECT);
        assert_eq!(clock.time_until_next(last), clock.interval());
        assert!(clock.poll(last + clock.interval() / 2).is_none());
        let tick = clock
            .poll(last + clock.interval())
            .expect("the change is due");
        assert_eq!(tick.damage, Some(RECT));
    }

    /// Damage that arrives after a full interval has already passed is due at
    /// once, not one interval later.
    #[test]
    fn damage_late_in_the_idle_wait_is_due_immediately() {
        let start = Instant::now();
        let mut clock = FrameClock::new(60, start).with_idle_rate(1);
        let emitted = run_still(&mut clock, start, start + Duration::from_secs(2));
        let arrived = *emitted.last().unwrap() + Duration::from_millis(500);
        clock.damage(RECT);
        assert_eq!(clock.time_until_next(arrived), Duration::ZERO);
        assert!(clock.poll(arrived).is_some());
    }

    #[test]
    fn an_idr_request_during_the_idle_wait_is_not_delayed_by_it() {
        let start = Instant::now();
        let mut clock = FrameClock::new(60, start).with_idle_rate(1);
        let emitted = run_still(&mut clock, start, start + Duration::from_secs(2));
        let last = *emitted.last().unwrap();
        clock.request_idr();
        let tick = clock
            .poll(last + clock.interval())
            .expect("the keyframe is due");
        assert!(tick.force_idr);
        assert!(tick.is_duplicate(), "an IDR request is not damage");
    }

    /// After a change the clock returns to full rate for the whole tail, so
    /// the frame after the change follows it promptly.
    #[test]
    fn a_change_restores_full_rate_for_the_tail() {
        let start = Instant::now();
        let mut clock = FrameClock::new(60, start).with_idle_rate(1);
        let emitted = run_still(&mut clock, start, start + Duration::from_secs(2));
        let last = *emitted.last().unwrap();

        clock.damage(RECT);
        let changed = last + clock.interval();
        clock.poll(changed).unwrap();
        let after = run_still(
            &mut clock,
            changed + Duration::from_micros(1),
            changed + IDLE_AFTER,
        );
        assert!(!after.is_empty());
        assert!(
            after.windows(2).all(|w| w[1] - w[0] == clock.interval()),
            "{after:?}"
        );
        assert_eq!(after[0] - changed, clock.interval());
    }

    #[test]
    fn an_idle_rate_at_or_above_full_rate_keeps_the_clock_fixed() {
        let start = Instant::now();
        for idle in [60, 120, 1000] {
            let mut clock = FrameClock::new(60, start).with_idle_rate(idle);
            assert_eq!(clock.idle_interval(), clock.interval());
            let emitted = run_still(&mut clock, start, start + Duration::from_secs(2));
            assert!(emitted.windows(2).all(|w| w[1] - w[0] == clock.interval()));
        }
        // And without one at all.
        let mut clock = FrameClock::new(60, start);
        let emitted = run_still(&mut clock, start, start + Duration::from_secs(2));
        assert!(emitted.windows(2).all(|w| w[1] - w[0] == clock.interval()));
    }

    #[test]
    fn an_absurd_framerate_is_clamped_rather_than_dividing_by_zero() {
        let now = Instant::now();
        assert!(FrameClock::new(0, now).interval() <= Duration::from_secs(1));
        assert!(FrameClock::new(100_000, now).interval() >= Duration::from_micros(1000) / 1000);
    }
}
