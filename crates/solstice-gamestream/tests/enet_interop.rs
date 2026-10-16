//! The ENet host against an independent ENet, over a network that loses,
//! duplicates, delays and reorders.
//!
//! The client is `rusty_enet`: a mechanical transpilation of upstream ENet's C,
//! so its reliability logic is ENet's own rather than a second reading of it.
//! It was the host's ENet until `stream::enet` replaced it (`docs/roadmap.md`
//! §7) and survives only here, as a dev-dependency.
//!
//! The network and both clocks are simulated, so a run is deterministic for a
//! given seed and covers minutes of protocol time in milliseconds. The real
//! Moonlight client is `crates/solstice/tests/real_moonlight.rs`; this is what
//! that cannot do, which is lose packets on purpose.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::{Duration, Instant};

use rusty_enet as enet;
use solstice_gamestream::stream::enet::{DisconnectReason, Event, Host, HostConfig};

const CONNECT_DATA: u32 = 0x5013_7105;
/// Moonlight's `CTRL_CHANNEL_COUNT`.
const CHANNELS: usize = 0x30;

type Client = enet::Host<enet::ReadWrite<SocketAddr, Infallible>>;

/// A xorshift, so a failing seed reproduces.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn chance(&mut self, per_mille: u64) -> bool {
        self.next() % 1000 < per_mille
    }
}

#[derive(Clone, Copy, Debug)]
struct Weather {
    loss: u64,
    duplicate: u64,
    /// Extra delay, up to this many milliseconds, drawn per datagram: so
    /// datagrams overtake one another.
    jitter_ms: u64,
}

const CLEAR: Weather = Weather {
    loss: 0,
    duplicate: 0,
    jitter_ms: 0,
};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum To {
    Host,
    Client,
}

struct Sim {
    rng: Rng,
    weather: Weather,
    clock: Rc<Cell<Duration>>,
    base: Instant,
    client_addr: SocketAddr,
    host_addr: SocketAddr,
    client: Client,
    host: Host,
    /// In flight: (arrival in ms, tiebreak) -> (direction, bytes).
    wire: BTreeMap<(u64, u64), (To, Vec<u8>)>,
    tiebreak: u64,
    host_events: Vec<Event>,
    client_received: Vec<(u8, Vec<u8>)>,
    client_connected: bool,
    client_disconnected: bool,
}

impl Sim {
    fn new(seed: u64, weather: Weather) -> Self {
        let clock = Rc::new(Cell::new(Duration::from_secs(1000)));
        let c = clock.clone();
        let client = enet::Host::new(
            enet::ReadWrite::new(),
            enet::HostSettings {
                peer_limit: 1,
                channel_limit: CHANNELS,
                time: Box::new(move || c.get()),
                seed: Some(seed as u32),
                ..Default::default()
            },
        )
        .unwrap();
        let base = Instant::now();
        Self {
            rng: Rng(seed | 1),
            weather,
            clock,
            base,
            client_addr: "10.0.0.2:40000".parse().unwrap(),
            host_addr: "10.0.0.1:47999".parse().unwrap(),
            client,
            host: Host::new(HostConfig::new(CONNECT_DATA), base),
            wire: BTreeMap::new(),
            tiebreak: 0,
            host_events: Vec::new(),
            client_received: Vec::new(),
            client_connected: false,
            client_disconnected: false,
        }
    }

    fn now_ms(&self) -> u64 {
        (self.clock.get() - Duration::from_secs(1000)).as_millis() as u64
    }

    fn now(&self) -> Instant {
        self.base + Duration::from_millis(self.now_ms())
    }

    fn post(&mut self, to: To, bytes: Vec<u8>) {
        let copies = if self.rng.chance(self.weather.duplicate) {
            2
        } else {
            1
        };
        for _ in 0..copies {
            if self.rng.chance(self.weather.loss) {
                continue;
            }
            let delay = 1 + self.rng.next() % (self.weather.jitter_ms + 1);
            self.tiebreak += 1;
            self.wire
                .insert((self.now_ms() + delay, self.tiebreak), (to, bytes.clone()));
        }
    }

    /// One millisecond of simulated time.
    fn step(&mut self) {
        // Deliver what has arrived.
        let now_ms = self.now_ms();
        while let Some(entry) = self.wire.first_entry() {
            if entry.key().0 > now_ms {
                break;
            }
            let (to, bytes) = entry.remove();
            match to {
                To::Host => {
                    let now = self.now();
                    self.host.handle_datagram(now, self.client_addr, &bytes);
                }
                To::Client => self.client.socket_mut().write(self.host_addr, bytes),
            }
        }

        // The client.
        while let Some(event) = self.client.service().unwrap() {
            match event {
                enet::Event::Connect { .. } => self.client_connected = true,
                enet::Event::Disconnect { .. } => self.client_disconnected = true,
                enet::Event::Receive {
                    channel_id, packet, ..
                } => self
                    .client_received
                    .push((channel_id, packet.data().to_vec())),
            }
        }
        while let Some((to, bytes)) = self.client.socket_mut().read() {
            assert_eq!(to, self.host_addr);
            self.post(To::Host, bytes);
        }

        // The host.
        let now = self.now();
        if self.host.poll_timeout().is_some_and(|t| t <= now) {
            self.host.handle_timeout(now);
        }
        while let Some(t) = self.host.poll_transmit() {
            assert_eq!(t.destination, self.client_addr);
            self.post(To::Client, t.payload);
        }
        while let Some(e) = self.host.poll_event() {
            self.host_events.push(e);
        }

        self.clock.set(self.clock.get() + Duration::from_millis(1));
    }

    fn run_until(&mut self, limit: Duration, mut done: impl FnMut(&Self) -> bool) {
        let end = self.now_ms() + limit.as_millis() as u64;
        while !done(self) {
            assert!(
                self.now_ms() < end,
                "gave up after {limit:?}: {:?}",
                self.host
            );
            self.step();
        }
    }

    fn peer(&mut self) -> &mut enet::Peer<enet::ReadWrite<SocketAddr, Infallible>> {
        self.client.peer_mut(enet::PeerID(0))
    }

    fn connect(&mut self) {
        let addr = self.host_addr;
        self.client.connect(addr, CHANNELS, CONNECT_DATA).unwrap();
        self.run_until(Duration::from_secs(10), |s| {
            s.client_connected && s.host.is_connected()
        });
        assert!(matches!(
            self.host_events.remove(0),
            Event::Connected { .. }
        ));
    }

    fn host_received(&self) -> Vec<(u8, Vec<u8>)> {
        self.host_events
            .iter()
            .filter_map(|e| match e {
                Event::Receive { channel, data } => Some((*channel, data.clone())),
                _ => None,
            })
            .collect()
    }
}

/// A message body that says where it belongs, and is the size of a real
/// input batch or a little more.
fn message(kind: &str, channel: u8, n: u32) -> Vec<u8> {
    let mut m = format!("{kind}/{channel}/{n:05}/").into_bytes();
    m.resize(24 + (n as usize % 60), b'.');
    m
}

/// The client talks, the host listens, and the host talks back, over the
/// given weather. Every reliable message must arrive exactly once and in
/// order per channel; unsequenced and unreliable ones at most once.
fn conversation(seed: u64, weather: Weather) {
    let mut sim = Sim::new(seed, weather);
    sim.connect();

    // The client folds anything past the granted channels onto 0, as
    // Moonlight's `sendMessageEnet` does; what it was granted is ENet's.
    let granted = sim.peer().channel_count() as u8;
    assert_eq!(granted, 2);

    const N: u32 = 300;
    let mut sent_reliable: BTreeMap<u8, Vec<Vec<u8>>> = BTreeMap::new();
    for n in 0..N {
        let channel = (n % 3 == 0) as u8;
        let m = message("rel", channel, n);
        sent_reliable.entry(channel).or_default().push(m.clone());
        sim.peer()
            .send(channel, &enet::Packet::reliable(m))
            .unwrap();
        if n % 5 == 0 {
            let u = message("unseq", 0, n);
            sim.peer()
                .send(0, &enet::Packet::unreliable_unsequenced(u))
                .unwrap();
        }
        if n % 7 == 0 {
            let u = message("unrel", 0, n);
            sim.peer().send(0, &enet::Packet::unreliable(u)).unwrap();
        }
        if n % 10 == 0 {
            let h = message("host", 0, n);
            sim.host.send(sim.now(), 0, &h).unwrap();
        }
        // About as fast as a mouse.
        for _ in 0..4 {
            sim.step();
        }
    }

    let want = sent_reliable.values().map(Vec::len).sum::<usize>();
    sim.run_until(Duration::from_secs(60), |s| {
        s.host_received()
            .iter()
            .filter(|(_, d)| d.starts_with(b"rel/"))
            .count()
            >= want
            && s.client_received.len() >= (N as usize).div_ceil(10)
    });
    // A little longer, for any duplicate that was going to slip through.
    for _ in 0..2000 {
        sim.step();
    }

    let got = sim.host_received();
    for (channel, sent) in &sent_reliable {
        let arrived: Vec<_> = got
            .iter()
            .filter(|(c, d)| c == channel && d.starts_with(b"rel/"))
            .map(|(_, d)| d.clone())
            .collect();
        assert_eq!(
            &arrived, sent,
            "channel {channel}, seed {seed}, {weather:?}"
        );
    }
    for kind in ["unseq/", "unrel/"] {
        let mut seen: Vec<_> = got
            .iter()
            .filter(|(_, d)| d.starts_with(kind.as_bytes()))
            .map(|(_, d)| d.clone())
            .collect();
        let total = seen.len();
        seen.sort();
        seen.dedup();
        assert_eq!(seen.len(), total, "a duplicated {kind} got through");
        if weather.loss == 0 && weather.jitter_ms == 0 && weather.duplicate == 0 {
            assert!(total > 0, "no {kind} arrived on a clear network");
        }
    }
    let unrel: Vec<u32> = got
        .iter()
        .filter(|(_, d)| d.starts_with(b"unrel/"))
        .map(|(_, d)| std::str::from_utf8(&d[8..13]).unwrap().parse().unwrap())
        .collect();
    // Unreliable is sequenced: whatever arrives, arrives in send order.
    assert!(unrel.windows(2).all(|w| w[0] < w[1]), "{unrel:?}");

    let host_sent: Vec<_> = (0..N)
        .step_by(10)
        .map(|n| (0u8, message("host", 0, n)))
        .collect();
    assert_eq!(sim.client_received, host_sent, "seed {seed}, {weather:?}");

    // And the end: the client says goodbye, and the host hears it.
    sim.peer().disconnect(42);
    sim.run_until(Duration::from_secs(10), |s| {
        s.host_events
            .iter()
            .any(|e| matches!(e, Event::Disconnected { .. }))
    });
    assert!(
        sim.host_events.contains(&Event::Disconnected {
            reason: DisconnectReason::Remote(42)
        }),
        "{:?}",
        sim.host_events.last()
    );
    assert!(!sim.host.is_connected());
}

#[test]
fn a_clear_network() {
    conversation(1, CLEAR);
}

#[test]
fn a_jittery_network_reorders_everything() {
    for seed in 1..=4 {
        conversation(
            seed,
            Weather {
                loss: 0,
                duplicate: 0,
                jitter_ms: 40,
            },
        );
    }
}

#[test]
fn a_network_that_duplicates() {
    for seed in 1..=4 {
        conversation(
            seed,
            Weather {
                loss: 0,
                duplicate: 200,
                jitter_ms: 5,
            },
        );
    }
}

#[test]
fn ten_percent_loss() {
    for seed in 1..=4 {
        conversation(
            seed,
            Weather {
                loss: 100,
                duplicate: 20,
                jitter_ms: 20,
            },
        );
    }
}

#[test]
fn thirty_percent_loss() {
    for seed in 1..=3 {
        conversation(
            seed,
            Weather {
                loss: 300,
                duplicate: 20,
                jitter_ms: 20,
            },
        );
    }
}

#[test]
fn a_client_that_vanishes_is_timed_out() {
    let mut sim = Sim::new(7, CLEAR);
    sim.connect();
    let gone_at = sim.now();
    // The client's process dies: nothing more from it, ever.
    sim.weather.loss = 1000;
    sim.run_until(Duration::from_secs(15), |s| !s.host.is_connected());
    let waited = sim.now() - gone_at;
    assert!(
        (Duration::from_secs(9)..=Duration::from_secs(11)).contains(&waited),
        "{waited:?}"
    );
    assert_eq!(
        sim.host_events.last(),
        Some(&Event::Disconnected {
            reason: DisconnectReason::TimedOut
        })
    );
}

#[test]
fn an_idle_connection_stays_up() {
    // ENet's own pings are what keep it alive: nothing else is sent for a
    // minute, which is six peer timeouts.
    let mut sim = Sim::new(9, CLEAR);
    sim.connect();
    for _ in 0..60_000 {
        sim.step();
    }
    assert!(sim.host.is_connected());
    assert!(!sim.client_disconnected);
    assert!(sim.host_events.is_empty(), "{:?}", sim.host_events);
}

#[test]
fn the_host_ending_the_session_reaches_the_client() {
    let mut sim = Sim::new(11, CLEAR);
    sim.connect();
    sim.host.disconnect(0);
    sim.run_until(Duration::from_secs(1), |s| s.client_disconnected);
}

#[test]
fn a_client_with_the_wrong_connect_data_never_connects() {
    let mut sim = Sim::new(13, CLEAR);
    let addr = sim.host_addr;
    sim.client
        .connect(addr, CHANNELS, CONNECT_DATA ^ 1)
        .unwrap();
    for _ in 0..12_000 {
        sim.step();
    }
    assert!(!sim.client_connected);
    assert!(sim.host_events.is_empty());
    // It retried, and every attempt was refused without a word.
    assert!(
        sim.host.stats().wrong_connect_data >= 3,
        "{:?}",
        sim.host.stats()
    );
}
