// Copyright (C) 2024, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use std::time::Duration;
use std::time::Instant;

use crate::recovery::gcongestion::Bandwidth;
use crate::recovery::rtt::RttStats;
use crate::recovery::RecoveryStats;

use super::Acked;
use super::CongestionControl;
use super::Lost;

const PKT_INFO_SLOT_COUNT: usize = 5;
const MIN_SAMPLE_COUNT: u64 = 50;
const MIN_ACK_RATE: f64 = 0.8;
const CWND_MULTIPLIER: f64 = 2.0;
#[cfg(test)]
const INITIAL_CONGESTION_WINDOW_PACKETS: usize = 10;

#[derive(Debug, Clone, Default)]
struct PktInfo {
    timestamp_sec: i64,
    ack_count: u64,
    loss_count: u64,
}

#[derive(Debug)]
pub(super) struct BrutalSender {
    /// Target send rate in bytes per second.
    bytes_per_sec: u64,

    /// Current maximum datagram size.
    max_datagram_size: usize,

    /// Smoothed fraction of packets that are not lost (ack / (ack + loss)).
    ack_rate: f64,

    /// Sliding window slots for ack rate estimation (one per second).
    pkt_info_slots: [PktInfo; PKT_INFO_SLOT_COUNT],

    /// Cached smoothed RTT for cwnd calculation.
    smoothed_rtt: Duration,

    /// Reference epoch for second-level bucketing.
    epoch: Instant,
}

impl BrutalSender {
    pub(super) fn new(
        bytes_per_sec: u64, _init_cwnd_packets: usize,
        _max_window_packets: usize, mss: usize, initial_rtt: Duration,
    ) -> Self {
        BrutalSender {
            bytes_per_sec,
            max_datagram_size: mss,
            ack_rate: 1.0,
            pkt_info_slots: Default::default(),
            smoothed_rtt: initial_rtt,
            epoch: Instant::now(),
        }
    }
}

impl CongestionControl for BrutalSender {
    #[cfg(feature = "qlog")]
    fn state_str(&self) -> &'static str {
        "brutal"
    }

    fn get_congestion_window(&self) -> usize {
        let rtt_secs = self.smoothed_rtt.as_secs_f64();
        if rtt_secs <= 0.0 {
            return self.max_datagram_size;
        }

        let cwnd = (self.bytes_per_sec as f64 * rtt_secs * CWND_MULTIPLIER /
            self.ack_rate) as usize;

        cwnd.max(self.max_datagram_size)
    }

    fn get_congestion_window_in_packets(&self) -> usize {
        self.get_congestion_window() / self.max_datagram_size
    }

    fn can_send(&self, bytes_in_flight: usize) -> bool {
        bytes_in_flight <= self.get_congestion_window()
    }

    fn on_packet_sent(
        &mut self, _sent_time: Instant, _bytes_in_flight: usize,
        _packet_number: u64, _bytes: usize, _is_retransmissible: bool,
    ) {
        // Brutal does not track per-packet state.
    }

    fn on_congestion_event(
        &mut self, rtt_updated: bool, _prior_in_flight: usize,
        _bytes_in_flight: usize, event_time: Instant, acked_packets: &[Acked],
        lost_packets: &[Lost], _least_unacked: u64, rtt_stats: &RttStats,
        _recovery_stats: &mut RecoveryStats,
    ) {
        if rtt_updated {
            self.smoothed_rtt = rtt_stats.smoothed_rtt;
        }

        if acked_packets.is_empty() && lost_packets.is_empty() {
            return;
        }

        // Update per-second packet stats for ack rate estimation.
        let current_sec = event_time.duration_since(self.epoch).as_secs() as i64;

        let slot = current_sec.unsigned_abs() as usize % PKT_INFO_SLOT_COUNT;

        if self.pkt_info_slots[slot].timestamp_sec == current_sec {
            self.pkt_info_slots[slot].ack_count += acked_packets.len() as u64;
            self.pkt_info_slots[slot].loss_count += lost_packets.len() as u64;
        } else {
            self.pkt_info_slots[slot] = PktInfo {
                timestamp_sec: current_sec,
                ack_count: acked_packets.len() as u64,
                loss_count: lost_packets.len() as u64,
            };
        }

        self.update_ack_rate(current_sec);
    }

    fn on_retransmission_timeout(&mut self, _packets_retransmitted: bool) {
        // Brutal does not react to RTO.
    }

    fn on_connection_migration(&mut self) {
        // Reset ack rate estimation on migration.
        self.ack_rate = 1.0;
        self.pkt_info_slots = Default::default();
    }

    fn is_in_recovery(&self) -> bool {
        false
    }

    fn is_cwnd_limited(&self, bytes_in_flight: usize) -> bool {
        bytes_in_flight >= self.get_congestion_window()
    }

    fn pacing_rate(
        &self, _bytes_in_flight: usize, _rtt_stats: &RttStats,
    ) -> Bandwidth {
        let rate = self.bytes_per_sec as f64 / self.ack_rate;
        Bandwidth::from_bytes_per_second(rate as u64)
    }

    fn bandwidth_estimate(&self, _rtt_stats: &RttStats) -> Bandwidth {
        let rate = self.bytes_per_sec as f64 / self.ack_rate;
        Bandwidth::from_bytes_per_second(rate as u64)
    }

    fn max_bandwidth(&self) -> Bandwidth {
        // Worst-case bandwidth at minimum ack rate.
        Bandwidth::from_bytes_per_second(
            (self.bytes_per_sec as f64 / MIN_ACK_RATE) as u64,
        )
    }

    fn update_mss(&mut self, new_mss: usize) {
        self.max_datagram_size = new_mss;
    }
}

impl BrutalSender {
    /// Calculate the moving average ack rate over the last
    /// `PKT_INFO_SLOT_COUNT` seconds.
    fn update_ack_rate(&mut self, current_timestamp: i64) {
        let min_timestamp = current_timestamp - PKT_INFO_SLOT_COUNT as i64;

        let mut ack_count: u64 = 0;
        let mut loss_count: u64 = 0;

        for info in &self.pkt_info_slots {
            if info.timestamp_sec < min_timestamp {
                continue;
            }
            ack_count += info.ack_count;
            loss_count += info.loss_count;
        }

        let total = ack_count + loss_count;
        if total < MIN_SAMPLE_COUNT {
            self.ack_rate = 1.0;
            return;
        }

        let rate = ack_count as f64 / total as f64;
        self.ack_rate = rate.max(MIN_ACK_RATE);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn brutal_initial_cwnd() {
        let brutal = BrutalSender::new(
            1_000_000, // 1 MB/s
            INITIAL_CONGESTION_WINDOW_PACKETS,
            20_000,
            1200,
            Duration::from_millis(100),
        );
        // cwnd = 1_000_000 * 0.1 * 2.0 / 1.0 = 200_000 bytes
        assert_eq!(brutal.get_congestion_window(), 200_000);
    }

    #[test]
    fn brutal_can_send() {
        let brutal = BrutalSender::new(
            1_000_000,
            INITIAL_CONGESTION_WINDOW_PACKETS,
            20_000,
            1200,
            Duration::from_millis(100),
        );
        assert!(brutal.can_send(100_000));
        assert!(!brutal.can_send(300_000));
    }

    #[test]
    fn brutal_pacing_rate() {
        let brutal = BrutalSender::new(
            1_000_000,
            INITIAL_CONGESTION_WINDOW_PACKETS,
            20_000,
            1200,
            Duration::from_millis(100),
        );
        let rate = brutal.pacing_rate(0, &RttStats::new(
            Duration::from_millis(100),
            Duration::from_millis(25),
        ));
        // 1M bytes/s * 8 = 8M bps
        assert_eq!(rate.to_bytes_per_second(), 1_000_000);
    }

    #[test]
    fn brutal_ack_rate_update() {
        let mut brutal = BrutalSender::new(
            1_000_000,
            INITIAL_CONGESTION_WINDOW_PACKETS,
            20_000,
            1200,
            Duration::from_millis(100),
        );

        // Simulate a congestion event with many acked and some lost packets.
        let now = Instant::now();
        let mut rtt_stats = RttStats::new(
            Duration::from_millis(100),
            Duration::from_millis(25),
        );
        rtt_stats.update_rtt(
            Duration::from_millis(100),
            Duration::ZERO,
            now,
            true,
        );

        let acked = (0..60)
            .map(|i| Acked {
                pkt_num: i,
                time_sent: now,
            })
            .collect::<Vec<_>>();
        let lost = (0..10)
            .map(|i| Lost {
                packet_number: i + 60,
                bytes_lost: 1200,
            })
            .collect::<Vec<_>>();

        brutal.on_congestion_event(
            true,
            0,
            0,
            now,
            &acked,
            &lost,
            0,
            &rtt_stats,
            &mut RecoveryStats::default(),
        );

        // With 60 acked and 10 lost, ack rate should be ~0.857
        assert!(brutal.ack_rate > MIN_ACK_RATE);
        assert!(brutal.ack_rate < 1.0);
    }

    #[test]
    fn brutal_not_in_recovery() {
        let brutal = BrutalSender::new(
            1_000_000,
            INITIAL_CONGESTION_WINDOW_PACKETS,
            20_000,
            1200,
            Duration::from_millis(100),
        );
        assert!(!brutal.is_in_recovery());
    }

    #[test]
    fn brutal_cwnd_zero_rtt_fallback() {
        let brutal = BrutalSender::new(
            1_000_000,
            INITIAL_CONGESTION_WINDOW_PACKETS,
            20_000,
            1200,
            Duration::ZERO,
        );
        // When RTT is 0, cwnd should be at least max_datagram_size
        assert_eq!(brutal.get_congestion_window(), 1200);
    }
}
