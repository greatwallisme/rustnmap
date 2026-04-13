// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026  greatwallisme
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

use std::sync::atomic::{AtomicU64, Ordering};

pub struct AtomicCounter {
    count: AtomicU64,
}

impl AtomicCounter {
    pub fn new() -> Self {
        Self {
            count: AtomicU64::new(0),
        }
    }

    #[inline]
    pub fn increment(&self) -> u64 {
        self.count.fetch_add(1, Ordering::Relaxed)
    }

    #[inline]
    pub fn get(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn add(&self, value: u64) -> u64 {
        self.count.fetch_add(value, Ordering::Relaxed)
    }

    #[inline]
    pub fn compare_and_swap(&self, current: u64, new: u64) -> u64 {
        self.count.compare_exchange(
            current,
            new,
            Ordering::SeqCst,
            Ordering::Relaxed,
        ).unwrap_or_else(|x| x)
    }
}

// Benchmark function
pub fn benchmark_atomic_counter() {
    use std::thread;
    use std::time::Instant;

    let counter = AtomicCounter::new();
    let start = Instant::now();

    let handles: Vec<_> = (0..8)
        .map(|_| {
            let counter = &counter;
            thread::spawn(move || {
                for _ in 0..1_000_000 {
                    counter.increment();
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().unwrap();
    }

    let duration = start.elapsed();
    println!("Final count: {}, Duration: {:?}", counter.get(), duration);
    println!("Ops/sec: {}", 8_000_000.0 / duration.as_secs_f64());
}