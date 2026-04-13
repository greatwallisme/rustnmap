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

use std::sync::{Arc, Mutex};
use std::thread;
use std::collections::VecDeque;

pub struct WorkStealingPool<T> {
    workers: Vec<StealingWorker<T>>,
    global_queue: Arc<Mutex<VecDeque<T>>>,
}

struct StealingWorker<T> {
    local_queue: Arc<Mutex<VecDeque<T>>>,
    thread: Option<thread::JoinHandle<()>>,
}

impl<T: Send + 'static> WorkStealingPool<T> {
    pub fn new(worker_count: usize) -> Self {
        let global_queue = Arc::new(Mutex::new(VecDeque::new()));
        let mut workers = Vec::with_capacity(worker_count);

        for _ in 0..worker_count {
            workers.push(StealingWorker {
                local_queue: Arc::new(Mutex::new(VecDeque::new())),
                thread: None,
            });
        }

        WorkStealingPool { workers, global_queue }
    }

    pub fn start(&mut self) {
        for worker in &mut self.workers {
            let global_queue = Arc::clone(&self.global_queue);
            let local_queue = Arc::clone(&worker.local_queue);

            worker.thread = Some(thread::spawn(move || {
                loop {
                    if let Some(task) = Self::try_get_task(&local_queue, &global_queue) {
                        task;
                    } else {
                        thread::yield_now();
                    }
                }
            }));
        }
    }

    fn try_get_task(local: &Arc<Mutex<VecDeque<T>>>, global: &Arc<Mutex<VecDeque<T>>>) -> Option<T> {
        // Try local queue first
        if let Some(task) = local.lock().unwrap().pop_front() {
            return Some(task);
        }

        // Try global queue
        if let Some(task) = global.lock().unwrap().pop_front() {
            return Some(task);
        }

        None
    }

    pub fn submit(&self, task: T) {
        self.global_queue.lock().unwrap().push_back(task);
    }
}