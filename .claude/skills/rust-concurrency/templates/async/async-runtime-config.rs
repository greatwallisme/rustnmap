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

use tokio::runtime::{Builder, Runtime};

pub struct RuntimeConfig {
    worker_threads: usize,
    io_threads: usize,
    blocking_threads: usize,
    thread_stack_size: usize,
    enable_threaded_scheduler: bool,
    enable_blocking_threads: bool,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            worker_threads: num_cpus::get(),
            io_threads: num_cpus::get(),
            blocking_threads: 512,
            thread_stack_size: 2 * 1024 * 1024, // 2MB
            enable_threaded_scheduler: true,
            enable_blocking_threads: true,
        }
    }
}

impl RuntimeConfig {
    pub fn optimized_for_server() -> Self {
        Self {
            worker_threads: num_cpus::get(),
            io_threads: num_cpus::get(),
            blocking_threads: 1024,
            thread_stack_size: 1 * 1024 * 1024, // 1MB for more connections
            enable_threaded_scheduler: true,
            enable_blocking_threads: true,
        }
    }

    pub fn optimized_for_cpu_work() -> Self {
        Self {
            worker_threads: num_cpus::get(),
            io_threads: 1,
            blocking_threads: 100,
            thread_stack_size: 4 * 1024 * 1024, // 4MB for CPU stacks
            enable_threaded_scheduler: true,
            enable_blocking_threads: false,
        }
    }

    pub fn build(self) -> Runtime {
        let mut builder = Builder::new_multi_thread()
            .worker_threads(self.worker_threads)
            .thread_stack_size(self.thread_stack_size)
            .enable_all();

        if !self.enable_blocking_threads {
            builder.max_blocking_threads(self.blocking_threads);
        }

        builder.build().unwrap()
    }

    pub fn custom<F>(self, configure: F) -> Runtime
    where
        F: FnOnce(Builder) -> Builder,
    {
        let mut builder = Builder::new_multi_thread()
            .worker_threads(self.worker_threads)
            .thread_stack_size(self.thread_stack_size)
            .enable_all();

        if !self.enable_blocking_threads {
            builder.max_blocking_threads(self.blocking_threads);
        }

        builder = configure(builder);
        builder.build().unwrap()
    }
}

// Usage examples:
// let runtime = RuntimeConfig::optimized_for_server().build();
// let runtime = RuntimeConfig::default().custom(|b| b.thread_name("my-app")).build();