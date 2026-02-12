// rustnmap-cli
// Copyright (C) 2026  greatwallisme
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Command-line interface for RustNmap network scanner.
//!
//! This crate provides the main `rustnmap` binary that integrates
//! all scanning modules into a unified Nmap-compatible CLI.

pub mod args;
pub mod cli;
pub mod orchestrator;

// Re-export main types
pub use args::Args;
