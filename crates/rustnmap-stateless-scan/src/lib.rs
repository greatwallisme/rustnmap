// rustnmap-stateless-scan
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

//! Stateless scanning module for `RustNmap` 2.0.
//!
//! Provides masscan-like high-speed scanning capabilities using encrypted
//! cookie encoding for stateless response matching.

// Allow pedantic lints with reasons
#![allow(
    clippy::missing_errors_doc,
    reason = "Internal API, errors are self-explanatory"
)]
#![allow(
    clippy::missing_panics_doc,
    reason = "Internal API, panics are not part of public contract"
)]
#![allow(
    clippy::must_use_candidate,
    reason = "Methods are used for side effects in internal flows"
)]
#![allow(
    clippy::module_name_repetitions,
    reason = "Module names are part of public API clarity"
)]
#![allow(
    clippy::uninlined_format_args,
    reason = "Consistent format across codebase"
)]
#![allow(
    clippy::manual_range_contains,
    reason = "Explicit comparison is clearer"
)]
#![allow(
    clippy::similar_names,
    reason = "Variable names follow domain conventions"
)]
#![allow(
    clippy::too_many_lines,
    reason = "Complex packet handling requires longer functions"
)]
#![allow(
    clippy::cast_possible_wrap,
    reason = "Statistics values are within i64 range"
)]
#![allow(
    clippy::cast_possible_truncation,
    reason = "Values are validated before casting"
)]
#![warn(clippy::allow_attributes_without_reason)]

mod cookie;
mod receiver;
mod sender;
mod stateless;

pub use cookie::{Cookie, CookieGenerator, VerifyResult};
pub use receiver::StatelessReceiver;
pub use sender::StatelessSender;
pub use stateless::{ScanEvent, StatelessConfig, StatelessScanner};
