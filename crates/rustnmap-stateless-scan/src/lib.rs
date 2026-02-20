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

mod cookie;
mod receiver;
mod sender;
mod stateless;

pub use cookie::{Cookie, CookieGenerator, VerifyResult};
pub use receiver::StatelessReceiver;
pub use sender::StatelessSender;
pub use stateless::{ScanEvent, StatelessConfig, StatelessScanner};
