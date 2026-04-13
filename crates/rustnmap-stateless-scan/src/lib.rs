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
