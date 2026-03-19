//! SSH-1 protocol library for NSE scripts.
//!
//! This module provides functions for the SSH-1 protocol, including
//! key fingerprint formatting functions.
//!
//! Reference: nmap/nselib/ssh1.lua

use std::fmt::Write;

use crate::error::Result;
use crate::lua::NseLua;

/// Format fingerprint as hex with colons.
fn format_fingerprint_hex(data: &[u8], algorithm: &str, bits: i64) -> String {
    let hex_parts: Vec<String> = data
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .chunks(2)
        .map(|chunk| chunk.join(""))
        .collect();

    let formatted = hex_parts.join(":");
    format!("{bits} {formatted} ({algorithm})")
}

/// Format fingerprint as base64.
fn format_fingerprint_base64(data: &[u8], hash: &str, algorithm: &str, bits: i64) -> String {
    let b64 = base64_encode(data);
    let b64_trimmed = b64.trim_end_matches('=');
    format!("{bits} {hash}:{b64_trimmed} ({algorithm})")
}

/// Format fingerprint as bubble babble.
fn format_fingerprint_bubblebabble(data: &[u8], algorithm: &str, bits: i64) -> String {
    let vowels = ['a', 'e', 'i', 'o', 'u', 'y'];
    let consonants = ['b', 'c', 'd', 'f', 'g', 'h', 'k', 'l', 'm', 'n', 'p', 'r', 's', 't', 'v', 'z', 'x'];

    let mut s = String::from("x");
    let mut seed: usize = 1;

    let len = data.len();
    for i in (0..len + 2).step_by(2) {
        if i < len || !len.is_multiple_of(2) {
            if i < len {
                let in1 = usize::from(data[i]);
                let idx1 = (((in1 >> 6) & 3) + seed) % 6;
                let idx2 = (in1 >> 2) & 15;
                let idx3 = ((in1 & 3) + seed / 6) % 6;

                s.push(vowels[idx1]);
                s.push(consonants[idx2]);
                s.push(vowels[idx3]);

                if i + 1 < len {
                    let in2 = usize::from(data[i + 1]);
                    let idx4 = (in2 >> 4) & 15;
                    let idx5 = in2 & 15;

                    s.push(consonants[idx4]);
                    s.push('-');
                    s.push(consonants[idx5]);

                    seed = (seed * 5 + in1 * 7 + in2) % 36;
                }
            } else {
                let idx1 = seed % 6;
                let idx2 = 16; // 'x' is at index 16
                let idx3 = (seed / 6) % 6;

                s.push(vowels[idx1]);
                s.push(consonants[idx2]);
                s.push(vowels[idx3]);
            }
        }
    }
    s.push('x');

    format!("{bits} {s} ({algorithm})")
}

/// Format fingerprint as visual ASCII art.
fn format_fingerprint_visual(data: &[u8], algorithm: &str, bits: i64) -> String {
    let characters = [' ', '.', 'o', '+', '=', '*', 'B', 'O', 'X', '@', '%', '&', '#', '/', '^', 'S', 'E'];

    let fieldsize_x = 17;
    let fieldsize_y = 9;

    // Initialize field with 1s (index for ' ')
    let mut field = vec![vec![1usize; fieldsize_y]; fieldsize_x];

    // Start in center and mark it
    let mut x = fieldsize_x / 2;
    let mut y = fieldsize_y / 2;
    field[x][y] = characters.len() - 1;

    // Iterate over fingerprint
    for &byte in data {
        let mut input = byte;
        for _ in 0..4 {
            x = if (input & 1) == 1 {
                (x + 1).min(fieldsize_x - 1)
            } else {
                x.saturating_sub(1).max(0)
            };
            y = if (input & 2) == 2 {
                (y + 1).min(fieldsize_y - 1)
            } else {
                y.saturating_sub(1).max(0)
            };

            if field[x][y] < characters.len() - 2 {
                field[x][y] += 1;
            }
            input >>= 2;
        }
    }

    // Mark end point
    field[x][y] = characters.len() - 1;

    // Build output
    let mut s = String::new();
    let _ = writeln!(&mut s, "+--[{algorithm:>4} {bits:>4}]----+");

    for j in 0..fieldsize_y {
        s.push('|');
        for i in 0..fieldsize_x {
            s.push(characters[field[i][j]]);
        }
        s.push_str("|\n");
    }
    s.push_str("+-----------------+\n");

    s
}

/// Register the ssh1 library with the Lua runtime.
///
/// # Errors
///
/// Returns an error if library registration fails.
#[allow(clippy::too_many_lines, reason = "Library registration has many similar function registrations")]
pub fn register(nse_lua: &mut NseLua) -> Result<()> {
    let lua = nse_lua.lua_mut();

    // Create the ssh1 table
    let ssh1_table = lua.create_table()?;

    // Register check_packet_length(buffer) function
    let check_packet_length_fn = lua.create_function(|lua, buffer: mlua::String| {
        let data = buffer.as_bytes();
        if data.len() < 4 {
            return Ok(mlua::Value::Nil);
        }

        let payload_length = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        let padding = (8 - (payload_length % 8)) % 8;
        let total = 4 + payload_length + padding;

        if total > data.len() {
            return Ok(mlua::Value::Nil);
        }

        let result = lua.create_table()?;
        result.set(1, i64::try_from(total).unwrap_or(0))?;
        result.set(2, i64::try_from(total).unwrap_or(0))?;
        Ok(mlua::Value::Table(result))
    })?;
    ssh1_table.set("check_packet_length", check_packet_length_fn)?;

    // Register fetch_host_key(host, port) - SSH-1 deprecated
    let fetch_host_key_fn = lua.create_function(|_lua, (_host, _port): (mlua::Value, mlua::Value)| {
        Ok(mlua::Value::Nil)
    })?;
    ssh1_table.set("fetch_host_key", fetch_host_key_fn)?;

    // Register fingerprint_hex
    let fingerprint_hex_fn = lua.create_function(|lua, (fingerprint, algorithm, bits): (mlua::String, String, i64)| {
        let data = fingerprint.as_bytes();
        let result = format_fingerprint_hex(&data, &algorithm, bits);
        lua.create_string(&result)
    })?;
    ssh1_table.set("fingerprint_hex", fingerprint_hex_fn)?;

    // Register fingerprint_base64
    let fingerprint_base64_fn = lua.create_function(|lua, (fingerprint, hash, algorithm, bits): (mlua::String, String, String, i64)| {
        let data = fingerprint.as_bytes();
        let result = format_fingerprint_base64(&data, &hash, &algorithm, bits);
        lua.create_string(&result)
    })?;
    ssh1_table.set("fingerprint_base64", fingerprint_base64_fn)?;

    // Register fingerprint_bubblebabble
    let fingerprint_bubblebabble_fn = lua.create_function(|lua, (fingerprint, algorithm, bits): (mlua::String, String, i64)| {
        let data = fingerprint.as_bytes();
        let result = format_fingerprint_bubblebabble(&data, &algorithm, bits);
        lua.create_string(&result)
    })?;
    ssh1_table.set("fingerprint_bubblebabble", fingerprint_bubblebabble_fn)?;

    // Register fingerprint_visual
    let fingerprint_visual_fn = lua.create_function(|lua, (fingerprint, algorithm, bits): (mlua::String, String, i64)| {
        let data = fingerprint.as_bytes();
        let result = format_fingerprint_visual(&data, &algorithm, bits);
        lua.create_string(&result)
    })?;
    ssh1_table.set("fingerprint_visual", fingerprint_visual_fn)?;

    // Register parse_known_hosts_file
    let parse_known_hosts_file_fn = lua.create_function(|lua, path: mlua::Value| {
        let path_str = if let mlua::Value::String(s) = path {
            s.to_str().map(|s| s.to_string()).unwrap_or_default()
        } else {
            let Ok(home) = std::env::var("HOME") else {
                return Ok(mlua::Value::Nil);
            };
            format!("{home}/.ssh/known_hosts")
        };

        let Ok(content) = std::fs::read_to_string(&path_str) else {
            return Ok(mlua::Value::Nil);
        };

        let entries = lua.create_table()?;
        let mut line_number = 0i64;

        for line in content.lines() {
            line_number += 1;
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }

            let entry = lua.create_table()?;
            let parts_table = lua.create_table()?;
            for (i, part) in parts.iter().enumerate() {
                let idx = i64::try_from(i + 1).unwrap_or(1);
                parts_table.set(idx, *part)?;
            }
            entry.set("entry", parts_table)?;
            entry.set("linenumber", line_number)?;
            entries.push(entry)?;
        }

        Ok(mlua::Value::Table(entries))
    })?;
    ssh1_table.set("parse_known_hosts_file", parse_known_hosts_file_fn)?;

    // Set the ssh1 table as a global
    lua.globals().set("ssh1", ssh1_table.clone())?;

    // Also register in package.preload
    let preload: mlua::Table = lua.globals()
        .get::<mlua::Table>("package")?
        .get("preload")?;
    preload.set("ssh1", ssh1_table)?;

    Ok(())
}

/// Base64 encoding helper.
fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = String::new();

    for chunk in input.chunks(3) {
        let b0 = usize::from(chunk[0]);
        let b1 = chunk.get(1).copied().map_or(0, usize::from);
        let b2 = chunk.get(2).copied().map_or(0, usize::from);

        result.push(char::from(ALPHABET[b0 >> 2]));
        result.push(char::from(ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)]));

        if chunk.len() > 1 {
            result.push(char::from(ALPHABET[((b1 & 0x0f) << 2) | (b2 >> 6)]));
        } else {
            result.push('=');
        }

        if chunk.len() > 2 {
            result.push(char::from(ALPHABET[b2 & 0x3f]));
        } else {
            result.push('=');
        }
    }

    result
}
