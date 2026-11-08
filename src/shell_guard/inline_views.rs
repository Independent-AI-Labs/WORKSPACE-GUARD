//! Normalized and bounded decoded views for the inline engine.
//!
//! Every view carries a byte-offset map back to the original file so findings
//! report the original line and column.

use regex::bytes::Regex;

#[derive(Clone)]
pub struct View {
    pub name: &'static str,
    pub data: Vec<u8>,
    pub offsets: Vec<usize>,
}

const ZERO_WIDTH: &[char] = &['\u{200b}', '\u{200c}', '\u{200d}', '\u{2060}', '\u{feff}'];

fn append_char(out: &mut String, map: &mut Vec<usize>, ch: char, original: usize) {
    let start = out.len();
    out.push(ch);
    for _ in start..out.len() {
        map.push(original);
    }
}

fn stage_joined(input: &str, offsets: &[usize]) -> (String, Vec<usize>) {
    let mut out = String::with_capacity(input.len());
    let mut map = Vec::with_capacity(input.len());
    let mut chars = input.char_indices().peekable();
    while let Some((index, ch)) = chars.next() {
        if ch == '\\' {
            if let Some(&(_, next)) = chars.peek() {
                if next == '\n' {
                    let _ = chars.next();
                    append_char(&mut out, &mut map, ' ', offsets[index]);
                    continue;
                }
            }
        }
        append_char(&mut out, &mut map, ch, offsets[index]);
    }
    (out, map)
}

fn hex_value(byte: u8) -> Option<u32> {
    match byte {
        b'0'..=b'9' => Some((byte - b'0') as u32),
        b'a'..=b'f' => Some((byte - b'a' + 10) as u32),
        b'A'..=b'F' => Some((byte - b'A' + 10) as u32),
        _ => None,
    }
}

fn parse_hex(bytes: &[u8], start: usize, len: usize) -> Option<char> {
    if start + len > bytes.len() {
        return None;
    }
    let mut value = 0u32;
    for byte in &bytes[start..start + len] {
        value = value * 16 + hex_value(*byte)?;
    }
    char::from_u32(value)
}

fn parse_octal(bytes: &[u8], start: usize) -> Option<(char, usize)> {
    let mut value = 0u32;
    let mut count = 0;
    for (offset, byte) in bytes[start..].iter().enumerate().take(3) {
        if !(b'0'..=b'7').contains(byte) {
            break;
        }
        value = value * 8 + (byte - b'0') as u32;
        count = offset + 1;
    }
    (count > 0)
        .then(|| char::from_u32(value))
        .flatten()
        .map(|ch| (ch, count))
}

fn stage_unescaped(input: &str, offsets: &[usize]) -> (String, Vec<usize>) {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut map = Vec::with_capacity(input.len());
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'\\' && index + 1 < bytes.len() {
            let marker = bytes[index + 1];
            let decoded = match marker {
                b'x' => parse_hex(bytes, index + 2, 2).map(|ch| (ch, 4)),
                b'u' => parse_hex(bytes, index + 2, 4).map(|ch| (ch, 6)),
                b'0'..=b'7' => parse_octal(bytes, index + 1),
                _ => None,
            };
            if let Some((ch, consumed)) = decoded {
                append_char(&mut out, &mut map, ch, offsets[index]);
                index += consumed;
                continue;
            }
        }
        if byte == b'%' {
            if let Some(ch) = parse_hex(bytes, index + 1, 2) {
                append_char(&mut out, &mut map, ch, offsets[index]);
                index += 3;
                continue;
            }
        }
        if byte < 0x80 {
            append_char(&mut out, &mut map, byte as char, offsets[index]);
            index += 1;
            continue;
        }
        let ch = input[index..].chars().next().expect("UTF-8 boundary");
        append_char(&mut out, &mut map, ch, offsets[index]);
        index += ch.len_utf8();
    }
    (out, map)
}

fn stage_zwstrip(input: &str, offsets: &[usize]) -> (String, Vec<usize>) {
    let mut out = String::with_capacity(input.len());
    let mut map = Vec::with_capacity(input.len());
    for (index, ch) in input.char_indices() {
        if ZERO_WIDTH.contains(&ch) {
            continue;
        }
        append_char(&mut out, &mut map, ch, offsets[index]);
    }
    (out, map)
}

fn stage_wssep(input: &str, offsets: &[usize]) -> (String, Vec<usize>) {
    let mut out = String::with_capacity(input.len());
    let mut map = Vec::with_capacity(input.len());
    for (index, ch) in input.char_indices() {
        let ch = if ch.is_whitespace() && !ch.is_ascii() {
            ' '
        } else {
            ch
        };
        append_char(&mut out, &mut map, ch, offsets[index]);
    }
    (out, map)
}

fn stage_fold(input: &str, offsets: &[usize]) -> (String, Vec<usize>) {
    let mut out = String::with_capacity(input.len());
    let mut map = Vec::with_capacity(input.len());
    for (index, ch) in input.char_indices() {
        for folded in ch.to_lowercase() {
            append_char(&mut out, &mut map, folded, offsets[index]);
        }
    }
    (out, map)
}

type Stage = fn(&str, &[usize]) -> (String, Vec<usize>);

fn normalized(text: &str, offsets: &[usize]) -> View {
    let mut current = text.to_string();
    let mut map = offsets.to_vec();
    let stages: [Stage; 5] = [
        stage_joined,
        stage_unescaped,
        stage_zwstrip,
        stage_wssep,
        stage_fold,
    ];
    for stage in stages {
        let (next, next_map) = stage(&current, &map);
        current = next;
        map = next_map;
    }
    View {
        name: "normalized",
        data: current.into_bytes(),
        offsets: map,
    }
}

fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn decode_base64(token: &str) -> Option<Vec<u8>> {
    let bytes = token.as_bytes();
    let mut out = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for byte in bytes {
        if *byte == b'=' {
            continue;
        }
        buffer = (buffer << 6) | base64_value(*byte)? as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    Some(out)
}

fn printable(raw: &[u8]) -> Option<String> {
    if raw.len() < 8 {
        return None;
    }
    let text = std::str::from_utf8(raw).ok()?;
    let printable = text
        .chars()
        .filter(|ch| ch.is_ascii_graphic() || ch.is_ascii_whitespace() || !ch.is_control())
        .count();
    (printable * 10 >= text.len() * 8).then(|| text.to_string())
}

type Decoder = fn(&str) -> Option<Vec<u8>>;

fn decoded_views(source: &View, depth: u32, seen: &mut Vec<String>) -> Vec<View> {
    if depth == 0 {
        return Vec::new();
    }
    if std::str::from_utf8(&source.data).is_err() {
        return Vec::new();
    }
    let mut views = Vec::new();
    let mut patterns: Vec<(Regex, Decoder)> = Vec::new();
    patterns.push((
        Regex::new(r"[A-Za-z0-9+/]{16,}={0,2}").expect("base64 pattern"),
        |token| {
            let trimmed = token.trim_end_matches('=');
            decode_base64(trimmed)
        },
    ));
    patterns.push((
        Regex::new(r"[0-9a-fA-F]{16,}").expect("hex pattern"),
        |token| {
            let even = &token[..token.len() - (token.len() % 2)];
            (0..even.len())
                .step_by(2)
                .map(|index| u8::from_str_radix(&even[index..index + 2], 16).ok())
                .collect()
        },
    ));
    patterns.push((
        Regex::new(r"(?:%[0-9A-Fa-f]{2}){3,}").expect("percent pattern"),
        |token| {
            (0..token.len())
                .step_by(3)
                .map(|index| u8::from_str_radix(&token[index + 1..index + 3], 16).ok())
                .collect()
        },
    ));
    for (pattern, decode) in patterns {
        for found in pattern.find_iter(&source.data) {
            let token = match std::str::from_utf8(&source.data[found.start()..found.end()]) {
                Ok(token) => token,
                Err(_) => continue,
            };
            let raw = match decode(token) {
                Some(raw) => raw,
                None => continue,
            };
            let text = match printable(&raw) {
                Some(text) => text,
                None => continue,
            };
            if seen.contains(&text) {
                continue;
            }
            seen.push(text.clone());
            let original = source.offsets.get(found.start()).copied().unwrap_or(0);
            let identity: Vec<usize> = std::iter::repeat_n(original, text.len()).collect();
            let decoded = View {
                name: "decoded",
                data: text.clone().into_bytes(),
                offsets: identity.clone(),
            };
            views.push(decoded.clone());
            let norm = normalized(&text, &identity);
            views.push(View {
                name: "decoded-normalized",
                data: norm.data,
                offsets: norm.offsets,
            });
            views.extend(decoded_views(&decoded, depth - 1, seen));
        }
    }
    views
}

pub fn build_views(text: &str, depth: u32) -> Vec<View> {
    let identity: Vec<usize> = (0..text.len()).collect();
    let raw = View {
        name: "raw",
        data: text.as_bytes().to_vec(),
        offsets: identity.clone(),
    };
    let norm = normalized(text, &identity);
    let mut views = vec![raw, norm];
    let source = View {
        name: "raw",
        data: text.as_bytes().to_vec(),
        offsets: identity,
    };
    let mut seen = vec![text.to_string()];
    views.extend(decoded_views(&source, depth, &mut seen));
    views
}
