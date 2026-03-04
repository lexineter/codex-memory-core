use crate::{bytes, CodexError, CME_BLOB_PREFIX, CME_JSON_PREFIX, CME_KV_PREFIX, CME_TEXT_PREFIX};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CmeInput<'a> {
    Text(&'a str),
    Json(&'a str),
    Kv(Vec<(String, Vec<u8>)>),
    Blob(Vec<u8>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmeKind {
    Text,
    Json,
    Kv,
    Blob,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonAst {
    Null,
    Bool(bool),
    Int(i64),
    Str(String),
    Arr(Vec<JsonAst>),
    Obj(Vec<(String, JsonAst)>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CmeAst {
    Text(String),
    Json(JsonAst),
    Kv(Vec<(String, u32)>),
    Blob(u32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CmeOutput {
    pub canonical_bytes: Vec<u8>,
    pub kind: CmeKind,
    pub debug_ast: Option<CmeAst>,
}

// v1 NFKC-LITE policy: accept ASCII only (plus tab/newline/carriage return controls).
pub fn ensure_ascii(s: &str) -> Result<(), CodexError> {
    for b in s.as_bytes() {
        if *b == b'\t' || *b == b'\n' || *b == b'\r' || (0x20..=0x7e).contains(b) {
            continue;
        }
        return Err(CodexError::InvalidInput("NON_ASCII_UNSUPPORTED_V1"));
    }
    Ok(())
}

pub fn normalize_newlines_ascii(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'\r' {
            if i + 1 < bytes.len() && bytes[i + 1] == b'\n' {
                i += 1;
            }
            out.push(b'\n');
        } else {
            out.push(bytes[i]);
        }
        i += 1;
    }
    out
}

pub fn collapse_ws_ascii(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut in_ws = false;
    for b in bytes {
        let ws = *b == b' ' || *b == b'\t' || *b == b'\n';
        if ws {
            in_ws = true;
            continue;
        }
        if in_ws && !out.is_empty() {
            out.push(b' ');
        }
        in_ws = false;
        out.push(*b);
    }
    out
}

fn canonical_with_prefix(prefix: &[u8; 8], payload: &[u8]) -> Result<Vec<u8>, CodexError> {
    let len_u32 = u32::try_from(payload.len())
        .map_err(|_| CodexError::InvalidInput("CME_PAYLOAD_TOO_LARGE"))?;
    let mut out = Vec::with_capacity(prefix.len() + 4 + payload.len());
    out.extend_from_slice(prefix);
    bytes::write_u32_be(&mut out, len_u32);
    out.extend_from_slice(payload);
    Ok(out)
}

struct JsonParser<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> JsonParser<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            bytes: input.as_bytes(),
            at: 0,
        }
    }

    fn parse(mut self) -> Result<JsonAst, CodexError> {
        self.skip_ws();
        let ast = self.parse_value()?;
        self.skip_ws();
        if self.at != self.bytes.len() {
            return Err(CodexError::ParseError("JSON_TRAILING_BYTES"));
        }
        Ok(ast)
    }

    fn skip_ws(&mut self) {
        while self.at < self.bytes.len() {
            let b = self.bytes[self.at];
            if b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' {
                self.at += 1;
            } else {
                break;
            }
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    fn consume(&mut self, expected: u8, err: &'static str) -> Result<(), CodexError> {
        match self.peek() {
            Some(b) if b == expected => {
                self.at += 1;
                Ok(())
            }
            _ => Err(CodexError::ParseError(err)),
        }
    }

    fn parse_value(&mut self) -> Result<JsonAst, CodexError> {
        self.skip_ws();
        match self.peek() {
            Some(b'n') => self.parse_null(),
            Some(b't') | Some(b'f') => self.parse_bool(),
            Some(b'"') => self.parse_string().map(JsonAst::Str),
            Some(b'[') => self.parse_array(),
            Some(b'{') => self.parse_object(),
            Some(b'-') | Some(b'0'..=b'9') => self.parse_number(),
            _ => Err(CodexError::ParseError("JSON_VALUE_EXPECTED")),
        }
    }

    fn parse_null(&mut self) -> Result<JsonAst, CodexError> {
        if self.at + 4 <= self.bytes.len() && &self.bytes[self.at..self.at + 4] == b"null" {
            self.at += 4;
            Ok(JsonAst::Null)
        } else {
            Err(CodexError::ParseError("JSON_INVALID_NULL"))
        }
    }

    fn parse_bool(&mut self) -> Result<JsonAst, CodexError> {
        if self.at + 4 <= self.bytes.len() && &self.bytes[self.at..self.at + 4] == b"true" {
            self.at += 4;
            Ok(JsonAst::Bool(true))
        } else if self.at + 5 <= self.bytes.len() && &self.bytes[self.at..self.at + 5] == b"false" {
            self.at += 5;
            Ok(JsonAst::Bool(false))
        } else {
            Err(CodexError::ParseError("JSON_INVALID_BOOL"))
        }
    }

    fn parse_hex4(&mut self) -> Result<u16, CodexError> {
        if self.at + 4 > self.bytes.len() {
            return Err(CodexError::ParseError("JSON_BAD_UNICODE_ESCAPE"));
        }
        let mut val = 0u16;
        for _ in 0..4 {
            let c = self.bytes[self.at];
            self.at += 1;
            val <<= 4;
            val |= match c {
                b'0'..=b'9' => (c - b'0') as u16,
                b'a'..=b'f' => (c - b'a' + 10) as u16,
                b'A'..=b'F' => (c - b'A' + 10) as u16,
                _ => return Err(CodexError::ParseError("JSON_BAD_UNICODE_ESCAPE")),
            };
        }
        Ok(val)
    }

    fn parse_string(&mut self) -> Result<String, CodexError> {
        self.consume(b'"', "JSON_STRING_EXPECTED")?;
        let mut out = String::new();
        while let Some(b) = self.peek() {
            self.at += 1;
            match b {
                b'"' => return Ok(out),
                b'\\' => {
                    let esc = self
                        .peek()
                        .ok_or(CodexError::ParseError("JSON_BAD_ESCAPE"))?;
                    self.at += 1;
                    let ch = match esc {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{0008}',
                        b'f' => '\u{000C}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let cp = self.parse_hex4()?;
                            if cp > 0x7f {
                                return Err(CodexError::InvalidInput("NON_ASCII_UNSUPPORTED_V1"));
                            }
                            char::from_u32(cp as u32)
                                .ok_or(CodexError::ParseError("JSON_BAD_UNICODE_ESCAPE"))?
                        }
                        _ => return Err(CodexError::ParseError("JSON_BAD_ESCAPE")),
                    };
                    let cb = ch as u32;
                    if !((0x20..=0x7e).contains(&cb) || cb == 0x09 || cb == 0x0a || cb == 0x0d) {
                        return Err(CodexError::InvalidInput("NON_ASCII_UNSUPPORTED_V1"));
                    }
                    out.push(ch);
                }
                0x00..=0x1f => return Err(CodexError::ParseError("JSON_CONTROL_IN_STRING")),
                _ => {
                    if !((0x20..=0x7e).contains(&b) || b == b'\t' || b == b'\n' || b == b'\r') {
                        return Err(CodexError::InvalidInput("NON_ASCII_UNSUPPORTED_V1"));
                    }
                    out.push(b as char);
                }
            }
        }
        Err(CodexError::ParseError("JSON_UNTERMINATED_STRING"))
    }

    fn parse_number(&mut self) -> Result<JsonAst, CodexError> {
        let start = self.at;
        if self.peek() == Some(b'-') {
            self.at += 1;
        }
        let first = self
            .peek()
            .ok_or(CodexError::ParseError("JSON_NUMBER_EXPECTED"))?;
        match first {
            b'0' => {
                self.at += 1;
                if matches!(self.peek(), Some(b'0'..=b'9')) {
                    return Err(CodexError::ParseError("JSON_LEADING_ZERO"));
                }
            }
            b'1'..=b'9' => {
                self.at += 1;
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.at += 1;
                }
            }
            _ => return Err(CodexError::ParseError("JSON_NUMBER_EXPECTED")),
        }

        if matches!(self.peek(), Some(b'.' | b'e' | b'E')) {
            return Err(CodexError::ParseError("JSON_NUMBER_NOT_INTEGER"));
        }

        let s = core::str::from_utf8(&self.bytes[start..self.at])
            .map_err(|_| CodexError::ParseError("JSON_NUMBER_INVALID"))?;
        let v = s
            .parse::<i64>()
            .map_err(|_| CodexError::ParseError("JSON_NUMBER_OUT_OF_RANGE"))?;
        Ok(JsonAst::Int(v))
    }

    fn parse_array(&mut self) -> Result<JsonAst, CodexError> {
        self.consume(b'[', "JSON_ARRAY_EXPECTED")?;
        self.skip_ws();
        let mut out = Vec::new();
        if self.peek() == Some(b']') {
            self.at += 1;
            return Ok(JsonAst::Arr(out));
        }
        loop {
            out.push(self.parse_value()?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.at += 1;
                    self.skip_ws();
                }
                Some(b']') => {
                    self.at += 1;
                    break;
                }
                _ => return Err(CodexError::ParseError("JSON_ARRAY_DELIM_EXPECTED")),
            }
        }
        Ok(JsonAst::Arr(out))
    }

    fn parse_object(&mut self) -> Result<JsonAst, CodexError> {
        self.consume(b'{', "JSON_OBJECT_EXPECTED")?;
        self.skip_ws();
        let mut out: Vec<(String, JsonAst)> = Vec::new();
        if self.peek() == Some(b'}') {
            self.at += 1;
            return Ok(JsonAst::Obj(out));
        }
        loop {
            let key = self.parse_string()?;
            for (k, _) in &out {
                if *k == key {
                    return Err(CodexError::ParseError("JSON_DUPLICATE_KEY"));
                }
            }
            self.skip_ws();
            self.consume(b':', "JSON_COLON_EXPECTED")?;
            self.skip_ws();
            let value = self.parse_value()?;
            out.push((key, value));
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.at += 1;
                    self.skip_ws();
                }
                Some(b'}') => {
                    self.at += 1;
                    break;
                }
                _ => return Err(CodexError::ParseError("JSON_OBJECT_DELIM_EXPECTED")),
            }
        }
        out.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
        Ok(JsonAst::Obj(out))
    }
}

fn escape_json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for b in s.as_bytes() {
        match *b {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            0x08 => out.push_str("\\b"),
            0x0c => out.push_str("\\f"),
            0x00..=0x1f => {
                out.push_str("\\u00");
                const HEX: &[u8; 16] = b"0123456789abcdef";
                out.push(HEX[((*b >> 4) & 0x0f) as usize] as char);
                out.push(HEX[(*b & 0x0f) as usize] as char);
            }
            _ => out.push(*b as char),
        }
    }
    out.push('"');
    out
}

fn emit_json(ast: &JsonAst) -> String {
    match ast {
        JsonAst::Null => "null".to_string(),
        JsonAst::Bool(v) => {
            if *v {
                "true".to_string()
            } else {
                "false".to_string()
            }
        }
        JsonAst::Int(v) => v.to_string(),
        JsonAst::Str(s) => escape_json_str(s),
        JsonAst::Arr(items) => {
            let mut out = String::from("[");
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&emit_json(item));
            }
            out.push(']');
            out
        }
        JsonAst::Obj(entries) => {
            let mut out = String::from("{");
            for (i, (k, v)) in entries.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&escape_json_str(k));
                out.push(':');
                out.push_str(&emit_json(v));
            }
            out.push('}');
            out
        }
    }
}

fn canonicalize_text(text: &str) -> Result<CmeOutput, CodexError> {
    ensure_ascii(text)?;
    let normalized = normalize_newlines_ascii(text.as_bytes());
    let collapsed = collapse_ws_ascii(&normalized);
    let final_text = String::from_utf8(collapsed)
        .map_err(|_| CodexError::InvalidInput("NON_ASCII_UNSUPPORTED_V1"))?;
    let canonical_bytes = canonical_with_prefix(CME_TEXT_PREFIX, final_text.as_bytes())?;
    Ok(CmeOutput {
        canonical_bytes,
        kind: CmeKind::Text,
        debug_ast: Some(CmeAst::Text(final_text)),
    })
}

fn canonicalize_json(text: &str) -> Result<CmeOutput, CodexError> {
    ensure_ascii(text)?;
    let ast = JsonParser::new(text).parse()?;
    let emitted = emit_json(&ast);
    let canonical_bytes = canonical_with_prefix(CME_JSON_PREFIX, emitted.as_bytes())?;
    Ok(CmeOutput {
        canonical_bytes,
        kind: CmeKind::Json,
        debug_ast: Some(CmeAst::Json(ast)),
    })
}

fn canonicalize_kv(mut kv: Vec<(String, Vec<u8>)>) -> Result<CmeOutput, CodexError> {
    for (k, _) in &kv {
        ensure_ascii(k)?;
        if k.is_empty() {
            return Err(CodexError::InvalidInput("KV_KEY_EMPTY"));
        }
    }
    kv.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    for i in 1..kv.len() {
        if kv[i - 1].0 == kv[i].0 {
            return Err(CodexError::InvalidInput("KV_DUPLICATE_KEY"));
        }
    }

    let n = u32::try_from(kv.len()).map_err(|_| CodexError::InvalidInput("KV_TOO_MANY_ENTRIES"))?;
    let mut payload = Vec::new();
    bytes::write_u32_be(&mut payload, n);
    let mut ast = Vec::with_capacity(kv.len());
    for (k, v) in kv {
        let klen =
            u16::try_from(k.len()).map_err(|_| CodexError::InvalidInput("KV_KEY_TOO_LONG"))?;
        let vlen =
            u32::try_from(v.len()).map_err(|_| CodexError::InvalidInput("KV_VALUE_TOO_LONG"))?;
        bytes::write_u16_be(&mut payload, klen);
        payload.extend_from_slice(k.as_bytes());
        bytes::write_u32_be(&mut payload, vlen);
        payload.extend_from_slice(&v);
        ast.push((k, vlen));
    }
    let canonical_bytes = canonical_with_prefix(CME_KV_PREFIX, &payload)?;
    Ok(CmeOutput {
        canonical_bytes,
        kind: CmeKind::Kv,
        debug_ast: Some(CmeAst::Kv(ast)),
    })
}

fn canonicalize_blob(blob: Vec<u8>) -> Result<CmeOutput, CodexError> {
    let len = u32::try_from(blob.len()).map_err(|_| CodexError::InvalidInput("BLOB_TOO_LARGE"))?;
    let canonical_bytes = canonical_with_prefix(CME_BLOB_PREFIX, &blob)?;
    Ok(CmeOutput {
        canonical_bytes,
        kind: CmeKind::Blob,
        debug_ast: Some(CmeAst::Blob(len)),
    })
}

pub fn canonicalize(input: CmeInput<'_>) -> Result<CmeOutput, CodexError> {
    match input {
        CmeInput::Text(text) => canonicalize_text(text),
        CmeInput::Json(text) => canonicalize_json(text),
        CmeInput::Kv(kv) => canonicalize_kv(kv),
        CmeInput::Blob(blob) => canonicalize_blob(blob),
    }
}
