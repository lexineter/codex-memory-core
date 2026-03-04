use crate::CodexError;

pub fn to_hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

pub fn from_hex_32(s: &str) -> Result<[u8; 32], CodexError> {
    let bytes = s.as_bytes();
    if bytes.len() != 64 {
        return Err(CodexError::InvalidInput("HEX_32_BAD_LENGTH"));
    }
    if (bytes.len() & 1) != 0 {
        return Err(CodexError::InvalidInput("HEX_ODD_LENGTH"));
    }
    let mut out = [0u8; 32];
    let mut i = 0usize;
    while i < 32 {
        let hi = hex_val(bytes[i * 2]).ok_or(CodexError::InvalidInput("HEX_INVALID_CHAR"))?;
        let lo = hex_val(bytes[i * 2 + 1]).ok_or(CodexError::InvalidInput("HEX_INVALID_CHAR"))?;
        out[i] = (hi << 4) | lo;
        i += 1;
    }
    Ok(out)
}
