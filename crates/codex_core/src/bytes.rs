use crate::{CodexError, CodexResult};

pub fn read_u16_be(input: &[u8]) -> CodexResult<u16> {
    if input.len() < 2 {
        return Err(CodexError::ParseError("read_u16_be: need 2 bytes"));
    }
    Ok(u16::from_be_bytes([input[0], input[1]]))
}

pub fn read_u32_be(input: &[u8]) -> CodexResult<u32> {
    if input.len() < 4 {
        return Err(CodexError::ParseError("read_u32_be: need 4 bytes"));
    }
    Ok(u32::from_be_bytes([input[0], input[1], input[2], input[3]]))
}

pub fn read_u64_be(input: &[u8]) -> CodexResult<u64> {
    if input.len() < 8 {
        return Err(CodexError::ParseError("read_u64_be: need 8 bytes"));
    }
    Ok(u64::from_be_bytes([
        input[0], input[1], input[2], input[3], input[4], input[5], input[6], input[7],
    ]))
}

pub fn read_i16_be(input: &[u8]) -> CodexResult<i16> {
    if input.len() < 2 {
        return Err(CodexError::ParseError("read_i16_be: need 2 bytes"));
    }
    Ok(i16::from_be_bytes([input[0], input[1]]))
}

pub fn write_u16_be(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}

pub fn write_u32_be(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

pub fn write_u64_be(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}

pub fn write_i16_be(out: &mut Vec<u8>, v: i16) {
    out.extend_from_slice(&v.to_be_bytes());
}

pub fn require_len(input: &[u8], n: usize, what: &'static str) -> CodexResult<()> {
    if input.len() == n {
        Ok(())
    } else {
        Err(CodexError::InvalidInput(what))
    }
}
