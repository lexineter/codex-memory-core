use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

use crate::ledger::header::LedgerHeaderV1;
use crate::schema::{self, Event};
use crate::{bytes, hash, CodexError, DOMAIN_EVENT, HASH_LEN};

pub const MAX_EVENT_LEN: u32 = 64 * 1024;

#[derive(Debug)]
pub struct LedgerReader {
    file: File,
    header: LedgerHeaderV1,
}

pub struct LedgerIter<'a> {
    reader: &'a mut LedgerReader,
    next_offset: u64,
    done: bool,
}

pub struct LedgerRawIter<'a> {
    reader: &'a mut LedgerReader,
    next_offset: u64,
    done: bool,
}

impl LedgerReader {
    pub fn open(ledger_path: &str) -> Result<LedgerReader, CodexError> {
        let mut file =
            File::open(ledger_path).map_err(|_| CodexError::InvalidInput("LEDGER_OPEN_FAILED"))?;
        let mut hdr_bytes = vec![0u8; LedgerHeaderV1::header_len()];
        file.read_exact(&mut hdr_bytes)
            .map_err(|_| CodexError::ParseError("LEDGER_READ_HEADER_FAILED"))?;
        let header = LedgerHeaderV1::decode(&hdr_bytes)?;
        Ok(LedgerReader { file, header })
    }

    pub fn header(&self) -> &LedgerHeaderV1 {
        &self.header
    }

    pub fn iter(&mut self) -> LedgerIter<'_> {
        LedgerIter {
            reader: self,
            next_offset: LedgerHeaderV1::header_len() as u64,
            done: false,
        }
    }

    pub fn iter_raw(&mut self) -> LedgerRawIter<'_> {
        LedgerRawIter {
            reader: self,
            next_offset: LedgerHeaderV1::header_len() as u64,
            done: false,
        }
    }

    fn read_frame_at(&mut self, offset: u64) -> Result<(Vec<u8>, [u8; HASH_LEN], u64), CodexError> {
        self.file
            .seek(SeekFrom::Start(offset))
            .map_err(|_| CodexError::ParseError("LEDGER_SEEK_FAILED"))?;

        let mut len_buf = [0u8; 4];
        self.file
            .read_exact(&mut len_buf)
            .map_err(|_| CodexError::ParseError("LEDGER_READ_EVENT_LEN_FAILED"))?;
        let event_len = bytes::read_u32_be(&len_buf)?;
        if !(HASH_LEN as u32..=MAX_EVENT_LEN).contains(&event_len) {
            return Err(CodexError::IntegrityError("EVENT_LEN_OUT_OF_RANGE"));
        }

        let payload_len = (event_len as usize) - HASH_LEN;
        let mut payload = vec![0u8; payload_len];
        self.file
            .read_exact(&mut payload)
            .map_err(|_| CodexError::ParseError("LEDGER_READ_PAYLOAD_FAILED"))?;
        let mut stored_commitment = [0u8; HASH_LEN];
        self.file
            .read_exact(&mut stored_commitment)
            .map_err(|_| CodexError::ParseError("LEDGER_READ_COMMITMENT_FAILED"))?;

        let next_offset = offset + 4 + (event_len as u64);
        Ok((payload, stored_commitment, next_offset))
    }

    fn read_at_inner(&mut self, offset: u64) -> Result<(Event, [u8; HASH_LEN], u64), CodexError> {
        let (payload, stored_commitment, next_offset) = self.read_frame_at(offset)?;
        let computed = hash::hash_domain(DOMAIN_EVENT, &payload);
        if computed != stored_commitment {
            return Err(CodexError::IntegrityError("EVENT_COMMITMENT_MISMATCH"));
        }

        let event = schema::decode_event_payload(&payload, self.header.flags)?;
        Ok((event, stored_commitment, next_offset))
    }

    pub fn read_at(&mut self, offset: u64) -> Result<(Event, [u8; HASH_LEN]), CodexError> {
        let (event, commitment, _) = self.read_at_inner(offset)?;
        Ok((event, commitment))
    }

    pub fn read_raw_at(&mut self, offset: u64) -> Result<(Vec<u8>, [u8; HASH_LEN]), CodexError> {
        let (payload, commitment, _) = self.read_frame_at(offset)?;
        Ok((payload, commitment))
    }
}

impl<'a> Iterator for LedgerIter<'a> {
    type Item = Result<(u64, Event, [u8; HASH_LEN]), CodexError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let file_len = match self.reader.file.metadata() {
            Ok(m) => m.len(),
            Err(_) => {
                self.done = true;
                return Some(Err(CodexError::ParseError("LEDGER_METADATA_FAILED")));
            }
        };
        if self.next_offset >= file_len {
            self.done = true;
            return None;
        }

        let offset = self.next_offset;
        match self.reader.read_at_inner(offset) {
            Ok((event, commitment, next_offset)) => {
                self.next_offset = next_offset;
                Some(Ok((offset, event, commitment)))
            }
            Err(e) => {
                self.done = true;
                Some(Err(e))
            }
        }
    }
}

impl<'a> Iterator for LedgerRawIter<'a> {
    type Item = Result<(u64, Vec<u8>, [u8; HASH_LEN]), CodexError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let file_len = match self.reader.file.metadata() {
            Ok(m) => m.len(),
            Err(_) => {
                self.done = true;
                return Some(Err(CodexError::ParseError("LEDGER_METADATA_FAILED")));
            }
        };
        if self.next_offset >= file_len {
            self.done = true;
            return None;
        }

        let offset = self.next_offset;
        match self.reader.read_frame_at(offset) {
            Ok((payload, commitment, next_offset)) => {
                self.next_offset = next_offset;
                Some(Ok((offset, payload, commitment)))
            }
            Err(e) => {
                self.done = true;
                Some(Err(e))
            }
        }
    }
}
