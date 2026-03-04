use std::fs::File;
use std::io::{Read, Write};

use crate::{
    bytes, hash, CodexError, DOMAIN_LEDGER_HEADER, HASH_ID_SHA256, MAGIC_INDEX, PARAMSET_ID_V1,
    SCHEMA_ID_V1,
};

const INDEX_VERSION: u16 = 1;
const INDEX_RECORD_EVENT_OFFSET: u8 = 0x01;
const INDEX_RECORD_DOC_LATEST: u8 = 0x02;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexHeaderV1 {
    pub magic: [u8; 8],
    pub version: u16,
    pub schema_id: u16,
    pub paramset_id: u16,
    pub hash_id: u16,
    pub reserved: [u8; 32],
    pub header_commitment: [u8; 32],
}

impl IndexHeaderV1 {
    pub fn header_len() -> usize {
        80
    }

    pub fn default_v1() -> Self {
        let mut out = IndexHeaderV1 {
            magic: *MAGIC_INDEX,
            version: INDEX_VERSION,
            schema_id: SCHEMA_ID_V1,
            paramset_id: PARAMSET_ID_V1,
            hash_id: HASH_ID_SHA256,
            reserved: [0u8; 32],
            header_commitment: [0u8; 32],
        };
        out.header_commitment = out.compute_commitment();
        out
    }

    fn encode_without_commitment(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::header_len() - 32);
        out.extend_from_slice(&self.magic);
        bytes::write_u16_be(&mut out, self.version);
        bytes::write_u16_be(&mut out, self.schema_id);
        bytes::write_u16_be(&mut out, self.paramset_id);
        bytes::write_u16_be(&mut out, self.hash_id);
        out.extend_from_slice(&self.reserved);
        out
    }

    fn compute_commitment(&self) -> [u8; 32] {
        hash::hash_domain(DOMAIN_LEDGER_HEADER, &self.encode_without_commitment())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.encode_without_commitment();
        out.extend_from_slice(&self.header_commitment);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CodexError> {
        if bytes.len() != Self::header_len() {
            return Err(CodexError::ParseError("INDEX_HEADER_BAD_LENGTH"));
        }
        let mut at = 0usize;
        let mut magic = [0u8; 8];
        magic.copy_from_slice(&bytes[at..at + 8]);
        at += 8;
        let version = bytes::read_u16_be(&bytes[at..at + 2])?;
        at += 2;
        let schema_id = bytes::read_u16_be(&bytes[at..at + 2])?;
        at += 2;
        let paramset_id = bytes::read_u16_be(&bytes[at..at + 2])?;
        at += 2;
        let hash_id = bytes::read_u16_be(&bytes[at..at + 2])?;
        at += 2;
        let mut reserved = [0u8; 32];
        reserved.copy_from_slice(&bytes[at..at + 32]);
        at += 32;
        let mut header_commitment = [0u8; 32];
        header_commitment.copy_from_slice(&bytes[at..at + 32]);

        let out = IndexHeaderV1 {
            magic,
            version,
            schema_id,
            paramset_id,
            hash_id,
            reserved,
            header_commitment,
        };

        if out.magic != *MAGIC_INDEX {
            return Err(CodexError::IntegrityError("INDEX_HEADER_MAGIC_MISMATCH"));
        }
        if out.version != INDEX_VERSION
            || out.schema_id != SCHEMA_ID_V1
            || out.paramset_id != PARAMSET_ID_V1
            || out.hash_id != HASH_ID_SHA256
        {
            return Err(CodexError::IntegrityError("INDEX_HEADER_MISMATCH"));
        }
        if out.reserved.iter().any(|b| *b != 0) {
            return Err(CodexError::IntegrityError("INDEX_HEADER_RESERVED_NONZERO"));
        }
        let expected = out.compute_commitment();
        if expected != out.header_commitment {
            return Err(CodexError::IntegrityError(
                "INDEX_HEADER_COMMITMENT_MISMATCH",
            ));
        }
        Ok(out)
    }
}

#[derive(Debug)]
pub struct IndexWriter {
    file: File,
}

impl IndexWriter {
    pub fn create(path: &str) -> Result<Self, CodexError> {
        let mut file =
            File::create(path).map_err(|_| CodexError::InvalidInput("INDEX_CREATE_FAILED"))?;
        let header = IndexHeaderV1::default_v1();
        file.write_all(&header.encode())
            .map_err(|_| CodexError::InvalidInput("INDEX_WRITE_HEADER_FAILED"))?;
        file.flush()
            .map_err(|_| CodexError::InvalidInput("INDEX_FLUSH_FAILED"))?;
        Ok(Self { file })
    }

    pub fn append_event_offset(
        &mut self,
        event_index: u64,
        ledger_offset: u64,
    ) -> Result<(), CodexError> {
        let mut rec = Vec::with_capacity(1 + 8 + 8);
        rec.push(INDEX_RECORD_EVENT_OFFSET);
        bytes::write_u64_be(&mut rec, event_index);
        bytes::write_u64_be(&mut rec, ledger_offset);
        self.file
            .write_all(&rec)
            .map_err(|_| CodexError::InvalidInput("INDEX_APPEND_EVENT_OFFSET_FAILED"))?;
        Ok(())
    }

    pub fn append_doc_latest(
        &mut self,
        doc_id: [u8; 32],
        event_index: u64,
    ) -> Result<(), CodexError> {
        let mut rec = Vec::with_capacity(1 + 32 + 8);
        rec.push(INDEX_RECORD_DOC_LATEST);
        rec.extend_from_slice(&doc_id);
        bytes::write_u64_be(&mut rec, event_index);
        self.file
            .write_all(&rec)
            .map_err(|_| CodexError::InvalidInput("INDEX_APPEND_DOC_LATEST_FAILED"))?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct IndexReader {
    _header: IndexHeaderV1,
    event_offsets: Vec<(u64, u64)>,
    doc_latest: Vec<([u8; 32], u64)>,
}

impl IndexReader {
    pub fn open(path: &str) -> Result<Self, CodexError> {
        let mut file =
            File::open(path).map_err(|_| CodexError::InvalidInput("INDEX_OPEN_FAILED"))?;
        let mut header_buf = vec![0u8; IndexHeaderV1::header_len()];
        file.read_exact(&mut header_buf)
            .map_err(|_| CodexError::ParseError("INDEX_READ_HEADER_FAILED"))?;
        let header = IndexHeaderV1::decode(&header_buf)?;

        let mut rest = Vec::new();
        file.read_to_end(&mut rest)
            .map_err(|_| CodexError::ParseError("INDEX_READ_BODY_FAILED"))?;

        let mut at = 0usize;
        let mut event_offsets = Vec::new();
        let mut doc_latest = Vec::new();
        while at < rest.len() {
            let tag = rest[at];
            at += 1;
            match tag {
                INDEX_RECORD_EVENT_OFFSET => {
                    if at + 16 > rest.len() {
                        return Err(CodexError::ParseError("INDEX_EVENT_OFFSET_TRUNCATED"));
                    }
                    let event_index = bytes::read_u64_be(&rest[at..at + 8])?;
                    at += 8;
                    let ledger_offset = bytes::read_u64_be(&rest[at..at + 8])?;
                    at += 8;
                    event_offsets.push((event_index, ledger_offset));
                }
                INDEX_RECORD_DOC_LATEST => {
                    if at + 40 > rest.len() {
                        return Err(CodexError::ParseError("INDEX_DOC_LATEST_TRUNCATED"));
                    }
                    let mut doc_id = [0u8; 32];
                    doc_id.copy_from_slice(&rest[at..at + 32]);
                    at += 32;
                    let event_index = bytes::read_u64_be(&rest[at..at + 8])?;
                    at += 8;
                    doc_latest.push((doc_id, event_index));
                }
                _ => return Err(CodexError::ParseError("INDEX_RECORD_TAG_UNKNOWN")),
            }
        }

        Ok(Self {
            _header: header,
            event_offsets,
            doc_latest,
        })
    }

    pub fn get_offset(&self, event_index: u64) -> Option<u64> {
        for (idx, off) in &self.event_offsets {
            if *idx == event_index {
                return Some(*off);
            }
        }
        None
    }

    pub fn get_latest(&self, doc_id: [u8; 32]) -> Option<u64> {
        for (id, idx) in self.doc_latest.iter().rev() {
            if *id == doc_id {
                return Some(*idx);
            }
        }
        None
    }
}
