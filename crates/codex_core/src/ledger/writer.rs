use std::fs::File;
use std::io::{Seek, SeekFrom, Write};

use crate::ledger::header::LedgerHeaderV1;
use crate::ledger::index::IndexWriter;
use crate::ledger::json_mirror::JsonMirrorWriter;
use crate::mmr::Mmr;
use crate::schema::{self, Event, EVENT_TYPE_PROTOCOL_LOCK};
use crate::{
    bytes, hash, CodexError, DOMAIN_EVENT, FEATURE_JSON_MIRROR, FEATURE_PROTOCOL_LOCK_REQUIRED,
    FEATURE_RECURSIVE_PROJECTION, FEATURE_SCORE_COMMITMENT, FEATURE_SCORE_PROOFS, HASH_LEN,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendResult {
    pub event_index: u64,
    pub event_commitment: [u8; HASH_LEN],
    pub root_after: [u8; HASH_LEN],
    pub ledger_offset: u64,
}

#[derive(Debug)]
pub struct LedgerWriter {
    ledger_file: File,
    index_writer: IndexWriter,
    json_writer: Option<JsonMirrorWriter>,
    mmr: Mmr,
    schema_flags: u32,
    next_event_index: u64,
    last_doc_id: Option<[u8; 32]>,
    seen_protocol_lock: bool,
    seen_non_lock_event: bool,
}

fn event_index(ev: &Event) -> u64 {
    match ev {
        Event::DocUpsert { common, .. } => common.event_index,
        Event::ScoreEvaluated { common, .. } => common.event_index,
        Event::LifecycleMutation { common, .. } => common.event_index,
        Event::Snapshot { common, .. } => common.event_index,
        Event::DivergenceLocator { common, .. } => common.event_index,
        Event::SnapshotDelta { common, .. } => common.event_index,
        Event::ProtocolLock { common, .. } => common.event_index,
    }
}

fn event_doc_id(ev: &Event) -> Option<[u8; 32]> {
    match ev {
        Event::DocUpsert { common, .. } => Some(common.doc_id),
        Event::ScoreEvaluated { common, .. } => Some(common.doc_id),
        Event::LifecycleMutation { common, .. } => Some(common.doc_id),
        Event::Snapshot { .. } => None,
        Event::DivergenceLocator { .. } => None,
        Event::SnapshotDelta { .. } => None,
        Event::ProtocolLock { .. } => None,
    }
}

impl LedgerWriter {
    pub fn create(
        ledger_path: &str,
        index_path: &str,
        json_path: Option<&str>,
        flags: u32,
    ) -> Result<LedgerWriter, CodexError> {
        if (flags & FEATURE_SCORE_COMMITMENT) != 0 && (flags & FEATURE_RECURSIVE_PROJECTION) == 0 {
            return Err(CodexError::InvalidInput(
                "SCORE_COMMITMENT_REQUIRES_QUERY_BYTES",
            ));
        }
        if (flags & FEATURE_SCORE_PROOFS) != 0 && (flags & FEATURE_SCORE_COMMITMENT) == 0 {
            return Err(CodexError::InvalidInput(
                "SCORE_PROOFS_REQUIRES_SCORE_COMMITMENT",
            ));
        }
        let mut ledger_file = File::create(ledger_path)
            .map_err(|_| CodexError::InvalidInput("LEDGER_CREATE_FAILED"))?;
        let header = LedgerHeaderV1::default_v1(flags);
        ledger_file
            .write_all(&header.encode())
            .map_err(|_| CodexError::InvalidInput("LEDGER_WRITE_HEADER_FAILED"))?;
        ledger_file
            .flush()
            .map_err(|_| CodexError::InvalidInput("LEDGER_FLUSH_FAILED"))?;

        let index_writer = IndexWriter::create(index_path)?;
        let json_writer = if (flags & FEATURE_JSON_MIRROR) != 0 {
            match json_path {
                Some(path) => Some(JsonMirrorWriter::create(path)?),
                None => None,
            }
        } else {
            None
        };

        Ok(LedgerWriter {
            ledger_file,
            index_writer,
            json_writer,
            mmr: Mmr::new(),
            schema_flags: header.flags,
            next_event_index: 0,
            last_doc_id: None,
            seen_protocol_lock: false,
            seen_non_lock_event: false,
        })
    }

    pub fn append(&mut self, ev: &Event) -> Result<AppendResult, CodexError> {
        let ev_index = event_index(ev);
        let is_protocol_lock = matches!(ev, Event::ProtocolLock { common, .. } if common.event_type == EVENT_TYPE_PROTOCOL_LOCK);
        let ev_doc_id = event_doc_id(ev);
        if ev_index != self.next_event_index {
            return Err(CodexError::InvalidInput("EVENT_INDEX_NOT_SEQUENTIAL"));
        }
        if is_protocol_lock {
            if self.seen_protocol_lock {
                return Err(CodexError::InvalidInput("PROTOCOL_LOCK_DUPLICATE"));
            }
            if self.seen_non_lock_event {
                return Err(CodexError::InvalidInput("PROTOCOL_LOCK_ORDER_INVALID"));
            }
        } else {
            if (self.schema_flags & FEATURE_PROTOCOL_LOCK_REQUIRED) != 0 && !self.seen_protocol_lock
            {
                return Err(CodexError::InvalidInput("PROTOCOL_LOCK_REQUIRED"));
            }
            self.seen_non_lock_event = true;
        }

        let payload = schema::encode_event_payload(ev, self.schema_flags)?;
        let event_commitment = hash::hash_domain(DOMAIN_EVENT, &payload);

        let payload_and_commitment_len = payload
            .len()
            .checked_add(HASH_LEN)
            .ok_or(CodexError::InvalidInput("EVENT_TOO_LARGE"))?;
        let event_len_u32 = u32::try_from(payload_and_commitment_len)
            .map_err(|_| CodexError::InvalidInput("EVENT_TOO_LARGE"))?;

        let ledger_offset = self
            .ledger_file
            .seek(SeekFrom::End(0))
            .map_err(|_| CodexError::InvalidInput("LEDGER_SEEK_END_FAILED"))?;
        let mut frame_prefix = Vec::with_capacity(4);
        bytes::write_u32_be(&mut frame_prefix, event_len_u32);
        self.ledger_file
            .write_all(&frame_prefix)
            .map_err(|_| CodexError::InvalidInput("LEDGER_WRITE_LEN_FAILED"))?;
        self.ledger_file
            .write_all(&payload)
            .map_err(|_| CodexError::InvalidInput("LEDGER_WRITE_PAYLOAD_FAILED"))?;
        self.ledger_file
            .write_all(&event_commitment)
            .map_err(|_| CodexError::InvalidInput("LEDGER_WRITE_COMMITMENT_FAILED"))?;
        self.ledger_file
            .flush()
            .map_err(|_| CodexError::InvalidInput("LEDGER_FLUSH_FAILED"))?;

        let root_after = self.mmr.append(event_commitment);

        self.index_writer
            .append_event_offset(ev_index, ledger_offset)?;
        if let Some(doc_id) = ev_doc_id {
            if self.last_doc_id != Some(doc_id) {
                self.index_writer.append_doc_latest(doc_id, ev_index)?;
                self.last_doc_id = Some(doc_id);
            }
        }

        if let Some(w) = self.json_writer.as_mut() {
            w.write_event_line(ev, event_commitment, root_after)?;
        }
        if is_protocol_lock {
            self.seen_protocol_lock = true;
        }

        self.next_event_index += 1;
        Ok(AppendResult {
            event_index: ev_index,
            event_commitment,
            root_after,
            ledger_offset,
        })
    }
}
