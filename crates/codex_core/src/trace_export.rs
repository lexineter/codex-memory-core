use std::fs::File;
use std::io::Write;

use crate::ledger::reader::LedgerReader;
use crate::mmr::Mmr;
use crate::schema::Event;
use crate::{bytes, hash, CodexError, DOMAIN_EVENT, DOMAIN_PRESTATE, HASH_LEN};

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

pub fn export_replay_trace(path: &str) -> Result<(), CodexError> {
    let mut reader = LedgerReader::open(path)?;
    let flags = reader.header().flags;
    let mut out = File::create(format!("{path}.trace"))
        .map_err(|_| CodexError::InvalidInput("TRACE_CREATE_FAILED"))?;

    let mut mmr = Mmr::new();
    let mut state_hash = hash::hash_domain(DOMAIN_PRESTATE, b"");

    for item in reader.iter_raw() {
        let (_, payload, _) = item?;
        let ev = crate::schema::decode_event_payload(&payload, flags)
            .map_err(|_| CodexError::ParseError("EVENT_PARSE_ERROR"))?;
        let idx = event_index(&ev);
        let commitment = hash::hash_domain(DOMAIN_EVENT, &payload);
        let root_after = mmr.append(commitment);
        let mut st = Vec::with_capacity(HASH_LEN * 2);
        st.extend_from_slice(&state_hash);
        st.extend_from_slice(&commitment);
        state_hash = hash::hash_domain(DOMAIN_PRESTATE, &st);

        let mut rec = Vec::with_capacity(8 + HASH_LEN * 3);
        bytes::write_u64_be(&mut rec, idx);
        rec.extend_from_slice(&commitment);
        rec.extend_from_slice(&state_hash);
        rec.extend_from_slice(&root_after);
        out.write_all(&rec)
            .map_err(|_| CodexError::InvalidInput("TRACE_WRITE_FAILED"))?;
    }
    out.flush()
        .map_err(|_| CodexError::InvalidInput("TRACE_FLUSH_FAILED"))?;
    Ok(())
}
