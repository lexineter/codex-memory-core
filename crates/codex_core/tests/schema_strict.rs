use codex_core::schema::{
    decode_event_payload, encode_event_payload, Event, EventCommon, LifecycleFields,
    EVENT_TYPE_LIFECYCLE_MUTATION, EVENT_TYPE_SCORE_EVALUATED,
};
use codex_core::{CodexError, STATE_DELTA_BYTES};

#[test]
fn score_decode_rejects_trailing_bytes_when_features_disabled() {
    let ev = Event::ScoreEvaluated {
        common: EventCommon {
            event_type: EVENT_TYPE_SCORE_EVALUATED,
            timestamp: 0,
            event_index: 0,
            doc_id: [1u8; 32],
            parent_auth_root: [2u8; 32],
            pre_state_hash: [3u8; 32],
            candidate_commitment: [4u8; 32],
            state_delta: [0u8; STATE_DELTA_BYTES],
        },
        extra: None,
        ordered: None,
        score: None,
        observer: None,
    };
    let mut payload = encode_event_payload(&ev, 0).unwrap();
    payload.push(0xAB);
    let err = decode_event_payload(&payload, 0).unwrap_err();
    assert_eq!(err, CodexError::ParseError("EVENT_PARSE_TRAILING_BYTES"));
}

#[test]
fn lifecycle_decode_rejects_trailing_bytes_when_features_disabled() {
    let ev = Event::LifecycleMutation {
        common: EventCommon {
            event_type: EVENT_TYPE_LIFECYCLE_MUTATION,
            timestamp: 0,
            event_index: 0,
            doc_id: [1u8; 32],
            parent_auth_root: [2u8; 32],
            pre_state_hash: [3u8; 32],
            candidate_commitment: [4u8; 32],
            state_delta: [0u8; STATE_DELTA_BYTES],
        },
        life: LifecycleFields {
            new_lifecycle_state: 1,
            new_representation_mode: 2,
            new_compressed_flag: 0,
            quarantined_until_event_index: 0,
        },
        governance: None,
        observer: None,
    };
    let mut payload = encode_event_payload(&ev, 0).unwrap();
    payload.push(0xCD);
    let err = decode_event_payload(&payload, 0).unwrap_err();
    assert_eq!(err, CodexError::ParseError("EVENT_PARSE_TRAILING_BYTES"));
}
