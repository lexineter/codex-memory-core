use codex_core::bytes;
use codex_core::cme::{canonicalize, CmeInput};
use codex_core::{CodexError, CME_JSON_PREFIX, CME_KV_PREFIX, CME_TEXT_PREFIX};

#[test]
fn text_canonicalization() {
    let out = canonicalize(CmeInput::Text("  hello\r\nworld\t\t")).unwrap();
    assert_eq!(&out.canonical_bytes[..8], CME_TEXT_PREFIX);
    let len = bytes::read_u32_be(&out.canonical_bytes[8..12]).unwrap() as usize;
    let payload = &out.canonical_bytes[12..];
    assert_eq!(len, payload.len());
    assert_eq!(payload, b"hello world");
}

#[test]
fn json_canonicalization_key_sort() {
    let out = canonicalize(CmeInput::Json("{\"b\":1,\"a\":2}")).unwrap();
    assert_eq!(&out.canonical_bytes[..8], CME_JSON_PREFIX);
    let len = bytes::read_u32_be(&out.canonical_bytes[8..12]).unwrap() as usize;
    let payload = &out.canonical_bytes[12..];
    assert_eq!(len, payload.len());
    assert_eq!(payload, b"{\"a\":2,\"b\":1}");
}

#[test]
fn json_reject_float() {
    let err = canonicalize(CmeInput::Json("{\"a\":1.2}")).unwrap_err();
    assert_eq!(err, CodexError::ParseError("JSON_NUMBER_NOT_INTEGER"));
}

#[test]
fn json_reject_duplicate_keys() {
    let err = canonicalize(CmeInput::Json("{\"a\":1,\"a\":2}")).unwrap_err();
    assert_eq!(err, CodexError::ParseError("JSON_DUPLICATE_KEY"));
}

#[test]
fn kv_canonicalization_sort() {
    let out = canonicalize(CmeInput::Kv(vec![
        ("b".to_string(), vec![2]),
        ("a".to_string(), vec![1, 3]),
    ]))
    .unwrap();
    assert_eq!(&out.canonical_bytes[..8], CME_KV_PREFIX);
    let payload = &out.canonical_bytes[12..];
    let n = bytes::read_u32_be(&payload[0..4]).unwrap();
    assert_eq!(n, 2);

    let k1_len = bytes::read_u16_be(&payload[4..6]).unwrap() as usize;
    assert_eq!(&payload[6..6 + k1_len], b"a");
    let v1_at = 6 + k1_len;
    let v1_len = bytes::read_u32_be(&payload[v1_at..v1_at + 4]).unwrap() as usize;
    assert_eq!(&payload[v1_at + 4..v1_at + 4 + v1_len], &[1, 3]);
}

#[test]
fn non_ascii_rejected() {
    let err = canonicalize(CmeInput::Text("café")).unwrap_err();
    assert_eq!(err, CodexError::InvalidInput("NON_ASCII_UNSUPPORTED_V1"));
}
