use codex_core::{bytes, hash, DOMAIN_EVENT, DOMAIN_LEDGER_HEADER};

#[test]
fn sha256_is_stable() {
    let a = hash::sha256(b"hello");
    let b = hash::sha256(b"hello");
    assert_eq!(a, b);
    assert_ne!(a, hash::sha256(b"hello!"));
}

#[test]
fn domain_hash_is_separated() {
    let payload = b"same-payload";
    let h1 = hash::hash_domain(DOMAIN_EVENT, payload);
    let h2 = hash::hash_domain(DOMAIN_LEDGER_HEADER, payload);
    assert_ne!(h1, h2);
}

#[test]
fn big_endian_roundtrip() {
    let mut v = Vec::new();
    bytes::write_u16_be(&mut v, 0xABCD);
    bytes::write_u32_be(&mut v, 0x01020304);
    bytes::write_u64_be(&mut v, 0x0102030405060708);
    bytes::write_i16_be(&mut v, -12345);

    assert_eq!(bytes::read_u16_be(&v[0..2]).unwrap(), 0xABCD);
    assert_eq!(bytes::read_u32_be(&v[2..6]).unwrap(), 0x01020304);
    assert_eq!(bytes::read_u64_be(&v[6..14]).unwrap(), 0x0102030405060708);
    assert_eq!(bytes::read_i16_be(&v[14..16]).unwrap(), -12345);
}
