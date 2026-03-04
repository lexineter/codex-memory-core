use crate::{
    bytes, hash, CodexError, COORD_TYPE_I16, DIM_V1, DOC_ID_BYTES, DOMAIN_LEDGER_HEADER,
    FEATURE_RECURSIVE_PROJECTION, FEATURE_SCORE_COMMITMENT, FEATURE_SCORE_PROOFS, HASH_ID_SHA256,
    LEDGER_VERSION, MAGIC_LEDGER, PARAMSET_ID_V1, SCHEMA_ID_V1, STATE_DELTA_BYTES,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerHeaderV1 {
    pub magic: [u8; 8],
    pub version: u16,
    pub schema_id: u16,
    pub paramset_id: u16,
    pub hash_id: u16,
    pub flags: u32,
    pub doc_id_bytes: u16,
    pub state_delta_bytes: u16,
    pub dim: u16,
    pub coord_type: u16,
    pub reserved: [u8; 32],
    pub header_commitment: [u8; 32],
}

impl LedgerHeaderV1 {
    pub fn header_len() -> usize {
        92
    }

    pub fn default_v1(flags: u32) -> LedgerHeaderV1 {
        let mut out = LedgerHeaderV1 {
            magic: *MAGIC_LEDGER,
            version: LEDGER_VERSION,
            schema_id: SCHEMA_ID_V1,
            paramset_id: PARAMSET_ID_V1,
            hash_id: HASH_ID_SHA256,
            flags,
            doc_id_bytes: DOC_ID_BYTES as u16,
            state_delta_bytes: STATE_DELTA_BYTES as u16,
            dim: DIM_V1,
            coord_type: COORD_TYPE_I16,
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
        bytes::write_u32_be(&mut out, self.flags);
        bytes::write_u16_be(&mut out, self.doc_id_bytes);
        bytes::write_u16_be(&mut out, self.state_delta_bytes);
        bytes::write_u16_be(&mut out, self.dim);
        bytes::write_u16_be(&mut out, self.coord_type);
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

    pub fn decode(bytes: &[u8]) -> Result<LedgerHeaderV1, CodexError> {
        if bytes.len() != Self::header_len() {
            return Err(CodexError::ParseError("LEDGER_HEADER_BAD_LENGTH"));
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
        let flags = bytes::read_u32_be(&bytes[at..at + 4])?;
        at += 4;
        let doc_id_bytes = bytes::read_u16_be(&bytes[at..at + 2])?;
        at += 2;
        let state_delta_bytes = bytes::read_u16_be(&bytes[at..at + 2])?;
        at += 2;
        let dim = bytes::read_u16_be(&bytes[at..at + 2])?;
        at += 2;
        let coord_type = bytes::read_u16_be(&bytes[at..at + 2])?;
        at += 2;

        let mut reserved = [0u8; 32];
        reserved.copy_from_slice(&bytes[at..at + 32]);
        at += 32;

        let mut header_commitment = [0u8; 32];
        header_commitment.copy_from_slice(&bytes[at..at + 32]);

        let out = LedgerHeaderV1 {
            magic,
            version,
            schema_id,
            paramset_id,
            hash_id,
            flags,
            doc_id_bytes,
            state_delta_bytes,
            dim,
            coord_type,
            reserved,
            header_commitment,
        };

        if out.magic != *MAGIC_LEDGER {
            return Err(CodexError::IntegrityError("LEDGER_HEADER_MAGIC_MISMATCH"));
        }
        if out.version != LEDGER_VERSION
            || out.schema_id != SCHEMA_ID_V1
            || out.paramset_id != PARAMSET_ID_V1
            || out.hash_id != HASH_ID_SHA256
            || out.doc_id_bytes != DOC_ID_BYTES as u16
            || out.state_delta_bytes != STATE_DELTA_BYTES as u16
            || out.dim != DIM_V1
            || out.coord_type != COORD_TYPE_I16
        {
            return Err(CodexError::IntegrityError("LEDGER_HEADER_MISMATCH"));
        }
        if out.reserved.iter().any(|b| *b != 0) {
            return Err(CodexError::IntegrityError("LEDGER_HEADER_RESERVED_NONZERO"));
        }
        if (out.flags & FEATURE_SCORE_COMMITMENT) != 0
            && (out.flags & FEATURE_RECURSIVE_PROJECTION) == 0
        {
            return Err(CodexError::InvalidInput(
                "SCORE_COMMITMENT_REQUIRES_QUERY_BYTES",
            ));
        }
        if (out.flags & FEATURE_SCORE_PROOFS) != 0 && (out.flags & FEATURE_SCORE_COMMITMENT) == 0 {
            return Err(CodexError::InvalidInput(
                "SCORE_PROOFS_REQUIRES_SCORE_COMMITMENT",
            ));
        }
        out.verify_commitment()?;
        Ok(out)
    }

    pub fn verify_commitment(&self) -> Result<(), CodexError> {
        let expected = self.compute_commitment();
        if self.header_commitment == expected {
            Ok(())
        } else {
            Err(CodexError::IntegrityError(
                "LEDGER_HEADER_COMMITMENT_MISMATCH",
            ))
        }
    }
}
