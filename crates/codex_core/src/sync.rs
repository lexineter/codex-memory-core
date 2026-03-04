use crate::mmr::Mmr;
use crate::{CodexError, HASH_LEN};

pub fn find_divergence_index(
    local_mmr: &Mmr,
    remote_root: [u8; HASH_LEN],
    remote_event_count: u64,
) -> Result<Option<u64>, CodexError> {
    let local_count = local_mmr.len();
    let local_root = local_mmr.root();
    if local_count == remote_event_count && local_root == remote_root {
        return Ok(None);
    }

    let min_count = core::cmp::min(local_count, remote_event_count);
    if local_count >= remote_event_count {
        let local_prefix_root = local_mmr.root_at(remote_event_count)?;
        if local_prefix_root == remote_root {
            return Ok(Some(remote_event_count));
        }
    }
    Ok(Some(min_count))
}
