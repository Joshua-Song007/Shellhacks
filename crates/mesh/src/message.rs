//! FR-M-2, DATA-3: signed mesh message {Threat_ID, gene_hash, sender_pubkey,
//! seq, ts, signature}. Signing/verifying the cryptography only -- whether
//! the sender is a paired, non-revoked device (FR-M-5) is verify.rs's job,
//! kept separate on purpose.

use libp2p::identity::PublicKey;
use serde::{Deserialize, Serialize};

use crate::identity::Identity;

/// `sender_pubkey`/`signature` are raw bytes (protobuf-encoded PublicKey /
/// raw Ed25519 signature), not libp2p types directly -- `PublicKey` has no
/// serde impl.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CureHint {
    pub threat_id: [u8; 32],
    pub gene_hash: [u8; 32],
    pub sender_pubkey: Vec<u8>,
    pub seq: u64,
    pub ts_ms: u64,
    pub signature: Vec<u8>,
}

impl CureHint {
    /// FR-M-2: signs {threat_id, gene_hash, seq, ts_ms} with `sender`'s
    /// persistent identity key -- the same one transport.rs uses for its
    /// PeerId/Noise static key (identity.rs), not a second signing key.
    pub fn sign(sender: &Identity, threat_id: [u8; 32], gene_hash: [u8; 32], seq: u64) -> Self {
        let ts_ms = now_ms();
        let signed_bytes = Self::signed_bytes(&threat_id, &gene_hash, seq, ts_ms);
        let signature = sender.keypair().sign(&signed_bytes).expect("ed25519 signing does not fail");
        Self { threat_id, gene_hash, sender_pubkey: sender.public().encode_protobuf(), seq, ts_ms, signature }
    }

    /// FR-M-5(a): verifies `signature` against `sender_pubkey` over the
    /// same canonical bytes `sign` produced. Only checks the cryptography
    /// -- not whether `sender_pubkey` belongs to a paired/non-revoked
    /// device (verify.rs).
    pub fn signature_valid(&self) -> bool {
        let Some(pubkey) = self.sender_public_key() else { return false };
        let signed_bytes = Self::signed_bytes(&self.threat_id, &self.gene_hash, self.seq, self.ts_ms);
        pubkey.verify(&signed_bytes, &self.signature)
    }

    pub fn sender_public_key(&self) -> Option<PublicKey> {
        PublicKey::try_decode_protobuf(&self.sender_pubkey).ok()
    }

    fn signed_bytes(threat_id: &[u8; 32], gene_hash: &[u8; 32], seq: u64, ts_ms: u64) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32 + 32 + 8 + 8);
        buf.extend_from_slice(threat_id);
        buf.extend_from_slice(gene_hash);
        buf.extend_from_slice(&seq.to_le_bytes());
        buf.extend_from_slice(&ts_ms.to_le_bytes());
        buf
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_identity() -> Identity {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.key");
        let identity = Identity::load_or_generate(&path).unwrap();
        std::mem::forget(dir);
        identity
    }

    #[test]
    fn a_freshly_signed_hint_verifies() {
        let sender = temp_identity();
        let hint = CureHint::sign(&sender, [1u8; 32], [2u8; 32], 7);
        assert!(hint.signature_valid());
    }

    #[test]
    fn tampering_with_threat_id_invalidates_the_signature() {
        let mut hint = CureHint::sign(&temp_identity(), [1u8; 32], [2u8; 32], 7);
        hint.threat_id[0] ^= 0xFF;
        assert!(!hint.signature_valid());
    }

    #[test]
    fn tampering_with_gene_hash_invalidates_the_signature() {
        let mut hint = CureHint::sign(&temp_identity(), [1u8; 32], [2u8; 32], 7);
        hint.gene_hash[0] ^= 0xFF;
        assert!(!hint.signature_valid());
    }

    #[test]
    fn tampering_with_seq_invalidates_the_signature() {
        let mut hint = CureHint::sign(&temp_identity(), [1u8; 32], [2u8; 32], 7);
        hint.seq += 1;
        assert!(!hint.signature_valid());
    }

    #[test]
    fn tampering_with_ts_invalidates_the_signature() {
        let mut hint = CureHint::sign(&temp_identity(), [1u8; 32], [2u8; 32], 7);
        hint.ts_ms += 1;
        assert!(!hint.signature_valid());
    }

    #[test]
    fn substituting_a_different_signers_pubkey_invalidates_the_signature() {
        let mut hint = CureHint::sign(&temp_identity(), [1u8; 32], [2u8; 32], 7);
        hint.sender_pubkey = temp_identity().public().encode_protobuf();
        assert!(!hint.signature_valid());
    }

    #[test]
    fn tampering_with_the_signature_bytes_invalidates_it() {
        let mut hint = CureHint::sign(&temp_identity(), [1u8; 32], [2u8; 32], 7);
        hint.signature[0] ^= 0xFF;
        assert!(!hint.signature_valid());
    }

    #[test]
    fn serde_json_round_trips_all_fields() {
        let hint = CureHint::sign(&temp_identity(), [3u8; 32], [4u8; 32], 42);
        let json = serde_json::to_string(&hint).unwrap();
        let back: CureHint = serde_json::from_str(&json).unwrap();
        assert_eq!(back.threat_id, hint.threat_id);
        assert_eq!(back.gene_hash, hint.gene_hash);
        assert_eq!(back.sender_pubkey, hint.sender_pubkey);
        assert_eq!(back.seq, hint.seq);
        assert_eq!(back.ts_ms, hint.ts_ms);
        assert_eq!(back.signature, hint.signature);
        assert!(back.signature_valid());
    }
}
