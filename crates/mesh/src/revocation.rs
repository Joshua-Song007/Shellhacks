//! FR-M-7: identity keys are long-lived -- identity.rs never rotates a
//! device's keypair on a schedule (no such code path exists there, so
//! that half of FR-M-7 is satisfied by omission). This file is the other
//! half: compromise is handled by revocation, not rotation.

use libp2p::identity::PublicKey;

/// A CRL-style list, not a deletion from `identity::Roster` -- a device
/// can be simultaneously "known" (still in the roster) and "revoked"
/// (checked separately by verify.rs). FR-M-7's "+ optional re-attestation"
/// needs no code here: re-attestation is just a fresh `PairingCode`/
/// `Roster::redeem` (identity.rs) under the normal pairing flow; a revoked
/// key is simply rejected by verify.rs going forward.
#[derive(Default)]
pub struct RevocationList {
    revoked: Vec<PublicKey>,
}

impl RevocationList {
    pub fn new() -> Self {
        Self::default()
    }

    /// Marks `key` as compromised. Idempotent: more than one peer might
    /// report the same compromise, so revoking twice is a no-op, not an
    /// error or a duplicate entry.
    pub fn revoke(&mut self, key: PublicKey) {
        if !self.revoked.contains(&key) {
            self.revoked.push(key);
        }
    }

    pub fn is_revoked(&self, key: &PublicKey) -> bool {
        self.revoked.contains(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair() -> PublicKey {
        libp2p::identity::Keypair::generate_ed25519().public()
    }

    #[test]
    fn a_revoked_key_is_reported_revoked() {
        let key = keypair();
        let mut list = RevocationList::new();
        list.revoke(key.clone());
        assert!(list.is_revoked(&key));
    }

    #[test]
    fn a_never_revoked_key_is_not_revoked() {
        let key = keypair();
        let list = RevocationList::new();
        assert!(!list.is_revoked(&key));
    }

    #[test]
    fn revoking_the_same_key_twice_does_not_duplicate() {
        let key = keypair();
        let mut list = RevocationList::new();
        list.revoke(key.clone());
        list.revoke(key.clone());
        assert_eq!(list.revoked.len(), 1);
    }
}
