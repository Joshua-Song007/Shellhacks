//! FR-M-1: per-device Ed25519 identity, one-time OOB pairing codes (<=5min
//! expiry), and a local "household" roster of paired peers' public keys.
//! NFR-4 ("SHOULD be stored in macOS Keychain/Secure Enclave") is NOT
//! implemented -- MVP simplification, a plain owner-only-permission file
//! instead; NFR-4 is SHOULD not MUST, revisit only if Keychain integration
//! (needs the `security-framework` crate) becomes worth the time.

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::{Duration, Instant};

use libp2p::identity::{Keypair, PeerId, PublicKey};
use rand::RngCore;

const PAIRING_TTL: Duration = Duration::from_secs(5 * 60);

/// The same keypair serves double duty as (a) transport.rs's libp2p
/// identity (PeerId, Noise static key) and (b) message.rs's future
/// message-signing key (FR-M-2) -- one identity per device, not two.
pub struct Identity {
    keypair: Keypair,
}

impl Identity {
    /// Loads the persisted Ed25519 keypair at `path`, or generates one and
    /// persists it (0600) if none exists yet. Same identity every restart
    /// -- PeerId (and later, message.rs's signing key) must stay stable.
    pub fn load_or_generate(path: &Path) -> io::Result<Self> {
        if path.exists() {
            let bytes = fs::read(path)?;
            let keypair = Keypair::from_protobuf_encoding(&bytes).map_err(io::Error::other)?;
            return Ok(Self { keypair });
        }
        let keypair = Keypair::generate_ed25519();
        let bytes = keypair.to_protobuf_encoding().map_err(io::Error::other)?;
        fs::write(path, &bytes)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        Ok(Self { keypair })
    }

    pub fn keypair(&self) -> &Keypair {
        &self.keypair
    }

    pub fn peer_id(&self) -> PeerId {
        self.keypair.public().to_peer_id()
    }

    pub fn public(&self) -> PublicKey {
        self.keypair.public()
    }
}

/// FR-M-1: a one-time out-of-band pairing code, valid for <=5 minutes.
/// QR-code *rendering* is the dashboard's job (Phase 8, untouched here) --
/// this only generates/validates the secret+expiry a QR would encode.
pub struct PairingCode {
    nonce: [u8; 16],
    issuer: PublicKey,
    expires_at: Instant,
}

impl PairingCode {
    pub fn generate(issuer: &Identity) -> Self {
        Self::with_ttl(issuer, PAIRING_TTL)
    }

    /// Test hook: same as `generate` but with an injectable TTL, so expiry
    /// can be exercised without a real 5-minute sleep.
    pub fn with_ttl(issuer: &Identity, ttl: Duration) -> Self {
        let mut nonce = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut nonce);
        Self { nonce, issuer: issuer.public(), expires_at: Instant::now() + ttl }
    }

    pub fn is_expired(&self) -> bool {
        Instant::now() > self.expires_at
    }

    pub fn nonce(&self) -> [u8; 16] {
        self.nonce
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum PairingError {
    Expired,
    NonceMismatch,
}

/// FR-M-1: "the household SHALL record every device's public key" -- a
/// local baseline roster. Anchoring it on-chain is FR-M-9 (MAY/stretch),
/// not this.
#[derive(Default)]
pub struct Roster {
    paired: Vec<PublicKey>,
}

impl Roster {
    pub fn new() -> Self {
        Self::default()
    }

    /// Redeems `code` against the nonce presented over the OOB channel.
    /// Constant-time compare so a mistyped/observed-in-transit code can't
    /// be brute-forced faster via early-exit timing. Redeeming the same
    /// issuer again is a no-op, not a duplicate roster entry.
    pub fn redeem(&mut self, code: &PairingCode, presented_nonce: &[u8; 16]) -> Result<(), PairingError> {
        if code.is_expired() {
            return Err(PairingError::Expired);
        }
        if !constant_time_eq(&code.nonce, presented_nonce) {
            return Err(PairingError::NonceMismatch);
        }
        if !self.paired.contains(&code.issuer) {
            self.paired.push(code.issuer.clone());
        }
        Ok(())
    }

    pub fn paired(&self) -> &[PublicKey] {
        &self.paired
    }

    /// Issuer-side counterpart to `redeem`: `code` was generated locally
    /// (`code.issuer` is always this device's own key), and `presenter` is
    /// whoever presented `presented_nonce` over the wire -- so this records
    /// `presenter`, not `code.issuer`. Same expiry/constant-time checks.
    pub fn admit(&mut self, code: &PairingCode, presented_nonce: &[u8; 16], presenter: PublicKey) -> Result<(), PairingError> {
        if code.is_expired() {
            return Err(PairingError::Expired);
        }
        if !constant_time_eq(&code.nonce, presented_nonce) {
            return Err(PairingError::NonceMismatch);
        }
        if !self.paired.contains(&presenter) {
            self.paired.push(presenter);
        }
        Ok(())
    }

    /// Raw, ceremony-free insert: restoring a persisted roster on startup,
    /// or recording a peer's self-attested (and PeerId-verified) pubkey
    /// after a successful pairing response -- neither has a `PairingCode`
    /// to run through `redeem`/`admit`. Push-if-absent, like both of those.
    pub fn add_trusted(&mut self, key: PublicKey) {
        if !self.paired.contains(&key) {
            self.paired.push(key);
        }
    }
}

fn constant_time_eq(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_identity() -> Identity {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.key");
        let identity = Identity::load_or_generate(&path).unwrap();
        std::mem::forget(dir); // keep the tempdir alive for the identity's lifetime in these short-lived tests
        identity
    }

    #[test]
    fn load_or_generate_persists_and_reloads_the_same_identity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.key");
        let a = Identity::load_or_generate(&path).unwrap();
        let b = Identity::load_or_generate(&path).unwrap();
        assert_eq!(a.peer_id(), b.peer_id(), "second load must reuse the persisted key, not generate a new one");
    }

    #[test]
    fn a_freshly_generated_pairing_code_is_not_expired() {
        let code = PairingCode::generate(&temp_identity());
        assert!(!code.is_expired());
    }

    #[test]
    fn a_pairing_code_past_its_ttl_is_expired() {
        let code = PairingCode::with_ttl(&temp_identity(), Duration::from_millis(1));
        std::thread::sleep(Duration::from_millis(20));
        assert!(code.is_expired());
    }

    #[test]
    fn roster_redeem_accepts_a_valid_code_once() {
        let issuer = temp_identity();
        let code = PairingCode::generate(&issuer);
        let mut roster = Roster::new();
        roster.redeem(&code, &code.nonce()).unwrap();
        assert_eq!(roster.paired().len(), 1);
        assert_eq!(roster.paired()[0], issuer.public());
    }

    #[test]
    fn roster_redeem_rejects_a_wrong_nonce() {
        let code = PairingCode::generate(&temp_identity());
        let mut roster = Roster::new();
        assert_eq!(roster.redeem(&code, &[0u8; 16]), Err(PairingError::NonceMismatch));
        assert!(roster.paired().is_empty());
    }

    #[test]
    fn roster_redeem_rejects_an_expired_code() {
        let code = PairingCode::with_ttl(&temp_identity(), Duration::from_millis(1));
        std::thread::sleep(Duration::from_millis(20));
        let mut roster = Roster::new();
        assert_eq!(roster.redeem(&code, &code.nonce()), Err(PairingError::Expired));
    }

    #[test]
    fn redeeming_the_same_issuer_twice_does_not_duplicate() {
        let issuer = temp_identity();
        let mut roster = Roster::new();
        let code1 = PairingCode::generate(&issuer);
        roster.redeem(&code1, &code1.nonce()).unwrap();
        let code2 = PairingCode::generate(&issuer);
        roster.redeem(&code2, &code2.nonce()).unwrap();
        assert_eq!(roster.paired().len(), 1);
    }

    #[test]
    fn admit_accepts_a_valid_presenter_once() {
        let owner = temp_identity();
        let presenter = temp_identity();
        let code = PairingCode::generate(&owner);
        let mut roster = Roster::new();
        roster.admit(&code, &code.nonce(), presenter.public()).unwrap();
        assert_eq!(roster.paired(), [presenter.public()], "admit records the presenter, not code.issuer");
    }

    #[test]
    fn admit_rejects_a_wrong_nonce() {
        let owner = temp_identity();
        let presenter = temp_identity();
        let code = PairingCode::generate(&owner);
        let mut roster = Roster::new();
        assert_eq!(roster.admit(&code, &[0u8; 16], presenter.public()), Err(PairingError::NonceMismatch));
        assert!(roster.paired().is_empty());
    }

    #[test]
    fn admit_rejects_an_expired_code() {
        let owner = temp_identity();
        let presenter = temp_identity();
        let code = PairingCode::with_ttl(&owner, Duration::from_millis(1));
        std::thread::sleep(Duration::from_millis(20));
        let mut roster = Roster::new();
        assert_eq!(roster.admit(&code, &code.nonce(), presenter.public()), Err(PairingError::Expired));
    }

    #[test]
    fn admitting_the_same_presenter_twice_does_not_duplicate() {
        let owner = temp_identity();
        let presenter = temp_identity();
        let mut roster = Roster::new();
        let code1 = PairingCode::generate(&owner);
        roster.admit(&code1, &code1.nonce(), presenter.public()).unwrap();
        let code2 = PairingCode::generate(&owner);
        roster.admit(&code2, &code2.nonce(), presenter.public()).unwrap();
        assert_eq!(roster.paired().len(), 1);
    }

    #[test]
    fn add_trusted_dedups_on_repeat() {
        let key = temp_identity().public();
        let mut roster = Roster::new();
        roster.add_trusted(key.clone());
        roster.add_trusted(key.clone());
        assert_eq!(roster.paired(), [key]);
    }
}
