//! Cryptographic primitives for `veryverysecure`.
//!
//! This crate implements only the two envelope-encryption primitives that the
//! rest of the KMS composes on top of:
//!
//! 1. **Wrap / unwrap of a user's private key with a KEK** via
//!    XChaCha20-Poly1305 (random 24-byte nonce prefixed to the ciphertext).
//! 2. **Seal / open of a DEK to a user's X25519 public key** via
//!    `crypto_box` sealed boxes (X25519 + XSalsa20-Poly1305 with an
//!    ephemeral sender key, as in libsodium's `crypto_box_seal`).
//!
//! Design invariants:
//!
//! - Secret material (`Kek`, `Dek`, `UserPriv`) never appears in `Debug`
//!   output. It is zeroized on drop.
//! - Decryption failures collapse to a single opaque `Decrypt` error to avoid
//!   leaking oracle bits about nonce, tag, or key material.
//! - All fixed-length wire formats are exposed as `pub const` so callers can
//!   size buffers and DB columns without guessing.
//!
//! What this crate intentionally does **not** do: symmetric encryption of
//! secret values with a DEK (that's a higher layer), row-level authenticity
//! bindings, Shamir secret sharing, or any persistence.

#![forbid(unsafe_code)]

use std::fmt;

use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Key as ChaChaKey, XChaCha20Poly1305, XNonce,
};
use crypto_box::{PublicKey, SecretKey};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Length of a KEK in bytes.
pub const KEK_LEN: usize = 32;
/// Length of a DEK in bytes.
pub const DEK_LEN: usize = 32;
/// Length of an X25519 private key in bytes.
pub const USER_PRIV_LEN: usize = 32;
/// Length of an X25519 public key in bytes.
pub const USER_PUB_LEN: usize = 32;

/// XChaCha20-Poly1305 nonce length.
pub const XCHACHA_NONCE_LEN: usize = 24;
/// Poly1305 authentication tag length.
pub const AEAD_TAG_LEN: usize = 16;

/// Length of a KEK-wrapped `UserPriv`: `nonce || ciphertext || tag`.
pub const WRAPPED_USER_PRIV_LEN: usize =
    XCHACHA_NONCE_LEN + USER_PRIV_LEN + AEAD_TAG_LEN;

/// Length of the ephemeral public key prepended to a sealed box.
pub const SEALED_EPHEMERAL_PUB_LEN: usize = 32;
/// Length of a sealed DEK: `ephemeral_pub || ciphertext || tag`.
pub const SEALED_DEK_LEN: usize =
    SEALED_EPHEMERAL_PUB_LEN + DEK_LEN + AEAD_TAG_LEN;

/// Errors produced by this crate.
///
/// All decryption failures — wrong key, tampered ciphertext, tampered nonce,
/// tampered ephemeral pubkey, unsupported plaintext length — collapse into
/// `Decrypt` to avoid leaking information to an attacker.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// Input buffer was not the expected fixed size.
    #[error("invalid length: expected {expected}, got {actual}")]
    InvalidLength {
        /// The length the API required.
        expected: usize,
        /// The length that was actually provided.
        actual: usize,
    },
    /// AEAD decryption / authentication failed.
    #[error("decryption failed")]
    Decrypt,
    /// AEAD encryption failed (in practice only on RNG or allocator failure).
    #[error("encryption failed")]
    Encrypt,
}

macro_rules! secret_newtype {
    ($name:ident, $len:expr, $label:literal) => {
        /// Secret key material. Zeroized on drop; `Debug` output is redacted.
        #[derive(Clone, Zeroize, ZeroizeOnDrop)]
        pub struct $name {
            bytes: [u8; $len],
        }

        impl $name {
            /// Wrap an existing byte array as this secret.
            pub fn from_bytes(bytes: [u8; $len]) -> Self {
                Self { bytes }
            }

            /// Borrow the raw bytes. Callers are responsible for not letting
            /// these bytes escape into logs or long-lived copies.
            pub fn as_bytes(&self) -> &[u8; $len] {
                &self.bytes
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!($label, "(<redacted>)"))
            }
        }
    };
}

secret_newtype!(Kek, KEK_LEN, "Kek");
secret_newtype!(Dek, DEK_LEN, "Dek");
secret_newtype!(UserPriv, USER_PRIV_LEN, "UserPriv");

impl Dek {
    /// Generate a cryptographically random DEK.
    pub fn generate() -> Self {
        let key = XChaCha20Poly1305::generate_key(&mut OsRng);
        let mut bytes = [0u8; DEK_LEN];
        bytes.copy_from_slice(key.as_slice());
        Self { bytes }
    }
}

/// An X25519 public key. Not secret; normal `Debug` impl.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserPub {
    bytes: [u8; USER_PUB_LEN],
}

impl UserPub {
    /// Construct from an explicit 32-byte array.
    pub fn from_bytes(bytes: [u8; USER_PUB_LEN]) -> Self {
        Self { bytes }
    }

    /// Borrow the raw bytes.
    pub fn as_bytes(&self) -> &[u8; USER_PUB_LEN] {
        &self.bytes
    }
}

/// Generate a fresh X25519 keypair for a user.
pub fn generate_user_keypair() -> (UserPriv, UserPub) {
    let sk = SecretKey::generate(&mut OsRng);
    let pk = sk.public_key();
    let priv_bytes = sk.to_bytes();
    let pub_bytes = *pk.as_bytes();
    (UserPriv::from_bytes(priv_bytes), UserPub::from_bytes(pub_bytes))
}

/// Derive the X25519 public key from a private key. Useful for rewrap flows
/// that want to verify the unwrapped private key still matches the stored
/// public key, and for tests.
pub fn user_pub_from_priv(priv_: &UserPriv) -> UserPub {
    let sk = SecretKey::from_bytes(*priv_.as_bytes());
    let pk = sk.public_key();
    UserPub::from_bytes(*pk.as_bytes())
}

/// Wrap a user's private key under a KEK.
///
/// Output layout: `nonce(24) || ciphertext(32) || tag(16)` = 72 bytes.
pub fn wrap_user_priv(kek: &Kek, priv_: &UserPriv) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(ChaChaKey::from_slice(kek.as_bytes()));
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ct = cipher
        .encrypt(&nonce, priv_.as_bytes().as_ref())
        .map_err(|_| CryptoError::Encrypt)?;

    let mut out = Vec::with_capacity(WRAPPED_USER_PRIV_LEN);
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(&ct);
    debug_assert_eq!(out.len(), WRAPPED_USER_PRIV_LEN);
    Ok(out)
}

/// Unwrap a KEK-wrapped private key.
pub fn unwrap_user_priv(kek: &Kek, wrapped: &[u8]) -> Result<UserPriv, CryptoError> {
    if wrapped.len() != WRAPPED_USER_PRIV_LEN {
        return Err(CryptoError::InvalidLength {
            expected: WRAPPED_USER_PRIV_LEN,
            actual: wrapped.len(),
        });
    }
    let (nonce_bytes, ct) = wrapped.split_at(XCHACHA_NONCE_LEN);
    let nonce = XNonce::from_slice(nonce_bytes);
    let cipher = XChaCha20Poly1305::new(ChaChaKey::from_slice(kek.as_bytes()));

    let pt = Zeroizing::new(
        cipher.decrypt(nonce, ct).map_err(|_| CryptoError::Decrypt)?,
    );
    if pt.len() != USER_PRIV_LEN {
        return Err(CryptoError::Decrypt);
    }
    let mut out = [0u8; USER_PRIV_LEN];
    out.copy_from_slice(&pt);
    let priv_ = UserPriv::from_bytes(out);
    out.zeroize();
    Ok(priv_)
}

/// Seal a DEK to a recipient's public key. Anyone can seal; only the holder
/// of the matching private key can open.
///
/// Output layout: `ephemeral_pub(32) || ciphertext(32) || tag(16)` = 80 bytes.
pub fn seal_dek(recipient: &UserPub, dek: &Dek) -> Result<Vec<u8>, CryptoError> {
    let pk = PublicKey::from_bytes(*recipient.as_bytes());
    let ct = pk
        .seal(&mut OsRng, dek.as_bytes().as_ref())
        .map_err(|_| CryptoError::Encrypt)?;
    debug_assert_eq!(ct.len(), SEALED_DEK_LEN);
    Ok(ct)
}

/// Open a sealed DEK with the recipient's private key.
pub fn open_dek(recipient_priv: &UserPriv, sealed: &[u8]) -> Result<Dek, CryptoError> {
    if sealed.len() != SEALED_DEK_LEN {
        return Err(CryptoError::InvalidLength {
            expected: SEALED_DEK_LEN,
            actual: sealed.len(),
        });
    }
    let sk = SecretKey::from_bytes(*recipient_priv.as_bytes());
    let pt = Zeroizing::new(sk.unseal(sealed).map_err(|_| CryptoError::Decrypt)?);
    if pt.len() != DEK_LEN {
        return Err(CryptoError::Decrypt);
    }
    let mut out = [0u8; DEK_LEN];
    out.copy_from_slice(&pt);
    let dek = Dek::from_bytes(out);
    out.zeroize();
    Ok(dek)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_kek() -> Kek {
        let key = XChaCha20Poly1305::generate_key(&mut OsRng);
        let mut bytes = [0u8; KEK_LEN];
        bytes.copy_from_slice(key.as_slice());
        Kek::from_bytes(bytes)
    }

    // ---------- length invariants ----------

    #[test]
    fn wrapped_user_priv_has_expected_length() {
        let kek = fresh_kek();
        let (priv_, _pub_) = generate_user_keypair();
        let wrapped = wrap_user_priv(&kek, &priv_).unwrap();
        assert_eq!(wrapped.len(), WRAPPED_USER_PRIV_LEN);
        assert_eq!(WRAPPED_USER_PRIV_LEN, 72);
    }

    #[test]
    fn sealed_dek_has_expected_length() {
        let (_sk, pk) = generate_user_keypair();
        let dek = Dek::generate();
        let sealed = seal_dek(&pk, &dek).unwrap();
        assert_eq!(sealed.len(), SEALED_DEK_LEN);
        assert_eq!(SEALED_DEK_LEN, 80);
    }

    // ---------- round trips ----------

    #[test]
    fn wrap_unwrap_round_trip_preserves_priv_bytes() {
        let kek = fresh_kek();
        let (priv_, pub_) = generate_user_keypair();
        let wrapped = wrap_user_priv(&kek, &priv_).unwrap();
        let recovered = unwrap_user_priv(&kek, &wrapped).unwrap();
        assert_eq!(recovered.as_bytes(), priv_.as_bytes());
        // And the derived pubkey still matches, i.e. we really recovered the
        // same scalar and not just 32 random bytes.
        assert_eq!(user_pub_from_priv(&recovered), pub_);
    }

    #[test]
    fn seal_open_round_trip_preserves_dek_bytes() {
        let (sk, pk) = generate_user_keypair();
        let dek = Dek::generate();
        let sealed = seal_dek(&pk, &dek).unwrap();
        let recovered = open_dek(&sk, &sealed).unwrap();
        assert_eq!(recovered.as_bytes(), dek.as_bytes());
    }

    // ---------- wrong keys ----------

    #[test]
    fn unwrap_with_wrong_kek_fails_decrypt() {
        let kek1 = fresh_kek();
        let kek2 = fresh_kek();
        let (priv_, _pub_) = generate_user_keypair();
        let wrapped = wrap_user_priv(&kek1, &priv_).unwrap();
        let err = unwrap_user_priv(&kek2, &wrapped).unwrap_err();
        assert!(matches!(err, CryptoError::Decrypt));
    }

    #[test]
    fn open_with_wrong_user_priv_fails_decrypt() {
        let (_sk_a, pk_a) = generate_user_keypair();
        let (sk_b, _pk_b) = generate_user_keypair();
        let dek = Dek::generate();
        let sealed = seal_dek(&pk_a, &dek).unwrap();
        let err = open_dek(&sk_b, &sealed).unwrap_err();
        assert!(matches!(err, CryptoError::Decrypt));
    }

    // ---------- tamper detection ----------

    #[test]
    fn tampering_wrapped_ciphertext_fails() {
        let kek = fresh_kek();
        let (priv_, _pub_) = generate_user_keypair();
        let mut wrapped = wrap_user_priv(&kek, &priv_).unwrap();
        // Flip a bit in the ciphertext region (past the 24-byte nonce).
        wrapped[XCHACHA_NONCE_LEN + 3] ^= 0x01;
        let err = unwrap_user_priv(&kek, &wrapped).unwrap_err();
        assert!(matches!(err, CryptoError::Decrypt));
    }

    #[test]
    fn tampering_wrapped_nonce_fails() {
        let kek = fresh_kek();
        let (priv_, _pub_) = generate_user_keypair();
        let mut wrapped = wrap_user_priv(&kek, &priv_).unwrap();
        wrapped[0] ^= 0x01;
        let err = unwrap_user_priv(&kek, &wrapped).unwrap_err();
        assert!(matches!(err, CryptoError::Decrypt));
    }

    #[test]
    fn tampering_wrapped_tag_fails() {
        let kek = fresh_kek();
        let (priv_, _pub_) = generate_user_keypair();
        let mut wrapped = wrap_user_priv(&kek, &priv_).unwrap();
        let last = wrapped.len() - 1;
        wrapped[last] ^= 0x01;
        let err = unwrap_user_priv(&kek, &wrapped).unwrap_err();
        assert!(matches!(err, CryptoError::Decrypt));
    }

    #[test]
    fn tampering_sealed_ephemeral_pub_fails() {
        let (sk, pk) = generate_user_keypair();
        let dek = Dek::generate();
        let mut sealed = seal_dek(&pk, &dek).unwrap();
        // The first 32 bytes are the ephemeral public key.
        sealed[0] ^= 0x01;
        let err = open_dek(&sk, &sealed).unwrap_err();
        assert!(matches!(err, CryptoError::Decrypt));
    }

    #[test]
    fn tampering_sealed_ciphertext_fails() {
        let (sk, pk) = generate_user_keypair();
        let dek = Dek::generate();
        let mut sealed = seal_dek(&pk, &dek).unwrap();
        sealed[SEALED_EPHEMERAL_PUB_LEN + 1] ^= 0x01;
        let err = open_dek(&sk, &sealed).unwrap_err();
        assert!(matches!(err, CryptoError::Decrypt));
    }

    #[test]
    fn tampering_sealed_tag_fails() {
        let (sk, pk) = generate_user_keypair();
        let dek = Dek::generate();
        let mut sealed = seal_dek(&pk, &dek).unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        let err = open_dek(&sk, &sealed).unwrap_err();
        assert!(matches!(err, CryptoError::Decrypt));
    }

    // ---------- wrong length ----------

    #[test]
    fn unwrap_rejects_short_input_with_invalid_length() {
        let kek = fresh_kek();
        let err = unwrap_user_priv(&kek, &[0u8; WRAPPED_USER_PRIV_LEN - 1]).unwrap_err();
        match err {
            CryptoError::InvalidLength { expected, actual } => {
                assert_eq!(expected, WRAPPED_USER_PRIV_LEN);
                assert_eq!(actual, WRAPPED_USER_PRIV_LEN - 1);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn unwrap_rejects_long_input_with_invalid_length() {
        let kek = fresh_kek();
        let err = unwrap_user_priv(&kek, &[0u8; WRAPPED_USER_PRIV_LEN + 1]).unwrap_err();
        assert!(matches!(err, CryptoError::InvalidLength { .. }));
    }

    #[test]
    fn open_rejects_wrong_length_with_invalid_length() {
        let (sk, _pk) = generate_user_keypair();
        let err = open_dek(&sk, &[0u8; SEALED_DEK_LEN - 1]).unwrap_err();
        assert!(matches!(err, CryptoError::InvalidLength { .. }));
    }

    // ---------- randomness ----------

    #[test]
    fn wrap_is_nondeterministic() {
        let kek = fresh_kek();
        let (priv_, _pub_) = generate_user_keypair();
        let w1 = wrap_user_priv(&kek, &priv_).unwrap();
        let w2 = wrap_user_priv(&kek, &priv_).unwrap();
        assert_ne!(w1, w2, "two wraps should use different nonces");
    }

    #[test]
    fn seal_is_nondeterministic() {
        let (_sk, pk) = generate_user_keypair();
        let dek = Dek::generate();
        let s1 = seal_dek(&pk, &dek).unwrap();
        let s2 = seal_dek(&pk, &dek).unwrap();
        assert_ne!(s1, s2, "two seals should use different ephemeral keys");
    }

    #[test]
    fn dek_generate_returns_distinct_values() {
        let a = Dek::generate();
        let b = Dek::generate();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    // ---------- keypair consistency ----------

    #[test]
    fn generated_pub_matches_pub_derived_from_priv() {
        for _ in 0..8 {
            let (priv_, pub_) = generate_user_keypair();
            assert_eq!(user_pub_from_priv(&priv_), pub_);
        }
    }

    // ---------- debug redaction ----------

    #[test]
    fn kek_debug_is_redacted() {
        let kek = Kek::from_bytes([0xAB; KEK_LEN]);
        let s = format!("{kek:?}");
        assert_eq!(s, "Kek(<redacted>)");
        assert!(!s.contains("ab"));
        assert!(!s.contains("AB"));
    }

    #[test]
    fn dek_debug_is_redacted() {
        let dek = Dek::from_bytes([0xCD; DEK_LEN]);
        let s = format!("{dek:?}");
        assert_eq!(s, "Dek(<redacted>)");
        assert!(!s.contains("cd"));
    }

    #[test]
    fn user_priv_debug_is_redacted() {
        let p = UserPriv::from_bytes([0xEF; USER_PRIV_LEN]);
        let s = format!("{p:?}");
        assert_eq!(s, "UserPriv(<redacted>)");
        assert!(!s.contains("ef"));
    }

    // ---------- user pub round trip ----------

    #[test]
    fn user_pub_from_to_bytes_round_trip() {
        let bytes = [0x42; USER_PUB_LEN];
        let p = UserPub::from_bytes(bytes);
        assert_eq!(p.as_bytes(), &bytes);
    }
}
