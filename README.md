# veryverysecure

A single-server REST Key Management System (KMS) in Rust implementing envelope encryption with a zero-server-knowledge property: a full database dump is cryptographically useless without per-user client-held keys.

## Threat Model

**Protected against:**
- Database dump / backup theft
- Disk snapshot
- Rogue database administrator
- Passive network observer (TLS)

**Out of scope:**
- Hoster with live process memory access (KEK transits RAM on every request)
- Compromised TLS termination

The core invariant: no server-side master secret exists. There is no startup passphrase, no server-held root key, no key derivation that the server could perform autonomously. Every sensitive value in the database is encrypted by a key that never leaves the client.

## Cryptographic Design

### Key Hierarchy

```
Client                          Server DB
──────                          ─────────
KEK (32 random bytes)
  │
  └─XChaCha20-Poly1305──►  UserServerPrivEnc  ◄── nonce prepended
                             UserServerPub      (plaintext, public by nature)
                               │
                               └─SealedBox──►  ValueEnc (per Permission row)
                                               └── contains plaintext DEK
```

Three key types:

- **KEK** (Key Encryption Key): 32 bytes from a CSPRNG. Generated and stored by the client. Never transmitted except in-request over TLS. Never persisted server-side.
- **UserServerPriv / UserServerPub**: An X25519 keypair generated at registration. The public key is stored plaintext. The private key is encrypted under the KEK using XChaCha20-Poly1305 and stored as `nonce || ciphertext`.
- **DEK** (Data Encryption Key): 32 bytes from a CSPRNG. The actual value the user stores in the KMS. Encrypted per-user under their X25519 public key via `SealedBox`.

### Algorithms

| Operation | Algorithm | Crate |
|---|---|---|
| Wrap/unwrap `UserServerPriv` | XChaCha20-Poly1305 | `chacha20poly1305` |
| Encrypt/decrypt DEK per user | X25519 + XSalsa20-Poly1305 (`SealedBox`) | `crypto_box` |
| Key generation | `OsRng` | `rand` |
| Secret zeroing | `ZeroizeOnDrop` | `zeroize` |

**Why XChaCha20 over AES-256-GCM:** 192-bit nonce makes random nonce generation unconditionally safe (birthday bound at 2^96 vs 2^48 for AES-GCM's 96-bit nonce). Constant-time in software without AES-NI.

**Why SealedBox over RSA-OAEP:** 32-byte keys vs 256-512 bytes, µs-range operations vs ms-range, constant-time by construction, no padding oracle attack surface.

### Authentication

There are no passwords or password hashes stored. Authentication is implicit in decryption: the server attempts `XChaCha20Poly1305::decrypt(UserServerPrivEnc, KEK)`. Poly1305 tag verification failure means wrong KEK → 401. Success means the user is authenticated and the server holds the plaintext `UserServerPriv` for the duration of the request.

### Per-Request Flow (DEK fetch)

```
1. Client:  POST /keys/{key_id}
            Authorization: Bearer <base64url(KEK)>

2. Server:  SELECT UserServerPrivEnc, UserServerPub FROM User WHERE Username = ?
            decrypt(UserServerPrivEnc, KEK) → UserServerPriv   [401 on tag failure]
            SELECT ValueEnc FROM Permission
              WHERE Username = ? AND KeyId = ?
            SealedBox::open(ValueEnc, UserServerPub, UserServerPriv) → DEK
            zeroize(UserServerPriv)
            return DEK

3. Client:  uses DEK locally, discards it
```

### Key Sharing (Alice → Bob)

```
1. Alice authenticates (decrypts her UserServerPriv)
2. Alice opens her Permission row → plaintext DEK
3. Server fetches Bob's UserServerPub from User table
4. Server re-encrypts: SealedBox::encrypt(DEK, bob_pub) → bob_ValueEnc
5. INSERT Permission(Bob, project, key_id, bob_ValueEnc, IsOwner=0)
6. zeroize all intermediates
```

Alice never learns Bob's KEK. Bob never learns Alice's KEK. The server holds the DEK plaintext only ephemerally in RAM during step 4.

**Only users with `IsOwner = 1`** on a given `(Projectname, KeyId)` may create new Permission rows for it. Non-owners cannot share.

## Database Schema

```sql
CREATE TABLE User (
  Username          TEXT NOT NULL,
  UserServerPrivEnc TEXT NOT NULL,  -- nonce || ciphertext, XChaCha20-Poly1305 under KEK
  UserServerPub     TEXT NOT NULL,  -- X25519 public key, base64url
  PRIMARY KEY (Username)
);

CREATE TABLE Project (
  Projectname TEXT NOT NULL,
  PRIMARY KEY (Projectname)
);

CREATE TABLE UserProject (
  Username    TEXT NOT NULL REFERENCES User(Username) ON DELETE CASCADE,
  Projectname TEXT NOT NULL REFERENCES Project(Projectname) ON DELETE CASCADE,
  PRIMARY KEY (Username, Projectname)
);

CREATE TABLE Permission (
  Username    TEXT NOT NULL REFERENCES User(Username) ON DELETE CASCADE,
  Projectname TEXT NOT NULL REFERENCES Project(Projectname) ON DELETE CASCADE,
  KeyId       TEXT NOT NULL,
  ValueEnc    TEXT NOT NULL,  -- SealedBox(DEK, UserServerPub), base64url
  IsOwner     INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (Username, Projectname, KeyId)
);
```

All binary values (keys, ciphertexts) are stored as base64url-encoded TEXT. `KeyId` is a server-generated UUID; client-supplied IDs are rejected. Usernames are NFC-normalized at the API boundary before any DB operation to prevent Unicode confusion attacks.

## Stack

- **Runtime**: tokio
- **HTTP**: Axum
- **Database**: sqlx (compile-time query verification) + SQLite (WAL mode)
- **Crypto**: `crypto_box`, `chacha20poly1305`, `rand`, `zeroize`, `secrecy`
- **Serialization**: serde + serde_json
- **Errors**: `thiserror` (typed domain errors) + `anyhow` (application layer)
- **Unit/integration tests**: `cargo test` + `tokio::test`
- **E2E tests**: pytest with contextmanager-based server lifecycle fixtures

## API Surface (planned)

```
POST   /users                               Register user, provide UserServerPub + UserServerPrivEnc
POST   /projects                            Create project
POST   /projects/{project}/members          Add user to project
POST   /projects/{project}/keys             Generate new DEK, return KeyId
GET    /projects/{project}/keys/{id}        Fetch DEK (authenticated via KEK in header)
POST   /projects/{project}/keys/{id}/share  Share key with another user
DELETE /projects/{project}/keys/{id}        Revoke key (owner only)
```

All endpoints except registration require `Authorization: Bearer <base64url(KEK)>`. The KEK must never appear in a URL path or query parameter (logged by proxies).

## Security Invariants

The implementation must maintain:

1. KEK never in URL, only in `Authorization` header or request body
2. `UserServerPriv` wrapped in `ZeroizeOnDrop`; wiped on every exit path including errors
3. `KeyId` server-generated (UUID), never client-supplied
4. `IsOwner` checked before any Permission INSERT
5. Username NFC-normalized before DB operations
6. `nonce || ciphertext` stored as a single blob — never split across columns
7. Server binds TLS only; no HTTP fallback
