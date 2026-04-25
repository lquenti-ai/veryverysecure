# veryverysecure

A single-server REST Key Management System (KMS) implementing envelope encryption with a zero-server-knowledge property: a full database dump is cryptographically useless without per-user client-held keys.

## Threat Model

**Protected against:**
- Database dump / backup theft
- Disk snapshot
- Rogue database administrator
- Passive network observer (TLS)

**Out of scope:**
- Hoster with live process memory access (KEK transits RAM on every request)
- Compromised TLS termination
- Malicious running server binary (the process sees KEK, DEK, and `UserServerPriv` plaintext during a request by design)
- Lost KEK with no recovery share (see [Recovery](#recovery-shamir-secret-sharing))

**Why client-held KEKs instead of a server passphrase.** The conventional design — a single high-entropy passphrase unlocking a server-side root key at startup — concentrates the entire system's security into one secret and one attack target. Every admin, every backup, and every process with access to that key becomes a single point of compromise. Pushing the KEK to the client removes the target entirely: there is no root key to steal, no passphrase to phish, and a full database dump decrypts to nothing.

This also cleanly separates operator liability from user data. Because operators never hold the material needed to decrypt a user's keys, they are structurally incapable of leaking that data — and can demonstrate as much in the event of a breach. Responsibility for the KEK rests with the user (or their organization), which is what [SSS recovery](#recovery-shamir-secret-sharing) exists to make manageable.

The core invariant: no server-side master secret exists at rest. There is no startup passphrase, no server-held root key, no key derivation that the server could perform autonomously. Every sensitive value in the database is encrypted by a key that never leaves the client.

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
                               └─sealed box──►  ValueEnc (per Permission row)
                                                └── contains plaintext DEK
```

Three key types:

- **KEK** (Key Encryption Key): 32 bytes from a CSPRNG. Generated and stored by the client. Never transmitted except in-request over TLS. Never persisted server-side.
- **UserServerPriv / UserServerPub**: An X25519 keypair generated at registration. The public key is stored plaintext. The private key is encrypted under the KEK using XChaCha20-Poly1305 and stored as `nonce || ciphertext`.
- **DEK** (Data Encryption Key): 32 bytes from a CSPRNG. The actual value the user stores in the KMS. Encrypted per-user under their X25519 public key via an *anonymous sealed box* — an ephemeral X25519 keypair encrypts to the recipient's pubkey using XSalsa20-Poly1305 with a deterministic, hash-derived nonce; the ephemeral pubkey is prepended to the ciphertext. No sender authentication. (libsodium calls this construction `SealedBox` / `crypto_box_seal`.)

### Algorithms

| Operation | Algorithm |
|---|---|
| Wrap/unwrap `UserServerPriv` | XChaCha20-Poly1305 |
| Encrypt/decrypt DEK per user | Anonymous sealed box: X25519 + XSalsa20-Poly1305, ephemeral sender key |
| Key generation | OS CSPRNG (`/dev/urandom`, `getrandom(2)`, or platform equivalent) |
| Secret zeroing | Explicit memory wipe on every secret's drop/free path |

**Why XChaCha20 over AES-256-GCM:** 192-bit nonce makes random nonce generation unconditionally safe (birthday bound at 2^96 vs 2^48 for AES-GCM's 96-bit nonce). Constant-time in software without AES-NI.

**Why a sealed box over RSA-OAEP:** 32-byte keys vs 256-512 bytes, µs-range operations vs ms-range, constant-time by construction, no padding oracle attack surface.

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
            seal_open(ValueEnc, UserServerPub, UserServerPriv) → DEK
            wipe(UserServerPriv)
            return DEK

3. Client:  uses DEK locally, discards it
```

### Key Sharing (Alice → Bob)

```
1. Alice authenticates (decrypts her UserServerPriv)
2. Alice opens her Permission row → plaintext DEK
3. Server fetches Bob's UserServerPub from User table
4. Server re-encrypts: seal(DEK, bob_pub) → bob_ValueEnc
5. INSERT Permission(Bob, project, key_id, bob_ValueEnc, IsOwner=0)
6. wipe all intermediates
```

Alice never learns Bob's KEK. Bob never learns Alice's KEK. The server holds the DEK plaintext only ephemerally in RAM during step 4.

**Only users with `IsOwner = 1`** on a given `(Projectname, KeyId)` may create new Permission rows for it. Non-owners cannot share.

### Known Row-Integrity Risks (rogue DBA)

A rogue DBA is in scope for the threat model, and the current design does **not** fully defend against row substitution on write paths. Two concrete attacks exist; both are accepted for 1.0 and addressed in [Future Work](#future-work).

**(1) DEK substitution via `Permission.ValueEnc` swap.**
The DBA generates their own `DEK'`, computes `seal(DEK', alice_pub)` (Alice's public key is, by design, plaintext in the DB), and overwrites Alice's `ValueEnc` row. On the next fetch, Alice unwraps `DEK'` — a value chosen by the attacker — with no integrity signal that it differs from the original. If Alice uses the DEK to encrypt application data stored elsewhere, the attacker can later decrypt that data. The sealed-box construction has no AAD slot, so binding `(Username, Projectname, KeyId)` cryptographically into the ciphertext requires either a signature layer or a switch to HPKE.

**(2) Public-key substitution at share time.**
The DBA replaces `Bob.UserServerPub` with an attacker-controlled pubkey just before Alice shares a key to Bob. The server (acting honestly) computes `seal(DEK, attacker_pub)` and writes it into Bob's Permission row. The attacker can now decrypt. Bob's legitimate fetches will fail (integrity tag mismatch against his real priv), so this is detectable *after the fact* — but the DEK has already leaked. Defense requires a trust root for public keys (TOFU pinning in the client, a signed pubkey record, or an out-of-band fingerprint check).

Note that `UserServerPrivEnc` substitution alone is *not* an integrity attack — swapping it causes the AEAD to fail on the legitimate KEK and the user gets a 401. It is a denial-of-service vector, not a confidentiality one.

## Database Schema

```sql
CREATE TABLE User (
  Username          TEXT NOT NULL,
  UserServerPrivEnc BLOB NOT NULL,  -- nonce || ciphertext, XChaCha20-Poly1305 under KEK
  UserServerPub     BLOB NOT NULL,  -- X25519 public key (32 bytes raw)
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
  ValueEnc    BLOB NOT NULL,  -- sealed box of DEK to UserServerPub, raw bytes
  IsOwner     INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (Username, Projectname, KeyId)
);

-- At most one owner per (Projectname, KeyId). Enforced at the DB level so
-- ownership transfer is a single atomic SET/UNSET that the schema polices.
CREATE UNIQUE INDEX OneOwnerPerKey
  ON Permission(Projectname, KeyId)
  WHERE IsOwner = 1;
```

Binary values (keys, ciphertexts, nonces) are stored as `BLOB` — no base64 at rest. Base64url is used only on the wire. `KeyId` is a server-generated UUIDv4; client-supplied IDs are rejected. Usernames are NFC-normalized at the API boundary before any DB operation to prevent Unicode confusion attacks.

Note on DEK uniqueness: the 32-byte DEK plaintext is never stored server-side, so no DB-level constraint on its value exists. DEKs are unique by birthday bound on 256 random bits — collision is not a practical concern. `KeyId` uniqueness is handled by the Permission primary key and UUIDv4 generation; hardening against the theoretical UUIDv4 collision is tracked in [Future Work](#future-work).

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

## Interface Split: HTTP vs CLI

Frequent, per-request operations are exposed over HTTP. Infrequent privileged operations (registration, project creation, KEK rotation, SSS) live in a CLI (`vvs-admin`) that talks to the SQLite file directly via the same data-access layer the server uses. This keeps the public attack surface small and makes privileged actions auditable through shell history rather than request logs.

**The server must be stopped while `vvs-admin` runs.** The CLI does not coordinate with a live server; it expects exclusive write access. This is a deliberate operational constraint — privileged operations are rare, and requiring downtime eliminates a class of concurrency bugs and ensures the CLI never races with a request.

The data-access layer is a single shared library, used by both the server and the `vvs-admin` CLI. There is no second schema, no parallel query set.

### HTTP API

All endpoints require `Authorization: Bearer <base64url(KEK)>`.

```
POST   /projects/{project}/members               Add existing user to project (project owner only)
POST   /projects/{project}/keys                   Generate DEK, return KeyId. Caller becomes IsOwner.
GET    /projects/{project}/keys/{id}              Fetch DEK (requires a Permission row)
POST   /projects/{project}/keys/{id}/share        Share with another user (key IsOwner only)
POST   /projects/{project}/keys/{id}/transfer     Transfer ownership to another user who already
                                                  has a Permission row (key IsOwner only)
DELETE /projects/{project}/keys/{id}/members/{u}  Revoke a single user's access (key IsOwner only)
DELETE /projects/{project}/keys/{id}              Revoke entirely — deletes ALL Permission rows
                                                  for the KeyId (key IsOwner only)
```

Project membership implies the ability to create keys in that project; the creator becomes sole IsOwner.

The KEK must never appear in a URL path or query parameter (logged by proxies, caches, browser history).

### CLI (`vvs-admin`)

```
vvs-admin user register <username>             Generate KEK + X25519 keypair client-side, write User row.
                                               Prints KEK (optionally SSS-splits into 2-of-3 shares).
                                               Registration is closed — only this command creates users.
vvs-admin user rewrap <username>               Prompts for old KEK, generates new KEK, re-wraps
                                               UserServerPrivEnc. DEKs are untouched.
vvs-admin project create <name>                Create a project. Project creation is CLI-only.
vvs-admin project add-member <project> <user>  Mirror of the HTTP add-member route, for bootstrapping
                                               or recovery scenarios where no HTTP owner exists yet.
vvs-admin sss split                            Offline. Reads KEK from stdin, prints 3 shares.
vvs-admin sss combine                          Offline. Reads 2 shares, prints KEK.
```

## Recovery (Shamir Secret Sharing)

The server has no role in KEK recovery. If a user loses their KEK and has no backup, their data is unrecoverable — this is a deliberate consequence of the zero-server-knowledge-at-rest property.

For organizations that need recovery, the CLI ships an SSS split/combine tool fixed at **2-of-3** (`k=2, n=3`). At registration the client may split the freshly-generated KEK into three shares for distribution (e.g., the user, a team lead, a sealed envelope in a safe). Reconstruction requires any two shares and happens entirely client-side; the server never sees a share. Losing two shares = lost data, and that is explicitly the organization's problem.

## TLS Terminator Policy

Exactly one of the following must hold:

1. **Direct TLS (default).** The server binds TLS itself, reading cert and key from `VVS_TLS_CERT` and `VVS_TLS_KEY`. No HTTP fallback, no plaintext listener. This is the recommended configuration.
2. **Trusted local proxy.** A reverse proxy terminates TLS and forwards over loopback or a Unix socket to the server. The proxy MUST: (a) forward the `Authorization` header unchanged, (b) exclude `Authorization` from all access logs, (c) not persist request bodies, (d) reject any `X-Forwarded-*` headers from upstream that would let a client spoof a local origin.

Remote TLS termination (cloud load balancer terminating TLS and re-originating HTTP over a shared network) is not supported. The KEK transits that hop in cleartext.

## Security Invariants

The implementation must maintain:

1. KEK never in URL path or query string; only in the `Authorization` header.
2. `UserServerPriv` and DEK plaintext are explicitly wiped on every exit path including errors and panics.
3. `KeyId` server-generated (UUID), never client-supplied.
4. `IsOwner` checked before any Permission INSERT.
5. Username NFC-normalized before DB operations.
6. `nonce || ciphertext` stored as a single BLOB — never split across columns.
7. Server binds TLS only, or is fronted by a proxy meeting the [TLS Terminator Policy](#tls-terminator-policy).
8. **Authorization is per-row.** A valid KEK for user A grants nothing about user B's keys. The Permission row is the sole authorization source; KeyId existence alone grants no access.
9. **Logging discipline.** Request/response bodies, `Authorization` headers, `UserServerPrivEnc`, `ValueEnc`, and any decrypted material MUST NOT appear in logs at any level. This is a tested property, not a deployment convention.
10. Registration is closed — no HTTP endpoint creates users. Only the admin CLI does.

## Future Work

Deferred until after a solid 1.0. Each of these is a known limitation of the current design, not an oversight.

- **Row-integrity signatures.** Add an Ed25519 signing keypair per user (priv wrapped under KEK alongside `UserServerPriv`). Creators sign `(Username, Projectname, KeyId, DEK)`; fetchers verify on open. Closes the DEK-substitution attack (§Known Row-Integrity Risks #1) and also defends against a malicious Alice shipping a bogus "DEK" to Bob at share time.
- **End-to-end sharing.** Alice's client performs `seal(DEK, bob_pub)` locally and ships an opaque blob; the server never sees DEK plaintext during sharing. Combined with signatures above, removes the server from the TCB for key sharing.
- **Public-key trust root.** TOFU pinning of `UserServerPub` in the client, or a signed pubkey record, to defeat pub-swap attacks (§Known Row-Integrity Risks #2).
- **Username-enumeration timing hardening.** Constant-time response path for "no such user" vs. "AEAD failure" on the login path (dummy decrypt against a fixed dummy `UserServerPrivEnc`).
- **DEK rotation.** Re-generate a DEK and re-share to all current grantees without changing `KeyId`.
- **Audit log.** Tamper-evident append-only log of privileged operations (share, revoke, register, rewrap).
- **UUIDv4 collision hardening.** The birthday bound on UUIDv4 (122 random bits) is astronomically safe for realistic key volumes, but a collision between two independently-generated `KeyId`s would break the Permission PK on insert and could, in adversarial generation scenarios, allow row-shadowing. Options: unique-check-with-retry on insert, switch to UUIDv7 (timestamp-prefixed, still collision-resistant on the random tail), or widen the random portion.
- **Compile-time SQL verification.** Queries are currently checked at runtime. If the implementation language and DB toolchain support it, statically verify SQL against the live schema at build time so schema drift fails the build rather than surfacing as a runtime error.
