# signal-lite

A small, readable implementation of Signal-style end-to-end encryption for a
course project. Two CLI clients exchange messages through an untrusted relay
that only ever sees public keys and ciphertext.

> **Educational project. Do not use this to protect real secrets.** It has not
> been audited, it omits several parts of the real Signal protocol, and the
> relay has no transport authentication.

## What is implemented

- **X3DH** asynchronous session setup with X25519 Diffie-Hellman.
- **Signed prekeys** and **one-time prekeys**, with the OPK consumed exactly once.
- **Double Ratchet**: DH ratchet on every round trip plus a symmetric hash
  ratchet for every message.
- **Out-of-order delivery**: skipped message keys are cached per
  `(ratchet public key, message number)`, up to `MAX_SKIP = 1000`.
- **AES-256-CBC + HMAC-SHA256**, encrypt-then-MAC. The entire header is
  authenticated as associated data and the MAC is checked before decryption.
- **Server blindness**: the relay stores only public bundles and opaque
  envelopes.
- **Trust-on-first-use identity pinning** with a warning when a peer's identity
  key changes, plus a deterministic safety number for out-of-band verification.
- **Persistent device state**, so a session survives a client restart.

## What is deliberately not implemented

These are the parts of the real Signal Protocol that do not fit in a one-day
project, and the report should say so explicitly:

- Group messaging / Sender Keys
- Attachments and media encryption
- Multi-device fan-out (one device per user here)
- Message retries, delivery receipts, and sender-side backfill
- Header encryption (headers are authenticated but not confidential)
- XEdDSA (see the deviation note below)
- Sealed sender, franking, abuse reporting
- Transport authentication, metadata protection, and account recovery
- Automatic OPK replenishment and signed-prekey rotation
- A key-verification UI that *enforces* the safety-number comparison

## Architecture

```
 Alice's device                 untrusted relay                 Bob's device
+---------------+          +----------------------+          +---------------+
| Account       |  HTTP    | /register            |  HTTP    | Account       |
|  identity keys|--------->|  public bundles      |<---------|  identity keys|
|  prekeys      |          | /bundle/<user>       |          |  prekeys      |
|  sessions     |          | /send                |          |  sessions     |
|               |          | /inbox/<user>        |          |               |
| Client        |          | stores ciphertext    |          | Client        |
|  X3DH         |          | cannot decrypt       |          |  X3DH         |
|  Double       |          +----------------------+          |  Double       |
|  Ratchet      |                                            |  Ratchet      |
+---------------+                                            +---------------+
```

The relay is a plain Python `http.server` with an in-memory dictionary. It has
no accounts, no authentication, and no durability. That is intentional: the
security of the messages must not depend on the relay.

## Protocol summary

### Keys on a device

| Key | Type | Purpose |
|---|---|---|
| Identity signing key | Ed25519 | Signs the identity binding and signed prekey |
| Identity DH key | X25519 | Long-term DH identity `IK` |
| Signed prekey `SPK` | X25519 | Medium-term DH key, signed by the identity key |
| One-time prekeys `OPK` | X25519 | Single-use DH keys for forward secrecy |
| Root key | 32 bytes | Input to the DH ratchet |
| Chain keys | 32 bytes | Input to the hash ratchet |
| Message keys | 80 bytes | 32-byte AES key, 32-byte HMAC key, 16-byte IV |

### Registration

The client uploads its public signing key, public identity DH key, the identity
binding signature, the signed prekey and its signature, and a batch of public
one-time prekeys. Private keys never leave the device.

### X3DH session setup

The initiator fetches the recipient's bundle, verifies both signatures, and
generates an ephemeral key `EK`:

```
master = DH(IK_A, SPK_B) || DH(EK_A, IK_B) || DH(EK_A, SPK_B)
         || DH(EK_A, OPK_B)              # omitted when no OPK is available
root   = HKDF-SHA256(master, salt=0^32, info="signal-lite/x3dh/v1")
```

The recipient derives the same value with its private keys. The initiator then
performs the first DH ratchet step:

```
root_1, chain_A = KDF_RK(root, DH(R_A, SPK_B))
```

where `R_A` is a fresh ratchet key pair. The first message carries the X3DH
material (`identity_key`, `signing_key`, `identity_signature`, `ephemeral`,
`signed_prekey_id`, `one_time_prekey_id`) and the ratchet key `R_A`.

Per the Messenger whitepaper, the initiator keeps advertising this prekey
material on every outgoing message until the recipient replies. This is what
lets a lost first message be recovered: the recipient can establish the
session from a later message and skip the missing message numbers.

### Double Ratchet

Root ratchet:

```
root', chain = HKDF-SHA256(dh_output, salt=root, info="signal-lite/ratchet/v1", length=64)
```

Hash ratchet:

```
message_key_seed = HMAC-SHA256(chain_key, 0x01)
next_chain_key   = HMAC-SHA256(chain_key, 0x02)
```

Message key expansion:

```
aes_key || mac_key || iv = HKDF-SHA256(message_key_seed, salt=0^32,
                                       info="signal-lite/message-key/v1",
                                       length=80)
```

> The whitepaper says a message key is 80 bytes but gives a 32-byte HMAC
> formula. libsignal expands the seed with HKDF; this project follows the
> reference implementation and documents the discrepancy.

On receiving a message with a new `dh` value, the receiver performs a DH
ratchet step: derive a new receiving chain with the old ratchet private key,
generate a new ratchet key pair, and derive a new sending chain. If the message
belongs to an older chain, a cached skipped key is used instead, and no ratchet
step happens.

Decryption is copy-on-write. The live session is updated only after the MAC
verifies, so a forged message cannot desynchronise the ratchet.

### Wire format

```json
{
  "header": {
    "type": "prekey",
    "sender": "alice",
    "sender_device": "default",
    "identity_key": "...",
    "signing_key": "...",
    "identity_signature": "...",
    "ephemeral": "...",
    "signed_prekey_id": 1,
    "one_time_prekey_id": 4,
    "dh": "...",
    "pn": 0,
    "n": 0
  },
  "iv": "...",
  "ct": "...",
  "mac": "..."
}
```

`mac = HMAC-SHA256(mac_key, canonical_json(header) || iv || ct)`. Subsequent
messages use `"type": "message"` and omit the prekey fields.

## Quick start

Requirements: Python 3.10+ with `cryptography` and `requests` (both already
present in this environment).

```bash
cd ~/Projects/signal-lite
python3 -m pytest              # 25 tests
```

Terminal 1 — relay:

```bash
python3 -m signallite.cli server --port 8765
```

Terminal 2 — Alice:

```bash
python3 -m signallite.cli client --user alice
```

Terminal 3 — Bob:

```bash
python3 -m signallite.cli client --user bob
```

In Alice's window:

```
/to bob
hello bob
```

Bob receives the message automatically. In Bob's window:

```
/to alice
hello alice
```

Other commands:

| Command | Meaning |
|---|---|
| `/to <user>` | Set the current recipient |
| `/users` | List users registered with the relay |
| `/fingerprint` | Show your own identity fingerprint |
| `/fingerprint <user>` | Show the pairwise safety number |
| `/help` | Show help |
| `/quit` | Exit and save state |

Device state lives in `state/<user>.json`. Delete that file to simulate a
reinstall with a fresh identity.

## Demo script

### 1. The relay cannot read messages

Send a message while the recipient is offline, then inspect the relay:

```bash
curl -s http://127.0.0.1:8765/debug/state | jq
```

The inbox contains a `header`, `iv`, `ct`, and `mac`; the plaintext is absent.
`grep` for the message text and show that it does not appear.

### 2. Tampering is detected

Capture an envelope, flip one byte of `ct`, and deliver it. The client rejects
it with `AuthenticationError` before decrypting, and the session still works
for the next legitimate message. The test
`test_tampered_ciphertext_is_rejected` automates this.

### 3. Identity changes are flagged

Stop Bob, delete `state/bob.json`, and start Bob again. Bob now has a new
identity. When he messages Alice, Alice prints:

```
!! SECURITY WARNING: the identity key for bob changed !!
```

Then compare safety numbers out of band. This demonstrates both the value and
the limitation of trust-on-first-use: the warning is only useful if the user
actually verifies the new key.

### 4. Forward secrecy

Send a few messages in each direction, then inspect `state/alice.json`. The
session contains only the current root key and chain keys, not a history of
message keys. A used message key is deleted from the skipped-key cache, so
replaying an old ciphertext fails with `ReplayError` even with full current
state. The report should explain the caveat: this is forward secrecy against
*state compromise after the fact*, not a guarantee against an attacker who was
recording and also compromised the device at the time.

## Tests

`python3 -m pytest` runs 25 tests:

- `tests/test_crypto.py` — X25519 agreement, Ed25519 signatures, AEAD
  round-trip, tamper rejection, KDF output sizes.
- `tests/test_x3dh.py` — initiator/responder root-key agreement with and
  without an OPK, tampered signed-prekey and identity-binding rejection.
- `tests/test_ratchet.py` — first message, replies, multiple round trips,
  out-of-order within a chain, out-of-order across a DH ratchet step, tampered
  ciphertext/header rejection, replay rejection, state serialisation.
- `tests/test_e2e.py` — full client/relay round trip, relay-blindness check,
  one-time-prekey consumption, tampered envelope rejection, identity-change
  warning, matching safety numbers, session persistence across a restart.

## Security analysis

### Threat model

- The relay is **honest-but-curious**: it follows the protocol but may inspect,
  store, and replay everything it sees. It may also try to substitute public
  keys.
- The network is untrusted: messages can be read, modified, dropped, delayed,
  reordered, or replayed.
- The device is trusted while it is running. An attacker who compromises the
  device *after* a message has been ratcheted away should not recover past
  plaintext (forward secrecy). An attacker who compromises the device and then
  observes future DH ratchet steps should lose decryption capability
  (post-compromise security / future secrecy).
- Out of scope: endpoint compromise at the time of decryption, malicious
  recipients, metadata protection, and denial of service.

### Properties achieved

| Property | Mechanism |
|---|---|
| Confidentiality | X3DH + Double Ratchet + AES-256-CBC |
| Integrity and authenticity | HMAC-SHA256 over header, IV, and ciphertext |
| Mutual authentication | Identity keys, signed prekeys, identity binding |
| Forward secrecy | Hash ratchet deletes old message keys; DH ratchet rotates chains |
| Post-compromise security | A fresh DH ratchet step on each round trip |
| Out-of-order tolerance | Cached skipped message keys |
| Server blindness | Relay never receives private keys or plaintext |

### Known limitations

- **Trust-on-first-use.** Without comparing safety numbers, a malicious relay
  can substitute its own bundle and MITM the session. The warning is only a
  prompt, not a prevention.
- **Unauthenticated relay.** Anyone who can reach the relay can fetch bundles,
  drain inboxes, or inject envelopes. Transport authentication is out of scope;
  message-level cryptography still protects confidentiality and integrity, but
  availability and metadata do not.
- **No header encryption.** The relay learns sender names, device ids, message
  counts, and timing.
- **One device per user.** The real Messenger uses client-side fan-out to every
  device; this project uses one device per username.
- **In-order assumption for the first message.** The initiator keeps sending
  prekey material until a reply, so a lost first message is recoverable, but a
  recipient who loses all local state cannot recover old sessions.
- **OPK deletion is not transactional.** The responder consumes the OPK before
  the first message authenticates. A forged prekey message can burn an OPK
  (a small denial-of-service vector).
- **No signed-prekey rotation.** A single signed prekey is generated at
  registration time.
- **No padding-oracle surface by design.** The MAC is verified before CBC
  decryption, so a modified ciphertext is rejected without exposing padding
  behaviour.

## Suggested report outline

1. **Introduction and threat model** — what E2EE promises, what the relay sees,
   and the difference between confidentiality against the server and
   authentication of the peer.
2. **Background** — X3DH, Double Ratchet, HKDF, PRF/PRP, encrypt-then-MAC, and
   why CBC alone is not enough.
3. **Design** — key registration, bundle verification, session setup, message
   format, ratchet state, and the prekey-advertisement rule.
4. **Implementation** — module map, libraries, state persistence, and the
   copy-on-write decryption decision.
5. **Security analysis** — the table above, plus explicit attacks: server
   reading the inbox, tampering, replay, out-of-order delivery, identity
   substitution, and device compromise before/after a ratchet step.
6. **Deviations from Signal** — XEdDSA replaced by Ed25519 + binding signature;
   message-key expansion; no header encryption; no group/attachment/retry
   support.
7. **Evaluation** — test results, demo transcript, relay dump, and a short
   performance note (messages are tiny; the cost is dominated by HTTP and
   key generation).
8. **Conclusion and future work** — group Sender Keys, safety-number
   verification UI, header encryption, sealed sender, OPK replenishment.

## File map

```
signallite/
  crypto.py     X25519, Ed25519, HKDF, KDF_RK/KDF_CK, AES-CBC+HMAC
  x3dh.py       PreKeyBundle, bundle verification, X3DH root-key derivation
  ratchet.py    Double Ratchet state machine, skipped keys, serialization
  account.py    device identity, prekeys, sessions, JSON persistence
  client.py     registration, session setup, send/receive, trust warnings
  server.py     stdlib HTTP relay and /debug/state
  cli.py        argparse entry points and interactive chat loop
  encoding.py   base64 and canonical JSON helpers
tests/
  conftest.py   relay fixture and client factory
  test_crypto.py
  test_x3dh.py
  test_ratchet.py
  test_e2e.py
```
