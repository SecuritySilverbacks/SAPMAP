# AS Java Secure Store — Offline Credential Recovery

Date researched: 2026-04-19
Status: **solved — stop using configtool.sh / consoleconfig.sh / secstorefs.sh**

## TL;DR

SAPMAP has been chasing the wrong primitive. SAP's own `configtool.sh` /
`consoleconfig.sh` / `secstorefs.sh` were the initial candidates, but:

- **SAP KBA 2732586** explicitly documents that the CONSOLE mode cannot read
  secure-store settings — GUI only.
- GUI needs a Swing display; running it headless is ugly and the decryption
  still happens with a locally-readable key anyway.

The short answer: **read `SecStore.key` off disk, deobfuscate with a known
static XOR, use that keyphrase to decrypt `SecStore.properties` *and*
J2EE_CONFIGENTRY VBYTES — completely offline in Python.**  ERPScan published
the algorithm in 2018.  We already have all the inputs (we're `<sid>adm` via
SAPXPG; the VBYTES are already being pulled via our JSP SQL query).

The 560 "failed_decrypts" on SJ1 are encrypted with the **same key** as the
SecStoreFS entries we DO decrypt.  We've been using SAP's in-engine
SecStoreFS.decrypt() API via JSP, which sometimes refuses format-byte `0x00`
rows (they're cleartext base64, not PBE-encrypted — engine wants to decrypt
everything, plaintext rows get rejected or returned empty).  Doing it in
Python lets us handle both format bytes explicitly.

## The algorithm (from ERPScan's SecStoreDec.py, 2018)

Citation: https://github.com/erpscanteam/SecStoreDec (one file, ~150 LOC, MIT
license).

### Step 1 — read SecStore.key

```
/usr/sap/<SID>/SYS/global/security/data/SecStore.key
```

File content is one line:
```
<major>.<minor>.<patch>.<build>|<obfuscated-keyphrase-base64-like>
```

e.g. `7.50.122.065|Lw==...`.  Parse with regex `(\d\.\d{2}\.\d{3})\.\d{3}\|(.*)`.

### Step 2 — deobfuscate

Static 20-byte XOR key (hardcoded in the SAP kernel since at least 7.00):

```python
SECRET = bytes([
    0x2b, 0xb6, 0x8f, 0xfa, 0x96, 0xec, 0xb6, 0x10,
    0x24, 0x47, 0x92, 0x65, 0x17, 0xb0, 0x09, 0xc4,
    0x3e, 0x0a, 0xd7, 0xbd,
])
keyphrase = bytes(obf[i] ^ SECRET[i % 20] for i in range(len(obf)))
```

Pre-7.00.000 appended the SID to the keyphrase; 7.00+ uses keyphrase alone.
Every system we care about is 7.5+.

### Step 3 — decrypt SecStore.properties

Each line (non-`$internal`) is `key=base64ciphertext`.  Decrypt each value:

```python
import jks.rfc7292
ct = base64.b64decode(value)
plain = jks.rfc7292.decrypt_PBEWithSHAAnd3KeyTripleDESCBC(
    ct, keyphrase,
    salt=b'\x00' * 16,
    iterations=0,
).split(b'|')
# plain = [prefix, length_str, value_bytes]
prop_value = plain[2][:int(plain[1])]
```

This recovers the SAP<SID>DB database password for the Java schema.

### Step 4 — decrypt J2EE_CONFIGENTRY VBYTES

Per row in J2EE_CONFIGENTRY, VBYTES is hex:

```python
data = bytes.fromhex(vbytes_hex)
fmt = data[0]          # format byte: 0x00 (cleartext) or 0x01 (encrypted)
                       # data[1] is a length/flag byte — unused
body = data[2:]
ALPHABET_SKIP = 18

if fmt == 0x00:
    # Already cleartext — stored base64-encoded, with an 18-byte header
    plain = base64.b64decode(body)[ALPHABET_SKIP:]

elif fmt == 0x01:
    # Encrypted with the same PBE scheme
    plain = jks.rfc7292.decrypt_PBEWithSHAAnd3KeyTripleDESCBC(
        body, keyphrase, salt=b'\x00' * 16, iterations=0,
    )[ALPHABET_SKIP:]
```

**Critical quote from ERPScan's research** (confirmed across 3 sources):

> "The key for Java Secure Storage in the file system and the key for
> encrypted data in the J2EE_CONFIGENTRY table are the same."

This includes UMEBackendConnection's SAPJSF password, JCo destination
passwords, MMR creds, DB pool creds — everything that has a `#~...password`
or `#~jco.client.passwd` row with VBYTES present.

## Why our current JSP engine-side path fails on 560 rows

Our `sap_java_secstore.py` invokes `SecStoreFS.decrypt()` via a deployed JSP,
letting the running engine do the work.  Hypotheses for the failures:

1. **Format `0x00` rows.**  These are cleartext (with an 18-byte header).
   The engine's decrypt API expects encrypted input and may reject them
   with "wrong algorithm" / empty.  Doing it ourselves in Python handles
   both format bytes explicitly.
2. **Rows where `getSecretKey()` needs a different key ring.**  Some
   entries are encrypted via `com.sap.engine.core.configuration.impl.
   security.getSecretKey()` which consults a different slot.  But since
   ERPScan confirms the keyphrase is the same, *our* offline decrypt
   should handle them — the engine's refusal is an API-level filter, not
   a cryptographic one.
3. **Row-level ACL in the engine.**  Some service destinations
   (UMEBackendConnection especially) have ACLs that block the calling
   JSP context.  An offline decrypt doesn't go through those ACLs.

## Implementation plan for SAPMAP

### New module: `sap_java_secstore_offline.py`

Pure Python, no SAP engine involvement.  ~200 LOC.

- `deobfuscate_seckey(seckey_bytes) -> bytes` — the XOR step.
- `decrypt_secstore_properties(props_text, keyphrase) -> dict` — parse +
  PBE-decrypt each row.
- `decrypt_vbytes(vbytes_hex, keyphrase) -> bytes | None` — format-byte
  dispatch + PBE or cleartext return.

Dependencies:
- `pyjks` (already pure Python) for the PBE-3DES decryption, OR
- Port the primitive ourselves with `pycryptodome` to avoid pulling in
  pyjks — it's only 40 lines (SHA1-based PKCS#12 KDF + 3DES/CBC).

Recommendation: port it.  Reduces dependencies; pyjks has its own JCE/JKS
format support we don't need.

### Wire-up

In `sapmap_exploit.py` where we currently call `extract_java_secstore`:

1. Run `/bin/cat /usr/sap/<SID>/SYS/global/security/data/SecStore.key` via
   SAPXPG (we already have `sj1adm` via the gateway).  Small file, one
   SAPXPG hit.
2. Run `/bin/cat .../SecStore.properties` via SAPXPG — one more hit.
3. Feed both to `sap_java_secstore_offline.deobfuscate_seckey` →
   keyphrase.
4. For every J2EE_CONFIGENTRY row currently tagged `failed_decrypts`,
   call `decrypt_vbytes(row.vbytes_hex, keyphrase)`.
5. Merge the offline-decrypted rows into `node.java_secstore_entries`
   alongside the existing engine-side successes.

The current JSP path can stay as the primary (fewer moving parts when
engine is live), with this as fallback.  Or we can flip it: offline
first, JSP for anything VBYTES-less.

### Testing

- Unit test `deobfuscate_seckey` with a synthetic `SecStore.key` we
  XOR-encode ourselves.
- Unit test `decrypt_vbytes` for both format bytes using a
  round-tripped PBE encryption.
- Integration test on SJ1 once implemented: confirm
  UMEBackendConnection's SAPJSF password decrypts.

## Sources

Primary (code-level):
- https://github.com/erpscanteam/SecStoreDec — ERPScan's reference
  implementation, 2018.  Single-file Python 2, under 150 LOC.  We port
  it to Python 3.

Algorithm confirmation (multiple independent sources):
- https://dzone.com/articles/sap-java-secure-storage — ERPScan's
  research summary.  Names the cipher, salt, iterations.
- https://erpscan.io/press-center/blog/sap-java-secure-storage/ —
  ERPScan blog (currently returning ECONNREFUSED but title indexed in
  search).
- https://sapbazar.com/articles/item/158-sap-java-secure-storage —
  reiterates the XOR + PBE algorithm.
- SAP Help Portal docs on Secure Storage in File System — confirms the
  storage path and the PBE cipher choice.

Disk layout:
- `/usr/sap/<SID>/SYS/global/security/data/SecStore.key`
- `/usr/sap/<SID>/SYS/global/security/data/SecStore.properties`
- Confirmed via SAP KBA 2126229 (recreating these files) and multiple
  community threads on `sapbazar.com` / `community.sap.com`.

Negative confirmations (dead ends, documented so we don't revisit):
- SAP KBA 2732586 — console configtool cannot read secure store.
- SAP KBA 1827807 — offline edit path requires the GUI configtool with
  `-console` explicitly NOT supporting secure store navigation.
- `secstorefs.sh` covers the filesystem SSFS (same data as
  SecStore.properties); does not expose cleartext on command line
  without the keyphrase, which it never prints.
- `rsecssfx` covers the ABAP-side RSECTAB / kernel-level SSFS, not the
  Java J2EE_CONFIGENTRY table.

## Vault vs SecStoreFS — the distinction clarified

Previously we assumed a separate "Vault" with a different master key.
ERPScan's research shows this is **not true for AS Java**.  The
"Vault-backed" terminology in SAP docs refers to deployment-time storage
of passwords outside DB plaintext — but the key used to encrypt them is
still the SecStoreFS keyphrase.  The ABAP-side "SECSTORE" transaction
and RSECTAB use a different mechanism (and a different key); those are
irrelevant to AS Java.

## Risk / detection

- Reading `SecStore.key` + `SecStore.properties` as `<sid>adm` does not
  write to any SAP log.  Pure filesystem reads.
- Decryption is offline — nothing hits the running engine.
- No NW RFC SDK, no JSP, no ICM request.  Only the SAPXPG OS-exec call
  that fetched the two files, which we already emit a `whoami` line for
  in the console.

## Future extensions

- Use the deobfuscated keyphrase to re-encrypt entries we WANT the SAP
  engine to accept (e.g. plant our own SAPJSF password that matches a
  user we created on the backend ABAP).  Out of scope for SAPMAP's
  read-only audit role, but documented here for completeness.
