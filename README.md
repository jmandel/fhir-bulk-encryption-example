# Optional End-to-End Encryption for FHIR Bulk Export

**Protocol draft v0.5 – 6 May 2025**

---

## 1 Goals

| #   | Goal                                                                             |
| --- | -------------------------------------------------------------------------------- |
| G-1 | Keep exported NDJSON files confidential and tamper-evident on untrusted storage. |
| G-2 | Deliver the symmetric content-encryption key (CEK) in-band via JWE and JWKS.     |
| G-3 | Preserve backward compatibility—legacy clients ignore the added `extension`.     |

---

## 2 Technical Approach

### 2.1 Content Encryption

* **Primitive:** `crypto_secretstream_xchacha20poly1305` (libsodium)
* **Header H:** 24 bytes at file offset 0.
* **Chunk size C:** fixed **1 MiB (1 048 576 bytes)** of plaintext per `push()`; final chunk may be shorter.
* **Chunk format:** each encrypted chunk = plaintext (≤ C) **+ 17-byte overhead** (1-byte stream tag + 16-byte Poly1305 MAC). Clients verify each chunk’s tag and MAC as they stream.

### 2.2 Key, Header, Chunk-Size, Media Packaging & Versioning

**CEK lifecycle:**

* **SHOULD** generate a fresh, unique CEK per file for maximum compartmentalization.
* **MAY** reuse the same CEK across all files in a single manifest to simplify key management; in that case, publish one JWE extension at the top-level manifest instead of per-file.

| Element           | Conveyed in JWE payload field | Description                                            |
| ----------------- | ----------------------------- | ------------------------------------------------------ |
| `v`               | `"v"`                         | Protocol version (e.g. `"0.5"                         |
| 32-byte key **K** | `"k"`                         | Base64-url-encoded CEK                                 |
| Chunk size **C**  | `"chunk"`                     | Bytes of plaintext per chunk (omit ⇒ default 1 MiB)    |
| Cipher identifier | `"cipher"`                    | `"secretstream_xchacha20poly1305"`                     |
| Media type        | `"content_type"`              | e.g. `"application/fhir+ndjson"`                       |
| Content encoding  | `"content_encoding"`          | omit ⇒ none; `"gzip"` ⇒ gzip applied before encryption |

#### JWE Protected Header

| Parameter | Description                                                                                           |
| --------- | ----------------------------------------------------------------------------------------------------- |
| `alg`     | Key management algorithm (`RSA-OAEP-256` or `ECDH-ES+A256KW`)                                         |
| `enc`     | Content encryption algorithm (`A256GCM`)                                                              |
| `kid`     | Key ID matching a JWK in the client's JWKS                                                            |
| `cty`     | Media type of the JWE payload (`application/json`)                                                    |
| `epk`     | Ephemeral public key for ECDH-ES (per RFC 7518 §4.6.1). MUST be included if `alg` is `ECDH-ES+A256KW` |

### 2.3 File Layout

```text
offset    size                   description
0         24                     header H (public)
24        N × (C + 17)           full chunk(s): ciphertext of C plaintext bytes + 17-byte overhead (TAG_MESSAGE)
...       ≤ C                    final body chunk: ciphertext of ≤ C plaintext bytes + 17-byte overhead
...       17                     tail: TAG_FINAL (17-byte authentication tag)
```

Clients should:

1. Read 24 B for the header, then initialize via `crypto_secretstream_xchacha20poly1305_init_pull(header, K)`.
2. **Loop**: while buffer ≥ (C+17):

   1. take `block = buffer.slice(0, C+17)`, decrypt with `pull(state, block)`, write plaintext.
   2. drop that slice.
3. Once fewer than (C+17+17) bytes remain:

   1. `finalBody = buf.slice(0, buf.length - 17)`, decrypt and write if nonzero.
   2. `tail = buf.slice(buf.length - 17)`, decrypt: verify `tag === TAG_FINAL`.

---

## 3 Manifest Carriage & Transport Security

For **per-file CEKs**, each file entry gets its own extension:

```json
{
  "type": "Patient",
  "url": "https://cdn.example.com/patient_file_1.sxch",
  "extension": {
    "http://argo.run/bulk-export-decryption-key": "<compact-JWE>"
  }
}
```

For **per-manifest CEKs** (CEK reuse), include a single top-level extension instead:

```json
{
  "transactionTime": "...",
  "request": "...",
  "requiresAccessToken": true,
  "extension": {
    "http://argo.run/bulk-export-decryption-key": "<compact-JWE>"
  },
  "output": [ ... ]
}
```

* **MUST** fetch manifests and encrypted blobs over **HTTPS/TLS** to protect metadata and ciphertext in transit.

---

## 4 JWKS Requirements

Clients must publish keys with:

| Field | Value                                  |
| ----- | -------------------------------------- |
| `use` | `"enc"`                                |
| `alg` | `"RSA-OAEP-256"` or `"ECDH-ES+A256KW"` |
| `kid` | Unique key identifier                  |

Servers select the first key whose `use==="enc"` and whose `alg` they support.

---

## 5 Compression Support

| JWE Field                   | Interpretation                                             |
| --------------------------- | ---------------------------------------------------------- |
| *(absent)*                  | No compression                                             |
| `"content_encoding":"gzip"` | Plaintext was GZIP-compressed (RFC 1952) before encryption |

Clients **MUST** inspect the JWE’s `"content_encoding"` claim and apply the corresponding decompressor to the decrypted stream.

---

## 6 Security & Operational Notes

* **Key Rotation:** Generate a fresh CEK per file or per export batch for forward secrecy.
* **Resumption:** Clients may resume on chunk boundaries via HTTP Range.

---
## 7 Reference Implementation (TypeScript/Bun)

For a minimal Bun‑based reference for streaming encryption and decryption using libsodium’s SecretStream API, see `./index.ts`(./index.ts).


# Demo Output

```
bun install
bun index.ts

------------------------------------------------------------------------------------------------------------
| Test Case                               | Encrypted Size     | Enc Time (ms) | Dec Time (ms) | Status    |
|-----------------------------------------|--------------------|---------------|---------------|-----------|
| ECDH-ES Demo - 1MB                      |         1023.88 KB |         29.50 |         44.17 | ✅ SUCCESS |
| RSA-OAEP Demo - 1MB                     |         1023.78 KB |         13.70 |         14.01 | ✅ SUCCESS |
| ECDH-ES Demo - 1MB_GZIP                 |          174.06 KB |          2.99 |          3.10 | ✅ SUCCESS |
| RSA-OAEP Demo - 1MB_GZIP                |          174.18 KB |          2.53 |          3.39 | ✅ SUCCESS |
| ECDH-ES Demo - 10MB                     |              10 MB |        135.84 |        132.58 | ✅ SUCCESS |
| RSA-OAEP Demo - 10MB                    |              10 MB |        125.79 |        132.54 | ✅ SUCCESS |
| ECDH-ES Demo - 10MB_GZIP                |            1.69 MB |         21.81 |         22.22 | ✅ SUCCESS |
| RSA-OAEP Demo - 10MB_GZIP               |            1.69 MB |         19.39 |         23.76 | ✅ SUCCESS |
| ECDH-ES Demo - 20MB                     |              20 MB |        231.86 |        244.64 | ✅ SUCCESS |
| RSA-OAEP Demo - 20MB                    |              20 MB |        234.13 |        236.09 | ✅ SUCCESS |
| ECDH-ES Demo - 20MB_GZIP                |            3.39 MB |         43.88 |         44.31 | ✅ SUCCESS |
| RSA-OAEP Demo - 20MB_GZIP               |            3.39 MB |         40.10 |         44.26 | ✅ SUCCESS |
------------------------------------------------------------------------------------------------------------
```