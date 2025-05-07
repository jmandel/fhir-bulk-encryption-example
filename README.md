# Optional End-to-End Encryption for FHIR Bulk Export

**Protocol Version 0.5 – 6 May 2025**

This document describes how to encrypt FHIR bulk‑export NDJSON files end‑to‑end and securely convey decryption keys in‑band via JWE, using the client’s registered public key.

---

## 1. Goals

1. **Confidentiality & Integrity**: Ensure exported NDJSON files remain confidential and tamper‑evident on any storage platform.
2. **In‑Band Key Delivery**: Use a JSON Web Encryption (JWE) structure to deliver the per‑file or per‑batch Content Encryption Key (CEK) directly within the manifest or file entry.
3. **Compatibility**: Reuse the existing bulk-export manifest format so that clients familiar with the specification can parse and process manifests without structural changes.
4. **Streaming Efficiency**: Support streaming encryption and decryption of large NDJSON files to minimize total memory usage over arbitrarily large datasets.

---

## 2. High‑Level Workflow

1. **Generate CEK**: For each NDJSON file, generate a fresh symmetric key (the CEK) for `crypto_secretstream_xchacha20poly1305`. Optionally **gzip the NDJSON** file before encryption (recommended). You may generate one CEK per manifest and reuse it across all files.

2. **Encrypt Data**: Stream‑encrypt each file using libsodium’s SecretStream API, producing a public header + ciphertext chunks.

3. **Wrap CEK in JWE**: Create a compact JWE whose payload contains the CEK and related parameters, encrypted under the client’s public key (`use": "enc"`) from their registered JWK set.

4. **Publish Manifest**: Include the JWE as an `extension` on each file entry (or at top‑level for per‑batch keys) in the bulk‑export manifest.

5. **Decrypt**: Client fetches the manifest, locates the JWE, unwraps the CEK with their private key, then streams and decrypts each file.

---

## 3. Content Encryption Details

* **Algorithm**: `crypto_secretstream_xchacha20poly1305` (libsodium)
* **Header (H)**: 24 bytes at file start (public)
* **Chunk Size (C)**: Default 1 MiB, adjustable via JWE payload
* **Chunk Format**: Each chunk = up to C plaintext bytes + 17‑byte overhead (1‑byte tag + 16‑byte MAC); final tail = 17‑byte final‑tag.

**File Structure**:

```
offset    size        description
0         24 B        header H (public)
24        N×(C+17)    intermediate ciphertext chunks
...       ≤ C+17      final ciphertext chunk
...       17 B        final authentication tag
```

---

## 4. Conveying the CEK via JWE

### 4.1 JWE Payload (JSON)

The JWE plaintext (payload) holds parameters and keys:

```js
{
  "v": "0.5",                                 // Protocol version (fixed value)
  "k": "<base64url‑encoded CEK>",             // Symmetric CEK
  "chunk": 1048576,                           // Chunk size in bytes (optional)
  "cipher": "secretstream_xchacha20poly1305", // Fixed value as of version 0.5
  "content_type": "application/fhir+ndjson",  // Content-Type of plaintext
  "content_encoding": "gzip"                  // Only if plaintext was gzip'd before encryption
}
```

### 4.2 JWE Protected Header

Use either RSA‑OAEP‑256 or ECDH‑ES+A256KW for key wrapping, depending on what type of JWK the client has registered. The protected header contains:

| Parameter | Description                                                      |
| --------- | ---------------------------------------------------------------- |
| `alg`     | Key management algorithm: `RSA-OAEP-256` or `ECDH-ES+A256KW`     |
| `enc`     | Content encryption: `A256GCM`                                    |
| `kid`     | Key ID matching the client’s registered JWK entry (`use":"enc"`) |
| `cty`     | `application/json`                                               |
| `epk`     | Ephemeral public key (for ECDH‑ES+A256KW)                        |

The JWE is serialized in compact form and placed into the manifest’s `extension`.

---

## 5. Manifest Extensions

### 5.1 Per‑File CEK

Add an `extension` to each file entry:

```json
{
  "type": "Patient",
  "url": "https://cdn.example.com/patient_file_1.enc",
  "extension": {
    "url": "http://argo.run/bulk-export-decryption-key",
    "valueString": "<compact-JWE>"
  }
}
```

### 5.2 Per‑Manifest CEK

Reuse one CEK across all files; include JWE at the top level:

```js
{
  "transactionTime": "...",
  "request": "...",
  "requiresAccessToken": true,
  "extension": {
    "url": "http://argo.run/bulk-export-decryption-key",
    "valueString": "<compact-JWE>"
  },
  "output": [ /* file entries without per-file JWE */ ]
}
```

**Note**: Clients MUST use HTTPS/TLS to fetch both manifest and file blobs.

---

## 6. JWKS Representation of Client Keys

Clients MUST include an encryption key in their JWKS with fields:

* `use`: `"enc"`
* `alg`: `"RSA-OAEP-256"` or `"ECDH-ES+A256KW"`
* `kid`: Unique identifier

Servers pick the first JWK matching `use":"enc"` and a supported `alg`.

---
## 7. Operational Notes

* **Compression Support**: Servers SHOULD apply GZIP (RFC 1952) before encryption and indicate this in the `content_encoding` JWE claim
* **Resuming HTTP Requests**: Clients may resume downloads at chunk boundaries via HTTP Range requests.

---
## 8. Reference Implementation (TypeScript/Bun)

For a minimal Bun‑based reference for streaming encryption and decryption using libsodium’s SecretStream API, see [`index.ts`](./index.ts).


```bash
bun install
bun index.ts
```

The demo output verifies encrypted file size, timings, and successful decryptions for various file sizes and compression settings.


## Example Output

See a complete worked example at [worked-example.txt](./worked-example.txt)

```
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
