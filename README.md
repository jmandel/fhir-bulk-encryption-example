
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
* **Chunk size C:** fixed **1 MiB (1 048 576 bytes)** of plaintext per `push()`; final chunk may be shorter.
* **Chunk format:** each encrypted chunk = plaintext (≤ C) **+ 17‑byte overhead** (1‑byte stream tag + 16‑byte Poly1305 MAC). Clients verify each chunk’s tag and MAC as they stream.

### 2.2 Key, Header, Chunk-Size & Media Packaging

| Element           | Conveyed in JWE payload field | Description                                            |
| ----------------- | ----------------------------- | ------------------------------------------------------ |
| 32-byte key **K** | `"k"`                         | Base64-url-encoded CEK                                 |
| Chunk size **C**  | `"chunk"`                     | Bytes of plaintext per chunk (omit ⇒ default 1 MiB)    |
| Cipher identifier | `"cipher"`                    | `"secretstream_xchacha20poly1305"`                     |
| Media Type        | `"content_type"`              | e.g. `"application/fhir+ndjson"`                       |
| Content Encoding  | `"content_encoding"`          | omit ⇒ none; `"gzip"` ⇒ gzip applied before encryption |

#### JWE Protected Header

| Parameter | Description                                                   |
| --------- | ------------------------------------------------------------- |
| `alg`     | Key management algorithm (`RSA-OAEP-256` or `ECDH-ES+A256KW`) |
| `enc`     | Content encryption algorithm (`A256GCM`)                      |
| `kid`     | Key ID matching a JWK in the client's JWKS                    |
| `cty`     | Media type of the JWE payload (`application/json`)            |

### 2.3 File Layout

```text
offset    size                   description
0         24                     header H (public)
24        N × (C + 17)           full chunk(s): ciphertext of C plaintext bytes + 17‑byte overhead (TAG_MESSAGE)
...       ≤ C                    final body chunk: ciphertext of ≤ C plaintext bytes + 17‑byte overhead
...       17                     tail: TAG_FINAL (17‑byte authentication tag)
```

### 2.4 Manifest Carriage

```json
{
  "type": "Patient",
  "url": "https://cdn.example.com/patient_file_1.sxch",
  "extension": {
    "http://argo.run/bulk-export-decryption-key": "<compact-JWE>"
  }
}
```

* One JWE per file entry (or a single top-level extension if CEK is shared).

### 2.5 Chunk Framing Rules

1. **Header (24 B)** – the SecretStream header **H** at offset 0.
2. **Encrypted data region** – a sequence of:

   * N full chunks: each exactly **C** plaintext bytes + 17‑byte overhead (`TAG_MESSAGE`)
   * One final body chunk: ≤ **C** plaintext bytes + 17‑byte overhead (`TAG_MESSAGE`)
3. **Tail (17 B `TAG_FINAL`)** – the 17‑byte final authentication tag marking end of stream.

Clients should:

* Read 24 B for the header, then initialize via `crypto_secretstream_xchacha20poly1305_init_pull(header, K)`.
* **Loop**: while buffer ≥ (C+17):

  * take `block = buffer.slice(0, C+17)`, decrypt with `pull(state, block)`, write plaintext.
  * drop that slice.
* Once fewer than (C+17+17) bytes remain:

  * `finalBody = buf.slice(0, buf.length – 17)`, decrypt and write if nonzero.
  * `tail = buf.slice(buf.length – 17)`, decrypt: verify `tag === TAG_FINAL`.

---

## 3 Bun / TypeScript Reference Implementation

The following illustrates Bun-based file encryption and decryption:

### Decrypt

```ts
import sodium from "libsodium-wrappers";
import { file } from "bun";

export async function encryptFileStream(
  plainPath: string,
  encPath: string,
  key: Uint8Array,
  chunkSize: number = 1 << 20,        // 1 MiB default
  contentType: string = "application/fhir+ndjson"
) {
  await sodium.ready;
  const { header, state } = sodium.crypto_secretstream_xchacha20poly1305_init_push(key);
  const writer = file(encPath).writer();
  await writer.write(header);

  const reader = file(plainPath).stream().getReader();
  let buffer = new Uint8Array(0);

  while (true) {
    const { done, value } = await reader.read();
    if (!done && value) {
      const tmp = new Uint8Array(buffer.length + value.length);
      tmp.set(buffer);
      tmp.set(value, buffer.length);
      buffer = tmp;
    }
    while (buffer.length >= chunkSize || (done && buffer.length > 0)) {
      const plainChunk = buffer.slice(0, Math.min(chunkSize, buffer.length));
      buffer = buffer.slice(plainChunk.length);
      const enc = sodium.crypto_secretstream_xchacha20poly1305_push(
        state,
        plainChunk,
        null,
        sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
      );
      await writer.write(enc);
      if (done && buffer.length === 0) break;
    }
    if (done) break;
  }

  const final = sodium.crypto_secretstream_xchacha20poly1305_push(
    state,
    new Uint8Array(0),
    null,
    sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL
  );
  await writer.write(final);
  await writer.end();
}
```

### Encrypt
```ts
import sodium from "libsodium-wrappers";
import { file } from "bun";

export async function decryptFileStream(
  encryptedStreamHttpBody: ReadableStream<Uint8Array>,
  decPath: string,
  cek: Uint8Array,
  chunkSizeFromJWE: number,
  contentTypeFromJWE: string,
  contentEncodingFromJWE?: "gzip"
) {
  await sodium.ready;
  const reader = encryptedStreamHttpBody.getReader();
  const { value: firstChunk, done } = await reader.read();
  if (done || !firstChunk || firstChunk.length < sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES) {
    throw new Error('Incomplete header');
  }
  const header = firstChunk.subarray(0, sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES);
  const state = sodium.crypto_secretstream_xchacha20poly1305_init_pull(header, cek);
  let buffer = firstChunk.subarray(sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES);

  const writer = file(decPath).writer();
  const C = chunkSizeFromJWE;
  const ABYTES = sodium.crypto_secretstream_xchacha20poly1305_ABYTES;

  while (true) {
    while (buffer.length < C + ABYTES + ABYTES) {
      const { value: nextChunk, done: chunkDone } = await reader.read();
      if (chunkDone) break;
      if (nextChunk) {
        const tmp = new Uint8Array(buffer.length + nextChunk.length);
        tmp.set(buffer);
        tmp.set(nextChunk, buffer.length);
        buffer = tmp;
      }
    }
    if (buffer.length >= C + ABYTES) {
      const part = buffer.subarray(0, C + ABYTES);
      buffer = buffer.subarray(C + ABYTES);
      const { message } = sodium.crypto_secretstream_xchacha20poly1305_pull(state, part);
      await writer.write(message);
      continue;
    }
    break;
  }

  if (buffer.length < ABYTES) {
    throw new Error('Missing final tag');
  }
  const finalBodySize = buffer.length - ABYTES;
  if (finalBodySize > 0) {
    const { message } = sodium.crypto_secretstream_xchacha20poly1305_pull(
      state,
      buffer.subarray(0, finalBodySize)
    );
    await writer.write(message);
  }
  const { tag } = sodium.crypto_secretstream_xchacha20poly1305_pull(
    state,
    buffer.subarray(finalBodySize)
  );
  if (tag !== sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
    throw new Error('Invalid final tag');
  }
  await writer.end();
  console.log(`🔓 Decryption complete: ${decPath}`);
}
```

---

## 4 JWKS Requirements

Clients must publish keys with:

| Field | Value                                    |
| ----- | ---------------------------------------- |
| `use` | `"enc"`                                  |
| `alg` | `"RSA-OAEP-256"`  or  `"ECDH-ES+A256KW"` |
| `kid` | Unique key identifier                    |

Servers select the first key whose `use==="enc"` and whose `alg` they support.

---

## 5 Compression Support

| JWE Field                   | Interpretation                                             |
| --------------------------- | ---------------------------------------------------------- |
| *(absent)*                  | No compression                                             |
| `"content_encoding":"gzip"` | Plaintext was GZIP-compressed (RFC 1952) before encryption |

Clients MUST inspect the JWE’s `"content_encoding"` claim and apply the corresponding decompressor to the decrypted stream.

---

## 6 Security & Operational Notes

* **Uniqueness:** Never reuse CEK **K** across files or runs.
* **Length Validation:**

  1. File length ≥ 24 bytes (header) + 17 bytes (minimum final chunk).
  2. After header, zero or more full chunks of exactly C + 17 bytes, then one final chunk of 17–C+17 bytes. Deviations indicate corruption or truncation.
* **Resumption:** Clients may resume on chunk boundaries via HTTP Range.
* **Key Rotation:** Generate a fresh CEK per file or per export batch for forward secrecy.

---

## 7 Conclusion

This protocol couples libsodium’s streaming AEAD for chunk-level authenticity and resumable downloads with JWE for key delivery. Using familiar HTTP header names (`content_type`, `content_encoding`) in the JWE payload clearly signals media and compression, enabling uniform support in TypeScript, Rust, Go, Java, .NET, and any libsodium-enabled environment.

---

# Demo Output

```
bun install
bun index.ts

------------------------------------------------------------------------------------------------
| Test Case                               | Encrypted Size     | Duration (ms) | Status    |
|-----------------------------------------|--------------------|---------------|-----------|
| ECDH-ES Demo - 1MB                      |          1023.9 KB |        494.64 | ✅ SUCCESS |
| RSA-OAEP Demo - 1MB                     |          1023.8 KB |        445.84 | ✅ SUCCESS |
| ECDH-ES Demo - 1MB_GZIP                 |          174.07 KB |         56.44 | ✅ SUCCESS |
| RSA-OAEP Demo - 1MB_GZIP                |           174.2 KB |         48.31 | ✅ SUCCESS |
| ECDH-ES Demo - 10MB                     |              10 MB |       4803.53 | ✅ SUCCESS |
| RSA-OAEP Demo - 10MB                    |              10 MB |       3911.78 | ✅ SUCCESS |
| ECDH-ES Demo - 10MB_GZIP                |            1.69 MB |        662.49 | ✅ SUCCESS |
| RSA-OAEP Demo - 10MB_GZIP               |            1.69 MB |        622.65 | ✅ SUCCESS |
| ECDH-ES Demo - 20MB                     |              20 MB |       7743.96 | ✅ SUCCESS |
| RSA-OAEP Demo - 20MB                    |              20 MB |       7719.73 | ✅ SUCCESS |
| ECDH-ES Demo - 20MB_GZIP                |            3.39 MB |       1514.61 | ✅ SUCCESS |
| RSA-OAEP Demo - 20MB_GZIP               |            3.39 MB |       1215.62 | ✅ SUCCESS |
------------------------------------------------------------------------------------------------
```
