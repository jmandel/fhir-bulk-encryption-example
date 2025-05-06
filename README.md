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
* **Chunk format:** each encrypted chunk = *(plaintext ≤ C)* + 16 byte MAC. Clients verify each chunk’s MAC as they stream.

### 2.2 Key, Header, Chunk-Size & Media Packaging

| Element           | Conveyed in JWE payload field | Description                                            |
| ----------------- | ----------------------------- | ------------------------------------------------------ |
| 32-byte key **K** | `"k"`                         | Base64-url-encoded CEK                                 |
| Chunk size **C**  | `"chunk"`                     | Bytes of plaintext per chunk (omit ⇒ default 1 MiB)    |
| Cipher identifier | `"cipher"`                    | `"secretstream_xchacha20poly1305"`                     |
| Media Type        | `"content_type"`              | e.g. `"application/fhir+ndjson"`                       |
| Content Encoding  | `"content_encoding"`          | omit ⇒ none; `"gzip"` ⇒ gzip applied before encryption |

#### JWE payload examples

* **Uncompressed JSON**

  ```json
  {
    "k": "<base64url-K>",
    "chunk": 1048576,
    "cipher": "secretstream_xchacha20poly1305",
    "content_type": "application/javascript"
  }
  ```

* **Gzip-compressed FHIR NDJSON**

  ```json
  {
    "k": "<base64url-K>",
    "chunk": 1048576,
    "cipher": "secretstream_xchacha20poly1305",
    "content_type": "application/fhir+ndjson",
    "content_encoding": "gzip"
  }
  ```

<small>**JWE Protected Header:**

````
alg: "RSA-OAEP-256"  or  "ECDH-ES+A256KW"  
enc: "A256GCM"  
kid: <client key ID>  
cty: "application/json"  
```</small>

**Server rule:**  
1. If `content_encoding==="gzip"`, compress the plaintext with RFC 1952 GZIP (e.g. `gzip -6`) **before** streaming into `push()`.  
2. Build JWE payload as above and emit compact JWE in the manifest.

**Client rule:**  
1. Decrypt and parse JWE payload.  
2. Read header H, call `crypto_secretstream_xchacha20poly1305_init_pull(H,K)`.  
3. For each encrypted chunk, `pull()` to obtain plaintext bytes.  
4. If payload `"content_encoding":"gzip"`, pipe the decrypted stream through a GZIP decoder (e.g. `zlib.createGunzip()` in Node or `new DecompressionStream('gzip')` in browsers).

### 2.3 File Layout  
````

offset  size           description
0       24             header H (public)
24      …              encrypted chunks
└─ each = (plaintext ≤ C) + 16 MAC bytes

````
All chunks except the final are exactly `C + 16` bytes; the final chunk ranges from 16 to `C + 16` bytes.

### 2.4 Manifest Carriage  
```json
{
  "type": "Patient",
  "url": "https://cdn.example.com/patient_file_1.sxch",
  "extension": {
    "http://argo.run/bulk-export-decryption-key": "<compact-JWE>"
  }
}
````

* One JWE per file entry.
* If all files share the same CEK, a single JWE may appear in the top-level `extension`.

---

## 3 Reference Bun / TypeScript Encryption Snippet

```ts
import sodium from "libsodium-wrappers";
import { file } from "bun";

export async function encryptFileStream(
  plainPath: string,
  encPath: string,
  key: Uint8Array,             // 32 bytes CEK
  chunkSize = 1 << 20,         // 1 MiB
  contentType = "application/fhir+ndjson",
  contentEncoding?: "gzip"
) {
  await sodium.ready;
  const { header, state } =
    sodium.crypto_secretstream_xchacha20poly1305_init_push(key);
  const writer = file(encPath).writer();
  await writer.write(header);

  const plainFile = file(plainPath);
  const plainStream = contentEncoding === "gzip"
    ? /* wrap plainFile.stream() through gzip encoder */
      /* e.g. use Bun.TransformStream or zlib in Node */
      /* pseudo-code: plainFile.stream().pipeThrough(new CompressionStream("gzip")) */
      /* for brevity, not shown here */
      plainFile.stream() 
    : plainFile.stream();

  const reader = plainStream.getReader();
  let offset = 0;
  const decoder = new TextDecoder(); // if needed

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    const chunk = value; // Uint8Array up to chunkSize
    const tag = sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;
    const enc = sodium.crypto_secretstream_xchacha20poly1305_push(
      state, chunk, null, tag
    );
    await writer.write(enc);
    offset += chunk.length;
  }
  // Finalize with TAG_FINAL
  const final = sodium.crypto_secretstream_xchacha20poly1305_push(
    state, new Uint8Array(0), null,
    sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL
  );
  await writer.write(final);
  await writer.end();
}
```

*Decryption follows the client rule in §2.2.*

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

  1. File length ≥ 24 bytes (header) + 16 bytes (minimum final chunk).
  2. After header, zero or more full chunks of exactly `C + 16` bytes, then one final chunk of 16–`C+16` bytes.
     Deviations indicate corruption or truncation.
* **Resumption:** Clients may resume on chunk boundaries via HTTP Range.
* **Key Rotation:** Generate a fresh CEK per file or per export batch for forward secrecy.

---

## 7 Conclusion

This protocol couples libsodium’s streaming AEAD for chunk-level authenticity and resumable downloads with JWE for key delivery. Using familiar HTTP header names (`content_type`, `content_encoding`) in the JWE payload clearly signals media and compression, enabling uniform support in TypeScript, Rust, Go, Java, .NET, and any libsodium-enabled environment.

