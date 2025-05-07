# Optional End-to-End Encryption for FHIR Bulk Export (AES-256-GCM)

**Protocol Version 0.5 – 6 May 2025**

This README describes how to perform end‑to‑end encryption of FHIR Bulk‑Export NDJSON files using browser-native Web Crypto (AES-256-GCM) in place of libsodium, and how to convey decryption parameters via a compact JWE.

---

## 1. Goals

1. **Confidentiality & Integrity (per chunk)**: Encrypt each NDJSON chunk with AES-256-GCM, providing a 128‑bit tag per chunk.
2. **Full‑File Authentication**: Use a precomputed SHA‑256 hash of the plaintext for file‑wide authenticity.
3. **In‑Band Key Delivery**: Wrap the Content Encryption Key (CEK) and IV prefix in a compact JWE under the client's public key.
4. **Compatibility**: Maintain the bulk‑export manifest format; clients parse JWE and then decrypt.
5. **Streaming Efficiency**: Process arbitrarily large files with minimal memory usage via WHATWG Streams.

---

## 2. High‑Level Workflow

1. **Precompute File Hash**: Compute SHA‑256 over the entire NDJSON plaintext; base64url‑encode it.
2. **Generate CEK & IV Prefix**: Use `crypto.subtle.generateKey` for AES‑GCM (256 bits), export raw CEK, and generate an 8‑byte random IV prefix. (The IV prefix is written to the stream, not included in the JWE).
3. **Encrypt Stream**: For each 1 MiB chunk:

   * Derive a 12‑byte IV = `iv_prefix ∥ counter`.
   * Call `crypto.subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, cek, chunk)`.
   * Write ciphertext ∥ 16‑byte tag to output stream.
4. **Wrap CEK in JWE**: Construct a compact JWE whose payload includes:

   ```json
   {
     "v": "0.5",
     "k": "<base64url-CEK>",
     "hash": "<base64url-SHA256-hash-of-plaintext>",
     "cty": "application/fhir+ndjson"
   }
   ```

   Encrypt the JWE payload (containing the CEK and plaintext hash) under the client's public key (RSA‑OAEP‑256 or ECDH‑ES+A256KW).
5. **Publish Manifest**: Embed the JWE in the bulk‑export manifest as an `extension` at the top level (or per file).
6. **Client Decrypts**: Client unwraps JWE to recover CEK and the expected plaintext hash, then reads the IV prefix from the stream, streams-decrypts each chunk, and finally verifies the full plaintext hash.

---

## 3. Content Encryption Details

The encrypted file has a simple structure: an initial IV prefix followed by a sequence of encrypted chunks.

```txt
Offset   Size                     Description
0        8 B                      IV prefix (public, random)
8        (chunk_size + 16 B)      Encrypted Chunk 1 (Ciphertext || 16-byte GCM Tag)
...      (chunk_size + 16 B)      Encrypted Chunk N (Ciphertext || 16-byte GCM Tag)
L        (remaining_data + 16 B)  Final Encrypted Chunk (Ciphertext || 16-byte GCM Tag)
```

*   **Plaintext Chunk Size**: Default 1 MiB (1,048,576 bytes). The encryption process reads plaintext in chunks of this size.
*   **IV Prefix**: 8 bytes, cryptographically random, generated once per file. It is written to the beginning of the encrypted output stream. This prefix is public.
*   **Per-Chunk IV Derivation**: For each plaintext chunk, a unique 12-byte IV is derived: `IV = IV_prefix || 4-byte Big-Endian chunk_counter`. The counter starts at 0 for the first chunk and increments for each subsequent chunk.
*   **Encryption (Packing Chunks)**:
    1.  Read a plaintext chunk (e.g., 1 MiB, or remaining bytes if it's the final, smaller chunk).
    2.  Derive the unique 12-byte IV for this chunk using the IV prefix and the current chunk counter.
    3.  Call `crypto.subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, cek, plaintext_chunk)`.
    4.  The result is a single `ArrayBuffer` containing the ciphertext of the chunk immediately followed by its 16-byte GCM authentication tag.
    5.  This combined `Ciphertext_Chunk_N || Tag_Chunk_N` block is written directly to the output stream. This process repeats for all plaintext chunks.
*   **Decryption (Unpacking Chunks)**:
    1.  Read the initial 8-byte IV prefix from the start of the encrypted stream.
    2.  Subsequently, read blocks of data from the stream. For full chunks, each block will be `Plaintext_Chunk_Size + 16` bytes long. The final block may be smaller if the original file size was not an exact multiple of the chunk size (it will be `Remaining_Plaintext_Bytes + 16` bytes).
    3.  For each block read:
        *   Derive the unique 12-byte IV for this chunk using the stored IV prefix and the current chunk counter.
        *   Call `crypto.subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, cek, encrypted_block)`.
        *   If decryption is successful, the result is the original plaintext chunk. This also verifies the chunk's integrity via the embedded tag.
        *   If decryption fails (e.g., due to a tampered block or incorrect key/IV), an error is thrown.
    4.  The decrypted plaintext chunks are reassembled to form the original file.
*   **Tag**: A 128-bit (16-byte) GCM authentication tag is generated and implicitly appended to the ciphertext of *each* chunk by `crypto.subtle.encrypt`. This tag ensures both confidentiality and authenticity at the chunk level. There is no separate file-wide tag generated by AES-GCM itself; overall file integrity is typically handled by a precomputed hash (see Section 1, Goal 2).

---

## 4. Conveying CEK & IV via JWE

### 4.1 JWE Payload

The JWE plaintext (payload) securely carries the Content Encryption Key (CEK) and the expected hash of the original plaintext file. The IV prefix is *not* part of the JWE; it is read directly from the beginning of the encrypted stream.

```json
{
  "v": "0.5",
  "k": "<base64url-encoded CEK>",
  "hash": "<base64url-encoded SHA-256 hash>",
  "cty": "application/fhir+ndjson",
  "enc_opt": "gzip"
}
```

*(Note: `cty` here refers to the original content type of the bulk data, while the JWE Protected Header's `cty` is `application/json` indicating the JWE payload itself is JSON).* 

### 4.2 JWE Protected Header

| Parameter | Description                                  |
| --------- | -------------------------------------------- |
| `alg`     | `RSA-OAEP-256` or `ECDH-ES+A256KW`           |
| `enc`     | `A256GCM`                                    |
| `kid`     | Key ID from the client's JWKS (`use":"enc"`) |
| `cty`     | `application/json`                           |

* Serialize compact form: 5 parts separated by `.`
* Place resulting string in manifest `extension.valueString`.

---

## 5. Manifest Extensions

### 5.1 Top‑Level JWE

```json
{
  "transactionTime": "...",
  "request": "...",
  "requiresAccessToken": true,
  "extension": {
    "url": "http://argo.run/bulk-export-decryption-key",
    "valueString": "<compact-JWE>"
  },
  "output": [ /* encrypted file URLs */ ]
}
```

### 5.2 Per‑File JWE (optional)

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

---

## 6. Client‑Side Decryption & Verification

1.  **Parse JWE**: Extract the `k` (CEK) and `hash` (expected plaintext SHA-256 hash) from the JWE payload. Decode the CEK from base64url to `Uint8Array`. Import the CEK for use with `crypto.subtle.decrypt`.
2.  **Stream-decrypt**:
    *   Read the initial 8-byte IV prefix directly from the beginning of the encrypted file/stream.
    *   Iteratively read blocks of encrypted data. Each block corresponds to an encrypted chunk (ciphertext + 16-byte tag). The expected size for most blocks is `plaintext_chunk_size + 16` bytes. The final block may be smaller.
    *   For each encrypted block:
        *   Derive the per-chunk IV using the IV prefix and the current chunk counter (starting at 0).
        *   Call `crypto.subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, importedCEK, encrypted_block)`.
        *   Append the resulting plaintext `ArrayBuffer` to a temporary store or write it directly to the final decrypted output stream.
3.  **Hash check**: After all chunks are decrypted and reassembled, compute the SHA-256 hash of the *entire recovered plaintext*. Compare this computed hash against the precomputed plaintext hash (which should be provided by the server, e.g., in the manifest `output` entry as an extension, or via another secure mechanism). This verifies full file integrity.

---

## 7. Operational Notes

* **Streaming**: Use WHATWG Streams to minimize memory.
* **Nonce safety**: Monitor chunk counter to avoid wrap‑around (\~4 billion chunks).
* **Integrity**: SHA‑256 ensures end‑to‑end authenticity across the full file.
* **Compatibility**: Clients only need native Web Crypto; no external WASM/JS ciphers.

---

## 8. Example Code Snippets

See `encrypt.js` and `decrypt.js` for complete working examples using the above scheme.
