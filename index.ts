import * as jose from 'jose';
import sodium from 'libsodium-wrappers';

// --- Constants ---
const BULK_EXPORT_DECRYPTION_KEY_URL = "http://argo.run/bulk-export-decryption-key";
const NDJSON_CIPHER_ALGORITHM = "secretstream_xchacha20poly1305";
const DEFAULT_PLAINTEXT_CHUNK_SIZE = 1 * 1024 * 1024; // 1 MiB
const DEFAULT_CONTENT_TYPE = "application/octet-stream"; // Default for this demo

const SAMPLE_NDJSON_DATA = [
  { resourceType: "Patient", id: "123", name: [{ family: "Doe", given: ["John"] }] },
  { resourceType: "Observation", id: "obs1", status: "final", code: { text: "Vital Signs" }, subject: { reference: "Patient/123" } },
].map(obj => JSON.stringify(obj)).join('\n');

// --- Helper Functions ---
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

function stringToUint8Array(str: string): Uint8Array {
  return textEncoder.encode(str);
}

function uint8ArrayToString(arr: Uint8Array): string {
  return textDecoder.decode(arr);
}

// --- Client Key Generation ---
interface ClientKeys {
  publicKey: jose.KeyLike;
  privateKey: jose.KeyLike; // This is the KeyLike object
  publicJwk: jose.JWK;     // Public key in JWK format
  privateJwk: jose.JWK;    // Private key in JWK format (NEW)
  keyType: 'EC' | 'RSA';
}

async function generateClientECKeys(): Promise<ClientKeys> {
  console.log("🔑 Client: Generating P-384 ECDH-ES key pair for key agreement...");
  const keyPairAlgorithm = 'ECDH-ES';
  const { publicKey, privateKey } = await jose.generateKeyPair(keyPairAlgorithm, { crv: 'P-384', extractable: true });
  
  const publicJwk = await jose.exportJWK(publicKey) as any;
  publicJwk.kid = `client-p384-key-${Math.random().toString(36).substring(2, 10)}`;
  publicJwk.alg = 'ECDH-ES+A256KW'; 
  publicJwk.use = "enc";
  publicJwk.exp = Math.floor(Date.now() / 1000) + (24 * 60 * 60); // Expires in 1 day
  
  const privateJwk = await jose.exportJWK(privateKey) as any;
  privateJwk.kid = publicJwk.kid; // Keep kid consistent
  privateJwk.alg = 'ECDH-ES+A256KW';

  console.log(`🔑 Client (EC): Generated Public JWK: ${JSON.stringify(publicJwk)}`);
  return { publicKey, privateKey, publicJwk, privateJwk, keyType: 'EC' };
}

async function generateClientRSAKeys(): Promise<ClientKeys> {
  console.log("🔑 Client: Generating RSA 3072-bit key pair (for RSA-OAEP-256)...");
  // 'PS384' generates an RSA key. Modulus length is important.
  // extractable: true is crucial for exporting the private key.
  const { publicKey, privateKey } = await jose.generateKeyPair('PS384', { modulusLength: 3072, extractable: true });
  
  const publicJwk = await jose.exportJWK(publicKey) as any;
  publicJwk.kid = `client-rsa3072-key-${Math.random().toString(36).substring(2, 10)}`;
  publicJwk.alg = 'RSA-OAEP-256'; // Indicate to server the JWE alg for encryption
  publicJwk.use = "enc";
  publicJwk.exp = Math.floor(Date.now() / 1000) + (24 * 60 * 60); // Expires in 1 day
  
  const privateJwk = await jose.exportJWK(privateKey) as any;
  privateJwk.kid = publicJwk.kid; // Keep kid consistent
  // For RSA, the private JWK often doesn't need an 'alg' if its kty is "RSA"
  // and its usage for decryption is inferred by the JWE alg header.
  // However, setting it can sometimes help certain JOSE implementations.
  // We will rely on importing it with the correct JWE alg in unwrapCEK.

  console.log(`🔑 Client (RSA): Generated Public JWK: ${JSON.stringify(publicJwk)}`);
  return { publicKey, privateKey, publicJwk, privateJwk, keyType: 'RSA' };
}


// --- Server-Side Simulation ---

function generateCEK(): Uint8Array {
  console.log("🛡️ Server: Generating Content Encryption Key (CEK) for NDJSON...");
  return sodium.crypto_secretstream_xchacha20poly1305_keygen();
}

async function wrapCEK(
  cek: Uint8Array,
  clientPublicJwk: jose.JWK, 
  jweAlg: 'ECDH-ES+A256KW' | 'RSA-OAEP-256',
  plaintextChunkSize: number, // New parameter
  contentType: string,        // New parameter
  contentEncoding?: "gzip",   // New optional parameter
  jweEnc: 'A256GCM' = 'A256GCM'
): Promise<string> {
  console.log(`🛡️ Server: Wrapping CEK with client's public key using JWE (alg: ${jweAlg})...`);
  const jwePayload: { k: string; cipher: string; chunk: number; content_type: string; content_encoding?: string } = {
    k: jose.base64url.encode(cek),
    cipher: NDJSON_CIPHER_ALGORITHM,
    chunk: plaintextChunkSize,
    content_type: contentType,
  };

  if (contentEncoding) {
    jwePayload.content_encoding = contentEncoding;
  }

  const clientPublicKeyForJWE = await jose.importJWK(clientPublicJwk, jweAlg); 

  const jwe = await new jose.CompactEncrypt(stringToUint8Array(JSON.stringify(jwePayload)))
    .setProtectedHeader({
      alg: jweAlg, 
      enc: jweEnc,       
      kid: clientPublicJwk.kid, 
      cty: 'application/json', 
    })
    .encrypt(clientPublicKeyForJWE);

  console.log("🛡️ Server: CEK wrapped in JWE compact serialization.");
  return jwe;
}

function createManifest(
  encryptedFileUrl: string,
  jweString: string,
  fileType: string = "Patient",
  manifestSuffix: string = ""
): object {
  console.log(`🛡️ Server: Creating Bulk Export manifest ${manifestSuffix}...`);
  const manifest = {
    transactionTime: new Date().toISOString(),
    request: `https://example.com/fhir/Patient/$export?_type=Patient,Observation&run=${manifestSuffix}`,
    requiresAccessToken: true,
    output: [
      {
        type: fileType,
        url: encryptedFileUrl,
        extension: {
          [BULK_EXPORT_DECRYPTION_KEY_URL]: jweString,
        },
      },
    ],
  };
  console.log("🛡️ Server: Manifest created.");
  return manifest;
}

// --- Client-Side Simulation ---

function resolveManifestAndExtractJWE(manifest: any, fileType: string = "Patient"): string | null {
  // ... (no changes)
  console.log(`📄 Client: Resolving manifest for file type "${fileType}"...`);
  const fileEntry = manifest.output?.find((entry: any) => entry.type === fileType);
  if (!fileEntry) {
    console.error(`📄 Client: No output entry found for type "${fileType}".`);
    return null;
  }

  const jweString = fileEntry.extension?.[BULK_EXPORT_DECRYPTION_KEY_URL];
  if (!jweString) {
    console.error(`📄 Client: No decryption key extension found for type "${fileType}".`);
    return null;
  }
  console.log("📄 Client: JWE string extracted from manifest.");
  return jweString;
}

async function unwrapCEK(
  jweCompact: string,
  clientPrivateJwk: jose.JWK, 
  expectedJweAlg: 'ECDH-ES+A256KW' | 'RSA-OAEP-256'
): Promise<{ cek: Uint8Array; cipher: string; plaintextChunkSize: number; contentType: string; contentEncoding?: "gzip" } | null> {
  console.log(`📄 Client: Unwrapping CEK from JWE (expecting alg: ${expectedJweAlg})...`);
  try {
    const privateKeyForJWE = await jose.importJWK(clientPrivateJwk, expectedJweAlg);
    const { plaintext, protectedHeader } = await jose.compactDecrypt(jweCompact, privateKeyForJWE);
    
    if (protectedHeader.alg !== expectedJweAlg) {
        console.error(`📄 Client: JWE header algorithm mismatch! Expected ${expectedJweAlg}, got ${protectedHeader.alg}.`);
        return null;
    }

    const payload = JSON.parse(uint8ArrayToString(plaintext));

    if (!payload.k || !payload.cipher || !payload.content_type) {
      console.error("📄 Client: Invalid JWE payload structure after decryption (missing k, cipher, or content_type).");
      return null;
    }
    if (payload.cipher !== NDJSON_CIPHER_ALGORITHM) {
      console.error(`📄 Client: Mismatch in expected NDJSON cipher algorithm. Expected ${NDJSON_CIPHER_ALGORITHM}, got ${payload.cipher}`);
      return null;
    }

    const cek = jose.base64url.decode(payload.k);
    const plaintextChunkSize = (typeof payload.chunk === 'number' && payload.chunk > 0) ? payload.chunk : DEFAULT_PLAINTEXT_CHUNK_SIZE;
    const contentType = payload.content_type;
    const contentEncoding = payload.content_encoding as ("gzip" | undefined);

    if (typeof payload.chunk !== 'undefined' && (typeof payload.chunk !== 'number' || payload.chunk <= 0)) {
        console.warn(`📄 Client: JWE payload had an invalid 'chunk' value (${payload.chunk}). Using default ${DEFAULT_PLAINTEXT_CHUNK_SIZE}.`);
    }

    console.log(`📄 Client: CEK successfully unwrapped (JWE alg: ${protectedHeader.alg}). ChunkSize: ${plaintextChunkSize}, ContentType: ${contentType}` + (contentEncoding ? `, ContentEncoding: ${contentEncoding}`: ""));
    return { cek, cipher: payload.cipher, plaintextChunkSize, contentType, contentEncoding };
  } catch (error: any) {
    console.error("📄 Client: Error unwrapping CEK:", error.message, error.code ? `(code: ${error.code})` : '');
    if (error.stack) console.error(error.stack);
    return null;
  }
}

// --- Main Execution Logic ---
async function main() {
  console.log("🚀 Starting FHIR Bulk Export Encryption/Decryption Demo 🚀");

  await sodium.ready;
  console.log("Sodium (libsodium-wrappers) initialized.");


  // --- Generate Client Keys (once) ---
  const ecClientKeys = await generateClientECKeys();
  const rsaClientKeys = await generateClientRSAKeys();

  // --- Define File Sizes for Performance Testing ---
  const fileSizesToTest = [
    1 * 1024 * 1024,       // 1 MB
    10 * 1024 * 1024,      // 10 MB
    100 * 1024 * 1024,     // 100 MB
    1000 * 1024 * 1024,    // 1 GB
  ];

  for (const size of fileSizesToTest) {
    const sizeString = `${(size / (1024 * 1024)).toFixed(0)}MB`;
    console.log(`
🧪🧪🧪 Starting Test Runs for File Size: ${sizeString} 🧪🧪🧪`);
    // --- Streaming file flow for EC keys ---
    await runStreamingFileDemo(ecClientKeys, "ECDH-ES Demo", size);
    // --- Streaming file flow for RSA keys ---
    await runStreamingFileDemo(rsaClientKeys, "RSA-OAEP Demo", size);
  }

  console.log("\n🎉 All Demo Flows and Performance Tests Complete 🎉");
}

main().catch(error => {
  console.error("🚨 Unhandled error in main execution:", error);
  process.exit(1);
});

// --- Streaming File Encryption/Decryption Demo (Bun File I/O) ---

const CHUNK_SIZE = 64 * 1024; // 64 KiB plaintext chunk
// const PLAIN_FILE_SIZE_BYTES = 100 * 1024 * 1024; // 100 MiB - Will be parameterized

async function createTempPlaintextFile(path: string, sizeBytes: number) {
  console.log(`📂 Creating plaintext file ${path} of size ${(sizeBytes / (1024 * 1024)).toFixed(0)} MB…`);
  const writer = Bun.file(path).writer();
  // Create a deterministic 64 KiB pattern chunk (so we can verify later)
  const pattern = new Uint8Array(CHUNK_SIZE);
  for (let i = 0; i < CHUNK_SIZE; i++) pattern[i] = i % 256;

  let written = 0;
  while (written < sizeBytes) {
    const bytesToWrite = Math.min(CHUNK_SIZE, sizeBytes - written);
    await writer.write(pattern.subarray(0, bytesToWrite));
    written += bytesToWrite;
  }
  await writer.end();
  console.log(`📂 Plaintext file created: ${path}`);
}

async function encryptFileStream(plainPath: string, encPath: string, cek: Uint8Array, chunkSize: number) {
  console.log(`🔐 Encrypting (stream) ${plainPath} → ${encPath} with chunk size ${chunkSize}`);
  const { header, state } = sodium.crypto_secretstream_xchacha20poly1305_init_push(cek);
  const writer = Bun.file(encPath).writer();
  
  // Write the header first
  await writer.write(header);
  
  const plainFile = Bun.file(plainPath);
  const fileSize = plainFile.size;
  let bytesRead = 0;
  
  // Process the file in fixed-size chunks
  while (bytesRead < fileSize) {
    const remainingBytes = fileSize - bytesRead;
    const currentChunkSize = Math.min(chunkSize, remainingBytes);
    
    // Read the chunk
    const chunk = new Uint8Array(await plainFile.slice(bytesRead, bytesRead + currentChunkSize).arrayBuffer());
    bytesRead += chunk.length;
    
    // Determine if this is the final chunk
    const tag = bytesRead >= fileSize ? 
      sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL : 
      sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;
    
    // Encrypt the chunk
    const cipherChunk = sodium.crypto_secretstream_xchacha20poly1305_push(state, chunk, null, tag);
    await writer.write(cipherChunk);
  }
  
  await writer.end();
  console.log(`🔐 Encryption complete: ${encPath}`);
}

async function decryptFileStream(
  encryptedStream: ReadableStream<Uint8Array>,
  decPath: string,
  cek: Uint8Array,
  plaintextChunkSizeUsedDuringEncryption: number
) {
  console.log(`🔓 Decrypting (stream) from HTTP stream → ${decPath} with original plaintext chunk size ${plaintextChunkSizeUsedDuringEncryption}`);

  const writer = Bun.file(decPath).writer();
  const reader = encryptedStream.getReader();
  
  const headerBytes = sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES;
  const ABYTES = sodium.crypto_secretstream_xchacha20poly1305_ABYTES;
  const encryptedMessageChunkSize = plaintextChunkSizeUsedDuringEncryption + ABYTES;

  let state: sodium.StateAddress;
  let isDone = false;

  // Optimized streamChunker async generator
  async function* streamChunker(
    streamReader: ReadableStreamDefaultReader<Uint8Array>,
    getChunkSize: () => number 
  ): AsyncGenerator<Uint8Array, void, undefined> {
    let chunkList: Uint8Array[] = [];
    let totalBufferedBytes = 0;
    let streamEnded = false;

    try {
      while (true) {
        const currentTargetSize = getChunkSize();
        if (currentTargetSize === 0) { // Optional: a way to signal explicit stop
           // console.log("[SC] Received target size 0, stopping.");
           return;
        }

        // Phase 1: Buffer enough data or until stream ends
        while (totalBufferedBytes < currentTargetSize && !streamEnded) {
          // console.log(`[SC] Need ${currentTargetSize}, have ${totalBufferedBytes}. Reading...`);
          const { done, value } = await streamReader.read();
          if (value && value.length > 0) {
            chunkList.push(value);
            totalBufferedBytes += value.length;
            // console.log(`[SC] Read ${value.length} bytes. Total buffered: ${totalBufferedBytes}`);
          }
          if (done) {
            // console.log("[SC] Stream ended.");
            streamEnded = true;
          }
        }

        // Phase 2: Yield chunk if possible
        if (totalBufferedBytes >= currentTargetSize) {
          const outputChunk = new Uint8Array(currentTargetSize);
          let bytesCopiedToOutput = 0;
          let newTotalBufferedBytes = 0;
          const newChunkList: Uint8Array[] = [];

          for (const buffer of chunkList) {
            if (bytesCopiedToOutput === currentTargetSize) { // outputChunk is full
              newChunkList.push(buffer); // This buffer remains untouched for next time
              newTotalBufferedBytes += buffer.length;
              continue;
            }

            const bytesToCopyFromThisBuffer = Math.min(buffer.length, currentTargetSize - bytesCopiedToOutput);
            outputChunk.set(buffer.subarray(0, bytesToCopyFromThisBuffer), bytesCopiedToOutput);
            bytesCopiedToOutput += bytesToCopyFromThisBuffer;

            if (bytesToCopyFromThisBuffer < buffer.length) { // Partially consumed this buffer
              const remainder = buffer.subarray(bytesToCopyFromThisBuffer);
              newChunkList.push(remainder);
              newTotalBufferedBytes += remainder.length;
            }
            // If fully consumed, it's simply not added to newChunkList
          }
          chunkList = newChunkList;
          totalBufferedBytes = newTotalBufferedBytes;
          // console.log(`[SC] Yielding chunk of size ${outputChunk.length}. Remaining buffered: ${totalBufferedBytes}`);
          yield outputChunk;
        } else if (streamEnded && totalBufferedBytes > 0) {
          // Stream ended, and we have some leftover data (less than currentTargetSize)
          // console.log(`[SC] Stream ended. Yielding final partial chunk of size ${totalBufferedBytes}.`);
          const finalChunk = new Uint8Array(totalBufferedBytes);
          let offset = 0;
          for (const buffer of chunkList) {
            finalChunk.set(buffer, offset);
            offset += buffer.length;
          }
          chunkList = [];
          totalBufferedBytes = 0;
          yield finalChunk;
          return; // End of generator
        } else if (streamEnded && totalBufferedBytes === 0) {
          // console.log("[SC] Stream ended and no data left.");
          return; // End of generator
        }
      }
    } finally {
      // Optional: Cleanup if needed, e.g., if reader was exclusively owned.
      // Here, reader is managed by decryptFileStream.
      // console.log("[SC] Exiting streamChunker.");
    }
  }

  let isReadingHeader = true;
  const getChunkSizeCallback = (): number => {
    if (isReadingHeader) {
      // console.log("[DSC] Requesting header chunk size: ", headerBytes);
      return headerBytes;
    }
    // console.log("[DSC] Requesting message chunk size: ", encryptedMessageChunkSize);
    return encryptedMessageChunkSize;
  };

  const chunkProvider = streamChunker(reader, getChunkSizeCallback);

  // 1. Read and extract header
  console.log("📄 Client: Reading stream for header using chunkProvider...");
  const headerResult = await chunkProvider.next();

  if (headerResult.done || !headerResult.value) {
    await writer.end();
    throw new Error("Stream ended prematurely or failed to read header via chunkProvider.");
  }
  if (headerResult.value.length !== headerBytes) {
    await writer.end();
    throw new Error(`Read incomplete header: expected ${headerBytes}, got ${headerResult.value.length}`);
  }
  const header = headerResult.value;

  try {
    state = sodium.crypto_secretstream_xchacha20poly1305_init_pull(header, cek);
  } catch (e: any) {
    await writer.end();
    console.error("📄 Client: Failed to initialize decryption state with header from stream.", e.message);
    throw e;
  }
  console.log("📄 Client: Decryption state initialized with stream header.");
  isReadingHeader = false; // Switch to message chunk size for subsequent calls

  // 2. Process encrypted chunks
  console.log("📄 Client: Reading encrypted messages using chunkProvider...");
  for await (const encryptedChunk of chunkProvider) {
    if (isDone) break; // Should not be strictly necessary if TAG_FINAL is handled

    if (!encryptedChunk || encryptedChunk.length === 0) {
        // console.log("📄 Client: Received empty or null chunk from provider, assuming end.");
        break; // Should be handled by generator's own termination
    }

    // console.log(`📄 Client: Received chunk of size ${encryptedChunk.length} for decryption.`);
    const res = sodium.crypto_secretstream_xchacha20poly1305_pull(state, encryptedChunk);
    if (!res) {
      await writer.end();
      console.error(`📄 Client: Decryption failed – bad MAC or incomplete chunk. Chunk size: ${encryptedChunk.length}`);
      throw new Error("Decryption failed – bad MAC or incomplete chunk.");
    }
    
    await writer.write(res.message);
    // console.log(`📄 Client: Decrypted ${res.message.length} bytes from chunk.`);
    
    if (res.tag === sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
      isDone = true;
      console.log("📄 Client: TAG_FINAL encountered, decryption complete.");
      // Once TAG_FINAL is processed, we expect the generator to yield no more data or an empty final chunk.
      // The loop will then terminate naturally or via the break for empty chunk.
      break; 
    }
  }
  
  await writer.end();

  if (!isDone) {
     console.warn("🔓 Decryption stream processing finished, but TAG_FINAL was not encountered. The decrypted file might be incomplete or corrupted.");
  }
  console.log(`🔓 Decryption complete: ${decPath}`);
}

async function runStreamingFileDemo(clientKeys: ClientKeys, demoName: string, fileSizeBytes: number) {
  const sizeSuffix = `${(fileSizeBytes / (1024 * 1024)).toFixed(0)}MB`;
  const fullDemoName = `${demoName} - ${sizeSuffix}`;
  console.log(`
--- Starting ${fullDemoName} Streaming File Flow (${clientKeys.keyType} Keys) ---`);

  await sodium.ready;
  const baseSuffix = `${demoName.toLowerCase().replace(/ /g, '_')}_${sizeSuffix.replace(/ /g, '')}`;
  const tmpPlain = `./tmp_plain_${baseSuffix}.bin`;
  const tmpEnc   = `./tmp_enc_${baseSuffix}.bin`; 
  const tmpDec   = `./tmp_dec_${baseSuffix}.bin`; 

  // 1. Ensure plaintext file exists (this is outside the timer)
  //    Only create if it doesn't exist to save time on repeated runs for the same size during dev,
  //    but for a formal perf test, one might want to create it fresh each time or ensure it's pre-created.
  if (!(await Bun.file(tmpPlain).exists())) {
    await createTempPlaintextFile(tmpPlain, fileSizeBytes);
  }

  console.time(`⏱️ E2E Demo (${fullDemoName})`);

  // --- Server Simulation ---
  const cek_K = generateCEK();
  const CHUNK_SIZE_1MB = 1024 * 1024; // 1 MiB (plaintext chunk size for crypto stream)
  
  await encryptFileStream(tmpPlain, tmpEnc, cek_K, CHUNK_SIZE_1MB); 

  const encryptedFileName = `encrypted_export_${baseSuffix}.bin`;
  const server = Bun.serve({
    port: 0, 
    fetch(req) {
      const url = new URL(req.url);
      if (url.pathname === `/download/${encryptedFileName}`) {
        // console.log(`💻 Server: Serving ${tmpEnc} for download...`);
        return new Response(Bun.file(tmpEnc), {
          headers: {
            "Content-Type": "application/octet-stream",
            "Content-Disposition": `attachment; filename="${encryptedFileName}"`
          }
        });
      }
      return new Response("Not Found", { status: 404 });
    },
    error(error) {
      console.error("💻 Server error:", error);
      return new Response("Server Error", { status: 500 });
    }
  });
  // console.log(`💻 Server: HTTP server listening on port ${server.port} to serve ${tmpEnc}`);
  const encryptedFileUrl = `http://${server.hostname}:${server.port}/download/${encryptedFileName}`;

  const jweAlg = clientKeys.keyType === 'EC' ? 'ECDH-ES+A256KW' : 'RSA-OAEP-256';
  // Pass the actual plaintext chunk size used for encryption and content type to wrapCEK
  const jweString = await wrapCEK(cek_K, clientKeys.publicJwk, jweAlg, CHUNK_SIZE_1MB, DEFAULT_CONTENT_TYPE);
  const manifest = createManifest(encryptedFileUrl, jweString, "Binary", `${fullDemoName} Stream`);

  // --- Client Simulation ---
  const extractedJwe = resolveManifestAndExtractJWE(manifest, "Binary");
  if (!extractedJwe) {
    console.error("Failed to extract JWE from manifest");
    server.stop(true);
    console.timeEnd(`⏱️ E2E Demo (${fullDemoName})`); // End timer on error
    return;
  }

  const unwrapped = await unwrapCEK(extractedJwe, clientKeys.privateJwk, jweAlg);
  if (!unwrapped) {
    console.error("Failed to unwrap CEK");
    server.stop(true);
    console.timeEnd(`⏱️ E2E Demo (${fullDemoName})`); // End timer on error
    return;
  }

  // console.log(`📄 Client: Fetching encrypted file from ${encryptedFileUrl}...`);
  const response = await fetch(encryptedFileUrl);

  if (!response.ok || !response.body) {
    console.error(`📄 Client: Failed to download encrypted file. Status: ${response.status}`);
    server.stop(true);
    console.timeEnd(`⏱️ E2E Demo (${fullDemoName})`); // End timer on error
    return;
  }
  // console.log("📄 Client: Encrypted file download started, streaming to decryption...");

  try {
    // Use the plaintextChunkSize from the unwrapped JWE payload
    await decryptFileStream(response.body, tmpDec, unwrapped.cek, unwrapped.plaintextChunkSize);
  } catch (error) {
    console.error(`❌ FAILURE (${fullDemoName} Stream): Error during decryption from stream:`, error);
    server.stop(true);
    console.timeEnd(`⏱️ E2E Demo (${fullDemoName})`); // End timer on error
    return; 
  }

  const hashPlain = Bun.hash(await Bun.file(tmpPlain).bytes());
  const hashDec   = Bun.hash(await Bun.file(tmpDec).bytes());
  
  if (hashPlain === hashDec) {
    console.log(`✅ SUCCESS (${fullDemoName} Stream): Decrypted file matches original.`);
  } else {
    console.error(`❌ FAILURE (${fullDemoName} Stream): Decrypted file does NOT match original.`);
    console.error(`Hash Plain: ${hashPlain}, Hash Dec: ${hashDec}`);
  }
  
  console.timeEnd(`⏱️ E2E Demo (${fullDemoName})`);
  
  server.stop(true); 
  // console.log("💻 Server: HTTP server stopped.");

  // Cleanup temporary files
  // console.log(`🧹 Cleaning up temporary files for ${fullDemoName}...`);
  try {
    if (await Bun.file(tmpPlain).exists()) await Bun.file(tmpPlain).delete();
    if (await Bun.file(tmpEnc).exists()) await Bun.file(tmpEnc).delete();
    if (await Bun.file(tmpDec).exists()) await Bun.file(tmpDec).delete();
    // console.log(`🧹 Cleanup complete for ${fullDemoName}.`);
  } catch (e) {
    console.warn(`🧹 Warning: Error during cleanup for ${fullDemoName}:`, e);
  }

  console.log(`--- ${fullDemoName} Streaming File Flow Complete ---
`);
}

// Run the streaming demo after existing demos
