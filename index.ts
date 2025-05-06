import * as jose from 'jose';
import sodium from 'libsodium-wrappers';

// --- Constants ---
const BULK_EXPORT_DECRYPTION_KEY_URL = "http://argo.run/bulk-export-decryption-key";
const NDJSON_CIPHER_ALGORITHM = "secretstream_xchacha20poly1305";
const DEFAULT_PLAINTEXT_CHUNK_SIZE = 1 * 1024 * 1024; // 1 MiB
const DEFAULT_CONTENT_TYPE = "application/fhir+ndjson"; // Changed to FHIR specific type

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
  publicKey: CryptoKey;
  privateKey: CryptoKey; // This is the KeyLike object
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
  const cek = sodium.crypto_secretstream_xchacha20poly1305_keygen();
  // For demo purposes, log the CEK. In production, NEVER log raw keys.
  console.log(`🛡️ Server: Generated CEK (base64url): ${jose.base64url.encode(cek)} (DEMO ONLY - DO NOT LOG IN PROD)`);
  return cek;
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
  console.log("🛡️ Server: JWE Payload to be encrypted:", JSON.stringify(jwePayload, null, 2));

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
  console.log("🛡️ Server: Compact JWE:", jwe);
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
  console.log("🛡️ Server: Manifest created:", JSON.stringify(manifest, null, 2));
  return manifest;
}

// --- Client-Side Simulation ---

function resolveManifestAndExtractJWE(manifest: any, fileType: string = "Patient"): string | null {
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
  console.log("📄 Client: JWE string extracted from manifest:", jweString);
  return jweString;
}

async function unwrapCEK(
  jweCompact: string,
  clientPrivateJwk: jose.JWK, 
  expectedJweAlg: 'ECDH-ES+A256KW' | 'RSA-OAEP-256'
): Promise<{ cek: Uint8Array; cipher: string; plaintextChunkSize: number; contentType: string; contentEncoding?: "gzip" } | null> {
  console.log(`📄 Client: Unwrapping CEK from JWE (expecting alg: ${expectedJweAlg})...`);
  console.log(`📄 Client: Received Compact JWE for unwrapping:`, jweCompact);
  try {
    const privateKeyForJWE = await jose.importJWK(clientPrivateJwk, expectedJweAlg);
    const { plaintext, protectedHeader } = await jose.compactDecrypt(jweCompact, privateKeyForJWE);
    
    if (protectedHeader.alg !== expectedJweAlg) {
        console.error(`📄 Client: JWE header algorithm mismatch! Expected ${expectedJweAlg}, got ${protectedHeader.alg}.`);
        return null;
    }

    const payload = JSON.parse(uint8ArrayToString(plaintext));
    console.log("📄 Client: Decrypted JWE Payload:", JSON.stringify(payload, null, 2));

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

    // For demo purposes, log the unwrapped CEK. In production, NEVER log raw keys.
    console.log(`📄 Client: Unwrapped CEK (base64url): ${jose.base64url.encode(cek)} (DEMO ONLY - DO NOT LOG IN PROD)`);
    console.log(`📄 Client: CEK successfully unwrapped (JWE alg: ${protectedHeader.alg}). ChunkSize: ${plaintextChunkSize}, ContentType: ${contentType}` + (contentEncoding ? `, ContentEncoding: ${contentEncoding}`: ""));
    return { cek, cipher: payload.cipher, plaintextChunkSize, contentType, contentEncoding };
  } catch (error: any) {
    console.error("📄 Client: Error unwrapping CEK:", error.message, error.code ? `(code: ${error.code})` : '');
    if (error.stack) console.error(error.stack);
    return null;
  }
}

// --- Main Execution Logic ---
let mainHasRun = false; // Guard against multiple executions

async function main() {
  if (mainHasRun) {
    console.warn("🚨 Main function called more than once. Skipping subsequent run.");
    return;
  }
  mainHasRun = true;

  console.log("🚀 Starting FHIR Bulk Export Encryption/Decryption Demo 🚀");

  await sodium.ready;
  console.log("Sodium (libsodium-wrappers) initialized.");

  // --- Generate Client Keys (once) ---
  const ecClientKeys = await generateClientECKeys();
  const rsaClientKeys = await generateClientRSAKeys();

  // --- Define File Sizes for Performance Testing ---
  const fileSizesToTest = [
    // 1 * 1024 * 1024,       // 1 MB
    10 * 1024 * 1024,      // 10 MB
    // 20 * 1024 * 1024,     // 20 MB
  ];

  for (const size of fileSizesToTest) {
    const sizeString = `${(size / (1024 * 1024)).toFixed(0)}MB`;
    console.log(`
🧪🧪🧪 Starting Test Runs for File Size: ${sizeString} 🧪🧪🧪`);
    // --- Streaming file flow for EC keys ---
    await runStreamingFileDemo(ecClientKeys, "ECDH-ES Demo", size, false);
    // --- Streaming file flow for RSA keys ---
    await runStreamingFileDemo(rsaClientKeys, "RSA-OAEP Demo", size, false);

    // GZIP runs
    console.log(`
--- ${sizeString} / GZIP ---`);
    await runStreamingFileDemo(ecClientKeys, "ECDH-ES Demo", size, true);
    await runStreamingFileDemo(rsaClientKeys, "RSA-OAEP Demo", size, true);
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

async function generateRandomPlaintextFile(path: string, sizeBytes: number) {
  console.log(`📂 Generating base plaintext file ${path} of size ${(sizeBytes / (1024 * 1024)).toFixed(0)} MB…`);
  const writer = Bun.file(path).writer();
  const pattern = new Uint8Array(CHUNK_SIZE);
  for (let i = 0; i < CHUNK_SIZE; i++) pattern[i] = i % 256;
  let written = 0;
  while (written < sizeBytes) {
    const bytesToWrite = Math.min(CHUNK_SIZE, sizeBytes - written);
    await writer.write(pattern.subarray(0, bytesToWrite));
    written += bytesToWrite;
  }
  await writer.end();
  console.log(`📂 Base plaintext file generated: ${path}`);
}

async function ensurePlaintextAndGzippedFiles(baseOutputName: string, sizeBytes: number): Promise<{ plain: string; gzipped: string; gzippedSize: number | null }> {
  const filePathPlain = `./${baseOutputName}.ndjson`;
  const filePathGzipped = `./${baseOutputName}.ndjson.gz`;
  let gzippedSize: number | null = null;

  if (!(await Bun.file(filePathPlain).exists())) {
    await generateRandomPlaintextFile(filePathPlain, sizeBytes);
  }

  if (!(await Bun.file(filePathGzipped).exists())) {
    console.log(`🧬 Compressing ${filePathPlain} to ${filePathGzipped}...`);
    const plainContent = await Bun.file(filePathPlain).bytes();
    const gzippedContent = Bun.gzipSync(plainContent);
    await Bun.write(filePathGzipped, gzippedContent);
    console.log(`🧬 Compressed file created: ${filePathGzipped}`);
  }
  // Get gzipped size if it exists
  if (await Bun.file(filePathGzipped).exists()) {
    gzippedSize = await Bun.file(filePathGzipped).size;
  }
  return { plain: filePathPlain, gzipped: filePathGzipped, gzippedSize };
}

// Unified chunker - now accepts a reader directly
async function* flexibleStreamChunker(
  streamReader: ReadableStreamDefaultReader<Uint8Array>,
  getTargetChunkSize: () => number
): AsyncGenerator<Uint8Array, void, undefined> {
  const reader = streamReader; 
  let buffer = new Uint8Array(0); 
  let streamEnded = false;

  try {
    while (true) {
      const currentTargetSize = getTargetChunkSize();
      if (currentTargetSize <= 0) { 
        return;
      }

      while (buffer.length < currentTargetSize && !streamEnded) {
        const { done, value } = await reader.read();
        if (value && value.length > 0) {
          const newBuffer = new Uint8Array(buffer.length + value.length);
          newBuffer.set(buffer);
          newBuffer.set(value, buffer.length);
          buffer = newBuffer;
        }
        if (done) {
          streamEnded = true;
        }
      }

      if (buffer.length >= currentTargetSize) {
        const chunkToYield = buffer.subarray(0, currentTargetSize);
        buffer = buffer.subarray(currentTargetSize);
        yield chunkToYield;
      } else if (streamEnded && buffer.length > 0) { 
        yield buffer;
        buffer = new Uint8Array(0); 
        return; 
      } else if (streamEnded && buffer.length === 0) { 
        return; 
      }
    }
  } finally {
  }
}

async function encryptFileStream(
  plainPath: string, 
  encPath: string, 
  key: Uint8Array, 
  chunkSizeForPush: number, 
  _contentType: string, 
  _contentEncoding?: "gzip"
) {
  console.log(`🔐 Encrypting ${plainPath} → ${encPath}`);
  const { header, state } = sodium.crypto_secretstream_xchacha20poly1305_init_push(key);
  const encFileWriter = Bun.file(encPath).writer();
  
  await encFileWriter.write(header);
  
  const sourceDataStream: ReadableStream<Uint8Array> = Bun.file(plainPath).stream();
  const fileStreamReader = sourceDataStream.getReader();
  const chunkedSource = flexibleStreamChunker(fileStreamReader, () => chunkSizeForPush);

  try {
    for await (const dataChunkToPush of chunkedSource) {
      const tag = sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;
      const cipherChunk = sodium.crypto_secretstream_xchacha20poly1305_push(state, dataChunkToPush, null, tag);
      await encFileWriter.write(cipherChunk);
    }
  } finally {
    if (fileStreamReader) fileStreamReader.releaseLock();
  }
  
  const finalPlainChunk = new Uint8Array(0);
  const finalTag = sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL;
  const finalCipherChunk = sodium.crypto_secretstream_xchacha20poly1305_push(state, finalPlainChunk, null, finalTag);
  await encFileWriter.write(finalCipherChunk);
  
  await encFileWriter.end();
  console.log(`🔐 Encryption complete: ${encPath}`);
}

async function decryptFileStream(
  encryptedStreamHttpBody: ReadableStream<Uint8Array>, // Changed parameter type back to ReadableStream
  decPath: string, 
  cek: Uint8Array,
  chunkSizeFromJWE: number, 
  _contentTypeFromJWE: string, 
  contentEncodingFromJWE?: "gzip"
) {
  console.log(`🔓 Decrypting from HTTP stream → ${decPath} (JWE chunkSize: ${chunkSizeFromJWE} B, ContentEncoding: ${contentEncodingFromJWE || 'none'})`);

  if (contentEncodingFromJWE === "gzip") {
    console.log(`   JWE indicates content was GZIPped. Output file ${decPath} will contain GZIPped data.`);
  } else {
    console.log(`   JWE indicates content was not GZIPped. Output file ${decPath} will contain raw decrypted data.`);
  }

  const finalFileWriter = Bun.file(decPath).writer();
  
  const ABYTES = sodium.crypto_secretstream_xchacha20poly1305_ABYTES;
  const headerBytes = sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES;
  let isDone = false;
  let sodiumState: sodium.StateAddress | undefined = undefined;
  let httpBodyReader: ReadableStreamDefaultReader<Uint8Array> | undefined = undefined; // Define for finally block scope

  try {
    httpBodyReader = encryptedStreamHttpBody.getReader(); // Get reader here
    const parser = structuredStreamParser(httpBodyReader, headerBytes, chunkSizeFromJWE + ABYTES, ABYTES);

    for await (const segment of parser) {
      if (segment.type === 'header') {
        try {
          sodiumState = sodium.crypto_secretstream_xchacha20poly1305_init_pull(segment.content, cek);
        } catch (e: any) {
          await finalFileWriter.end();
          console.error("[DEC-ERR] Failed to initialize decryption state with header.", e.message);
          throw e;
        }
      } else if (segment.type === 'body' || segment.type === 'body_partial') {
        if (!sodiumState) {
          await finalFileWriter.end();
          throw new Error("[DEC-ERR] sodiumState not initialized before processing body chunk.");
        }
        const res = sodium.crypto_secretstream_xchacha20poly1305_pull(sodiumState, segment.content);
        
        if (!res) {
          await finalFileWriter.end();
          const errMsg = `[DEC-ERR] Decryption MAC failed. Encrypted chunk size: ${segment.content.length} B`; // Simplified error
          console.error(errMsg);
          throw new Error("Decryption MAC verification failed.");
        }
        
        await finalFileWriter.write(res.message); 
        
        if (res.tag === sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
          isDone = true;
          console.log("📄 Client: TAG_FINAL encountered, decryption complete."); // Kept this important status
          break;
        }
      } else if (segment.type === 'tail') {
        if (!sodiumState) {
          await finalFileWriter.end();
          throw new Error("[DEC-ERR] sodiumState not initialized before processing tail chunk.");
        }
        const res = sodium.crypto_secretstream_xchacha20poly1305_pull(sodiumState, segment.content);
        
        if (!res) {
          await finalFileWriter.end();
          const errMsg = `[DEC-ERR] Decryption MAC failed. Encrypted chunk size: ${segment.content.length} B`; // Simplified error
          console.error(errMsg);
          throw new Error("Decryption MAC verification failed.");
        }
        
        if (res.message.length === 0 && res.tag === sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
          isDone = true;
          console.log("📄 Client: TAG_FINAL encountered, decryption complete."); // Kept this important status
          break;
        } else {
          console.error(`❌ FAILURE (${decPath}): Invalid tail encountered. Decryption might have failed.`);
          await finalFileWriter.end();
          throw new Error("Invalid tail encountered. Decryption might have failed.");
        }
      }
    }
    await finalFileWriter.end();
    if (!isDone) {
      console.warn("[DEC-WARN] Decryption stream processing finished, but TAG_FINAL was NOT encountered.");
    }
    console.log(`🔓 Decryption stream processing finalized for ${decPath}`);

  } finally {
    if (httpBodyReader) httpBodyReader.releaseLock(); // This should now correctly release the reader
  }
}

async function runStreamingFileDemo(clientKeys: ClientKeys, demoName: string, fileSizeBytes: number, useGzip: boolean) {
  const sizeSuffix = `${(fileSizeBytes / (1024 * 1024)).toFixed(0)}MB`;
  const gzipSuffix = useGzip ? "_GZIP" : "";
  const fullDemoName = `${demoName} - ${sizeSuffix}${gzipSuffix}`;
  console.log(`
--- Starting ${fullDemoName} Streaming File Flow (${clientKeys.keyType} Keys) ---`);

  await sodium.ready;
  
  const baseOutputNameForSource = `source_data_${demoName.toLowerCase().replace(/ /g, '_')}_${sizeSuffix.replace(/ /g, '')}`;
  const runIdentifierSuffix = `${demoName.toLowerCase().replace(/ /g, '_')}_${sizeSuffix.replace(/ /g, '')}${gzipSuffix.toLowerCase()}`;
  
  const tmpEnc   = `./tmp_enc_${runIdentifierSuffix}.bin`; 
  const tmpDec   = `./tmp_dec_${runIdentifierSuffix}.bin`; 

  console.log(`[RUN] Pre-emptively deleting ${tmpEnc} and ${tmpDec} if they exist...`);
  try {
    if (await Bun.file(tmpEnc).exists()) await Bun.file(tmpEnc).delete();
    if (await Bun.file(tmpDec).exists()) await Bun.file(tmpDec).delete();
    console.log(`[RUN] Pre-emptive deletion complete.`);
  } catch (e: any) {
    console.warn(`[RUN] Warning: Error during pre-emptive cleanup for ${fullDemoName}:`, e.message);
  }

  console.time(`⏱️ E2E Demo (${fullDemoName})`);
  const sourceFiles = await ensurePlaintextAndGzippedFiles(baseOutputNameForSource, fileSizeBytes);
  const actualSourceFileForEncryption = useGzip ? sourceFiles.gzipped : sourceFiles.plain;
  
  const cek_K = generateCEK();
  const FIXED_CHUNK_SIZE_FOR_PUSH = 1024 * 1024;

  // JWE chunk parameter is now ALWAYS FIXED_CHUNK_SIZE_FOR_PUSH
  const jweChunkParameter = FIXED_CHUNK_SIZE_FOR_PUSH;
  if (useGzip) {
    console.log(`[RUN] GZIP mode: JWE chunk parameter is FIXED at ${jweChunkParameter} B (actual gzipped size was ${sourceFiles.gzippedSize || 'N/A'} B)`);
    if (!sourceFiles.gzippedSize) {
      // This error is less critical now for jweChunkParameter, but still indicates a problem with the source file for encryption.
      console.error(`[RUN] Error: GZIP mode selected but gzippedSize is null for ${sourceFiles.gzipped}. Encryption might use an empty/wrong file.`);
      console.timeEnd(`⏱️ E2E Demo (${fullDemoName})`);
      return;
    }
  } else {
    console.log(`[RUN] Non-GZIP mode: JWE chunk parameter set to fixed size: ${jweChunkParameter} B`);
  }

  await encryptFileStream(
    actualSourceFileForEncryption, 
    tmpEnc, 
    cek_K, 
    FIXED_CHUNK_SIZE_FOR_PUSH, 
    DEFAULT_CONTENT_TYPE, 
    useGzip ? "gzip" : undefined
  ); 

  const encryptedFileName = `encrypted_export_${runIdentifierSuffix}.bin`;
  const server = Bun.serve({
    port: 0, 
    fetch(req) {
      const url = new URL(req.url);
      if (url.pathname === `/download/${encryptedFileName}`) {
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
  const encryptedFileUrl = `http://${server.hostname}:${server.port}/download/${encryptedFileName}`;

  const jweAlg = clientKeys.keyType === 'EC' ? 'ECDH-ES+A256KW' : 'RSA-OAEP-256';
  const jweString = await wrapCEK(cek_K, clientKeys.publicJwk, jweAlg, jweChunkParameter, DEFAULT_CONTENT_TYPE, useGzip ? "gzip" : undefined);
  const manifest = createManifest(encryptedFileUrl, jweString, "Binary", `${fullDemoName} Stream`);

  const extractedJwe = resolveManifestAndExtractJWE(manifest, "Binary");
  if (!extractedJwe) {
    console.error("Failed to extract JWE from manifest");
    server.stop(true);
    console.timeEnd(`⏱️ E2E Demo (${fullDemoName})`);
    return;
  }

  const unwrapped = await unwrapCEK(extractedJwe, clientKeys.privateJwk, jweAlg);
  if (!unwrapped) {
    console.error("Failed to unwrap CEK");
    server.stop(true);
    console.timeEnd(`⏱️ E2E Demo (${fullDemoName})`);
    return;
  }

  const response = await fetch(encryptedFileUrl);

  if (!response.ok || !response.body) {
    console.error(`📄 Client: Failed to download encrypted file. Status: ${response.status}`);
    server.stop(true);
    console.timeEnd(`⏱️ E2E Demo (${fullDemoName})`);
    return;
  }

  try {
    await decryptFileStream(
      response.body, 
      tmpDec, 
      unwrapped.cek, 
      unwrapped.plaintextChunkSize, 
      unwrapped.contentType,
      unwrapped.contentEncoding
    );
  } catch (error) {
    console.error(`❌ FAILURE (${fullDemoName} Stream): Error during decryption from stream:`, error);
    server.stop(true);
    console.timeEnd(`⏱️ E2E Demo (${fullDemoName})`);
    return; 
  }

  const hashOriginal = Bun.hash(await Bun.file(actualSourceFileForEncryption).bytes());
  const hashDec      = Bun.hash(await Bun.file(tmpDec).bytes());
  
  if (hashOriginal === hashDec) {
    console.log(`✅ SUCCESS (${fullDemoName} Stream): Decrypted file matches original (${useGzip ? 'gzipped source' : 'plain source'}).`);
  } else {
    console.error(`❌ FAILURE (${fullDemoName} Stream): Decrypted file does NOT match original (${useGzip ? 'gzipped source' : 'plain source'}).`);
    console.error(`Hash Original (${actualSourceFileForEncryption}): ${hashOriginal}, Hash Decrypted (${tmpDec}): ${hashDec}`);
  }
  
  console.timeEnd(`⏱️ E2E Demo (${fullDemoName})`);
  
  server.stop(true); 

  try {
    if (await Bun.file(tmpEnc).exists()) await Bun.file(tmpEnc).delete();
    if (await Bun.file(tmpDec).exists()) await Bun.file(tmpDec).delete();
  } catch (e:any) {
    console.warn(`🧹 Warning: Error during cleanup for ${fullDemoName}:`, e.message);
  }

  console.log(`--- ${fullDemoName} Streaming File Flow Complete ---\n`);
}

// New Structured Stream Parser
async function* structuredStreamParser(
  streamReader: ReadableStreamDefaultReader<Uint8Array>,
  headerSize: number,
  bodyChunkSize: number, 
  tailSize: number
): AsyncGenerator<{ type: 'header' | 'body' | 'body_partial' | 'tail'; content: Uint8Array }, void, undefined> {
  let buffer = new Uint8Array(0);
  let streamEnded = false;
  let yieldedHeader = false;
  let yieldedTail = false;

  const readIntoBuffer = async (minBytesNeeded: number): Promise<boolean> => {
    while (buffer.length < minBytesNeeded && !streamEnded) {
      const { done, value } = await streamReader.read();
      if (value && value.length > 0) {
        const newBuffer = new Uint8Array(buffer.length + value.length);
        newBuffer.set(buffer);
        newBuffer.set(value, buffer.length);
        buffer = newBuffer;
      }
      if (done) {
        streamEnded = true;
        break;
      }
    }
    return buffer.length >= minBytesNeeded;
  };

  if (headerSize > 0) {
    if (await readIntoBuffer(headerSize)) {
      yield { type: 'header', content: buffer.subarray(0, headerSize) };
      buffer = buffer.subarray(headerSize);
      yieldedHeader = true;
    } else {
      if (buffer.length > 0) {
        console.warn('[SSP] Yielding partial header as stream ended prematurely.');
        yield { type: 'header', content: buffer }; 
        buffer = new Uint8Array(0);
      }
      return;
    }
  } else {
    yieldedHeader = true; 
  }

  // 2. Yield Body Chunks
  if (bodyChunkSize > 0) {
    while (true) {
      if (buffer.length >= bodyChunkSize) {
        if (streamEnded && buffer.length === bodyChunkSize && tailSize > 0) {
          const potentialDataMsgSize = bodyChunkSize - tailSize;
          if (potentialDataMsgSize > 0) {
             yield { type: 'body_partial', content: buffer.subarray(0, potentialDataMsgSize) };
          }
          buffer = buffer.subarray(potentialDataMsgSize);
        } else {
          yield { type: 'body', content: buffer.subarray(0, bodyChunkSize) };
          buffer = buffer.subarray(bodyChunkSize);
        }
        continue;
      }

      if (streamEnded) {
        break;
      }

      const { done, value } = await streamReader.read();
      if (value && value.length > 0) {
        const newBuffer = new Uint8Array(buffer.length + value.length);
        newBuffer.set(buffer);
        newBuffer.set(value, buffer.length);
        buffer = newBuffer;
      }
      if (done) {
        streamEnded = true;
      }

      if (streamEnded && buffer.length < bodyChunkSize) {
         break;
      }
    }

    if (streamEnded && buffer.length > 0) {
      if (tailSize > 0 && buffer.length > tailSize) {
        yield { type: 'body_partial', content: buffer.subarray(0, buffer.length - tailSize) };
        buffer = buffer.subarray(buffer.length - tailSize); 
      } else if (tailSize > 0 && buffer.length === tailSize) {
        // Do nothing, let tail logic handle it.
      } else if (buffer.length > 0) { 
        yield { type: 'body_partial', content: buffer.subarray(0) };
        buffer = new Uint8Array(0);
      }
    }
  }

  if (tailSize > 0) {
    if (buffer.length === tailSize) { 
      yield { type: 'tail', content: buffer };
      buffer = new Uint8Array(0);
      yieldedTail = true;
    } else if (buffer.length > tailSize) {
        console.warn(`[SSP-WARN] Tail logic: buffer has ${buffer.length} B, more than expected tailSize ${tailSize}B.`);
        yield { type: 'body_partial', content: buffer.subarray(0, buffer.length - tailSize) };
        yield { type: 'tail', content: buffer.subarray(buffer.length - tailSize) };
        buffer = new Uint8Array(0);
        yieldedTail = true;
    } else { 
      if (await readIntoBuffer(tailSize - buffer.length)) { 
        if (buffer.length === tailSize) {
          yield { type: 'tail', content: buffer };
          buffer = new Uint8Array(0);
          yieldedTail = true;
        } else {
          if (buffer.length > 0) console.warn(`[SSP-WARN] After reading for tail, buffer has ${buffer.length}B, expected ${tailSize}B. Yielding what was read.`);
          if (buffer.length > 0) yield { type: 'tail', content: buffer }; 
          buffer = new Uint8Array(0);
          yieldedTail = true; 
        }
      } else {
        if (buffer.length > 0) console.warn(`[SSP-WARN] Stream ended while reading for tail. Buffer has ${buffer.length}B, expected ${tailSize}B. Yielding what was read.`);
        if (buffer.length > 0) yield { type: 'tail', content: buffer }; 
        buffer = new Uint8Array(0);
        yieldedTail = true; 
      }
    }
  }

  if (buffer.length > 0) {
    // console.warn(`[SSP] Stream processed, but ${buffer.length} bytes remain in buffer.`);
  }
}

main().catch(error => {
  console.error("🚨 Unhandled error in main execution:", error);
  process.exit(1);
});
