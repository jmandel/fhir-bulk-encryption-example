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

// --- Sample Data for Patient Generation ---
const SAMPLE_SURNAMES = ["Smith", "Jones", "Williams", "Brown", "Davis", "Miller", "Wilson", "Moore", "Taylor", "Anderson", "Thomas", "Jackson", "White", "Harris", "Martin"];
const SAMPLE_GIVEN_NAMES = ["James", "Mary", "John", "Patricia", "Robert", "Jennifer", "Michael", "Linda", "William", "Elizabeth", "David", "Barbara", "Richard", "Susan", "Joseph"];
const SAMPLE_IDENTIFIER_SYSTEMS = [
  "urn:oid:2.16.840.1.113883.4.6", // NPI
  "http://myhospital.org/mrn",
  "urn:oid:1.2.3.4.5.6.7",
  "http://example.com/fhir/sid/patient-id",
  "urn:ietf:rfc:3986"
];

function generateRandomFhirPatient(): any {
  const family = SAMPLE_SURNAMES[Math.floor(Math.random() * SAMPLE_SURNAMES.length)];
  const given = SAMPLE_GIVEN_NAMES[Math.floor(Math.random() * SAMPLE_GIVEN_NAMES.length)];
  
  const birthYear = 1920 + Math.floor(Math.random() * 101); // 1920-2020
  const birthMonth = (Math.floor(Math.random() * 12) + 1).toString().padStart(2, '0');
  // Ensure day is valid for the month (simplified: 1-28 for all months)
  const birthDay = (Math.floor(Math.random() * 28) + 1).toString().padStart(2, '0'); 
  const birthDate = `${birthYear}-${birthMonth}-${birthDay}`;

  const identifierSystem = SAMPLE_IDENTIFIER_SYSTEMS[Math.floor(Math.random() * SAMPLE_IDENTIFIER_SYSTEMS.length)];
  // Generate a more typical looking random alphanumeric identifier value
  const identifierValue = Array(10).fill(0).map(() => Math.random().toString(36)[2]).join('').toUpperCase();

  return {
    resourceType: "Patient",
    id: crypto.randomUUID(), // Use UUID for patient ID
    identifier: [{
      system: identifierSystem,
      value: identifierValue,
      period: { start: `${birthYear - Math.floor(Math.random()*5)}-${birthMonth}-${birthDay}` } // Identifier valid sometime before birthDate
    }],
    name: [{
      use: "official",
      family: family,
      given: [given, ...(Math.random() > 0.7 ? [SAMPLE_GIVEN_NAMES[Math.floor(Math.random() * SAMPLE_GIVEN_NAMES.length)]] : [])] // Optional middle name
    }],
    gender: Math.random() > 0.5 ? "male" : "female",
    birthDate: birthDate,
    active: Math.random() > 0.1 // Most patients are active
  };
}
// --- End Sample Data ---

// --- Helper Functions ---
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

function formatBytes(bytes: number, decimals = 2): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

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

  const ecClientKeys = await generateClientECKeys();
  const rsaClientKeys = await generateClientRSAKeys();

  const fileSizesToTest = [
    1 * 1024 * 1024, 
    10 * 1024 * 1024, 
    20 * 1024 * 1024, 
  ];

  const testResults: Array<{name: string, durationMs: number, success: boolean, encryptedSize?: number}> = [];

  for (const size of fileSizesToTest) {
    const sizeString = `${(size / (1024 * 1024)).toFixed(0)}MB`;
    console.log(`
🧪🧪🧪 Starting Test Runs for File Size: ${sizeString} 🧪🧪🧪`);
    
    testResults.push(await runStreamingFileDemo(ecClientKeys, "ECDH-ES Demo", size, false));
    testResults.push(await runStreamingFileDemo(rsaClientKeys, "RSA-OAEP Demo", size, false));

    console.log(`
--- ${sizeString} / GZIP ---`);
    testResults.push(await runStreamingFileDemo(ecClientKeys, "ECDH-ES Demo", size, true));
    testResults.push(await runStreamingFileDemo(rsaClientKeys, "RSA-OAEP Demo", size, true));
  }

  console.log("\n🎉 All Demo Flows and Performance Tests Complete 🎉");

  // --- Print Timing Table ---
  console.log("\n📊 Timing Summary Table 📊");
  console.log("------------------------------------------------------------------------------------------------");
  console.log("| Test Case                               | Encrypted Size     | Duration (ms) | Status    |");
  console.log("|-----------------------------------------|--------------------|---------------|-----------|");
  for (const result of testResults) {
    const nameStr = result.name.padEnd(39);
    const encSizeStr = (result.encryptedSize !== undefined ? formatBytes(result.encryptedSize) : 'N/A').padStart(18);
    const durationStr = result.durationMs.toFixed(2).padStart(13);
    const statusStr = (result.success ? "✅ SUCCESS" : "❌ FAILURE").padEnd(9);
    console.log(`| ${nameStr} | ${encSizeStr} | ${durationStr} | ${statusStr} |`);
  }
  console.log("------------------------------------------------------------------------------------------------");
}

main().catch(error => {
  console.error("🚨 Unhandled error in main execution:", error);
  process.exit(1);
});

// --- Streaming File Encryption/Decryption Demo (Bun File I/O) ---

const CHUNK_SIZE = 64 * 1024; // 64 KiB plaintext chunk
// const PLAIN_FILE_SIZE_BYTES = 100 * 1024 * 1024; // 100 MiB - Will be parameterized

async function generateRandomPlaintextFile(path: string, sizeBytes: number) {
  console.log(`📂 Generating FHIR Patient NDJSON file ${path} of approx. size ${formatBytes(sizeBytes)}...`);
  const writer = Bun.file(path).writer();
  let writtenBytes = 0;
  const newline = textEncoder.encode('\n');

  while (writtenBytes < sizeBytes) {
    const patient = generateRandomFhirPatient();
    const patientJsonString = JSON.stringify(patient);
    const patientBytes = textEncoder.encode(patientJsonString);

    // Check if adding this patient would exceed the target size too much
    // Allow exceeding by a bit to ensure the last patient is fully written
    if (writtenBytes + patientBytes.length + newline.length > sizeBytes && writtenBytes > 0) {
        // If we've already written something and the next patient pushes us significantly over,
        // (e.g. > 10% over or simply over if we must be strict, but for NDJSON better to complete the line)
        // for simplicity, we'll just stop here to avoid partial lines or grossly oversized files.
        // A more sophisticated approach might try to fill closer to the exact byte target.
        break; 
    }

    await writer.write(patientBytes);
    await writer.write(newline);
    writtenBytes += patientBytes.length + newline.length;
  }
  await writer.end();
  console.log(`📂 FHIR Patient NDJSON file generated: ${path}, actual size: ${formatBytes(writtenBytes)}`);
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
  
  const sourceStream: ReadableStream<Uint8Array> = Bun.file(plainPath).stream();
  const reader = sourceStream.getReader();
  const parser = structuredStreamParser(reader, 0, chunkSizeForPush, 0); // headerSize=0, tailSize=0

  try {
    for await (const seg of parser) {
      if (seg.type === 'body' || seg.type === 'final_body') {
        if (seg.content.length === 0) continue; // skip empty
        const tag = sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;
        const cipherChunk = sodium.crypto_secretstream_xchacha20poly1305_push(state, seg.content, null, tag);
        await encFileWriter.write(cipherChunk);
      }
    }
  } finally {
    reader.releaseLock();
  }
  // push final tag
  const finalCipher = sodium.crypto_secretstream_xchacha20poly1305_push(
      state,
      new Uint8Array(0),
      null,
      sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL
  );
  await encFileWriter.write(finalCipher);
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
  let httpBodyReader: ReadableStreamDefaultReader<Uint8Array> | undefined = undefined; // Re-declare here

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
      } else if (segment.type === 'body' || segment.type === 'final_body') {
        if (!sodiumState) throw new Error("[DEC-ERR] sodiumState not initialized before body chunks");
        const res = sodium.crypto_secretstream_xchacha20poly1305_pull(sodiumState, segment.content);
        if (!res) {
          await finalFileWriter.end();
          throw new Error("Decryption MAC verification failed.");
        }
        await finalFileWriter.write(res.message);
        if (res.tag === sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
          // TAG_FINAL should *not* appear on body/final_body – would indicate tail mis-classification.
          throw new Error("TAG_FINAL encountered on body/final_body segment – possible misclassification");
        }
      } else if (segment.type === 'tail') {
        if (!sodiumState) throw new Error("[DEC-ERR] sodiumState not initialized before tail chunk");
        const res = sodium.crypto_secretstream_xchacha20poly1305_pull(sodiumState, segment.content);
        if (!res || res.tag !== sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
          await finalFileWriter.end();
          throw new Error("Invalid tail chunk – expected TAG_FINAL");
        }
        isDone = true;
        console.log("📄 Client: TAG_FINAL encountered, decryption complete.");
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

async function runStreamingFileDemo(clientKeys: ClientKeys, demoName: string, fileSizeBytes: number, useGzip: boolean): Promise<{name: string, durationMs: number, success: boolean, encryptedSize?: number}> {
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

  const startTime = performance.now();
  let success = false;
  let server: import('bun').Server | undefined = undefined;
  let encryptedFileSize: number | undefined = undefined; // Variable to store encrypted size

  try {
    const sourceFiles = await ensurePlaintextAndGzippedFiles(baseOutputNameForSource, fileSizeBytes);
    const actualSourceFileForEncryption = useGzip ? sourceFiles.gzipped : sourceFiles.plain;
    
    const cek_K = generateCEK();
    const FIXED_CHUNK_SIZE_FOR_PUSH = 1024 * 1024;

    const jweChunkParameter = FIXED_CHUNK_SIZE_FOR_PUSH;
    if (useGzip) {
      console.log(`[RUN] GZIP mode: JWE chunk parameter is FIXED at ${jweChunkParameter} B (actual gzipped size was ${sourceFiles.gzippedSize || 'N/A'} B)`);
      if (!sourceFiles.gzippedSize) {
        console.error(`[RUN] Error: GZIP mode selected but gzippedSize is null for ${sourceFiles.gzipped}.`);
        throw new Error("Gzipped source size not found"); // Propagate error
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
    encryptedFileSize = await Bun.file(tmpEnc).size; // Get encrypted file size

    const encryptedFileName = `encrypted_export_${runIdentifierSuffix}.bin`;
    server = Bun.serve({ // Assign to server here
      port: 0, 
      fetch(req) {
        const url = new URL(req.url);
        if (url.pathname === `/download/${encryptedFileName}`) {
          return new Response(Bun.file(tmpEnc), {
            headers: { "Content-Type": "application/octet-stream", "Content-Disposition": `attachment; filename="${encryptedFileName}"` }
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
    if (!extractedJwe) throw new Error("Failed to extract JWE from manifest");

    const unwrapped = await unwrapCEK(extractedJwe, clientKeys.privateJwk, jweAlg);
    if (!unwrapped) throw new Error("Failed to unwrap CEK");

    const response = await fetch(encryptedFileUrl);
    if (!response.ok || !response.body) throw new Error(`Failed to download encrypted file. Status: ${response.status}`);

    await decryptFileStream(
      response.body, 
      tmpDec, 
      unwrapped.cek, 
      unwrapped.plaintextChunkSize, 
      unwrapped.contentType,
      unwrapped.contentEncoding
    );

    const hashOriginal = Bun.hash(await Bun.file(actualSourceFileForEncryption).bytes());
    const hashDec      = Bun.hash(await Bun.file(tmpDec).bytes());
    
    if (hashOriginal === hashDec) {
      console.log(`✅ SUCCESS (${fullDemoName} Stream): Decrypted file matches original (${useGzip ? 'gzipped source' : 'plain source'}). Encrypted size: ${encryptedFileSize !== undefined ? formatBytes(encryptedFileSize) : 'N/A'}`);
      success = true;
    } else {
      console.error(`❌ FAILURE (${fullDemoName} Stream): Decrypted file does NOT match original (${useGzip ? 'gzipped source' : 'plain source'}). Encrypted size: ${encryptedFileSize !== undefined ? formatBytes(encryptedFileSize) : 'N/A'}`);
      console.error(`Hash Original (${actualSourceFileForEncryption}): ${hashOriginal}, Hash Decrypted (${tmpDec}): ${hashDec}`);
      success = false;
    }

  } catch (error: any) {
    console.error(`❌ Error during ${fullDemoName}:`, error.message);
    success = false;
    // No explicit return here, finally block will handle it
  } finally {
    const endTime = performance.now();
    const durationMs = endTime - startTime;
    
    if (server) server.stop(true); 

    try {
      if (await Bun.file(tmpEnc).exists()) await Bun.file(tmpEnc).delete();
      if (await Bun.file(tmpDec).exists()) await Bun.file(tmpDec).delete();
    } catch (e:any) {
      console.warn(`🧹 Warning: Error during cleanup for ${fullDemoName}:`, e.message);
    }

    console.log(`--- ${fullDemoName} Streaming File Flow Complete (${success ? 'SUCCESS' : 'FAILURE'} in ${durationMs.toFixed(2)} ms, Enc Size: ${encryptedFileSize !== undefined ? formatBytes(encryptedFileSize) : 'N/A'}) ---
`);
    return { name: fullDemoName, durationMs, success, encryptedSize: encryptedFileSize }; // Return encryptedSize
  }
}

// ===== Redesigned Stream Parser =========================================================
//  Produces a canonical sequence for any bytestream that follows:
//    [ header (fixed) ][ 0..N * fullBodyChunk ][ finalBodyChunk (<=full) ][ tail (fixed) ]
// -----------------------------------------------------------------------------------------
async function* structuredStreamParser(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  headerSize: number,
  fullBodyChunkSize: number,  // plaintextChunkSize + ABYTES for crypto_secretstream
  tailSize: number
): AsyncGenerator<{ type: 'header' | 'body' | 'final_body' | 'tail'; content: Uint8Array }, void, undefined> {
  let buffer = new Uint8Array(0);
  let streamEnded = false;

  // Utility: read from the reader until we have at least `minBytes` in buffer OR stream ends.
  const fillBuffer = async (minBytes: number) => {
    while (!streamEnded && buffer.length < minBytes) {
      const { done, value } = await reader.read();
      if (done) {
        streamEnded = true;
        break;
      }
      if (value && value.length) {
        const tmp = new Uint8Array(buffer.length + value.length);
        tmp.set(buffer);
        tmp.set(value, buffer.length);
        buffer = tmp;
      }
    }
  };

  // 1) Header
  await fillBuffer(headerSize);
  if (buffer.length < headerSize) throw new Error("Stream ended before header could be read");
  if (headerSize > 0) {
    yield { type: 'header', content: buffer.subarray(0, headerSize) };
  }
  buffer = buffer.subarray(headerSize);

  // 2) Zero or more *full* body chunks
  while (true) {
    // Ensure we have either a full body chunk OR enough to decide there's no more full chunks.
    await fillBuffer(fullBodyChunkSize + tailSize); // read ahead to distinguish tail

    // If we still have a full body chunk available *not counting* tail+final parts, yield it.
    if (buffer.length >= fullBodyChunkSize + tailSize) {
      yield { type: 'body', content: buffer.subarray(0, fullBodyChunkSize) };
      buffer = buffer.subarray(fullBodyChunkSize);
      continue; // maybe there are more full chunks
    }
    break; // no more full body chunks possible
  }

  // 3) At this point, buffer has < fullBodyChunkSize + tailSize bytes.
  //    Make sure we have the entire remaining stream in buffer to classify final_body vs tail.
  if (!streamEnded) {
    // Read until end.
    await fillBuffer(Number.MAX_SAFE_INTEGER);
  }

  if (buffer.length < tailSize) {
    throw new Error("Stream shorter than expected tail size");
  }

  const finalBodySize = buffer.length - tailSize; // could be 0
  if (finalBodySize > 0) {
    yield { type: 'final_body', content: buffer.subarray(0, finalBodySize) };
  }
  if (tailSize > 0) {
    yield { type: 'tail', content: buffer.subarray(buffer.length - tailSize) };
  }
  buffer = new Uint8Array(0);
}

// ===== End  redesigned parser ===========================================================

main().catch(error => {
  console.error("🚨 Unhandled error in main execution:", error);
  process.exit(1);
});
