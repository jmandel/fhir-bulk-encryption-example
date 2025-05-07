// @ts-nocheck
import * as jose from 'jose';

function concatUint8(a: ArrayLike<number>, b: ArrayLike<number>): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

// --- Constants ---
const BULK_EXPORT_DECRYPTION_KEY_URL = "http://argo.run/bulk-export-decryption-key";
const DEFAULT_PLAINTEXT_CHUNK_SIZE = 1 * 1024 * 1024; // 1 MiB
const DEFAULT_CONTENT_TYPE = "application/fhir+ndjson"; // Changed to FHIR specific type

// --- AES-GCM Constants ---
const AES_GCM_JWE_CIPHER_VALUE = "AES256GCM";
const AES_GCM_IV_PREFIX_BYTES = 8;
const AES_GCM_IV_TOTAL_BYTES = 12; // Standard for AES-GCM (96 bits)
const AES_GCM_TAG_LENGTH_BITS = 128; // Standard tag length in bits
const AES_GCM_CEK_BYTES = 32; // 256 bits for AES key

// --- JWE Payload Types ---
interface JWEPayloadBase {
  v: string; // Protocol version
  k: string; // base64url-encoded CEK
  cipher: string; // Algorithm identifier
  content_type: string;
  content_encoding?: "gzip";
}

interface JWEPayloadAesGcm extends JWEPayloadBase {
  cipher: typeof AES_GCM_JWE_CIPHER_VALUE;
  hash: string; // base64url-encoded SHA-256 hash of plaintext (pre-encryption)
  // chunk size for AES-GCM encryption is handled by the streaming functions
}

type JWEPayload = JWEPayloadAesGcm;

// Define the success result type for unwrapCEK
type UnwrappedCekSuccessResult = {
  cek: Uint8Array;
  cipher: typeof AES_GCM_JWE_CIPHER_VALUE;
  contentType: string;
  contentEncoding?: "gzip";
  // For secretstream
  plaintextChunkSize?: number;
  plaintextHashB64: string;
};

// --- Sample Data for Patient Generation ---
const SAMPLE_SURNAMES = ["Smith", "Jones", "Williams", "Brown", "Davis", "Miller", "Wilson", "Moore", "Taylor", "Anderson", "Thomas", "Jackson", "White", "Harris", "Martin"];
const SAMPLE_GIVEN_NAMES = ["James", "Mary", "John", "Patricia", "Robert", "Jennifer", "Michael", "Linda", "William", "Elizabeth", "David", "Barbara", "Richard", "Susan", "Joseph"];
const SAMPLE_IDENTIFIER_SYSTEMS = [
  "urn:oid:2.16.840.1.113883.4.6",
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
    active: Math.random() > 0.1
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
  console.log(`🔑 Client (EC): Generated Private JWK (DEMO ONLY): ${JSON.stringify(privateJwk)}`);
  return { publicKey, privateKey, publicJwk, privateJwk, keyType: 'EC' };
}

async function generateClientRSAKeys(): Promise<ClientKeys> {
  console.log("🔑 Client: Generating RSA-OAEP-256 3072-bit key pair...");
  // Use RSA-OAEP-256 for encryption key wrap (not PS384)
  const { publicKey, privateKey } = await jose.generateKeyPair(
    'RSA-OAEP-256',
    { modulusLength: 3072, extractable: true }
  );
  
  const publicJwk = await jose.exportJWK(publicKey) as any;
  publicJwk.kid = `client-rsa3072-key-${Math.random().toString(36).substring(2, 10)}`;
  publicJwk.alg = 'RSA-OAEP-256';
  publicJwk.use = 'enc';
  publicJwk.exp = Math.floor(Date.now() / 1000) + 24 * 60 * 60;
  
  const privateJwk = await jose.exportJWK(privateKey) as any;
  privateJwk.kid = publicJwk.kid;

  console.log(`🔑 Client (RSA): Generated Public JWK: ${JSON.stringify(publicJwk)}`);
  console.log(`🔑 Client (RSA): Generated Private JWK (DEMO ONLY): ${JSON.stringify(privateJwk)}`);
  return { publicKey, privateKey, publicJwk, privateJwk, keyType: 'RSA' };
}


// --- Server-Side Simulation ---

function generateCEK(): Uint8Array {
  console.log("🛡️ Server: Generating Content Encryption Key (CEK) for AES-GCM...");
  const cek = new Uint8Array(AES_GCM_CEK_BYTES);
  crypto.getRandomValues(cek); // Use Web Crypto for random bytes
  console.log(`🛡️ Server: Generated CEK (base64url): ${jose.base64url.encode(cek)} (DEMO ONLY - DO NOT LOG IN PROD)`);
  return cek;
}

async function wrapCEK(
  cek: Uint8Array,
  clientPublicJwk: jose.JWK, 
  jweAlg: 'ECDH-ES+A256KW' | 'RSA-OAEP-256',
  contentType: string,       
  plaintextHashB64: string, 
  contentEncoding?: "gzip",  
  jweEnc: 'A256GCM' = 'A256GCM' 
): Promise<string> {
  console.log(`🛡️ Server: Wrapping CEK with client's public key using JWE (alg: ${jweAlg}, cipher: ${AES_GCM_JWE_CIPHER_VALUE})...`);
  
  const jwePayloadObject: JWEPayloadAesGcm = { 
    v: "0.5", 
    k: jose.base64url.encode(cek),
    cipher: AES_GCM_JWE_CIPHER_VALUE,
    hash: plaintextHashB64,
    content_type: contentType,
  };
  if (contentEncoding) {
    jwePayloadObject.content_encoding = contentEncoding;
  }
  
  console.log("🛡️ Server: JWE Payload to be encrypted:", JSON.stringify(jwePayloadObject, null, 2));

  const clientPublicKeyForJWE = await jose.importJWK(clientPublicJwk, jweAlg); 

  const jwe = await new jose.CompactEncrypt(stringToUint8Array(JSON.stringify(jwePayloadObject)))
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
): Promise<UnwrappedCekSuccessResult | null> {
  console.log(`📄 Client: Unwrapping CEK from JWE (expecting alg: ${expectedJweAlg})...`);
  console.log(`📄 Client: Received Compact JWE for unwrapping:`, jweCompact);
  try {
    const privateKeyForJWE = await jose.importJWK(clientPrivateJwk, expectedJweAlg);
    const { plaintext, protectedHeader } = await jose.compactDecrypt(jweCompact, privateKeyForJWE);
    
    if (protectedHeader.alg !== expectedJweAlg) {
        console.error(`📄 Client: JWE header algorithm mismatch! Expected ${expectedJweAlg}, got ${protectedHeader.alg}.`);
        return null;
    }

    const payload = JSON.parse(uint8ArrayToString(plaintext)) as JWEPayloadAesGcm;
    console.log("📄 Client: Decrypted JWE Payload:", JSON.stringify(payload, null, 2));

    if (payload.cipher !== AES_GCM_JWE_CIPHER_VALUE) {
        console.error(`📄 Client: Incorrect cipher in JWE payload. Expected ${AES_GCM_JWE_CIPHER_VALUE}, got ${payload.cipher}.`);
        return null;
    }

    if (!payload.k || !payload.content_type || !payload.hash) {
      console.error("📄 Client: Invalid AES-GCM JWE payload structure (missing k, content_type, or hash).");
      return null;
    }
    
    const cek = jose.base64url.decode(payload.k);
    const resultFields: UnwrappedCekSuccessResult = {
        cek,
        cipher: payload.cipher, 
        contentType: payload.content_type,
        contentEncoding: payload.content_encoding,
        plaintextHashB64: payload.hash
    };
    
    console.log(`📄 Client: Unwrapped for AES-GCM. Plaintext Hash (b64): ${payload.hash}`);
    console.log(`📄 Client: Unwrapped CEK (base64url): ${jose.base64url.encode(cek)} (DEMO ONLY - DO NOT LOG IN PROD)`);
    console.log(`📄 Client: CEK successfully unwrapped (JWE alg: ${protectedHeader.alg}). Cipher: ${payload.cipher}, ContentType: ${resultFields.contentType}` + (resultFields.contentEncoding ? `, ContentEncoding: ${resultFields.contentEncoding}`: ""));
    return resultFields;
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

  console.log("🚀 Starting FHIR Bulk Export AES-GCM Encryption/Decryption Demo 🚀");

  const ecClientKeys = await generateClientECKeys();
  const rsaClientKeys = await generateClientRSAKeys();

  const fileSizesToTest = [
    1 * 1024 * 1024, 
    10 * 1024 * 1024, 
    20 * 1024 * 1024, 
    // 100 * 1024 * 1024, 
  ];

  const testResults: Array<{name: string, encryptionMs: number, decryptionMs: number, success: boolean, encryptedSize?: number}> = [];

  for (const size of fileSizesToTest) {
    const sizeString = `${(size / (1024 * 1024)).toFixed(0)}MB`;
    console.log(`\n🧪🧪🧪 Starting Test Runs for File Size: ${sizeString} (AES-GCM) 🧪🧪🧪`);

    testResults.push(await runStreamingFileDemo(ecClientKeys, "ECDH-ES AES-GCM", size, false));
    testResults.push(await runStreamingFileDemo(rsaClientKeys, "RSA-OAEP AES-GCM", size, false));

    console.log(`\n--- ${sizeString} / GZIP (AES-GCM) ---`);
    testResults.push(await runStreamingFileDemo(ecClientKeys, "ECDH-ES AES-GCM", size, true));
    testResults.push(await runStreamingFileDemo(rsaClientKeys, "RSA-OAEP AES-GCM", size, true));
  }

  console.log("\n🎉 All Demo Flows and Performance Tests Complete 🎉");

  console.log("\n📊 Timing Summary Table 📊");
  console.log("------------------------------------------------------------------------------------------------------------");
  console.log("| Test Case                               | Encrypted Size     | Enc Time (ms) | Dec Time (ms) | Status    |");
  console.log("|-----------------------------------------|--------------------|---------------|---------------|-----------|");
  for (const result of testResults) {
    const nameStr = result.name.padEnd(39);
    const encSizeStr = (result.encryptedSize !== undefined ? formatBytes(result.encryptedSize) : 'N/A').padStart(18);
    const encDurationStr = result.encryptionMs.toFixed(2).padStart(13);
    const decDurationStr = result.decryptionMs.toFixed(2).padStart(13);
    const statusStr = (result.success ? "✅ SUCCESS" : "❌ FAILURE").padEnd(9);
    console.log(`| ${nameStr} | ${encSizeStr} | ${encDurationStr} | ${decDurationStr} | ${statusStr} |`);
  }
  console.log("------------------------------------------------------------------------------------------------------------");
}

main().catch(error => {
  console.error("🚨 Unhandled error in main execution:", error);
  process.exit(1);
});

// --- Streaming File Encryption/Decryption Demo (Bun File I/O) ---

async function generateRandomPlaintextFile(path: string, sizeBytes: number) {
  console.log(`📂 Generating FHIR Patient NDJSON file ${path} of approx. size ${formatBytes(sizeBytes)}...`);
  const writer = Bun.file(path).writer();
  let writtenBytes = 0;
  const newline = textEncoder.encode('\n');

  while (writtenBytes < sizeBytes) {
    const patient = generateRandomFhirPatient();
    const patientJsonString = JSON.stringify(patient);
    const patientBytes = textEncoder.encode(patientJsonString);

    if (writtenBytes + patientBytes.length + newline.length > sizeBytes && writtenBytes > 0) {
        break; 
    }

    writer.write(patientBytes);
    writer.write(newline);
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
  if (await Bun.file(filePathGzipped).exists()) {
    gzippedSize = await Bun.file(filePathGzipped).size;
  }
  return { plain: filePathPlain, gzipped: filePathGzipped, gzippedSize };
}


async function runStreamingFileDemo(
  clientKeys: ClientKeys, 
  demoName: string, 
  fileSizeBytes: number, 
  useGzip: boolean
): Promise<{name: string, encryptionMs: number, decryptionMs: number, success: boolean, encryptedSize?: number}> {
  const sizeSuffix = `${(fileSizeBytes / (1024 * 1024)).toFixed(0)}MB`;
  const gzipSuffix = useGzip ? "_GZIP" : "";
  const fullDemoName = `${demoName} - ${sizeSuffix}${gzipSuffix}`; 
  console.log(`\n--- Starting ${fullDemoName} Streaming File Flow (${clientKeys.keyType} Keys, Scheme: AES-GCM) ---`);
  
  const safeDemoNameBase = demoName.toLowerCase().replace(/[^a-z0-9_]/g, '_');
  const baseOutputNameForSource = `source_data_${safeDemoNameBase}_${sizeSuffix.replace(/ /g, '')}`;
  const runIdentifierSuffix = `${safeDemoNameBase}_${sizeSuffix.replace(/ /g, '')}${gzipSuffix.toLowerCase()}_aesgcm`;
  
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

  let success = false;
  let server: import('bun').Server | undefined = undefined;
  let encryptedFileSize: number | undefined = undefined;
  let encryptionDurationMs = 0;
  let decryptionDurationMs = 0;

  try {
    const sourceFiles = await ensurePlaintextAndGzippedFiles(baseOutputNameForSource, fileSizeBytes);
    const actualSourceFileForEncryption = useGzip ? sourceFiles.gzipped : sourceFiles.plain;
    
    const cek_K = generateCEK(); 
    const FIXED_CHUNK_SIZE_FOR_ENCRYPTION = DEFAULT_PLAINTEXT_CHUNK_SIZE; 

    const encStartTime = performance.now();

    // ivPrefix is generated here and passed to encryptStreamAesGcm
    const ivPrefix = new Uint8Array(AES_GCM_IV_PREFIX_BYTES);
    crypto.getRandomValues(ivPrefix); 
    console.log(`[RUN AES-GCM] Generated IV Prefix (b64): ${jose.base64url.encode(ivPrefix)}`);

    await encryptStreamAesGcm(
        actualSourceFileForEncryption,
        tmpEnc,
        cek_K,
        ivPrefix, // Pass ivPrefix here
        FIXED_CHUNK_SIZE_FOR_ENCRYPTION
    );
    encryptedFileSize = await Bun.file(tmpEnc).size;
    encryptionDurationMs = performance.now() - encStartTime;
    
    const plainFileHashBytes = await calculateFileSha256Streaming(actualSourceFileForEncryption);
    const plainFileHashB64 = jose.base64url.encode(plainFileHashBytes);
    console.log(`[RUN AES-GCM] Calculated Plaintext Hash (b64): ${plainFileHashB64}`);

    const encryptedFileNameForUrl = `encrypted_export_${runIdentifierSuffix}.bin`;
    server = Bun.serve({ 
        port: 0, 
        fetch(req) {  
            const url = new URL(req.url);
            if (url.pathname === `/download/${encryptedFileNameForUrl}`) {
                return new Response(Bun.file(tmpEnc), {
                    headers: { "Content-Type": "application/octet-stream", "Content-Disposition": `attachment; filename="${encryptedFileNameForUrl}"` }
                });
            }
            return new Response("Not Found", { status: 404 });
        }, 
        error(err) { console.error("💻 Server error (AES):", err); return new Response("Server Error", {status: 500});} 
    });
    const encryptedFileUrl = `http://${server.hostname}:${server.port}/download/${encryptedFileNameForUrl}`;

    const jweAlg = clientKeys.keyType === 'EC' ? 'ECDH-ES+A256KW' : 'RSA-OAEP-256';
    const jweString = await wrapCEK(
        cek_K, 
        clientKeys.publicJwk, 
        jweAlg, 
        DEFAULT_CONTENT_TYPE, 
        plainFileHashB64,
        useGzip ? "gzip" : undefined
    );
    
    const manifest = createManifest(encryptedFileUrl, jweString, "Patient", `${fullDemoName} Stream`);
    const extractedJwe = resolveManifestAndExtractJWE(manifest, "Patient");
    if (!extractedJwe) throw new Error("Failed to extract JWE from manifest");

    const jweAlgForUnwrap = clientKeys.keyType === 'EC' ? 'ECDH-ES+A256KW' : 'RSA-OAEP-256';
    const unwrapped = await unwrapCEK(extractedJwe, clientKeys.privateJwk, jweAlgForUnwrap);
    if (!unwrapped) throw new Error("Failed to unwrap CEK");
    
    const decStartTime = performance.now();
    
    if (!(await Bun.file(tmpEnc).exists())) {
        throw new Error(`Encrypted file ${tmpEnc} not found for decryption.`);
    }
    
    const aesGcmEncryptedChunkSizeWithTag = FIXED_CHUNK_SIZE_FOR_ENCRYPTION + (AES_GCM_TAG_LENGTH_BITS / 8);

    await decryptStreamAesGcm(
        tmpEnc, 
        tmpDec, 
        unwrapped.cek,
        unwrapped.plaintextHashB64,
        AES_GCM_TAG_LENGTH_BITS,
        aesGcmEncryptedChunkSizeWithTag
    );
    decryptionDurationMs = performance.now() - decStartTime;

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
    console.error(`❌ Error during ${fullDemoName}:`, error.message, error.stack ? error.stack: '');
    success = false;
  } finally {
    if (server) server.stop(true);

    try {
    if (await Bun.file(tmpEnc).exists()) await Bun.file(tmpEnc).delete(); 
    if (await Bun.file(tmpDec).exists()) await Bun.file(tmpDec).delete(); 
    } catch (e:any) {
      console.warn(`🧹 Warning: Error during cleanup for ${fullDemoName}:`, e.message);
    }

    console.log(`--- ${fullDemoName} Streaming File Flow Complete (${success ? 'SUCCESS' : 'FAILURE'} in Enc: ${encryptionDurationMs.toFixed(2)} ms, Dec: ${decryptionDurationMs.toFixed(2)} ms, Enc Size: ${encryptedFileSize !== undefined ? formatBytes(encryptedFileSize) : 'N/A'}) ---
`);
    return { name: fullDemoName, encryptionMs: encryptionDurationMs, decryptionMs: decryptionDurationMs, success, encryptedSize: encryptedFileSize };
  }
}

// --- AES-GCM Helper Functions ---
function deriveIv(ivPrefix: Uint8Array, counter: number): Uint8Array {
  if (ivPrefix.length !== AES_GCM_IV_PREFIX_BYTES) {
    throw new Error(`IV prefix must be ${AES_GCM_IV_PREFIX_BYTES} bytes. Got ${ivPrefix.length}`);
  }
  const iv = new Uint8Array(AES_GCM_IV_TOTAL_BYTES);
  iv.set(ivPrefix); // First part is the prefix

  if (AES_GCM_IV_TOTAL_BYTES - AES_GCM_IV_PREFIX_BYTES === 4) {
    const counterView = new DataView(iv.buffer, AES_GCM_IV_PREFIX_BYTES, 4);
    counterView.setUint32(0, counter, false); // false for big-endian
  } else {
    const counterPartLength = AES_GCM_IV_TOTAL_BYTES - AES_GCM_IV_PREFIX_BYTES;
    for (let i = 0; i < counterPartLength; i++) {
      iv[AES_GCM_IV_PREFIX_BYTES + i] = (counter >> ((counterPartLength - 1 - i) * 8)) & 0xFF;
    }
  }
  return iv;
}

async function importAesGcmKey(cekBytes: Uint8Array): Promise<CryptoKey> {
  if (cekBytes.length !== AES_GCM_CEK_BYTES) {
    throw new Error(`Invalid CEK length for AES-GCM. Expected ${AES_GCM_CEK_BYTES}, got ${cekBytes.length}`);
  }
  return crypto.subtle.importKey(
    "raw",
    cekBytes,
    { name: "AES-GCM", length: AES_GCM_CEK_BYTES * 8 },
    true, 
    ["encrypt", "decrypt"]
  );
}

async function calculateFileSha256Streaming(filePath: string): Promise<Uint8Array> {
  const hasher = new Bun.CryptoHasher("sha256");
  const file = Bun.file(filePath);
  const stream = file.stream();
  const reader = stream.getReader();
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        hasher.update(value);
      }
    }
  } finally {
    reader.releaseLock();
  }
  return new Uint8Array(hasher.digest());
}

async function encryptStreamAesGcm(
  plainFilePath: string,
  encryptedFilePath: string,
  cekBytes: Uint8Array,
  ivPrefix: Uint8Array,
  plaintextChunkSize: number = DEFAULT_PLAINTEXT_CHUNK_SIZE
) {
  console.log(`🔐 AES-GCM Encrypting ${plainFilePath} → ${encryptedFilePath}`);
  const cekCryptoKey = await importAesGcmKey(cekBytes);
  
  const writer = Bun.file(encryptedFilePath).writer();
  await writer.write(ivPrefix.buffer as any);

  const reader = Bun.file(plainFilePath).stream().getReader();
  let buffer: Uint8Array = new Uint8Array(0);
  let chunkIndex = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (value && value.length > 0) { 
        buffer = concatUint8(buffer, new Uint8Array(value)); 
      }

      while (buffer.length >= plaintextChunkSize) {
        const currentPlaintextChunk = buffer.subarray(0, plaintextChunkSize);
        buffer = buffer.subarray(plaintextChunkSize);
        
        const iv = deriveIv(ivPrefix, chunkIndex++);
        const ciphertextChunk = await crypto.subtle.encrypt(
          { name: 'AES-GCM', iv, tagLength: AES_GCM_TAG_LENGTH_BITS },
          cekCryptoKey,
          currentPlaintextChunk
        );
        await writer.write(new Uint8Array(ciphertextChunk));
      }

      if (done) {
        if (buffer.length > 0) {
          const iv = deriveIv(ivPrefix, chunkIndex++);
          const ciphertextChunk = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv, tagLength: AES_GCM_TAG_LENGTH_BITS },
            cekCryptoKey,
            buffer
          );
          await writer.write(new Uint8Array(ciphertextChunk));
        }
        break;
      }
    }
  } finally {
    reader.releaseLock();
    const endResultEncrypt = writer.end();
    if (typeof endResultEncrypt === 'object' && endResultEncrypt && typeof endResultEncrypt.then === 'function') {
        await endResultEncrypt;
    }
  }
  console.log(`🔐 AES-GCM Encryption complete: ${encryptedFilePath}`);
}

async function decryptStreamAesGcm(
  encryptedFilePath: string,
  plainFilePath: string,
  cekBytes: Uint8Array,
  expectedPlaintextHashB64: string, 
  tagLengthBits: number = AES_GCM_TAG_LENGTH_BITS,
  encryptedChunkSizeWithTag: number = DEFAULT_PLAINTEXT_CHUNK_SIZE + (AES_GCM_TAG_LENGTH_BITS / 8)
) {
  console.log(`🔓 AES-GCM Decrypting ${encryptedFilePath} → ${plainFilePath}`);
  const cekCryptoKey = await importAesGcmKey(cekBytes);

  const reader = Bun.file(encryptedFilePath).stream().getReader();
  const writer = Bun.file(plainFilePath).writer();

  let ivPrefixFromFile: Uint8Array = new Uint8Array(AES_GCM_IV_PREFIX_BYTES);
  let bytesReadForIv = 0;
  let tempBufferForIv: Uint8Array = new Uint8Array(0);

  while(bytesReadForIv < AES_GCM_IV_PREFIX_BYTES) {
    const {value: ivChunk, done: ivDone} = await reader.read();
    if (ivDone) {
      if (ivChunk && (ivChunk as Uint8Array).length > 0) {
         tempBufferForIv = concatUint8(tempBufferForIv, new Uint8Array(ivChunk));
      }
      if (tempBufferForIv.length < AES_GCM_IV_PREFIX_BYTES) { 
        throw new Error("Stream ended before IV prefix could be fully read.");
      }
    }
    
    if(!ivChunk && !ivDone) continue; 
    if(ivChunk && (ivChunk as Uint8Array).length > 0){
        tempBufferForIv = concatUint8(tempBufferForIv, new Uint8Array(ivChunk));
    }

    if (tempBufferForIv.length >= AES_GCM_IV_PREFIX_BYTES) {
        ivPrefixFromFile = tempBufferForIv.subarray(0, AES_GCM_IV_PREFIX_BYTES);
        bytesReadForIv = AES_GCM_IV_PREFIX_BYTES;
        tempBufferForIv = tempBufferForIv.subarray(AES_GCM_IV_PREFIX_BYTES);
        break; 
    }
    if(ivDone && tempBufferForIv.length < AES_GCM_IV_PREFIX_BYTES) { 
        throw new Error("Stream ended definitively before IV prefix could be fully read.");
    }
  }
  
  console.log(`📄 AES-GCM: Using IV Prefix from stream (b64): ${jose.base64url.encode(ivPrefixFromFile)}`);

  let chunkIndex = 0;
  const plainBuffersForHash: Uint8Array[] = [];
  let remainingBuffer = tempBufferForIv;

  try {
    while (true) {
      while(remainingBuffer.length < encryptedChunkSizeWithTag) {
          const { value: encryptedBlockValue, done } = await reader.read(); 
          
          if (encryptedBlockValue && encryptedBlockValue.length > 0) { 
            remainingBuffer = concatUint8(remainingBuffer, new Uint8Array(encryptedBlockValue));
          }

          if (done) {
              break; 
          }
      }
      
      if (remainingBuffer.length === 0) {
          break;
      }

      const currentBlockToDecrypt = remainingBuffer.length < encryptedChunkSizeWithTag ?
                                    remainingBuffer : 
                                    remainingBuffer.subarray(0, encryptedChunkSizeWithTag);
      
      if (currentBlockToDecrypt.length === 0) {
          break; 
      }
      
      remainingBuffer = remainingBuffer.length <= encryptedChunkSizeWithTag ?
                        new Uint8Array(0) :
                        remainingBuffer.subarray(encryptedChunkSizeWithTag);

      const iv = deriveIv(ivPrefixFromFile, chunkIndex++);
      const plaintextChunk = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv, tagLength: tagLengthBits },
        cekCryptoKey,
        currentBlockToDecrypt
      );
      const plainUint8 = new Uint8Array(plaintextChunk);
      await writer.write(plainUint8);
      plainBuffersForHash.push(plainUint8);
    }
  } finally {
    reader.releaseLock();
    const endResultDecrypt = writer.end();
    if (typeof endResultDecrypt === 'object' && endResultDecrypt && typeof endResultDecrypt.then === 'function') {
        await endResultDecrypt;
    }
  }

  let totalLength = 0;
  plainBuffersForHash.forEach(b => totalLength += b.byteLength);
  const fullPlaintext = new Uint8Array(totalLength);
  let offset = 0;
  plainBuffersForHash.forEach(b => {
    fullPlaintext.set(b, offset);
    offset += b.byteLength;
  });

  const digest = await crypto.subtle.digest('SHA-256', fullPlaintext);
  const gotHashBytes = new Uint8Array(digest);
  const gotPlaintextHashB64 = jose.base64url.encode(gotHashBytes);

  if (gotPlaintextHashB64 !== expectedPlaintextHashB64) {
    console.error(`Hash mismatch. Expected: ${expectedPlaintextHashB64}, Got: ${gotPlaintextHashB64}`);
    throw new Error('File integrity check failed: SHA-256 hash mismatch.');
  }
  console.log(`📄 AES-GCM: Plaintext SHA-256 hash verified: ${gotPlaintextHashB64}`);
  console.log(`🔓 AES-GCM Decryption complete: ${plainFilePath}`);
}

// Add pipeable ReadableStream for AES-GCM encryption
function encryptStreamAesGcmStream(
  sourceStream: ReadableStream<Uint8Array>,
  cekBytes: Uint8Array,
  ivPrefix: Uint8Array,
  plaintextChunkSize: number = DEFAULT_PLAINTEXT_CHUNK_SIZE
): ReadableStream<ArrayBuffer> {
  const reader = sourceStream.getReader();
  let buffer = new Uint8Array(0);
  let chunkIndex = 0;
  let done = false;
  const cekCryptoKeyPromise = importAesGcmKey(cekBytes);

  return new ReadableStream<ArrayBuffer>({
    async start(controller) {
      // Emit IV prefix first
      controller.enqueue(ivPrefix.buffer as any);
    },
    async pull(controller) {
      const cekCryptoKey = await cekCryptoKeyPromise;
      // Fill buffer until we have a full chunk or source ends
      while (!done && buffer.length < plaintextChunkSize) {
        const { value, done: readerDone } = await reader.read();
        if (value && value.length > 0) buffer = concatUint8(buffer, value);
        if (readerDone) done = true;
      }
      if (buffer.length === 0) {
        controller.close();
        reader.releaseLock();
        return;
      }
      // Take one chunk
      const chunk = buffer.length > plaintextChunkSize
        ? buffer.subarray(0, plaintextChunkSize)
        : buffer;
      buffer = buffer.length > plaintextChunkSize
        ? buffer.subarray(plaintextChunkSize)
        : new Uint8Array(0);
      // Encrypt and enqueue
      const iv = deriveIv(ivPrefix, chunkIndex++);
      const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv, tagLength: AES_GCM_TAG_LENGTH_BITS },
        cekCryptoKey,
        chunk
      );
      controller.enqueue(ciphertext);
      // Close if done
      if (done && buffer.length === 0) {
        controller.close();
        reader.releaseLock();
      }
    },
    cancel(reason) {
      reader.cancel(reason);
    }
  });
}

// Add pipeable ReadableStream for AES-GCM decryption with hash verification
function decryptStreamAesGcmStream(
  sourceStream: ReadableStream<Uint8Array>,
  cekBytes: Uint8Array,
  expectedPlaintextHashB64: string,
  tagLengthBits: number = AES_GCM_TAG_LENGTH_BITS,
  encryptedChunkSizeWithTag: number = DEFAULT_PLAINTEXT_CHUNK_SIZE + (AES_GCM_TAG_LENGTH_BITS / 8)
): ReadableStream<ArrayBuffer> {
  const reader = sourceStream.getReader();
  let tempBuffer = new Uint8Array(0);
  let ivPrefixFromFile: Uint8Array | null = null;
  let done = false;
  let chunkIndex = 0;
  const cekCryptoKeyPromise = importAesGcmKey(cekBytes);
  const hasher = new Bun.CryptoHasher('sha256');

  return new ReadableStream<ArrayBuffer>({
    async pull(controller) {
      const cekCryptoKey = await cekCryptoKeyPromise;
      // Read IV prefix if not yet
      if (ivPrefixFromFile === null) {
        while (tempBuffer.length < AES_GCM_IV_PREFIX_BYTES) {
          const { value, done: readerDone } = await reader.read();
          if (value && value.length > 0) tempBuffer = concatUint8(tempBuffer, value);
          if (readerDone) break;
        }
        if (tempBuffer.length < AES_GCM_IV_PREFIX_BYTES) {
          throw new Error('Stream ended before IV prefix could be fully read.');
        }
        ivPrefixFromFile = tempBuffer.subarray(0, AES_GCM_IV_PREFIX_BYTES);
        tempBuffer = tempBuffer.subarray(AES_GCM_IV_PREFIX_BYTES);
      }
      // Fill buffer for encrypted block
      while (!done && tempBuffer.length < encryptedChunkSizeWithTag) {
        const { value, done: readerDone } = await reader.read();
        if (value && value.length > 0) tempBuffer = concatUint8(tempBuffer, value);
        if (readerDone) done = true;
      }
      if (tempBuffer.length === 0) {
        // No more data: finalize
        controller.close();
        reader.releaseLock();
        const digest = new Uint8Array(hasher.digest());
        const gotHash = jose.base64url.encode(digest);
        if (gotHash !== expectedPlaintextHashB64) {
          controller.error(new Error(`Hash mismatch. Expected: ${expectedPlaintextHashB64}, Got: ${gotHash}`));
        }
        return;
      }
      // Take one encrypted block
      const block = tempBuffer.length > encryptedChunkSizeWithTag
        ? tempBuffer.subarray(0, encryptedChunkSizeWithTag)
        : tempBuffer;
      tempBuffer = tempBuffer.length > encryptedChunkSizeWithTag
        ? tempBuffer.subarray(encryptedChunkSizeWithTag)
        : new Uint8Array(0);
      // Decrypt and enqueue
      const iv = deriveIv(ivPrefixFromFile, chunkIndex++);
      const plaintextBuffer = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv, tagLength: tagLengthBits },
        cekCryptoKey,
        block
      );
      // Update hash and enqueue raw ArrayBuffer
      hasher.update(new Uint8Array(plaintextBuffer) as any);
      controller.enqueue(plaintextBuffer as any);
      // Close if done
      if (done && tempBuffer.length === 0) {
        const digest = new Uint8Array(hasher.digest());
        const gotHash = jose.base64url.encode(digest);
        if (gotHash !== expectedPlaintextHashB64) {
          controller.error(new Error(`Hash mismatch. Expected: ${expectedPlaintextHashB64}, Got: ${gotHash}`));
        } else {
          controller.close();
          reader.releaseLock();
        }
      }
    },
    cancel(reason) {
      reader.cancel(reason);
    }
  });
}