/**
 * CPoE Browser Extension — Standalone Evidence Engine
 *
 * When the native messaging host (desktop app / CLI) is not installed,
 * this module provides a lightweight in-browser evidence chain using
 * Web Crypto API and IndexedDB. Evidence is weaker than the full engine
 * (no VDF proofs, no hardware attestation, no Secure Enclave) but still
 * provides a hash-chained, timestamped record of the writing process.
 *
 * When the desktop app IS installed, this module is not used — the
 * background script routes everything through native messaging instead.
 */

const DB_NAME = "writersproof-evidence";
const DB_VERSION = 1;
const STORE_SESSIONS = "sessions";
const STORE_CHECKPOINTS = "checkpoints";

let db = null;

async function openDB() {
  if (db) return db;
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = (e) => {
      const d = e.target.result;
      if (!d.objectStoreNames.contains(STORE_SESSIONS)) {
        d.createObjectStore(STORE_SESSIONS, { keyPath: "id" });
      }
      if (!d.objectStoreNames.contains(STORE_CHECKPOINTS)) {
        const store = d.createObjectStore(STORE_CHECKPOINTS, {
          keyPath: "id",
          autoIncrement: true,
        });
        store.createIndex("sessionId", "sessionId", { unique: false });
      }
    };
    req.onsuccess = (e) => {
      db = e.target.result;
      resolve(db);
    };
    req.onerror = () => reject(req.error);
  });
}

function generateId() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function sha256Hex(data) {
  const encoded =
    typeof data === "string" ? new TextEncoder().encode(data) : data;
  const hash = await crypto.subtle.digest("SHA-256", encoded);
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// --- Public API (called from background.js) ---

async function standaloneStartSession(url, title) {
  const d = await openDB();
  const sessionId = generateId();
  const nonce = generateId();
  const now = Date.now();

  const genesisInput = `CPoE-StandaloneGenesis-v1:${nonce}`;
  const genesisHash = await sha256Hex(genesisInput);

  const session = {
    id: sessionId,
    url,
    title,
    nonce,
    startedAt: now,
    lastCheckpointAt: now,
    checkpointCount: 0,
    prevHash: genesisHash,
    mode: "standalone",
  };

  const tx = d.transaction(STORE_SESSIONS, "readwrite");
  tx.objectStore(STORE_SESSIONS).put(session);
  await txComplete(tx);

  return {
    type: "session_started",
    session_id: sessionId,
    session_nonce: nonce,
    mode: "standalone",
  };
}

async function standaloneCheckpoint(sessionId, contentHash, charCount, delta) {
  const d = await openDB();
  const tx = d.transaction([STORE_SESSIONS, STORE_CHECKPOINTS], "readwrite");
  const sessionStore = tx.objectStore(STORE_SESSIONS);
  const cpStore = tx.objectStore(STORE_CHECKPOINTS);

  const session = await storeGet(sessionStore, sessionId);
  if (!session) {
    return { type: "error", code: "NO_SESSION", message: "No active session" };
  }

  const ordinal = session.checkpointCount + 1;
  const now = Date.now();

  // Chain: SHA-256(prevHash || contentHash || ordinal || timestamp)
  const chainInput = `${session.prevHash}:${contentHash}:${ordinal}:${now}`;
  const checkpointHash = await sha256Hex(chainInput);

  const checkpoint = {
    sessionId,
    ordinal,
    timestamp: now,
    contentHash,
    charCount,
    delta,
    prevHash: session.prevHash,
    checkpointHash,
  };

  cpStore.put(checkpoint);

  session.prevHash = checkpointHash;
  session.checkpointCount = ordinal;
  session.lastCheckpointAt = now;
  sessionStore.put(session);

  await txComplete(tx);

  return {
    type: "checkpoint_created",
    checkpoint_count: ordinal,
    hash: checkpointHash.slice(0, 24),
    mode: "standalone",
  };
}

async function standaloneStopSession(sessionId) {
  const d = await openDB();
  const tx = d.transaction(STORE_SESSIONS, "readwrite");
  const store = tx.objectStore(STORE_SESSIONS);
  const session = await storeGet(store, sessionId);

  if (session) {
    session.endedAt = Date.now();
    store.put(session);
    await txComplete(tx);
  }

  return {
    type: "session_stopped",
    message: "Standalone session ended",
    checkpoint_count: session?.checkpointCount || 0,
    mode: "standalone",
  };
}

async function standaloneGetStatus(sessionId) {
  if (!sessionId) {
    return {
      type: "status",
      active: false,
      tracked_files: 0,
      total_checkpoints: 0,
      mode: "standalone",
    };
  }

  const d = await openDB();
  const session = await storeGet(
    d.transaction(STORE_SESSIONS).objectStore(STORE_SESSIONS),
    sessionId
  );

  return {
    type: "status",
    active: session && !session.endedAt,
    tracked_files: session ? 1 : 0,
    total_checkpoints: session?.checkpointCount || 0,
    mode: "standalone",
  };
}

async function standaloneExportEvidence(sessionId) {
  const d = await openDB();
  const tx = d.transaction([STORE_SESSIONS, STORE_CHECKPOINTS]);
  const session = await storeGet(
    tx.objectStore(STORE_SESSIONS),
    sessionId
  );
  if (!session) return null;

  const checkpoints = await storeGetAllByIndex(
    tx.objectStore(STORE_CHECKPOINTS),
    "sessionId",
    sessionId
  );

  return {
    version: 1,
    mode: "standalone",
    session: {
      id: session.id,
      url: session.url,
      title: session.title,
      startedAt: session.startedAt,
      endedAt: session.endedAt,
      nonce: session.nonce,
    },
    checkpoints: checkpoints.map((cp) => ({
      ordinal: cp.ordinal,
      timestamp: cp.timestamp,
      contentHash: cp.contentHash,
      charCount: cp.charCount,
      delta: cp.delta,
      prevHash: cp.prevHash,
      checkpointHash: cp.checkpointHash,
    })),
  };
}

// --- IndexedDB helpers ---

function txComplete(tx) {
  return new Promise((resolve, reject) => {
    tx.oncomplete = resolve;
    tx.onerror = () => reject(tx.error);
  });
}

function storeGet(store, key) {
  return new Promise((resolve, reject) => {
    const req = store.get(key);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function storeGetAllByIndex(store, indexName, key) {
  return new Promise((resolve, reject) => {
    const req = store.index(indexName).getAll(key);
    req.onsuccess = () => resolve(req.result || []);
    req.onerror = () => reject(req.error);
  });
}
