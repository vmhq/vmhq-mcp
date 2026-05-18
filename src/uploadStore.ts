import { randomUUID } from "node:crypto";

export type UploadMetadata = {
  filename: string;
  contentType: string;
  expectedSize?: number;
  expectedBase64Length?: number;
  fields: Record<string, string | number | Array<string | number>>;
};

export type UploadSession = UploadMetadata & {
  uploadId: string;
  createdAt: number;
  expiresAt: number;
  chunks: Map<number, string>;
};

export type UploadStoreOptions = {
  now?: () => number;
  ttlMs?: number;
  maxDecodedBytes?: number;
  maxChunkBase64Length?: number;
};

export type UploadStartInput = UploadMetadata;

const DEFAULT_TTL_MS = 15 * 60 * 1000;
const DEFAULT_MAX_DECODED_BYTES = 50 * 1024 * 1024;
const DEFAULT_MAX_CHUNK_BASE64_LENGTH = 64 * 1024;
const BASE64_RE = /^[A-Za-z0-9+/=]*$/;

function error(message: string): never {
  throw new Error(message);
}

function assertSafeFilename(filename: string): void {
  if (!filename.trim()) error("filename is required.");
  if (filename.includes("/") || filename.includes("\\")) error("filename must be a basename, not a path.");
  if (filename === "." || filename === "..") error("filename is invalid.");
}

function assertBase64Chunk(chunkBase64: string): void {
  if (!chunkBase64) error("chunkBase64 is required.");
  if (!BASE64_RE.test(chunkBase64)) error("chunkBase64 must contain base64 data only, not paths or file:// references.");
}

function decodedLength(base64: string): number {
  const padding = base64.endsWith("==") ? 2 : base64.endsWith("=") ? 1 : 0;
  return Math.floor((base64.length * 3) / 4) - padding;
}

function assertPdf(bytes: Buffer, contentType: string): void {
  if (contentType.toLowerCase() !== "application/pdf") return;
  if (bytes.length < 5 || bytes.subarray(0, 5).toString("ascii") !== "%PDF-") {
    error("Decoded file is not a valid PDF: missing %PDF- header.");
  }
}

export class UploadStore {
  private readonly sessions = new Map<string, UploadSession>();
  private readonly now: () => number;
  readonly ttlMs: number;
  readonly maxDecodedBytes: number;
  readonly maxChunkBase64Length: number;

  constructor(options: UploadStoreOptions = {}) {
    this.now = options.now ?? (() => Date.now());
    this.ttlMs = options.ttlMs ?? DEFAULT_TTL_MS;
    this.maxDecodedBytes = options.maxDecodedBytes ?? DEFAULT_MAX_DECODED_BYTES;
    this.maxChunkBase64Length = options.maxChunkBase64Length ?? DEFAULT_MAX_CHUNK_BASE64_LENGTH;
  }

  cleanupExpired(): number {
    const now = this.now();
    let removed = 0;
    for (const [uploadId, session] of this.sessions.entries()) {
      if (session.expiresAt <= now) {
        this.sessions.delete(uploadId);
        removed += 1;
      }
    }
    return removed;
  }

  start(input: UploadStartInput): { uploadId: string; expiresAt: string; maxChunkBase64Length: number } {
    this.cleanupExpired();
    assertSafeFilename(input.filename);

    if (input.expectedSize !== undefined && input.expectedSize > this.maxDecodedBytes) {
      error(`expectedSize exceeds maximum upload size of ${this.maxDecodedBytes} bytes.`);
    }

    const createdAt = this.now();
    const expiresAt = createdAt + this.ttlMs;
    const uploadId = randomUUID();

    this.sessions.set(uploadId, {
      ...input,
      contentType: input.contentType || "application/pdf",
      uploadId,
      createdAt,
      expiresAt,
      chunks: new Map(),
    });

    return {
      uploadId,
      expiresAt: new Date(expiresAt).toISOString(),
      maxChunkBase64Length: this.maxChunkBase64Length,
    };
  }

  addChunk(uploadId: string, index: number, chunkBase64: string): { uploadId: string; receivedChunks: number; expiresAt: string } {
    this.cleanupExpired();
    const session = this.get(uploadId);
    if (!Number.isInteger(index) || index < 0) error("index must be a non-negative integer.");
    if (chunkBase64.length > this.maxChunkBase64Length) error(`chunkBase64 exceeds maximum chunk length of ${this.maxChunkBase64Length}.`);
    assertBase64Chunk(chunkBase64);

    session.chunks.set(index, chunkBase64);

    return {
      uploadId,
      receivedChunks: session.chunks.size,
      expiresAt: new Date(session.expiresAt).toISOString(),
    };
  }

  finish(uploadId: string): { session: UploadSession; bytes: Buffer } {
    this.cleanupExpired();
    const session = this.get(uploadId);
    if (session.chunks.size === 0) error("No chunks received for upload.");

    const indexes = [...session.chunks.keys()].sort((a, b) => a - b);
    for (let expected = 0; expected < indexes.length; expected += 1) {
      if (indexes[expected] !== expected) error(`Missing chunk index ${expected}.`);
    }

    const base64 = indexes.map((index) => session.chunks.get(index)).join("");
    if (session.expectedBase64Length !== undefined && base64.length !== session.expectedBase64Length) {
      error(`Combined base64 length ${base64.length} did not match expectedBase64Length ${session.expectedBase64Length}.`);
    }

    assertBase64Chunk(base64);
    const estimatedDecodedLength = decodedLength(base64);
    if (estimatedDecodedLength > this.maxDecodedBytes) error(`Decoded file exceeds maximum upload size of ${this.maxDecodedBytes} bytes.`);

    const bytes = Buffer.from(base64, "base64");
    if (session.expectedSize !== undefined && bytes.length !== session.expectedSize) {
      error(`Decoded file size ${bytes.length} did not match expectedSize ${session.expectedSize}.`);
    }
    assertPdf(bytes, session.contentType);

    this.sessions.delete(uploadId);
    return { session, bytes };
  }

  abort(uploadId: string): { uploadId: string; aborted: boolean } {
    this.cleanupExpired();
    return { uploadId, aborted: this.sessions.delete(uploadId) };
  }

  get(uploadId: string): UploadSession {
    const session = this.sessions.get(uploadId);
    if (!session) error("Unknown or expired uploadId.");
    if (session.expiresAt <= this.now()) {
      this.sessions.delete(uploadId);
      error("Unknown or expired uploadId.");
    }
    return session;
  }
}

export const paperlessUploadStore = new UploadStore();
