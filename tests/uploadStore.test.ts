import { describe, expect, test } from "bun:test";
import { UploadStore } from "../src/uploadStore.js";

const pdfBase64 = Buffer.from("%PDF-1.4\nhello\n%%EOF\n").toString("base64");

describe("UploadStore", () => {
  test("reassembles chunks and validates PDFs", () => {
    const store = new UploadStore({ maxChunkBase64Length: 8 });
    const started = store.start({
      filename: "document.pdf",
      contentType: "application/pdf",
      expectedSize: Buffer.from(pdfBase64, "base64").length,
      expectedBase64Length: pdfBase64.length,
      fields: { title: "Document" },
    });

    for (let index = 0; index * 8 < pdfBase64.length; index += 1) {
      store.addChunk(started.uploadId, index, pdfBase64.slice(index * 8, index * 8 + 8));
    }

    const finished = store.finish(started.uploadId);
    expect(finished.session.filename).toBe("document.pdf");
    expect(finished.session.fields).toEqual({ title: "Document" });
    expect(finished.bytes.subarray(0, 5).toString("ascii")).toBe("%PDF-");
    expect(() => store.get(started.uploadId)).toThrow("Unknown or expired uploadId");
  });

  test("rejects paths as filenames", () => {
    const store = new UploadStore();
    expect(() => store.start({ filename: "/tmp/document.pdf", contentType: "application/pdf", fields: {} })).toThrow("basename");
  });

  test("rejects file URLs and non-base64 chunks", () => {
    const store = new UploadStore();
    const started = store.start({ filename: "document.pdf", contentType: "application/pdf", fields: {} });
    expect(() => store.addChunk(started.uploadId, 0, "file:///tmp/document.pdf")).toThrow("base64 data only");
  });

  test("rejects missing chunks on finish", () => {
    const store = new UploadStore();
    const started = store.start({ filename: "document.pdf", contentType: "application/pdf", fields: {} });
    store.addChunk(started.uploadId, 1, pdfBase64);
    expect(() => store.finish(started.uploadId)).toThrow("Missing chunk index 0");
  });

  test("rejects decoded non-PDF content for application/pdf", () => {
    const store = new UploadStore();
    const started = store.start({ filename: "document.pdf", contentType: "application/pdf", fields: {} });
    store.addChunk(started.uploadId, 0, Buffer.from("not a pdf").toString("base64"));
    expect(() => store.finish(started.uploadId)).toThrow("missing %PDF- header");
  });

  test("abort deletes session and is idempotent", () => {
    const store = new UploadStore();
    const started = store.start({ filename: "document.pdf", contentType: "application/pdf", fields: {} });
    expect(store.abort(started.uploadId)).toEqual({ uploadId: started.uploadId, aborted: true });
    expect(store.abort(started.uploadId)).toEqual({ uploadId: started.uploadId, aborted: false });
  });

  test("cleanup removes expired sessions", () => {
    let now = 1_000;
    const store = new UploadStore({ now: () => now, ttlMs: 10 });
    const started = store.start({ filename: "document.pdf", contentType: "application/pdf", fields: {} });
    now = 1_011;
    expect(store.cleanupExpired()).toBe(1);
    expect(() => store.get(started.uploadId)).toThrow("Unknown or expired uploadId");
  });
});
