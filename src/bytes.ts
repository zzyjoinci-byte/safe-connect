import { timingSafeEqual as tse } from "node:crypto";

export function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

export function fromUtf8(b: Uint8Array): string {
  return new TextDecoder().decode(b);
}

export function b64e(b: Uint8Array): string {
  return Buffer.from(b).toString("base64");
}

export function b64d(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "base64"));
}

export function hexe(b: Uint8Array): string {
  return Buffer.from(b).toString("hex");
}

export function hexd(s: string): Uint8Array {
  const clean = s.trim().toLowerCase();
  if (!/^[0-9a-f]*$/.test(clean) || clean.length % 2 !== 0) {
    throw new Error("invalid hex");
  }
  return new Uint8Array(Buffer.from(clean, "hex"));
}

export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  return tse(Buffer.from(a), Buffer.from(b));
}

export function jsonBytes(value: unknown): Uint8Array {
  return utf8(JSON.stringify(value));
}
