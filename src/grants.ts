import { b64d, b64e, utf8 } from "./bytes.js";
import {
  aeadDecrypt,
  aeadEncrypt,
  keyedHash,
  memzero,
  sealOpen,
} from "./crypto.js";
import { GRANT_TTL_MS } from "./config.js";
import type { CryptoGrant, PlainCredential } from "./types.js";

export function deriveGrantKey(
  pairingKey: Uint8Array,
  requestId: string,
  url: string,
): Uint8Array {
  return keyedHash(pairingKey, utf8(`grant|${requestId}|${url}`));
}

export function createGrant(input: {
  pairingKey: Uint8Array;
  publicKey: Uint8Array;
  privateKey: Uint8Array;
  sealedDekB64: string;
  requestId: string;
  url: string;
  ttlMs?: number;
  now?: number;
}): CryptoGrant {
  const dek = sealOpen(b64d(input.sealedDekB64), input.publicKey, input.privateKey);
  const now = input.now ?? Date.now();
  const ttl = Math.min(input.ttlMs ?? GRANT_TTL_MS, GRANT_TTL_MS);
  const expires_at = now + ttl;
  const aad = utf8(`${input.requestId}|${input.url}|${expires_at}`);
  const grantKey = deriveGrantKey(input.pairingKey, input.requestId, input.url);
  try {
    const box = aeadEncrypt(grantKey, dek, aad);
    return {
      request_id: input.requestId,
      url: input.url,
      expires_at,
      nonce: b64e(box.nonce),
      ciphertext: b64e(box.ciphertext),
    };
  } finally {
    memzero(dek);
    memzero(grantKey);
  }
}

export function openGrant(input: {
  pairingKey: Uint8Array;
  grant: CryptoGrant;
  requestId: string;
  url: string;
  now?: number;
  consumed?: Set<string>;
}): Uint8Array {
  const now = input.now ?? Date.now();
  if (input.grant.request_id !== input.requestId) {
    throw new Error("grant request_id mismatch");
  }
  if (input.grant.url !== input.url) {
    throw new Error("grant url mismatch");
  }
  if (now > input.grant.expires_at) {
    throw new Error("grant expired");
  }
  if (input.consumed?.has(input.requestId)) {
    throw new Error("grant already used");
  }
  const aad = utf8(`${input.requestId}|${input.url}|${input.grant.expires_at}`);
  const grantKey = deriveGrantKey(input.pairingKey, input.requestId, input.url);
  try {
    const dek = aeadDecrypt(
      grantKey,
      b64d(input.grant.nonce),
      b64d(input.grant.ciphertext),
      aad,
    );
    input.consumed?.add(input.requestId);
    return dek;
  } finally {
    memzero(grantKey);
  }
}

export function decryptItem(dek: Uint8Array, nonceB64: string, ciphertextB64: string): PlainCredential {
  const plain = aeadDecrypt(dek, b64d(nonceB64), b64d(ciphertextB64), utf8("item"));
  try {
    const cred = JSON.parse(Buffer.from(plain).toString("utf8")) as PlainCredential;
    if (typeof cred.username !== "string" || typeof cred.password !== "string") {
      throw new Error("invalid credential payload");
    }
    return cred;
  } finally {
    memzero(plain);
  }
}

export function zeroizeCredential(cred: PlainCredential): void {
  cred.username = "";
  cred.password = "";
}
