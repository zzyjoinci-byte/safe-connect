export type Mode = "local" | "cloud";
export type Grade = "L0" | "L1";
export type RequestStatus = "pending" | "filled" | "denied" | "expired";
export type CompanionStatus = "paired" | "missing" | "not_required";

export interface PublicItem {
  id: string;
  label: string;
  origin: string;
  grade: Grade;
}

export interface SealedSecret {
  nonce: string;
  ciphertext: string;
  sealed_dek: string;
}

export interface SealedItem extends PublicItem {
  sealed: SealedSecret;
}

export interface PlainCredential {
  username: string;
  password: string;
}

export interface LoginRequestInput {
  purpose: string;
  url: string;
  item_id?: string;
  grade?: Grade;
  ttl_seconds?: number;
}

export interface LoginRequestView {
  request_id: string;
  status: RequestStatus;
  error?: string;
}

export interface LoginRequestRecord extends LoginRequestView {
  purpose: string;
  url: string;
  item_id: string;
  grade: Grade;
  created_at: number;
  grant_expires_at: number;
  confirm_code?: string;
}

export interface UnwrapChallenge {
  request_id: string;
  url: string;
  purpose: string;
  grade: Grade;
  expires_in: number;
  confirm_code: string;
  sealed_dek: string;
}

export interface CryptoGrant {
  request_id: string;
  url: string;
  expires_at: number;
  nonce: string;
  ciphertext: string;
}

export interface HealthBody {
  status: "ok" | "fail_closed";
  mode: Mode;
  companion: CompanionStatus;
  version: string;
}

export interface PairingMaterial {
  pairingKey: Uint8Array;
  publicKey: Uint8Array;
  /** Companion only. Cloud brokers must not hold this. */
  privateKey?: Uint8Array;
}

export interface FillResult {
  ok: boolean;
  error?: string;
}

export type Filler = (url: string, username: string, password: string) => Promise<FillResult>;
