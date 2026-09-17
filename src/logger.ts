const SECRET_RE =
  /(password|passphrase|secret|token|dek|unwrap|pairing[_-]?key|ciphertext|grant)/i;

export function looksSecret(text: string): boolean {
  return SECRET_RE.test(text);
}

export function logInfo(message: string): void {
  if (looksSecret(message)) {
    console.error("[safe-connect] (redacted log line)");
    return;
  }
  console.error(`[safe-connect] ${message}`);
}

export function logError(message: string): void {
  if (looksSecret(message)) {
    console.error("[safe-connect] error (redacted)");
    return;
  }
  console.error(`[safe-connect] ${message}`);
}

/** Public DTO: never copy unknown objects through to agent responses. */
export function publicStatus(
  request_id: string,
  status: string,
  error?: string,
): { request_id: string; status: string; error?: string } {
  const out: { request_id: string; status: string; error?: string } = {
    request_id,
    status,
  };
  if (error) out.error = error;
  return out;
}
