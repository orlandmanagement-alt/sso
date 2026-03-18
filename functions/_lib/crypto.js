export async function pbkdf2Hash(password, saltB64, iterations = 100000) {
  const enc = new TextEncoder();
  const pwKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );
  const saltBuf = Uint8Array.from(atob(saltB64), c => c.charCodeAt(0));
  const keyBuffer = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: saltBuf,
      iterations: iterations,
      hash: "SHA-256"
    },
    pwKey,
    256
  );
  return Array.from(new Uint8Array(keyBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
}
