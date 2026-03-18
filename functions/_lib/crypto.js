export async function hashData(text) {
  if(!text) return null;
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text + "orland_enterprise_salt_999"));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}
