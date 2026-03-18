export function makeSessionCookie(sid, maxAgeSec = 604800) {
  // 604800 detik = 7 Hari. HttpOnly dan Secure wajib untuk Enterprise!
  return `sid=${sid}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAgeSec}`;
}

export function clearSessionCookie() {
  return `sid=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}
