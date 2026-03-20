const DOMAIN = ".orlandmanagement.com"; // HARUS DIAWALI TITIK agar berlaku untuk semua subdomain

export function makeSessionCookie(sid, maxAgeSec = 259200) {
  // SameSite=Lax aman untuk navigasi biasa, SameSite=None wajib jika cross-site fetch (butuh Secure)
  // Kita gunakan None; Secure agar Fetch API dari portal talent/client bisa membawa cookie ini ke API
  return `sid=${sid}; Domain=${DOMAIN}; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=${maxAgeSec}`;
}

export function clearSessionCookie() {
  return `sid=; Domain=${DOMAIN}; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=0`;
}

export function parseCookies(request) {
  const cookieHeader = request.headers.get("Cookie");
  if (!cookieHeader) return {};
  return cookieHeader.split(";").reduce((acc, cookie) => {
    const [key, value] = cookie.trim().split("=");
    acc[key] = value;
    return acc;
  }, {});
}
