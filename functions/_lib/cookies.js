// Ganti domain dengan domain utama Anda
const DOMAIN = ".orlandmanagement.com"; 

export function makeSessionCookie(sid, maxAgeSec = 604800) {
  return `sid=${sid}; Domain=${DOMAIN}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAgeSec}`;
}

export function clearSessionCookie() {
  return `sid=; Domain=${DOMAIN}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

// Fungsi pembantu untuk membaca cookie dari request header
export function parseCookies(request) {
  const cookieHeader = request.headers.get("Cookie");
  if (!cookieHeader) return {};
  return cookieHeader.split(";").reduce((acc, cookie) => {
    const [key, value] = cookie.trim().split("=");
    acc[key] = value;
    return acc;
  }, {});
}
