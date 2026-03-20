const DOMAIN = ".orlandmanagement.com"; 

export function makeSessionCookie(sid, maxAgeSec = 259200) {
  // PERUBAHAN KRUSIAL: SameSite=None agar Cookie bisa terbang antar subdomain via Fetch API
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
