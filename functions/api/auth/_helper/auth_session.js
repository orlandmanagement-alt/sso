export function parseCookies(raw = ""){
  const out = {};
  String(raw || "").split(";").forEach(part => {
    const idx = part.indexOf("=");
    if(idx < 0) return;
    const key = part.slice(0, idx).trim();
    const val = part.slice(idx + 1).trim();
    if(!key) return;
    out[key] = decodeURIComponent(val);
  });
  return out;
}

export function getNow(){
  return Math.floor(Date.now() / 1000);
}

export function getSessionCookieName(){
  return "om_session";
}

export function buildSessionCookie(token, maxAge = 60 * 60 * 24 * 14){
  const name = getSessionCookieName();
  return `${name}=${encodeURIComponent(String(token || ""))}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}; Domain=.orlandmanagement.com`;
}

export function clearSessionCookie(){
  const name = getSessionCookieName();
  return `${name}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Domain=.orlandmanagement.com`;
}

export function makeId(prefix){
  return `${prefix}_${crypto.randomUUID()}`;
}

export function makeOtp(){
  return String(Math.floor(100000 + Math.random() * 900000));
}

export function makeToken(){
  return crypto.randomUUID().replace(/-/g, "") + crypto.randomUUID().replace(/-/g, "");
}

export function getClientIp(request){
  return request.headers.get("cf-connecting-ip") || request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || "";
}

export function getUserAgent(request){
  return request.headers.get("user-agent") || "";
}

export function makeDeviceFingerprint(request, userId = ""){
  const ua = getUserAgent(request);
  const ip = getClientIp(request);
  return btoa(`${userId}|${ua}|${ip}`).slice(0, 120);
}
