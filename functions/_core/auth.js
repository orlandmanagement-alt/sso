function parseCookies(raw = ""){
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

function getNow(){
  return Math.floor(Date.now() / 1000);
}

function maskPhone(value = ""){
  const s = String(value || "").trim();
  if(s.length < 6) return s;
  return s.slice(0, 4) + "****" + s.slice(-3);
}

function maskEmail(value = ""){
  const s = String(value || "").trim();
  const parts = s.split("@");
  if(parts.length !== 2) return s;
  const name = parts[0];
  const domain = parts[1];
  if(name.length <= 2) return `${name[0] || "*"}***@${domain}`;
  return `${name.slice(0, 2)}***@${domain}`;
}

async function sha256Hex(input){
  const data = new TextEncoder().encode(String(input || ""));
  const buf = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(buf)].map(x => x.toString(16).padStart(2, "0")).join("");
}

export function getSessionCookieName(){
  return "om_session";
}

export function buildSessionCookie(token, maxAge = 60 * 60 * 24 * 14){
  const name = getSessionCookieName();
  return `${name}=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}; Domain=.orlandmanagement.com`;
}

export function clearSessionCookie(){
  const name = getSessionCookieName();
  return `${name}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Domain=.orlandmanagement.com`;
}

export async function hashSessionToken(token){
  return await sha256Hex(`om_session|${String(token || "")}`);
}

export async function getSessionRecord(env, request){
  const cookies = parseCookies(request.headers.get("cookie") || "");
  const token = cookies[getSessionCookieName()] || "";
  if(!token) return null;

  const tokenHash = await hashSessionToken(token);

  let row = await env.DB.prepare(`
    SELECT
      s.id,
      s.user_id,
      s.session_token,
      s.session_token_hash,
      s.status,
      s.expires_at,
      s.created_at,
      s.last_seen_at,
      u.email,
      u.phone,
      u.display_name,
      u.status AS user_status
    FROM auth_sessions s
    JOIN auth_users u ON u.id = s.user_id
    WHERE s.session_token_hash = ?
    LIMIT 1
  `).bind(tokenHash).first();

  if(!row){
    row = await env.DB.prepare(`
      SELECT
        s.id,
        s.user_id,
        s.session_token,
        s.session_token_hash,
        s.status,
        s.expires_at,
        s.created_at,
        s.last_seen_at,
        u.email,
        u.phone,
        u.display_name,
        u.status AS user_status
      FROM auth_sessions s
      JOIN auth_users u ON u.id = s.user_id
      WHERE s.session_token = ?
      LIMIT 1
    `).bind(token).first();
  }

  if(!row) return null;
  if(String(row.status || "") !== "active") return null;
  if(String(row.user_status || "") !== "active") return null;
  if(Number(row.expires_at || 0) < getNow()) return null;

  await env.DB.prepare(`
    UPDATE auth_sessions
    SET last_seen_at = ?, updated_at = ?
    WHERE id = ?
  `).bind(getNow(), getNow(), row.id).run();

  const rolesRes = await env.DB.prepare(`
    SELECT r.name
    FROM auth_user_roles ur
    JOIN auth_roles r ON r.id = ur.role_id
    WHERE ur.user_id = ?
    ORDER BY r.name ASC
  `).bind(row.user_id).all();

  return {
    session: row,
    user: {
      id: row.user_id,
      email: row.email || "",
      email_masked: row.email ? maskEmail(row.email) : "",
      phone: row.phone || "",
      phone_masked: row.phone ? maskPhone(row.phone) : "",
      display_name: row.display_name || "",
      status: row.user_status || "active"
    },
    roles: (rolesRes.results || []).map(x => String(x.name || "")).filter(Boolean)
  };
}

export async function requireSession(env, request){
  const found = await getSessionRecord(env, request);
  if(!found){
    return { ok: false };
  }

  return {
    ok: true,
    user: found.user,
    roles: found.roles,
    session: found.session
  };
}
