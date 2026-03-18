import { cookie, inferCookieDomain, parseCookies } from "../../_lib/cookies.js";
import { safeNextPath } from "../../_lib/validate.js";
import { getUserRoles } from "../../repos/users_repo.js";

export function nowSec(){
  return Math.floor(Date.now() / 1000);
}

export async function sha256Base64(str){
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(String(str)));
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

export function randomDigits(len = 6){
  const arr = crypto.getRandomValues(new Uint8Array(len));
  return Array.from(arr).map(x => String(x % 10)).join("");
}

export function randomB64(bytes = 18){
  const u8 = crypto.getRandomValues(new Uint8Array(bytes));
  let s = "";
  for(const c of u8) s += String.fromCharCode(c);
  return btoa(s);
}

export function portalAccessFromRoles(roles){
  const r = new Set((roles || []).map(String));
  return {
    dashboard: r.has("super_admin") || r.has("admin") || r.has("staff") || r.has("security_admin"),
    talent: r.has("super_admin") || r.has("admin") || r.has("staff") || r.has("talent"),
    client: r.has("super_admin") || r.has("admin") || r.has("staff") || r.has("client")
  };
}

export function defaultPortalFromRoles(roles){
  const p = portalAccessFromRoles(roles);
  if(p.dashboard) return "dashboard";
  if(p.talent) return "talent";
  if(p.client) return "client";
  return null;
}

export function portalBaseUrl(env, portal){
  if(portal === "dashboard") return env.SSO_DEFAULT_REDIRECT_ADMIN || "https://dashboard.orlandmanagement.com";
  if(portal === "talent") return env.SSO_DEFAULT_REDIRECT_TALENT || "https://talent.orlandmanagement.com";
  if(portal === "client") return env.SSO_DEFAULT_REDIRECT_CLIENT || "https://client.orlandmanagement.com";
  return env.SSO_DEFAULT_REDIRECT_ADMIN || "https://dashboard.orlandmanagement.com";
}

export function buildPortalRedirectUrl(env, portal, next = "/"){
  return `${String(portalBaseUrl(env, portal)).replace(/\/+$/, "")}${safeNextPath(next, "/")}`;
}

export function deniedUrl(env, reason = "role_not_allowed"){
  const base = env.SSO_DEFAULT_REDIRECT_DENIED || "https://sso.orlandmanagement.com/access-denied.html";
  const u = new URL(base);
  u.searchParams.set("reason", reason);
  return u.toString();
}

export function makeSessionCookie(request, env, sid, maxAgeSec){
  return cookie("sid", sid, {
    path: "/",
    domain: inferCookieDomain(request, env),
    maxAge: maxAgeSec,
    httpOnly: true,
    secure: true,
    sameSite: "Lax"
  });
}

export function clearSessionCookie(request, env){
  return cookie("sid", "", {
    path: "/",
    domain: inferCookieDomain(request, env),
    maxAge: 0,
    httpOnly: true,
    secure: true,
    sameSite: "Lax"
  });
}

export async function createSessionRow(env, user_id, roles){
  const sid = crypto.randomUUID();
  const now = nowSec();
  const ttlMin = Math.max(10, Number(env.SESSION_TTL_MIN || 720));
  const ttlSec = ttlMin * 60;

  await env.DB.prepare(`
    INSERT INTO sessions (
      id, user_id, token_hash, created_at, expires_at, revoked_at,
      ip_hash, ua_hash, role_snapshot, ip_prefix_hash, last_seen_at,
      roles_json, session_version, revoke_reason
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(
    sid,
    user_id,
    sid,
    now,
    now + ttlSec,
    null,
    null,
    null,
    JSON.stringify(roles || []),
    null,
    now,
    JSON.stringify(roles || []),
    1,
    null
  ).run();

  return { sid, ttlSec };
}

export async function requireSessionAuth(env, request){
  const cookies = parseCookies(request);
  const sid = String(cookies.sid || "").trim();
  if(!sid) return { ok: false };

  const row = await env.DB.prepare(`
    SELECT id, user_id, expires_at, revoked_at, roles_json, role_snapshot
    FROM sessions
    WHERE id = ?
    LIMIT 1
  `).bind(sid).first();

  if(!row) return { ok: false };
  if(row.revoked_at) return { ok: false };
  if(Number(row.expires_at || 0) < nowSec()) return { ok: false };

  let roles = [];
  try{
    roles = JSON.parse(row.roles_json || row.role_snapshot || "[]") || [];
  }catch{}

  if(!roles.length){
    roles = await getUserRoles(env, row.user_id);
  }

  return {
    ok: true,
    sid: row.id,
    uid: row.user_id,
    roles
  };
}
