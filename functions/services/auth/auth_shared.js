import { cookie, inferCookieDomain, parseCookies } from "../../_lib/cookies.js";
import { safeNextPath } from "../../_lib/validate.js";

export function nowSec(){ return Math.floor(Date.now() / 1000); }

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

export function makeSessionCookie(request, env, sid, maxAgeSec){
  return cookie("sid", sid, { path: "/", domain: inferCookieDomain(request, env), maxAge: maxAgeSec, httpOnly: true, secure: true, sameSite: "Lax" });
}

export function clearSessionCookie(request, env){
  return cookie("sid", "", { path: "/", domain: inferCookieDomain(request, env), maxAge: 0, httpOnly: true, secure: true, sameSite: "Lax" });
}

export async function createSessionRow(env, user_id, roles, ip_hash = null, ua_hash = null){
  const sid = crypto.randomUUID();
  const now = nowSec();
  const ttlSec = Math.max(10, Number(env.SESSION_TTL_MIN || 720)) * 60;
  await env.DB.prepare(`
    INSERT INTO sessions (
      id, user_id, token_hash, created_at, expires_at, revoked_at,
      ip_hash, ua_hash, role_snapshot, last_seen_at,
      roles_json, session_version
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(sid, user_id, sid, now, now + ttlSec, null, ip_hash, ua_hash, JSON.stringify(roles || []), now, JSON.stringify(roles || []), 1).run();
  return { sid, ttlSec };
}
