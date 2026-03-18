import { jsonOk, jsonInvalid, jsonUnauthorized, jsonForbidden, jsonError } from "../../_lib/response.js";
import { normEmail } from "../../_lib/validate.js";
import { pbkdf2Hash } from "../../_lib/crypto.js";
import { findUserByEmail, findUserByWa, getUserRoles, updateLoginFailure, resetLoginFailure } from "../../repos/users_repo.js";
import { createOtp, getActiveOtp, consumeOtp, bumpOtp } from "../../repos/auth_otp_repo.js";
import { nowSec, randomDigits, randomB64, sha256Base64, defaultPortalFromRoles, buildPortalRedirectUrl, makeSessionCookie, createSessionRow } from "./auth_shared.js";

function detectIdentifierType(identifier){
  const s = String(identifier || "").trim();
  return s.includes("@") ? "email" : "wa";
}

export async function loginPasswordService({ request, env, body }){
  const email = normEmail(body.email);
  const password = String(body.password || "");
  if(!email || !email.includes("@") || !password) return jsonInvalid({ message: "email_and_password_required" });
  
  const user = await findUserByEmail(env, email);
  if(!user?.id) return jsonUnauthorized({ message: "invalid_credentials" });
  
  const now = Math.floor(Date.now() / 1000);
  if (user.locked_until && user.locked_until > now) {
    const waitMins = Math.ceil((user.locked_until - now) / 60);
    return jsonForbidden({ message: `account_locked_try_again_in_${waitMins}_minutes` });
  }
  if(String(user.status || "").toLowerCase() !== "active") return jsonForbidden({ message: "user_not_active" });
  
  const hash = await pbkdf2Hash(password, user.password_salt, user.password_iter);
  if(String(hash) !== String(user.password_hash || "")){
    const failCount = (user.pw_fail_count || 0) + 1;
    let lockUntil = null;
    if (failCount >= 5) lockUntil = now + (15 * 60);
    await updateLoginFailure(env, user.id, failCount, lockUntil, now);
    return jsonUnauthorized({ message: "invalid_credentials" });
  }
  
  if (user.pw_fail_count > 0) await resetLoginFailure(env, user.id);
  
  const roles = await getUserRoles(env, user.id);
  const portal = defaultPortalFromRoles(roles);
  if(!portal) return jsonForbidden({ message: "no_portal_access" });
  
  const clientIp = request.headers.get("cf-connecting-ip") || "0.0.0.0";
  const userAgent = request.headers.get("user-agent") || "unknown";
  const ip_hash = await sha256Base64(`${clientIp}|${env.HASH_PEPPER}`);
  const ua_hash = await sha256Base64(`${userAgent}|${env.HASH_PEPPER}`);
  
  try{
    const sess = await createSessionRow(env, user.id, roles, ip_hash, ua_hash);
    return jsonOk({
      logged_in: true,
      user_id: user.id,
      roles,
      redirect_url: buildPortalRedirectUrl(env, portal, "/")
    }, {
      "set-cookie": makeSessionCookie(request, env, sess.sid, sess.ttlSec)
    });
  }catch(err){
    return jsonError({ message: "failed_to_create_session", detail: String(err?.message || err) });
  }
}

export async function requestOtpService({ env, body, purpose = "login" }){
  const identifier = String(body.identifier || body.email || body.wa || "").trim();
  const channel = String(body.channel || body.otp_channel || "email").trim().toLowerCase();
  if(!identifier) return jsonInvalid({ message: "identifier_required" });
  const now = nowSec();
  const ttl = Math.max(60, Number(env.SSO_OTP_TTL_SEC || 300));
  const otp = randomDigits(6);
  const salt = randomB64(12);
  const otp_hash = await sha256Base64(`${otp}|${salt}|${env.HASH_PEPPER || ""}`);
  const identifier_hash = await sha256Base64(`${identifier}|${env.HASH_PEPPER || ""}`);
  try{
    await createOtp(env, { id: crypto.randomUUID(), purpose, identifier_hash, otp_hash, otp_salt: salt, attempts: 0, max_attempts: 5, created_at: now, expires_at: now + ttl, consumed_at: null });
    return jsonOk({ sent: true, purpose, channel, identifier, expires_at: now + ttl, otp_preview: env.DEV_SHOW_OTP === "1" ? otp : undefined });
  }catch(err){
    return jsonError({ message: "failed_to_create_otp", detail: String(err?.message || err) });
  }
}

export async function verifyOtpLoginService({ request, env, body }){
  const identifier = String(body.identifier || body.email || body.wa || "").trim();
  const otp = String(body.otp || "").trim();
  if(!identifier || !otp) return jsonInvalid({ message: "identifier_and_otp_required" });
  const identifier_hash = await sha256Base64(`${identifier}|${env.HASH_PEPPER || ""}`);
  const now = nowSec();
  const row = await getActiveOtp(env, "login", identifier_hash, now);
  if(!row) return jsonUnauthorized({ message: "otp_not_found_or_expired" });
  const check_hash = await sha256Base64(`${otp}|${row.otp_salt}|${env.HASH_PEPPER || ""}`);
  if(String(check_hash) !== String(row.otp_hash || "")){
    await bumpOtp(env, row.id);
    return jsonUnauthorized({ message: "otp_invalid" });
  }
  const kind = detectIdentifierType(identifier);
  const user = kind === "email" ? await findUserByEmail(env, identifier) : await findUserByWa(env, identifier);
  if(!user?.id) return jsonForbidden({ message: "user_not_found" });
  if(String(user.status || "").toLowerCase() !== "active") return jsonForbidden({ message: "user_not_active" });
  const roles = await getUserRoles(env, user.id);
  const portal = defaultPortalFromRoles(roles);
  if(!portal) return jsonForbidden({ message: "no_portal_access" });
  await consumeOtp(env, row.id, now);
  
  const clientIp = request.headers.get("cf-connecting-ip") || "0.0.0.0";
  const userAgent = request.headers.get("user-agent") || "unknown";
  const ip_hash = await sha256Base64(`${clientIp}|${env.HASH_PEPPER}`);
  const ua_hash = await sha256Base64(`${userAgent}|${env.HASH_PEPPER}`);
  
  try{
    const sess = await createSessionRow(env, user.id, roles, ip_hash, ua_hash);
    return jsonOk({ logged_in: true, user_id: user.id, roles, redirect_url: buildPortalRedirectUrl(env, portal, "/") }, { "set-cookie": makeSessionCookie(request, env, sess.sid, sess.ttlSec) });
  }catch(err){
    return jsonError({ message: "failed_to_create_session", detail: String(err?.message || err) });
  }
}
