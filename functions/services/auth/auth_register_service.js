import { jsonOk, jsonInvalid, jsonConflict, jsonError, jsonUnauthorized } from "../../_lib/response.js";
import { normEmail } from "../../_lib/validate.js";
import { randomB64, sha256Base64, nowSec } from "./auth_shared.js";
import { pbkdf2Hash } from "../../_lib/crypto.js";
import { createOtp, getActiveOtp, consumeOtp, bumpOtp } from "../../repos/auth_otp_repo.js";
import { findUserByEmail, createUser, attachRole } from "../../repos/users_repo.js";

export async function registerService({ env, body }){
  const role = String(body.role || "").trim().toLowerCase();
  const email = normEmail(body.email);
  const wa = String(body.wa || "").trim();
  const password = String(body.password || "");
  const otp_channel = String(body.otp_channel || "email").trim().toLowerCase();
  if(!["talent", "client"].includes(role)) return jsonInvalid({ message: "role_must_be_talent_or_client" });
  if(!email || !email.includes("@") || !wa ) return jsonInvalid({ message: "invalid_register_payload" });
  const exists = await findUserByEmail(env, email);
  if(exists?.id) return jsonConflict({ message: "email_already_used" });
  const identifier = otp_channel === "wa" ? wa : email;
  const now = nowSec();
  const ttl = Math.max(60, Number(env.SSO_OTP_TTL_SEC || 300));
  const otp = String(Math.floor(100000 + Math.random() * 900000));
  const salt = randomB64(12);
  const otp_hash = await sha256Base64(`${otp}|${salt}|${env.HASH_PEPPER || ""}`);
  const identifier_hash = await sha256Base64(`${identifier}|${env.HASH_PEPPER || ""}`);
  try{
    await createOtp(env, { id: crypto.randomUUID(), purpose: "register", identifier_hash, otp_hash, otp_salt: salt, attempts: 0, max_attempts: 5, created_at: now, expires_at: now + ttl, consumed_at: null });
    return jsonOk({ registered_pending: true, role, email, wa, otp_channel, expires_at: now + ttl, otp_preview: env.DEV_SHOW_OTP === "1" ? otp : undefined });
  }catch(err){
    return jsonError({ message: "failed_to_start_registration", detail: String(err?.message || err) });
  }
}

export async function verifyRegisterService({ env, body }){
  const role = String(body.role || "").trim().toLowerCase();
  const email = normEmail(body.email);
  const wa = String(body.wa || "").trim();
  const password = String(body.password || "");
  const otp_channel = String(body.otp_channel || "email").trim().toLowerCase();
  const otp = String(body.otp || "").trim();
  if(!["talent", "client"].includes(role) || !email || !wa || !password || !otp) return jsonInvalid({ message: "invalid_verify_register_payload" });
  const identifier = otp_channel === "wa" ? wa : email;
  const identifier_hash = await sha256Base64(`${identifier}|${env.HASH_PEPPER || ""}`);
  const row = await getActiveOtp(env, "register", identifier_hash, nowSec());
  if(!row) return jsonUnauthorized({ message: "otp_not_found_or_expired" });
  const check_hash = await sha256Base64(`${otp}|${row.otp_salt}|${env.HASH_PEPPER || ""}`);
  if(String(check_hash) !== String(row.otp_hash || "")){
    await bumpOtp(env, row.id);
    return jsonUnauthorized({ message: "otp_invalid" });
  }
  const exists = await findUserByEmail(env, email);
  if(exists?.id) return jsonConflict({ message: "email_already_used" });
  const user_id = crypto.randomUUID();
  const salt = randomB64(16);
  const iter = 100000;
  const hash = await pbkdf2Hash(password, salt, iter);
  const now = nowSec();
  try{
    await createUser(env, { id: user_id, email_norm: email, display_name: email.split("@")[0] || role, status: "active", phone: wa, password_hash: hash, password_salt: salt, password_iter: iter, password_algo: "pbkdf2_sha256", created_at: now, updated_at: now });
    await attachRole(env, user_id, role);
    await consumeOtp(env, row.id, now);
    
    if (role === 'talent' && env.DB_TALENT) {
      const profileId = crypto.randomUUID();
      await env.DB_TALENT.prepare("INSERT INTO talent_profiles (id, user_id, display_name, visibility_status, created_at, updated_at) VALUES (?, ?, ?, 'private', ?, ?)").bind(profileId, user_id, email.split("@")[0], now, now).run();
    } else if (role === 'client' && env.DB_CLIENT) {
      const orgId = crypto.randomUUID();
      await env.DB_CLIENT.prepare("INSERT INTO client_organizations (id, owner_user_id, name, status, verification_status, created_at, updated_at) VALUES (?, ?, ?, 'active', 'unverified', ?, ?)").bind(orgId, user_id, `Perusahaan ${email.split("@")[0]}`, now, now).run();
    }
    
    return jsonOk({ created: true, user_id, role, email });
  }catch(err){
    return jsonError({ message: "failed_to_create_user", detail: String(err?.message || err) });
  }
}
