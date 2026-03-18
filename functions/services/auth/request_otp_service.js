import { jsonOk, jsonInvalid, jsonForbidden, jsonError } from "../../_lib/response.js";
import { normEmail, safeNextPath } from "../../_lib/validate.js";
import { findUserByEmail, getUserRoles, findInviteByEmailHash } from "../../repos/auth_repo.js";
import { insertOtpRequest } from "../../repos/otp_repo.js";
import { nowSec, randomDigits, randomB64, sha256Base64, defaultPortalFromRoles } from "./shared.js";

export async function onRequestOtp({ request, env, body }){
  const email = normEmail(body.email);
  const requestedPortal = String(body.portal || "").trim();
  const next = safeNextPath(body.next || "/", "/");

  if(!email || !email.includes("@")) return jsonInvalid({ message: "email_required" });

  const user = await findUserByEmail(env, email);
  let roles = [];
  if(user?.id) roles = await getUserRoles(env, user.id);

  if((!roles || !roles.length) && env.HASH_PEPPER){
    const email_hash = await sha256Base64(email + "|" + env.HASH_PEPPER);
    const inv = await findInviteByEmailHash(env, email_hash);
    if(inv?.role) roles = [String(inv.role)];
  }

  const portal = requestedPortal || defaultPortalFromRoles(roles);
  if(requestedPortal && portal !== requestedPortal && !roles.includes(requestedPortal)){
    return jsonForbidden({ message: "role_not_allowed_for_portal", portal: requestedPortal });
  }

  const now = nowSec();
  const ttl = Math.max(60, Number(env.SSO_OTP_TTL_SEC || 300));
  const otp = randomDigits(6);
  const salt = randomB64(12);
  const otp_hash = await sha256Base64(`${otp}|${salt}|${env.HASH_PEPPER || ""}`);
  const identifier_hash = await sha256Base64(`${email}|${env.HASH_PEPPER || ""}`);

  try{
    await insertOtpRequest(env, { id: crypto.randomUUID(), purpose: "login", identifier_hash, otp_hash, otp_salt: salt, attempts: 0, max_attempts: 5, created_at: now, expires_at: now + ttl, consumed_at: null });
    return jsonOk({ sent: true, channel: "email", email, portal: portal || null, next, otp_preview: env.DEV_SHOW_OTP === "1" ? otp : undefined, expires_at: now + ttl });
  }catch(err){
    return jsonError({ message: "failed_to_create_otp", detail: String(err?.message || err) });
  }
}
