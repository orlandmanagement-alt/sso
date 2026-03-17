import { jsonOk, jsonInvalid, jsonForbidden, jsonUnauthorized, jsonError } from "../../_lib/response.js";
import { normEmail, safeNextPath, isOtpFormat } from "../../_lib/validate.js";
import { findUserByEmail, getUserRoles } from "../../repos/auth_repo.js";
import { getLatestActiveOtp, bumpOtpAttempt, consumeOtp } from "../../repos/otp_repo.js";
import { createSession } from "../../repos/session_repo.js";
import {
  nowSec,
  sha256Base64,
  defaultPortalFromRoles,
  buildPortalRedirectUrl,
  deniedUrl,
  makeSessionCookie
} from "./shared.js";

export async function onVerifyOtp({ request, env, body }){
  const email = normEmail(body.email);
  const otp = String(body.otp || "").trim();
  const requestedPortal = String(body.portal || "").trim();
  const next = safeNextPath(body.next || "/", "/");

  if(!email || !email.includes("@")){
    return jsonInvalid({ message: "email_required" });
  }

  if(!isOtpFormat(otp)){
    return jsonInvalid({ message: "otp_invalid" });
  }

  const identifier_hash = await sha256Base64(`${email}|${env.HASH_PEPPER || ""}`);
  const now = nowSec();
  const row = await getLatestActiveOtp(env, "login", identifier_hash, now);

  if(!row){
    return jsonUnauthorized({ message: "otp_not_found_or_expired" });
  }

  const otp_hash = await sha256Base64(`${otp}|${row.otp_salt}|${env.HASH_PEPPER || ""}`);
  if(String(otp_hash) !== String(row.otp_hash || "")){
    await bumpOtpAttempt(env, row.id);
    return jsonUnauthorized({ message: "otp_invalid" });
  }

  const user = await findUserByEmail(env, email);
  if(!user?.id){
    return jsonForbidden({ message: "user_not_found" });
  }

  const roles = await getUserRoles(env, user.id);
  const portal = requestedPortal || defaultPortalFromRoles(roles);

  if(!portal){
    return jsonForbidden({ message: "no_portal_access" });
  }

  const access = new Set((roles || []).map(String));
  if(
    requestedPortal &&
    !access.has(requestedPortal) &&
    !["super_admin","admin","staff","security_admin"].some(x => access.has(x))
  ){
    return jsonForbidden({
      message: "role_not_allowed_for_portal",
      portal: requestedPortal,
      denied_url: deniedUrl(env, "role_not_allowed", requestedPortal, next)
    });
  }

  await consumeOtp(env, row.id, now);

  const ttlMin = Math.max(10, Number(env.SESSION_TTL_MIN || 720));
  const ttlSec = ttlMin * 60;
  const sid = crypto.randomUUID();

  try{
    await createSession(env, {
      id: sid,
      user_id: user.id,
      token_hash: sid,
      created_at: now,
      expires_at: now + ttlSec,
      revoked_at: null,
      ip_hash: null,
      ua_hash: null,
      role_snapshot: JSON.stringify(roles || []),
      ip_prefix_hash: null,
      last_seen_at: now,
      roles_json: JSON.stringify(roles || []),
      session_version: 1,
      revoke_reason: null
    });

    return jsonOk({
      verified: true,
      sid,
      portal,
      roles,
      redirect_url: buildPortalRedirectUrl(env, portal, next)
    }, {
      "set-cookie": makeSessionCookie(request, env, sid, ttlSec)
    });
  }catch(err){
    return jsonError({
      message: "failed_to_create_session",
      detail: String(err?.message || err)
    });
  }
}
