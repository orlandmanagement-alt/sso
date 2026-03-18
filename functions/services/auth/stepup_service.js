import { jsonOk, jsonInvalid, jsonUnauthorized, jsonError } from "../../_lib/response.js";
import { requireSessionAuth, nowSec, randomDigits, randomB64, sha256Base64 } from "./shared.js";
import { createOtp, getActiveOtp, consumeOtp, bumpOtp } from "../../repos/auth_otp_repo.js";
import { readJson } from "../../_lib/validate.js";

export async function onStepUpRequest({ request, env }){
  const auth = await requireSessionAuth(env, request);
  if(!auth.ok) return jsonUnauthorized({ message: "unauthorized" });
  
  const body = await readJson(request) || {};
  const action = String(body.action || "general_step_up").trim();
  const now = nowSec();
  const ttl = 300;
  const otp = randomDigits(6);
  const salt = randomB64(12);
  
  const otp_hash = await sha256Base64(`${otp}|${salt}|${env.HASH_PEPPER || ""}`);
  const identifier_hash = await sha256Base64(`${auth.uid}|stepup|${env.HASH_PEPPER || ""}`);
  
  try{
    await createOtp(env, { id: crypto.randomUUID(), purpose: "step_up", identifier_hash, otp_hash, otp_salt: salt, attempts: 0, max_attempts: 3, created_at: now, expires_at: now + ttl, consumed_at: null });
    return jsonOk({ step_up_required: true, action, sent: true, expires_at: now + ttl, otp_preview: env.DEV_SHOW_OTP === "1" ? otp : undefined });
  }catch(err){
    return jsonError({ message: "failed_to_request_step_up", detail: String(err?.message || err) });
  }
}

export async function onStepUpVerify({ request, env }){
  const auth = await requireSessionAuth(env, request);
  if(!auth.ok) return jsonUnauthorized({ message: "unauthorized" });
  
  const body = await readJson(request) || {};
  const otp = String(body.otp || "").trim();
  if(!otp) return jsonInvalid({ message: "otp_required" });
  
  const identifier_hash = await sha256Base64(`${auth.uid}|stepup|${env.HASH_PEPPER || ""}`);
  const now = nowSec();
  const row = await getActiveOtp(env, "step_up", identifier_hash, now);
  
  if(!row) return jsonUnauthorized({ message: "otp_not_found_or_expired" });
  
  const check_hash = await sha256Base64(`${otp}|${row.otp_salt}|${env.HASH_PEPPER || ""}`);
  if(String(check_hash) !== String(row.otp_hash || "")){
    await bumpOtp(env, row.id);
    return jsonUnauthorized({ message: "otp_invalid" });
  }
  
  await consumeOtp(env, row.id, now);
  
  return jsonOk({ verified: true, message: "step_up_successful", user_id: auth.uid });
}

export async function onVerifyPhone(){
  return jsonOk({ verified: true, message: "phone_verification_not_enabled" });
}

export async function onExchange(){
  return jsonOk({ exchanged: false, message: "exchange_not_enabled" });
}

export async function onSyncOtpSettings(){
  return jsonOk({ synced: true });
}
