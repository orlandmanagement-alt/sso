import { jsonOk, jsonInvalid, jsonUnauthorized, jsonNotFound, jsonError } from "../../_lib/response.js";
import { findUserByEmail, findUserByWa, updateUserPassword } from "../../repos/users_repo.js";
import { getActiveOtp, consumeOtp, bumpOtp } from "../../repos/auth_otp_repo.js";
import { requestOtpService } from "./auth_login_service.js";
import { sha256Base64, randomB64, nowSec } from "./auth_shared.js";
import { pbkdf2Hash } from "../../_lib/crypto.js";

function detectIdentifierType(identifier){
  const s = String(identifier || "").trim();
  return s.includes("@") ? "email" : "wa";
}

export async function requestPasswordResetService({ env, body }){
  const identifier = String(body.identifier || "").trim();
  if(!identifier) return jsonInvalid({ message: "identifier_required" });

  const kind = detectIdentifierType(identifier);
  const user = kind === "email" ? await findUserByEmail(env, identifier) : await findUserByWa(env, identifier);
  if(!user?.id) return jsonNotFound({ message: "user_not_found" });

  return await requestOtpService({ env, body: { identifier, channel: body.channel || "email" }, purpose: "reset_password" });
}

export async function verifyPasswordResetService({ env, body }){
  const identifier = String(body.identifier || "").trim();
  const otp = String(body.otp || "").trim();
  const new_password = String(body.new_password || "").trim();

  if(!identifier || !otp || new_password.length < 5) return jsonInvalid({ message: "invalid_reset_payload" });

  const kind = detectIdentifierType(identifier);
  const user = kind === "email" ? await findUserByEmail(env, identifier) : await findUserByWa(env, identifier);
  if(!user?.id) return jsonNotFound({ message: "user_not_found" });

  const identifier_hash = await sha256Base64(`${identifier}|${env.HASH_PEPPER || ""}`);
  const row = await getActiveOtp(env, "reset_password", identifier_hash, nowSec());
  if(!row) return jsonUnauthorized({ message: "otp_not_found_or_expired" });

  const check_hash = await sha256Base64(`${otp}|${row.otp_salt}|${env.HASH_PEPPER || ""}`);
  if(String(check_hash) !== String(row.otp_hash || "")){
    await bumpOtp(env, row.id);
    return jsonUnauthorized({ message: "otp_invalid" });
  }

  const salt = randomB64(16);
  const iter = 100000;
  const hash = await pbkdf2Hash(new_password, salt, iter);

  try{
    await updateUserPassword(env, user.id, { password_hash: hash, password_salt: salt, password_iter: iter, password_algo: "pbkdf2_sha256", updated_at: nowSec() });
    await consumeOtp(env, row.id, nowSec());
    return jsonOk({ reset: true, user_id: user.id });
  }catch(err){
    return jsonError({ message: "failed_to_reset_password", detail: String(err?.message || err) });
  }
}
