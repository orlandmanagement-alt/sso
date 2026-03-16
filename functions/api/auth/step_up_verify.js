import { jsonOk, jsonUnauthorized, jsonInvalid, jsonForbidden } from "../../_core/response.js";
import { parseCookies, getSessionCookieName } from "./_helper/auth_session.js";
import { getSessionRecord } from "./_helper/auth_service.js";
import { verifyStepUpChallenge } from "./_helper/auth_stepup.js";
import { isOtpCode } from "./_helper/auth_validator.js";

function norm(value){
  return String(value || "").trim();
}

export async function onRequestPost({ request, env }){
  const auth = await getSessionRecord(env, request, parseCookies, getSessionCookieName);

  if(!auth){
    return jsonUnauthorized("session_not_found");
  }

  let body;
  try{
    body = await request.json();
  }catch{
    return jsonInvalid("invalid_json");
  }

  const otpCode = norm(body?.otp_code);
  const reason = norm(body?.reason || "step_up");

  if(!isOtpCode(otpCode)){
    return jsonInvalid("otp_code_required");
  }

  const result = await verifyStepUpChallenge(env, auth.user.id, reason, otpCode);

  if(!result.ok){
    return jsonForbidden(result.reason || "step_up_failed");
  }

  return jsonOk({
    verified: true,
    reason
  });
}
