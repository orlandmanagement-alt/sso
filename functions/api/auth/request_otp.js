import { jsonOk, jsonInvalid } from "../../_core/response.js";
import { normLower, normalizePhone, isEmail, isPhone } from "./_helper/auth_validator.js";
import { createOtpRequest } from "./_helper/auth_service.js";

export async function onRequestPost({ request, env }){
  let body;
  try{
    body = await request.json();
  }catch{
    return jsonInvalid("invalid_json");
  }

  const identityRaw = String(body?.identity || "").trim();
  const identityTypeRaw = String(body?.identity_type || "").trim().toLowerCase();

  let identityType = identityTypeRaw;
  let identityValue = identityRaw;

  if(identityType === "email" || (!identityType && identityRaw.includes("@"))){
    identityType = "email";
    identityValue = normLower(identityRaw);
    if(!isEmail(identityValue)) return jsonInvalid("invalid_email");
  }else{
    identityType = "phone";
    identityValue = normalizePhone(identityRaw);
    if(!isPhone(identityValue)) return jsonInvalid("invalid_phone");
  }

  const result = await createOtpRequest(env, request, identityType, identityValue);

  if(!result.ok){
    return jsonInvalid(result.reason || "otp_request_failed");
  }

  return jsonOk({
    challenge_id: result.challenge_id,
    identity_type: result.identity_type,
    expires_at: result.expires_at,
    delivery: result.delivery
  });
}
