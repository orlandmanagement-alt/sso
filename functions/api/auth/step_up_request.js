import { jsonOk, jsonUnauthorized, jsonInvalid } from "../../_core/response.js";
import { parseCookies, getSessionCookieName } from "./_helper/auth_session.js";
import { getSessionRecord } from "./_helper/auth_service.js";
import { createStepUpChallenge } from "./_helper/auth_stepup.js";

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

  const reason = norm(body?.reason || "step_up");
  const result = await createStepUpChallenge(env, auth.user.id, reason);

  return jsonOk(result);
}
