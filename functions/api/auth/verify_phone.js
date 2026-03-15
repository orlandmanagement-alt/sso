import { jsonOk, jsonInvalid, jsonUnauthorized, jsonForbidden } from "../../_core/response.js";
import { requireSession } from "../../_core/auth.js";

function norm(value){
  return String(value || "").trim();
}

function makeFingerprint(request, userId){
  const ua = request.headers.get("user-agent") || "";
  const ip = request.headers.get("cf-connecting-ip") || "";
  return btoa(`${userId}|${ua}|${ip}`).slice(0, 80);
}

export async function onRequestPost({ request, env }){
  const auth = await requireSession(env, request);
  if(!auth.ok){
    return jsonUnauthorized("session_not_found");
  }

  let body;
  try{
    body = await request.json();
  }catch{
    return jsonInvalid("invalid_json");
  }

  const otpCode = norm(body?.otp_code);
  if(!otpCode){
    return jsonInvalid("otp_code_required");
  }

  const fingerprint = makeFingerprint(request, auth.user.id);
  const row = await env.DB.prepare(`
    SELECT id, status
    FROM auth_trusted_devices
    WHERE user_id = ?
      AND device_fingerprint = ?
    LIMIT 1
  `).bind(auth.user.id, fingerprint).first();

  if(!row){
    return jsonForbidden("device_challenge_not_found");
  }

  if(String(row.status || "") === "active"){
    return jsonOk({
      verified: true,
      flow: "device_verification",
      already_active: true
    });
  }

  const now = Math.floor(Date.now() / 1000);

  await env.DB.prepare(`
    UPDATE auth_trusted_devices
    SET
      status = 'active',
      last_seen_at = ?,
      updated_at = ?
    WHERE id = ?
  `).bind(now, now, row.id).run();

  return jsonOk({
    verified: true,
    flow: "device_verification"
  });
}
