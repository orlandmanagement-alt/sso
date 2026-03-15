import { jsonOk, jsonUnauthorized, jsonInvalid, jsonForbidden } from "../../_core/response.js";
import { requireSession } from "../../_core/auth.js";

function norm(value){
  return String(value || "").trim();
}

async function sha256Hex(input){
  const data = new TextEncoder().encode(String(input || ""));
  const buf = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(buf)].map(x => x.toString(16).padStart(2, "0")).join("");
}

async function hashStepUp(userId, reason, code){
  return await sha256Hex(`stepup|${String(userId || "")}|${String(reason || "")}|${String(code || "")}`);
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
  const reason = norm(body?.reason || "step_up");

  if(!otpCode){
    return jsonInvalid("otp_code_required");
  }

  const now = Math.floor(Date.now() / 1000);

  const row = await env.DB.prepare(`
    SELECT id, code, code_hash, expires_at, status
    FROM auth_step_up_challenges
    WHERE user_id = ?
      AND reason = ?
      AND status = 'pending'
    ORDER BY created_at DESC
    LIMIT 1
  `).bind(auth.user.id, reason).first();

  if(!row){
    return jsonForbidden("step_up_not_requested");
  }

  if(Number(row.expires_at || 0) < now){
    await env.DB.prepare(`
      UPDATE auth_step_up_challenges
      SET status = 'expired',
          updated_at = ?
      WHERE id = ?
    `).bind(now, row.id).run();

    return jsonForbidden("step_up_expired");
  }

  const expectedHash = await hashStepUp(auth.user.id, reason, otpCode);
  const validByHash = String(row.code_hash || "") === expectedHash;
  const validByLegacy = String(row.code || "") === otpCode;

  if(!validByHash && !validByLegacy){
    await env.DB.prepare(`
      UPDATE auth_step_up_challenges
      SET attempt_count = COALESCE(attempt_count, 0) + 1,
          updated_at = ?
      WHERE id = ?
    `).bind(now, row.id).run();

    return jsonForbidden("invalid_step_up_code");
  }

  await env.DB.prepare(`
    UPDATE auth_step_up_challenges
    SET status = 'verified',
        used_at = ?,
        updated_at = ?
    WHERE id = ?
  `).bind(now, now, row.id).run();

  return jsonOk({
    verified: true,
    reason
  });
}
