import { jsonOk, jsonUnauthorized, jsonInvalid, jsonConflict } from "../../_core/response.js";
import { requireSession } from "../../_core/auth.js";

function norm(value){
  return String(value || "").trim();
}

function createCode(){
  return String(Math.floor(100000 + Math.random() * 900000));
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

  const reason = norm(body?.reason || "step_up");
  const now = Math.floor(Date.now() / 1000);

  const recent = await env.DB.prepare(`
    SELECT id, created_at, expires_at
    FROM auth_step_up_challenges
    WHERE user_id = ?
      AND reason = ?
      AND status = 'pending'
    ORDER BY created_at DESC
    LIMIT 1
  `).bind(auth.user.id, reason).first();

  if(recent){
    const age = now - Number(recent.created_at || 0);
    if(age < 30){
      return jsonConflict("step_up_resend_cooldown", {
        challenge_id: recent.id,
        retry_after_sec: 30 - age
      });
    }

    if(Number(recent.expires_at || 0) > now){
      await env.DB.prepare(`
        UPDATE auth_step_up_challenges
        SET status = 'expired',
            updated_at = ?
        WHERE id = ?
      `).bind(now, recent.id).run();
    }
  }

  const code = createCode();
  const codeHash = await hashStepUp(auth.user.id, reason, code);
  const expiresAt = now + 300;
  const id = `sup_${crypto.randomUUID()}`;

  await env.DB.prepare(`
    INSERT INTO auth_step_up_challenges (
      id,
      user_id,
      reason,
      code,
      code_hash,
      status,
      expires_at,
      created_at,
      updated_at
    ) VALUES (?, ?, ?, ?, ?, 'pending', ?, ?, ?)
  `).bind(
    id,
    auth.user.id,
    reason,
    code,
    codeHash,
    expiresAt,
    now,
    now
  ).run();

  return jsonOk({
    challenge_id: id,
    reason,
    expires_at: expiresAt
  });
}
