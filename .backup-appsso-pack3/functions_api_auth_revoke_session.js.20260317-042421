import { jsonOk, jsonUnauthorized, jsonInvalid, jsonForbidden } from "../../_core/response.js";
import { requireSession } from "../../_core/auth.js";

function norm(value){
  return String(value || "").trim();
}

export async function onRequestPost({ request, env }){
  const auth = await requireSession(env, request);
  const now = Math.floor(Date.now() / 1000);

  if(!auth.ok){
    return jsonUnauthorized("session_not_found");
  }

  let body;
  try{
    body = await request.json();
  }catch{
    return jsonInvalid("invalid_json");
  }

  const sessionId = norm(body?.session_id);
  if(!sessionId){
    return jsonInvalid("session_id_required");
  }

  const row = await env.DB.prepare(`
    SELECT id, user_id
    FROM auth_sessions
    WHERE id = ?
    LIMIT 1
  `).bind(sessionId).first();

  if(!row){
    return jsonInvalid("session_not_found");
  }

  if(String(row.user_id || "") !== String(auth.user.id || "")){
    return jsonForbidden("cannot_revoke_foreign_session");
  }

  await env.DB.prepare(`
    UPDATE auth_sessions
    SET status = 'revoked', updated_at = ?
    WHERE id = ?
  `).bind(now, sessionId).run();

  return jsonOk({
    revoked: true,
    session_id: sessionId
  });
}
