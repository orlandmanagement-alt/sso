import { jsonOk, jsonUnauthorized } from "../../_core/response.js";
import { requireSession, buildSessionCookie, hashSessionToken } from "../../_core/auth.js";

function now(){
  return Math.floor(Date.now() / 1000);
}

export async function onRequestPost({ request, env }){
  const auth = await requireSession(env, request);

  if(!auth.ok){
    return jsonUnauthorized("session_not_found");
  }

  const newToken = crypto.randomUUID().replace(/-/g,"") + crypto.randomUUID().replace(/-/g,"");
  const newTokenHash = await hashSessionToken(newToken);
  const newExpire = now() + (60 * 60 * 24 * 14);

  await env.DB.prepare(`
    UPDATE auth_sessions
    SET
      session_token = ?,
      session_token_hash = ?,
      expires_at = ?,
      updated_at = ?,
      last_seen_at = ?
    WHERE id = ?
  `).bind(
    newToken,
    newTokenHash,
    newExpire,
    now(),
    now(),
    auth.session.id
  ).run();

  const res = jsonOk({
    refreshed: true,
    session_id: auth.session.id,
    expires_at: newExpire
  });

  res.headers.set("set-cookie", buildSessionCookie(newToken));
  return res;
}
