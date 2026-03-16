import { jsonOk, jsonUnauthorized } from "../../_core/response.js";
import { requireSession, clearSessionCookie } from "../../_core/auth.js";

export async function onRequestPost({ request, env }){
  const auth = await requireSession(env, request);
  const now = Math.floor(Date.now() / 1000);

  if(!auth.ok){
    const res = jsonUnauthorized("session_not_found");
    res.headers.set("set-cookie", clearSessionCookie());
    return res;
  }

  await env.DB.prepare(`
    UPDATE auth_sessions
    SET status='revoked', updated_at = ?
    WHERE user_id = ?
  `).bind(now, auth.user.id).run();

  const res = jsonOk({
    revoked: true,
    scope: "all_sessions"
  });

  res.headers.set("set-cookie", clearSessionCookie());
  return res;
}
