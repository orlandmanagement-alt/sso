import { jsonOk, jsonUnauthorized } from "../../_core/response.js";
import { requireSession } from "../../_core/auth.js";

export async function onRequestGet({ request, env }){
  const auth = await requireSession(env, request);
  if(!auth.ok){
    return jsonUnauthorized("session_not_found");
  }

  const rows = await env.DB.prepare(`
    SELECT
      id,
      status,
      device_info,
      ip_address,
      created_at,
      updated_at,
      last_seen_at,
      expires_at
    FROM auth_sessions
    WHERE user_id = ?
    ORDER BY created_at DESC
  `).bind(auth.user.id).all();

  return jsonOk({
    items: rows.results || []
  });
}
