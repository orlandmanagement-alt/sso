import { jsonOk, jsonUnauthorized } from "../../_core/response.js";
import { requireSession } from "../../_core/auth.js";

export async function onRequestGet({ request, env }){
  const auth = await requireSession(env, request);
  if(!auth.ok){
    return jsonUnauthorized("session_not_found");
  }

  return jsonOk({
    user: auth.user,
    roles: auth.roles,
    session: {
      id: auth.session.id,
      created_at: auth.session.created_at,
      expires_at: auth.session.expires_at,
      last_seen_at: auth.session.last_seen_at || null
    }
  });
}
