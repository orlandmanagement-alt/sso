import { jsonOk, jsonUnauthorized } from "../../_core/response.js";
import { requireSession } from "../../_core/auth.js";

export async function onRequestPost({ request, env }){
  const auth = await requireSession(env, request);
  if(!auth.ok){
    return jsonUnauthorized("session_not_found");
  }

  return jsonOk({
    exchanged: true,
    user: auth.user,
    roles: auth.roles,
    session: {
      id: auth.session.id,
      expires_at: auth.session.expires_at,
      last_seen_at: auth.session.last_seen_at || null
    }
  });
}
