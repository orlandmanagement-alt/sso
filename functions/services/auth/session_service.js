import { jsonOk, jsonUnauthorized, jsonInvalid } from "../../_lib/response.js";
import { readJson } from "../../_lib/validate.js";
import { revokeSession, revokeAllSessions, listUserSessions } from "../../repos/session_repo.js";
import { requireSessionAuth, nowSec, clearSessionCookie } from "./shared.js";

export async function onMe({ request, env }){
  const a = await requireSessionAuth(env, request);
  if(!a.ok) return jsonUnauthorized({ message: "unauthorized" });

  return jsonOk({
    user_id: a.uid,
    roles: a.roles || []
  });
}

export async function onSessions({ request, env }){
  const a = await requireSessionAuth(env, request);
  if(!a.ok) return jsonUnauthorized({ message: "unauthorized" });

  const rows = await listUserSessions(env, a.uid);
  return jsonOk({
    items: rows.map(x => ({
      id: x.id,
      user_id: x.user_id,
      created_at: x.created_at,
      expires_at: x.expires_at,
      revoked_at: x.revoked_at,
      last_seen_at: x.last_seen_at,
      roles_json: x.roles_json,
      session_version: x.session_version,
      revoke_reason: x.revoke_reason
    }))
  });
}

export async function onLogout({ request, env }){
  const a = await requireSessionAuth(env, request);
  if(a.ok){
    await revokeSession(env, a.sid, nowSec(), "logout");
  }

  return jsonOk({ logged_out: true }, {
    "set-cookie": clearSessionCookie(request, env)
  });
}

export async function onLogoutAll({ request, env }){
  const a = await requireSessionAuth(env, request);
  if(!a.ok) return jsonUnauthorized({ message: "unauthorized" });

  await revokeAllSessions(env, a.uid, nowSec(), "logout_all");

  return jsonOk({ logged_out_all: true }, {
    "set-cookie": clearSessionCookie(request, env)
  });
}

export async function onRevokeSession({ request, env }){
  const a = await requireSessionAuth(env, request);
  if(!a.ok) return jsonUnauthorized({ message: "unauthorized" });

  const body = await readJson(request) || {};
  const sid = String(body.sid || "").trim();
  if(!sid) return jsonInvalid({ message: "sid_required" });

  await revokeSession(env, sid, nowSec(), "self_revoke");
  return jsonOk({ revoked: true, sid });
}

export async function onRefresh({ request, env }){
  const a = await requireSessionAuth(env, request);
  if(!a.ok) return jsonUnauthorized({ message: "unauthorized" });

  return jsonOk({
    refreshed: true,
    user_id: a.uid,
    roles: a.roles || []
  });
}
