import { jsonOk, jsonUnauthorized } from "../../_core/response.js";
import { parseCookies, getSessionCookieName, clearSessionCookie } from "./_helper/auth_session.js";
import { getSessionRecord } from "./_helper/auth_service.js";
import { revokeSessionById } from "./_helper/auth_queries.js";

export async function onRequestPost({ request, env }){
  const auth = await getSessionRecord(env, request, parseCookies, getSessionCookieName);

  if(!auth){
    const res = jsonUnauthorized("session_not_found");
    res.headers.set("set-cookie", clearSessionCookie());
    return res;
  }

  await revokeSessionById(env, auth.session.id);

  const res = jsonOk({
    revoked: true,
    scope: "current_session",
    session_id: auth.session.id
  });

  res.headers.set("set-cookie", clearSessionCookie());
  return res;
}
