import { jsonOk, jsonUnauthorized } from "../../_core/response.js";
import { parseCookies, getSessionCookieName } from "./_helper/auth_session.js";
import { getSessionRecord } from "./_helper/auth_service.js";
import { listSessionsByUserId } from "./_helper/auth_queries.js";

export async function onRequestGet({ request, env }){
  const auth = await getSessionRecord(env, request, parseCookies, getSessionCookieName);

  if(!auth){
    return jsonUnauthorized("session_not_found");
  }

  const items = await listSessionsByUserId(env, auth.user.id);

  return jsonOk({
    items
  });
}
