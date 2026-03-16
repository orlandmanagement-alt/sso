import { jsonOk, jsonUnauthorized } from "../../_core/response.js";
import { parseCookies, getSessionCookieName } from "./_helper/auth_session.js";
import { getSessionRecord } from "./_helper/auth_service.js";
import { defaultPortalFromRoles, portalRedirectUrl, safeNextPath } from "./_helper/auth_redirect.js";

export async function onRequestGet({ request, env }){
  const auth = await getSessionRecord(env, request, parseCookies, getSessionCookieName);

  if(!auth){
    return jsonUnauthorized("session_not_found");
  }

  const url = new URL(request.url);
  const nextPath = safeNextPath(url.searchParams.get("next") || "/", "/");
  const portal = defaultPortalFromRoles(auth.roles || []);
  const redirectUrl = portalRedirectUrl(env, portal, nextPath);

  return jsonOk({
    portal,
    redirect_url: redirectUrl,
    roles: auth.roles || [],
    next_path: nextPath
  });
}
