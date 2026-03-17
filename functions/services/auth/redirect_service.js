import { jsonOk, jsonUnauthorized } from "../../_lib/response.js";
import { safeNextPath } from "../../_lib/validate.js";
import { requireSessionAuth, defaultPortalFromRoles, buildPortalRedirectUrl, deniedUrl } from "./shared.js";

export async function onResolveRedirect({ request, env }){
  const a = await requireSessionAuth(env, request);
  if(!a.ok) return jsonUnauthorized({ message: "unauthorized" });

  const url = new URL(request.url);
  const requestedPortal = String(url.searchParams.get("portal") || "").trim();
  const next = safeNextPath(url.searchParams.get("next") || "/", "/");

  const roles = a.roles || [];
  const s = new Set(roles);
  const adminAccess = s.has("super_admin") || s.has("admin") || s.has("staff") || s.has("security_admin");
  const canTalent = adminAccess || s.has("talent");
  const canClient = adminAccess || s.has("client");
  const canDashboard = adminAccess;

  if(requestedPortal === "dashboard" && !canDashboard){
    return jsonOk({ redirect_url: deniedUrl(env, "role_not_allowed", "dashboard", next) });
  }
  if(requestedPortal === "talent" && !canTalent){
    return jsonOk({ redirect_url: deniedUrl(env, "role_not_allowed", "talent", next) });
  }
  if(requestedPortal === "client" && !canClient){
    return jsonOk({ redirect_url: deniedUrl(env, "role_not_allowed", "client", next) });
  }

  const portal = requestedPortal || defaultPortalFromRoles(roles) || "dashboard";
  return jsonOk({ redirect_url: buildPortalRedirectUrl(env, portal, next) });
}
