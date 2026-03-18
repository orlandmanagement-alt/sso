import { jsonOk, jsonUnauthorized } from "../../_lib/response.js";
import { requireSessionAuth, defaultPortalFromRoles, buildPortalRedirectUrl } from "./shared.js";

export async function onResolveRedirect({ request, env }) {
  const auth = await requireSessionAuth(env, request);
  if (!auth.ok) return jsonUnauthorized({ message: "unauthorized" });

  const portal = defaultPortalFromRoles(auth.roles);
  if (!portal) return jsonUnauthorized({ message: "no_portal_access" });

  const redirect_url = buildPortalRedirectUrl(env, portal, "/");
  return jsonOk({ redirect_url });
}
