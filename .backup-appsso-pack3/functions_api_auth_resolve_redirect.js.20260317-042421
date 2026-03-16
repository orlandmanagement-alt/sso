import { jsonOk, jsonUnauthorized } from "../../_core/response.js";
import { requireSession } from "../../_core/auth.js";

function resolveDomain(roles){
  if(roles.includes("super_admin")) return "https://admin.orlandmanagement.com";
  if(roles.includes("admin")) return "https://admin.orlandmanagement.com";
  if(roles.includes("security_admin")) return "https://admin.orlandmanagement.com";
  if(roles.includes("audit_admin")) return "https://admin.orlandmanagement.com";
  if(roles.includes("ops_admin")) return "https://admin.orlandmanagement.com";
  if(roles.includes("staff")) return "https://admin.orlandmanagement.com";
  if(roles.includes("client")) return "https://client.orlandmanagement.com";
  if(roles.includes("talent")) return "https://talent.orlandmanagement.com";
  return "https://sso.orlandmanagement.com/app/pages/sso/access-denied.html?reason=no_portal";
}

function portalRoles(roles){
  const list = [];
  if(roles.includes("super_admin") || roles.includes("admin") || roles.includes("security_admin") || roles.includes("audit_admin") || roles.includes("ops_admin") || roles.includes("staff")){
    list.push("admin");
  }
  if(roles.includes("client")) list.push("client");
  if(roles.includes("talent")) list.push("talent");
  return list;
}

export async function onRequestGet({ request, env }){
  const auth = await requireSession(env, request);

  if(!auth.ok){
    return jsonUnauthorized("session_not_found");
  }

  const portals = portalRoles(auth.roles);

  if(portals.length > 1){
    return jsonOk({
      redirect: "https://sso.orlandmanagement.com/app/pages/sso/choose-role.html",
      roles: auth.roles,
      user: auth.user
    });
  }

  const target = resolveDomain(auth.roles);

  return jsonOk({
    redirect: target,
    roles: auth.roles,
    user: auth.user
  });
}
