export function portalAccessFromRoles(roles = []){
  const set = new Set((roles || []).map(x => String(x)));
  return {
    dashboard: set.has("super_admin") || set.has("admin") || set.has("staff"),
    talent: set.has("super_admin") || set.has("admin") || set.has("staff") || set.has("talent"),
    client: set.has("super_admin") || set.has("admin") || set.has("staff") || set.has("client")
  };
}

export function defaultPortalFromRoles(roles = []){
  const p = portalAccessFromRoles(roles);
  if(p.dashboard) return "dashboard";
  if(p.client) return "client";
  if(p.talent) return "talent";
  return "dashboard";
}

export function safeNextPath(nextPath, fallback = "/"){
  const s = String(nextPath || "").trim();
  if(!s.startsWith("/") || s.startsWith("//")) return fallback;
  return s;
}

export function portalBaseUrl(env, portal){
  if(portal === "dashboard") return env.DASHBOARD_URL || "https://dashboard.orlandmanagement.com";
  if(portal === "client") return env.CLIENT_URL || "https://client.orlandmanagement.com";
  if(portal === "talent") return env.TALENT_URL || "https://talent.orlandmanagement.com";
  return env.DASHBOARD_URL || "https://dashboard.orlandmanagement.com";
}

export function portalRedirectUrl(env, portal, nextPath = "/"){
  return `${portalBaseUrl(env, portal)}${safeNextPath(nextPath, "/")}`;
}
