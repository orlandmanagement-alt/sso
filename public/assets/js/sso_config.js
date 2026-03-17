export const SSO_CONFIG = {
  apiBaseUrl: "",
  defaultPortalUrls: {
    dashboard: "https://dashboard.orlandmanagement.com",
    talent: "https://talent.orlandmanagement.com",
    client: "https://client.orlandmanagement.com"
  },
  deniedUrl: "https://sso.orlandmanagement.com/access-denied.html"
};

export function ssoApiUrl(path){
  const clean = String(path || "").startsWith("/") ? String(path) : `/${String(path || "")}`;
  return clean;
}
