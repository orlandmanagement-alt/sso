export function cookie(name, value, opt = {}){
  const parts = [`${name}=${value}`];
  parts.push(`Path=${opt.path || "/"}`);
  if(opt.domain) parts.push(`Domain=${opt.domain}`);
  if(opt.maxAge != null) parts.push(`Max-Age=${Math.floor(opt.maxAge)}`);
  if(opt.httpOnly !== false) parts.push("HttpOnly");
  if(opt.secure !== false) parts.push("Secure");
  parts.push(`SameSite=${opt.sameSite || "Lax"}`);
  return parts.join("; ");
}

export function parseCookies(request){
  const raw = request.headers.get("cookie") || "";
  const out = {};
  raw.split(";").map(x => x.trim()).filter(Boolean).forEach(part => {
    const i = part.indexOf("=");
    if(i > 0) out[part.slice(0, i)] = part.slice(i + 1);
  });
  return out;
}

export function inferCookieDomain(request, env){
  if(env.COOKIE_DOMAIN) return env.COOKIE_DOMAIN;
  try{
    const host = new URL(request.url).hostname;
    if(host === "orlandmanagement.com" || host.endsWith(".orlandmanagement.com")){
      return ".orlandmanagement.com";
    }
  }catch{}
  return undefined;
}
