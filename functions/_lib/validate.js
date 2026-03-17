export async function readJson(request){
  try{
    const ct = request.headers.get("content-type") || "";
    if(!ct.includes("application/json")) return null;
    return await request.json();
  }catch{
    return null;
  }
}

export function normEmail(email){
  return String(email || "").trim().toLowerCase();
}

export function safeNextPath(nextPath, fallback = "/"){
  const s = String(nextPath || "").trim();
  if(!s.startsWith("/") || s.startsWith("//")) return fallback;
  return s;
}

export function isOtpFormat(v){
  return /^\d{4,8}$/.test(String(v || "").trim());
}
