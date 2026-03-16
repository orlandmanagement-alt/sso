export function norm(value){
  return String(value || "").trim();
}

export function normLower(value){
  return norm(value).toLowerCase();
}

export function isEmail(value){
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(norm(value));
}

export function digitsOnly(value){
  return String(value || "").replace(/[^\d]/g, "");
}

export function normalizePhone(value){
  const raw = digitsOnly(value);
  if(raw.startsWith("62")) return raw;
  if(raw.startsWith("08")) return `62${raw.slice(1)}`;
  return raw;
}

export function isPhone(value){
  const v = normalizePhone(value);
  return v.startsWith("62") && v.length >= 10;
}

export function isOtpCode(value){
  return /^[0-9]{4,8}$/.test(norm(value));
}

export function safeJsonParse(raw, fallback = null){
  try{
    return JSON.parse(String(raw || ""));
  }catch{
    return fallback;
  }
}
