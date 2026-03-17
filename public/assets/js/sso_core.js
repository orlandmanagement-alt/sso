import { ssoApiUrl } from "./sso_config.js";

export function getQueryParam(name, fallback = ""){
  const url = new URL(location.href);
  return url.searchParams.get(name) || fallback;
}

export function setNotice(message, type = ""){
  const el = document.getElementById("notice");
  if(!el) return;
  el.className = `notice ${type}`.trim();
  el.textContent = message || "";
}

export async function parseJsonSafe(res){
  const text = await res.text();
  try{
    return JSON.parse(text);
  }catch{
    return {
      status: "error",
      data: {
        message: "invalid_server_response",
        raw: text
      }
    };
  }
}

export async function postJson(path, body){
  const res = await fetch(ssoApiUrl(path), {
    method: "POST",
    credentials: "include",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body || {})
  });

  const json = await parseJsonSafe(res);
  return {
    ok: res.ok && json?.status === "ok",
    statusCode: res.status,
    status: json?.status || "error",
    data: json?.data || null,
    raw: json
  };
}
