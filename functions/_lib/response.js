const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, HEAD, POST, OPTIONS, PUT, DELETE",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, Cookie",
  "Access-Control-Allow-Credentials": "true",
};
export const json = (data, status = 200, extraHeaders = {}) => {
  return new Response(JSON.stringify(data), { 
    status, 
    headers: { ...CORS_HEADERS, "Content-Type": "application/json;charset=UTF-8", ...extraHeaders } 
  });
};
export const jsonOk = (data, cookie) => {
    const h = cookie ? { "Set-Cookie": cookie } : {};
    return json(data, 200, h);
};
export const jsonError = (msg, status=400) => json({ status: "error", message: msg || "Server error" }, status);
export const redirect = (url) => new Response(null, { status: 302, headers: { "Location": url } });
