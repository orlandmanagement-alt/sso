const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*", // Sementara star untuk debug, nanti ganti Origin spesifik
  "Access-Control-Allow-Methods": "GET, HEAD, POST, OPTIONS, PUT, DELETE",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, Cookie",
  "Access-Control-Allow-Credentials": "true", // WAJIB TRUE agar cookie mau dikirim
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
export const jsonInvalid = (msg) => json({ ok: false, message: msg || "Data tidak valid" }, 400);
export const jsonUnauthorized = (msg) => json({ ok: false, message: msg || "Silakan login kembali" }, 401);
export const jsonForbidden = (msg) => json({ ok: false, message: msg || "Akses ditolak" }, 403);
export const jsonError = (msg) => json({ ok: false, message: msg || "Server error" }, 500);
