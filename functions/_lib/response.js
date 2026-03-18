export const jsonOk = (data, cookieHeader = null) => {
  const headers = { "Content-Type": "application/json" };
  if (cookieHeader) headers["Set-Cookie"] = cookieHeader;
  return new Response(JSON.stringify({ status: "ok", ...data }), { status: 200, headers });
};

export const jsonError = (msg, code = 400) => 
  new Response(JSON.stringify({ status: "error", message: msg }), { status: code, headers: { "Content-Type": "application/json" } });

export const redirect = (url, cookieHeader = null) => {
  const headers = { "Location": url };
  if (cookieHeader) headers["Set-Cookie"] = cookieHeader;
  return new Response(null, { status: 302, headers });
};
