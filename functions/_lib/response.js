export function json(status, st, data = null, extraHeaders = {}){
  return new Response(JSON.stringify({ status: st, data }, null, 0), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...extraHeaders
    }
  });
}

export function jsonOk(data = null, headers = {}){
  return json(200, "ok", data, headers);
}

export function jsonInvalid(data = null){
  return json(400, "invalid_input", data);
}

export function jsonUnauthorized(data = null){
  return json(401, "unauthorized", data);
}

export function jsonForbidden(data = null){
  return json(403, "forbidden", data);
}

export function jsonNotFound(data = null){
  return json(404, "not_found", data);
}

export function jsonError(data = null){
  return json(500, "server_error", data);
}
