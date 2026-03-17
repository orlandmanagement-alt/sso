export function json(status, payload) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store"
    }
  });
}

export function jsonOk(data = {}) {
  return json(200, { status: "ok", data });
}

export function jsonInvalid(message = "invalid_input", data = null) {
  return json(400, {
    status: "invalid_input",
    data: data ?? { message }
  });
}

export function jsonUnauthorized(message = "unauthorized", data = null) {
  return json(401, {
    status: "unauthorized",
    data: data ?? { message }
  });
}

export function jsonForbidden(message = "forbidden", data = null) {
  return json(403, {
    status: "forbidden",
    data: data ?? { message }
  });
}

export function jsonError(message = "server_error", data = null) {
  return json(500, {
    status: "error",
    data: data ?? { message }
  });
}
