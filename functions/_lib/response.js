export function json(data, init = {}) {
  return new Response(JSON.stringify(data), {
    status: init.status || 200,
    headers: { "Content-Type": "application/json", ...(init.headers || {}) }
  });
}
export const jsonOk = (data, init) => json({ status: "ok", ...data }, { status: 200, ...init });
export const jsonInvalid = (data, init) => json({ status: "error", ...data }, { status: 400, ...init });
export const jsonUnauthorized = (data, init) => json({ status: "error", ...data }, { status: 401, ...init });
export const jsonForbidden = (data, init) => json({ status: "error", ...data }, { status: 403, ...init });
export const jsonNotFound = (data, init) => json({ status: "error", ...data }, { status: 404, ...init });
export const jsonConflict = (data, init) => json({ status: "error", ...data }, { status: 409, ...init });
export const jsonError = (data, init) => json({ status: "error", ...data }, { status: 500, ...init });
