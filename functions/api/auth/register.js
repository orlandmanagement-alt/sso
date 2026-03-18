import { readJson } from "../../_lib/validate.js";
import { registerService, verifyRegisterService } from "../../services/auth/auth_register_service.js";

export async function onRequestPost({ request, env }){
  const body = await readJson(request) || {};
  const mode = String(body.mode || "start").trim().toLowerCase();

  return mode === "verify"
    ? await verifyRegisterService({ env, body })
    : await registerService({ env, body });
}
