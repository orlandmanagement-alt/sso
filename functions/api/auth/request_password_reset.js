import { readJson } from "../../_lib/validate.js";
import { requestPasswordResetService } from "../../services/auth/auth_reset_service.js";

export async function onRequestPost({ request, env }){
  const body = await readJson(request) || {};
  return await requestPasswordResetService({ env, body });
}
