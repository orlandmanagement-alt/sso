import { onRevokeSession } from "../../services/auth/session_service.js";

export async function onRequestPost({ request, env }){
  return onRevokeSession({ request, env });
}
