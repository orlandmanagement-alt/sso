import { onRefresh } from "../../services/auth/session_service.js";

export async function onRequestPost({ request, env }){
  return onRefresh({ request, env });
}
