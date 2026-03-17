import { onMe } from "../../services/auth/session_service.js";

export async function onRequestGet({ request, env }){
  return onMe({ request, env });
}
