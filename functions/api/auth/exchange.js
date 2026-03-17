import { onExchange } from "../../services/auth/stepup_service.js";

export async function onRequestPost({ request, env }){
  return onExchange({ request, env });
}
