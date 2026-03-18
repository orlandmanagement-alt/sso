import { loginPasswordService } from "../../services/auth/auth_login_service.js";
export async function onRequestPost(context){
  const clone = await context.request.clone();
  const body = await clone.json().catch(()=>({}));
  body.email = body.identifier; // Adaptasi format lama
  body.password = body.pin;     // PIN dibaca sebagai password
  context.body = body;
  return loginPasswordService(context);
}
