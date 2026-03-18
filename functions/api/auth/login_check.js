import { jsonOk, jsonNotFound, jsonInvalid } from "../../_lib/response.js";
import { findUserByEmail, findUserByWa } from "../../repos/users_repo.js";
import { normEmail } from "../../_lib/validate.js";

export async function onRequestPost({ request, env }){
  const body = await request.json().catch(()=>({}));
  const id = String(body.identifier||"").trim();
  if(!id) return jsonInvalid({message:"identifier_required"});
  const user = id.includes("@") ? await findUserByEmail(env, normEmail(id)) : await findUserByWa(env, id);
  if(!user?.id) return jsonNotFound({message:"user_not_found"});
  return jsonOk({exists: true});
}
