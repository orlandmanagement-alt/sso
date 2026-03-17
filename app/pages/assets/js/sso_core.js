const API_BASE = "https://sso.orlandmanagement.com/api";

function qs(id){
  return document.getElementById(id);
}

function showMsg(msg){
  const el = qs("msg");
  if(el) el.innerText = msg;
}

async function parseJsonSafe(res){
  const text = await res.text();
  try{
    return JSON.parse(text);
  }catch{
    return {
      status: "error",
      data: {
        message: "invalid_server_response",
        status_code: res.status,
        raw: text
      }
    };
  }
}
