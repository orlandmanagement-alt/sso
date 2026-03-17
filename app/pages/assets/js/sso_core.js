const API_BASE = "https://sso.orlandmanagement.com/functions/api";

function qs(id){
  return document.getElementById(id);
}

function showMsg(msg){
  const el = qs("msg");
  if(el) el.innerText = msg;
}
