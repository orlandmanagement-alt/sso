import { jsonOk } from "../../_lib/response.js";

export async function onRequestPost() {
  // Fitur ini telah dilebur ke dalam arsitektur baru.
  // Mengembalikan response OK agar cron/internal fetch tidak error.
  return jsonOk({ message: "Sync bypassed (Legacy)" });
}

export async function onRequestGet() {
  return jsonOk({ message: "Sync bypassed (Legacy)" });
}
