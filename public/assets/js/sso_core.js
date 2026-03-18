import { CONFIG } from "./sso_config.js";

export async function apiCall(endpoint, payload) {
  try {
    const res = await fetch(`${CONFIG.apiBaseUrl}/${endpoint}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      credentials: 'omit' // Cloudflare Pages di domain yang sama otomatis akan menyertakan/menyimpan cookie HttpOnly
    });
    return await res.json();
  } catch (error) {
    return { status: "error", message: "Gagal terhubung ke server." };
  }
}

export function showToast(message, type = 'success') {
  const container = document.getElementById('toast-container');
  if(!container) return;
  const toast = document.createElement('div');
  const icon = type === 'success' ? '<i class="fa-solid fa-circle-check text-green-500 text-2xl"></i>' : '<i class="fa-solid fa-circle-exclamation text-red-500 text-2xl"></i>';
  toast.className = 'toast flex items-center w-80';
  toast.innerHTML = `${icon}<div class="text-sm font-medium text-gray-700 leading-snug">${message}</div>`;
  container.appendChild(toast);
  requestAnimationFrame(() => setTimeout(() => toast.classList.add('show'), 10));
  setTimeout(() => { toast.classList.remove('show'); setTimeout(() => toast.remove(), 300); }, 4000);
}
