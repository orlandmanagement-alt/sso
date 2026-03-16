from pathlib import Path
import json

root = Path(".")
files = [
    "functions/api/auth/sessions.js",
    "functions/api/auth/revoke_session.js",
    "functions/api/auth/resolve_redirect.js",
]

checks = {}
for f in files:
    p = root / f
    checks[f] = {
        "exists": p.exists(),
        "size_ok": False
    }
    if p.exists():
        checks[f]["size_ok"] = len(p.read_text().strip()) > 40

(root / "tools/appsso_pack3_audit.json").write_text(json.dumps(checks, indent=2))

lines = []
lines.append("[SUMMARY]")
for k, v in checks.items():
    lines.append(f"{k}.exists: {v['exists']}")
    lines.append(f"{k}.size_ok: {v['size_ok']}")
    lines.append("")
(root / "tools/appsso_pack3_audit.txt").write_text("\n".join(lines))
print("[OK] wrote tools/appsso_pack3_audit.txt")
