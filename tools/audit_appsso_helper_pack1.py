from pathlib import Path
import json

root = Path(".")
helper_dir = root / "functions/api/auth/_helper"

expected = [
    "auth_queries.js",
    "auth_service.js",
    "auth_validator.js",
    "auth_session.js",
    "auth_stepup.js",
    "auth_redirect.js",
]

existing = sorted([p.name for p in helper_dir.glob("*.js")]) if helper_dir.exists() else []
missing = [x for x in expected if x not in existing]

report = {
    "helper_dir_exists": helper_dir.exists(),
    "expected_count": len(expected),
    "existing_count": len(existing),
    "missing_count": len(missing),
    "missing": missing
}

(root / "tools/appsso_helper_pack1_audit.json").write_text(json.dumps(report, indent=2))

lines = []
lines.append("[SUMMARY]")
lines.append(f"helper_dir_exists: {report['helper_dir_exists']}")
lines.append(f"expected_count: {report['expected_count']}")
lines.append(f"existing_count: {report['existing_count']}")
lines.append(f"missing_count: {report['missing_count']}")
lines.append("")
lines.append("[MISSING]")
if missing:
  for x in missing:
    lines.append(f"- {x}")
else:
  lines.append("- none")

(root / "tools/appsso_helper_pack1_audit.txt").write_text("\n".join(lines))
print("[OK] wrote tools/appsso_helper_pack1_audit.txt")
