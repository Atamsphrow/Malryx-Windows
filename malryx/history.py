"""Historique des détections et rapports d'analyse."""
import json
from datetime import datetime

from .paths import data_dir

HIST = data_dir("historique.jsonl")
REPORTS = data_dir("rapports")


def add(source, result, action):
    entry = {"date": datetime.now().isoformat(timespec="seconds"), "source": source,
             "threat": result.get("threat") or result.get("verdict"), "verdict": result.get("verdict"),
             "path": result.get("package") or result.get("path"), "sha256": result.get("sha256"),
             "action": action, "reasons": result.get("reasons", [])[:6]}
    with open(HIST, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return entry


def entries(limit=2000):
    if not HIST.exists():
        return []
    out = []
    for line in HIST.read_text(encoding="utf-8", errors="ignore").splitlines()[-limit:]:
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return list(reversed(out))


def clear():
    HIST.write_text("", encoding="utf-8")


def save_report(summary, results, stages=None):
    rep = {"date": datetime.now().isoformat(timespec="seconds"), "summary": summary, "stages": stages or [],
           "detections": results}
    p = REPORTS / f"analyse_{datetime.now():%Y%m%d_%H%M%S}.json"
    p.write_text(json.dumps(rep, indent=2, ensure_ascii=False), encoding="utf-8")
    return p


def reports():
    out = []
    for p in sorted(REPORTS.glob("analyse_*.json"), reverse=True)[:200]:
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
            d["file"] = str(p)
            out.append(d)
        except ValueError:
            continue
    return out
