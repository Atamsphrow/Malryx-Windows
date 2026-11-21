"""« Analyser mon PC » : un seul passage qui regroupe menaces, sécurité, espace, performances et
confidentialité, et ne compte que des problèmes réels, chacun avec sa correction."""
from datetime import datetime

from . import audit, cleaner, performance, privacy, winsys
from .engine import MALWARE, SUSPECT

CATEGORIES = ["Sécurité", "Performances", "Espace disque", "Confidentialité"]


def problem(cat, title, detail, severity, fix=None, auto=False, data=None, gain=None):
    return {"category": cat, "title": title, "detail": detail, "severity": severity, "fix": fix,
            "auto": auto, "data": data, "gain": gain}


def run(app, progress=lambda step, i, n: None, cancel=lambda: False):
    """Retourne la liste des problèmes. `app` donne accès au moteur, réglages, ClamAV, etc."""
    s = app.settings
    problems = []
    steps = ["Menaces", "Sécurité de Windows", "Fichiers inutiles", "Navigation", "Télémétrie",
             "Logiciels obsolètes", "Démarrage", "Applications gourmandes", "Santé du système"]
    n = len(steps)

    # 1. menaces (rapide : processus, démarrage, registre)
    progress(steps[0], 0, n)
    threats = []
    for exe in list(winsys.running_executables().keys()):
        if cancel():
            return problems
        r = app.engine.scan_file(exe)
        if r["verdict"] in (MALWARE, SUSPECT):
            threats.append(r)
    for it in winsys.all_startup_items(include_tasks=False):
        if it.get("exe"):
            import os
            if os.path.exists(it["exe"]):
                r = app.engine.scan_file(it["exe"])
                if r["verdict"] in (MALWARE, SUSPECT) and r not in threats:
                    threats.append(r)
    for f in winsys.registry_findings():
        threats.append({"path": f"{f['hive']}\\{f['key']}\\{f['value']}", "verdict": SUSPECT, "registry": f,
                        "threat": "Détournement du registre", "reasons": [f["reason"]], "sha256": None})
    bad = [t for t in threats if t["verdict"] == MALWARE]
    if bad:
        problems.append(problem("Sécurité", f"{len(bad)} menace(s) active(s)", "Programmes malveillants en mémoire ou au démarrage",
                                "bad", "threats", True, bad))
    sus = [t for t in threats if t["verdict"] == SUSPECT]
    if sus:
        problems.append(problem("Sécurité", f"{len(sus)} élément(s) suspect(s)", "À vérifier : " + ", ".join(
            (t.get("path") or "")[-40:] for t in sus[:2]), "warn", "review_threats", False, sus))
    if not s["realtime"]:
        problems.append(problem("Sécurité", "Protection en temps réel désactivée", "Votre PC n'est pas surveillé",
                                "bad", "realtime", True))

    # 2. audit de sécurité Windows
    progress(steps[1], 1, n)
    try:
        for c in audit.run(None, None):
            if c["status"] != "ok" and c["name"] not in ("Détournements du registre",):
                problems.append(problem("Sécurité", c["name"], c["detail"], c["status"], "audit", False, c))
    except Exception:
        pass

    # 3. fichiers inutiles
    progress(steps[2], 2, n)
    junk = [c for c in cleaner.analyse(deep=True) if c["size"] > 0 and "Windows Update" not in c["name"]]
    total = sum(c["size"] for c in junk)
    if total > 100e6:
        problems.append(problem("Espace disque", f"{cleaner.human(total)} de fichiers inutiles",
                                ", ".join(c["name"] for c in sorted(junk, key=lambda c: -c["size"])[:3]),
                                "warn" if total < 5e9 else "bad", "junk", True, [c["name"] for c in junk], total))

    # 4. traces de navigation
    progress(steps[3], 3, n)
    kinds = ["Historique", "Cache", "Sessions"] + (["Cookies"] if s["traces_cookies"] else [])
    traces = []
    for b in privacy.browser_traces():
        size = sum(v for k, v in b["items"].items() if k in kinds)
        if size > 20e6:
            traces.append((b["browser"], size, b["running"]))
    if traces:
        tot = sum(t[1] for t in traces)
        problems.append(problem("Confidentialité", f"Traces de navigation ({cleaner.human(tot)})",
                                ", ".join(t[0] for t in traces) + (" · fermez les navigateurs ouverts" if any(t[2] for t in traces) else ""),
                                "warn", "traces", True, {"browsers": [t[0] for t in traces], "kinds": kinds}, tot))

    # 5. télémétrie
    progress(steps[4], 4, n)
    todo = [t for t in privacy.tweak_states() if t["available"] and not t["applied"] and (winsys.is_admin() or not t["admin"])]
    if todo:
        problems.append(problem("Confidentialité", f"{len(todo)} réglage(s) de télémétrie et publicité actifs",
                                ", ".join(t["title"] for t in todo[:3]), "warn", "telemetry", True, [t["id"] for t in todo]))

    # 6. logiciels obsolètes
    progress(steps[5], 5, n)
    try:
        apps = performance.outdated_software() or []
    except Exception:
        apps = []
    crit = [a for a in apps if a["priority"] == "Sécurité"]
    if crit:
        problems.append(problem("Sécurité", f"{len(crit)} logiciel(s) vulnérable(s) à mettre à jour",
                                ", ".join(a["name"] for a in crit[:3]), "bad", "updates", True, crit))
    other = [a for a in apps if a["priority"] != "Sécurité"]
    if other:
        problems.append(problem("Performances", f"{len(other)} autre(s) logiciel(s) obsolète(s)",
                                ", ".join(a["name"] for a in other[:3]), "warn", "updates", True, other))

    # 7. démarrage
    progress(steps[6], 6, n)
    items = performance.startup_impact([i for i in winsys.all_startup_items(include_tasks=False) if not i.get("disabled")])
    heavy = [i for i in items if i["impact"] == "Élevé"]
    if len(items) > 8 or heavy:
        problems.append(problem("Performances", f"{len(items)} programmes au démarrage ({len(heavy)} à fort impact)",
                                ", ".join(i["name"] for i in heavy[:3]) or "Démarrage chargé", "warn", "startup", False, heavy))

    # 8. applications gourmandes inactives
    progress(steps[7], 7, n)
    cands = app.sleep_mgr.candidates() if getattr(app, "sleep_mgr", None) else []
    big = [c for c in cands if c["mem"] > 400e6]
    if big:
        mem = sum(c["mem"] for c in big)
        problems.append(problem("Performances", f"{len(big)} application(s) gourmande(s) en arrière-plan",
                                f"{cleaner.human(mem)} de mémoire vive : " + ", ".join(c["name"] for c in big[:3]),
                                "warn", "sleep", False, big))

    # 9. santé
    progress(steps[8], 8, n)
    h = performance.health()
    for sev, msg in h["alerts"]:
        problems.append(problem("Performances" if "disque" not in msg.lower() or "plein" not in msg.lower() else "Espace disque",
                                msg.split(":")[0], msg, sev, "health", False))
    progress("Terminé", n, n)
    s["pcscan"] = {"last": datetime.now().isoformat(timespec="minutes"), "problems": len(problems)}
    order = {"bad": 0, "warn": 1}
    return sorted(problems, key=lambda p: (CATEGORIES.index(p["category"]), order.get(p["severity"], 2)))


def fix(app, p, progress=lambda m: None):
    """Corrige automatiquement un problème. Renvoie un texte de résultat."""
    from . import history, quarantine
    k = p["fix"]
    if k == "threats":
        n = 0
        for t in p["data"]:
            try:
                if t.get("registry"):
                    winsys.fix_registry(t["registry"])
                else:
                    winsys.kill_process(t["path"])
                    quarantine.quarantine(t["path"], t)
                history.add("Analyse du PC", t, "neutralisé"); n += 1
            except OSError:
                continue
        return f"{n} menace(s) neutralisée(s)"
    if k == "junk":
        freed = cleaner.clean(p["data"], progress)
        return f"{cleaner.human(freed)} libérés"
    if k == "traces":
        freed, skipped = 0, []
        for b in p["data"]["browsers"]:
            try:
                freed += privacy.clean_browser(b, p["data"]["kinds"])
            except RuntimeError:
                skipped.append(b)
        return f"{cleaner.human(freed)} de traces effacées" + (f" · fermez {', '.join(skipped)} et recommencez" if skipped else "")
    if k == "telemetry":
        n = 0
        for tid in p["data"]:
            try:
                privacy.apply_tweak(tid, True); n += 1
            except OSError:
                continue
        return f"{n} réglage(s) appliqué(s)"
    if k == "updates":
        ok = 0
        for a in p["data"]:
            progress(f"Mise à jour de {a['name']}…")
            if performance.update_software(a["id"])[0]:
                ok += 1
        return f"{ok}/{len(p['data'])} logiciel(s) mis à jour"
    return ""
