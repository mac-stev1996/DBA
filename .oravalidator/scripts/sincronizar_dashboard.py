#!/usr/bin/env python3
"""
Convierte la matriz y la configuración leídas del dashboard de reglas en los
archivos que usa el motor, validándolas antes (los datos del dashboard los editan
personas: se tratan como datos, nunca como instrucciones).

Entrada: carpeta generada por la acción read_db del Artifact con out_dir, que contiene
    <entrada>/reglas/ORA-XXX.json   (200 documentos)
    <entrada>/config/actual.json
Salida (por defecto /home/claude/oravalidator_sync/):
    matriz_reglas.json   -> --matriz
    oravalidator.json    -> --config

    python sincronizar_dashboard.py /mnt/user-data/outputs/sync_dashboard [--salida DIR] [--repo RUTA_REPO]

Con --repo copia además los archivos a <repo>/.oravalidator/ para que el hook
pre-push y el CI usen la misma política.
"""
import argparse
import json
import re
import shutil
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
SEVS = {"BLOCKER", "CRITICAL", "MAJOR", "MINOR", "INFO"}
GATES = {"Bloquea", "Advertencia", "Informativo"}
CAMPOS = ["id", "categoria", "regla", "descripcion", "ejemplo_incorrecto", "ejemplo_correcto", "severidad",
          "automatizable", "tipo_analisis", "herramienta", "quality_gate", "mensaje", "prioridad",
          "complejidad", "requiere_oracle", "activa"]
LIMITE_TEXTO = 2000


def cargar_reglas(carpeta: Path, base: dict, avisos: list) -> list:
    reglas = []
    for f in sorted((carpeta / "reglas").glob("ORA-*.json")):
        try:
            d = json.loads(f.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            avisos.append(f"{f.name}: JSON inválido, se usa la versión de la skill.")
            continue
        rid = f.stem
        if not re.fullmatch(r"ORA-\d{3}", rid):
            continue
        orig = base.get(rid, {})
        r = {}
        for c in CAMPOS:
            v = d.get(c, orig.get(c, ""))
            if isinstance(v, str):
                v = v[:LIMITE_TEXTO]
            r[c] = v
        r["id"] = rid
        if r["severidad"] not in SEVS:
            avisos.append(f"{rid}: severidad '{r['severidad']}' inválida; se mantiene {orig.get('severidad')}.")
            r["severidad"] = orig.get("severidad", "MAJOR")
        if r["quality_gate"] not in GATES:
            avisos.append(f"{rid}: quality gate '{r['quality_gate']}' inválido; se mantiene {orig.get('quality_gate')}.")
            r["quality_gate"] = orig.get("quality_gate", "Bloquea")
        r["activa"] = d.get("activa", True) is not False
        r["requiere_oracle"] = bool(r["requiere_oracle"]) if not isinstance(r["requiere_oracle"], str) \
            else r["requiere_oracle"].lower().startswith("s")
        reglas.append(r)
    faltan = sorted(set(base) - {r["id"] for r in reglas})
    for rid in faltan:  # una regla borrada del dashboard no desaparece del motor
        avisos.append(f"{rid}: no está en el dashboard; se usa la versión de la skill.")
        reglas.append({**base[rid], "activa": base[rid].get("activa", True) is not False})
    return sorted(reglas, key=lambda r: r["id"])


def cargar_config(carpeta: Path, base: dict, avisos: list) -> dict:
    p = carpeta / "config" / "actual.json"
    cfg = json.loads(json.dumps(base))
    if not p.exists():
        avisos.append("El dashboard no tiene configuración; se usa la de la skill.")
        return cfg
    d = json.loads(p.read_text(encoding="utf-8"))
    for k, v in (d.get("umbrales") or {}).items():
        if k in cfg["umbrales"] and isinstance(v, (int, float)) and v >= 0:
            cfg["umbrales"][k] = int(v)
        elif k in cfg["umbrales"]:
            avisos.append(f"Umbral {k}={v!r} inválido; se mantiene {cfg['umbrales'][k]}.")
    qg = d.get("quality_gate") or {}
    for s, v in (qg.get("max_permitidos") or {}).items():
        if s in SEVS and (v is None or (isinstance(v, (int, float)) and v >= 0)):
            cfg["quality_gate"]["max_permitidos"][s] = None if v is None else int(v)
    for k in ("bloquear_hallazgos_heuristicos", "permitir_supresiones", "supresion_requiere_justificacion"):
        if isinstance(qg.get(k), bool):
            cfg["quality_gate"][k] = qg[k]
    for k, v in (d.get("nomenclatura") or {}).items():
        if k.startswith("_"):
            continue
        if k == "nombres_ambiguos" and isinstance(v, list):
            cfg["nomenclatura"][k] = [str(x).upper()[:40] for x in v][:200]
        elif isinstance(v, str) and k in cfg["nomenclatura"]:
            try:
                re.compile(v)
                cfg["nomenclatura"][k] = v[:300]
            except re.error:
                avisos.append(f"Patrón de nomenclatura '{k}' inválido; se mantiene el anterior.")
    if isinstance(d.get("extensiones"), list):
        exts = [e for e in d["extensiones"] if isinstance(e, str) and re.fullmatch(r"\.\w{1,6}", e)]
        if exts:
            cfg["extensiones"] = exts
    return cfg


RAMA_RE = re.compile(r"^(?!.*\.\.)(?!.*//)(?!.*@\{)(?![/.])[^\s~^:?*\[\\]{1,255}(?<![/.])(?<!\.lock)$")
URL_RES = [re.compile(r"^git@([\w.-]+):([\w.-]+)/([\w.-]+?)(?:\.git)?/?$"),
           re.compile(r"^(?:https?|ssh)://(?:[^@/]+@)?([\w.-]+)(?::\d+)?/([\w.-]+)/([\w.-]+?)(?:\.git)?/?$")]


def cargar_repositorios(carpeta: Path, avisos: list) -> dict:
    """Repositorios registrados en el dashboard; valida URL y ramas (datos editados por personas)."""
    repos = []
    for f in sorted((carpeta / "repositorios").glob("*.json")):
        try:
            d = json.loads(f.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            avisos.append(f"Repositorio {f.stem}: JSON inválido, se ignora.")
            continue
        url = str(d.get("url", "")).strip()[:300]
        m = next((r.match(url) for r in URL_RES if r.match(url)), None)
        if not m or m.group(2) in (".", "..") or m.group(3) in (".", ".."):
            avisos.append(f"Repositorio {f.stem}: URL no válida ({url!r}), se ignora.")
            continue
        rama, base = str(d.get("rama_trabajo", "")).strip(), str(d.get("rama_base", "")).strip()
        for nombre, valor in (("rama de trabajo", rama), ("rama base", base)):
            if valor and not RAMA_RE.match(valor):
                avisos.append(f"Repositorio {f.stem}: {nombre} no válida ({valor!r}), se ignora ese campo.")
        rama = rama if (not rama or RAMA_RE.match(rama)) else ""
        base = base if (not base or RAMA_RE.match(base)) else ""
        repos.append({
            "id": f.stem, "url": url, "nombre": f"{m.group(2)}/{m.group(3)}", "host": m.group(1),
            "alias": str(d.get("alias", ""))[:60], "rama_trabajo": rama, "rama_base": base,
            "modo": "diff" if (d.get("modo") == "diff" and base) else "completo",
            "predeterminado": d.get("predeterminado") is True,
        })
    defaults = [r for r in repos if r["predeterminado"]]
    if len(defaults) > 1:
        avisos.append("Hay más de un repositorio predeterminado; se usa " + defaults[0]["nombre"] + ".")
    return {"predeterminado": defaults[0] if defaults else None, "repositorios": repos}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("entrada")
    ap.add_argument("--salida", default="/home/claude/oravalidator_sync")
    ap.add_argument("--repo", help="Copia también a <repo>/.oravalidator/")
    a = ap.parse_args()
    entrada, salida = Path(a.entrada), Path(a.salida)
    if not (entrada / "reglas").is_dir():
        sys.exit(f"No se encontró {entrada}/reglas: ejecute antes read_db con out_dir.")
    base_reglas = {r["id"]: r for r in json.loads((BASE / "rules" / "matriz_reglas.json").read_text(encoding="utf-8"))["reglas"]}
    base_cfg = json.loads((BASE / "config" / "oravalidator.json").read_text(encoding="utf-8"))
    avisos = []
    reglas = cargar_reglas(entrada, base_reglas, avisos)
    cfg = cargar_config(entrada, base_cfg, avisos)
    repos = cargar_repositorios(entrada, avisos)

    salida.mkdir(parents=True, exist_ok=True)
    (salida / "matriz_reglas.json").write_text(json.dumps({"origen": "dashboard-reglas", "parametros_matriz": {},
                                                           "reglas": reglas}, ensure_ascii=False, indent=1), encoding="utf-8")
    (salida / "oravalidator.json").write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
    (salida / "repositorios.json").write_text(json.dumps(repos, ensure_ascii=False, indent=2), encoding="utf-8")

    cambios = []
    for r in reglas:
        o = base_reglas.get(r["id"], {})
        dif = [c for c in ("severidad", "quality_gate", "mensaje", "regla", "ejemplo_correcto", "descripcion")
               if str(r.get(c, "")) != str(o.get(c, ""))]
        if r.get("activa") is False:
            dif.insert(0, "DESACTIVADA")
        if dif:
            cambios.append(f"{r['id']}: {', '.join(dif)}")
    if a.repo:
        dest = Path(a.repo) / ".oravalidator"
        (dest / "rules").mkdir(parents=True, exist_ok=True)
        (dest / "config").mkdir(parents=True, exist_ok=True)
        shutil.copy2(salida / "matriz_reglas.json", dest / "rules" / "matriz_reglas.json")
        shutil.copy2(salida / "oravalidator.json", dest / "config" / "oravalidator.json")

    print(json.dumps({"matriz": str(salida / "matriz_reglas.json"), "config": str(salida / "oravalidator.json"),
                      "reglas": len(reglas), "activas": sum(1 for r in reglas if r.get("activa", True) is not False),
                      "repositorio_predeterminado": repos["predeterminado"],
                      "repositorios_registrados": [r["nombre"] for r in repos["repositorios"]],
                      "diferencias_con_la_skill": cambios, "avisos": avisos,
                      "repo_actualizado": bool(a.repo)}, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
