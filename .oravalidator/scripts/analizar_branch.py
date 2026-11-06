#!/usr/bin/env python3
"""
Analiza el código Oracle de un branch de git contra la matriz de reglas,
genera el reporte de novedades y aplica el quality gate.

Modos:
  1) Branch (remoto o local) — para revisiones y pipelines CI:
       python analizar_branch.py --repo https://git.empresa.com/equipo/bd.git --rama feature/x --base develop
       python analizar_branch.py --repo . --rama feature/x --base main --modo completo

  2) Hook pre-push — lo invoca .githooks/pre-push; git envía las referencias por stdin:
       python analizar_branch.py --pre-push

Códigos de salida:  0 = quality gate APROBADO · 1 = RECHAZADO (push bloqueado) · 2 = error de la herramienta

Credenciales: para repos HTTPS privados define GIT_TOKEN (y opcionalmente GIT_USER,
por defecto 'oauth2'; GitHub usa 'x-access-token', Bitbucket 'x-token-auth').
El token nunca se imprime ni se guarda en el reporte. Para SSH se usan las llaves del sistema.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import asdict
from pathlib import Path
from urllib.parse import urlparse, urlunparse

sys.path.insert(0, str(Path(__file__).resolve().parent))
import oravalidator as ov  # noqa: E402
import reporte  # noqa: E402

CERO = "0" * 40


class ErrorGit(Exception):
    pass


def git(args, cwd=None, check=True, input_=None) -> str:
    r = subprocess.run(["git", *args], cwd=cwd, capture_output=True, input=input_,
                       env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})
    if check and r.returncode != 0:
        msg = r.stderr.decode("utf-8", "replace")
        tok = os.environ.get("GIT_TOKEN")
        if tok:
            msg = msg.replace(tok, "***")
        raise ErrorGit(f"git {' '.join(a for a in args if 'oauth' not in a)}: {msg.strip()}")
    return r.stdout.decode("utf-8", "replace")


def git_bytes(args, cwd) -> bytes:
    r = subprocess.run(["git", *args], cwd=cwd, capture_output=True)
    if r.returncode != 0:
        raise ErrorGit(r.stderr.decode("utf-8", "replace"))
    return r.stdout


def url_con_token(url: str) -> str:
    tok = os.environ.get("GIT_TOKEN")
    if not tok or not url.startswith("http"):
        return url
    p = urlparse(url)
    user = os.environ.get("GIT_USER", "oauth2")
    return urlunparse(p._replace(netloc=f"{user}:{tok}@{p.hostname}" + (f":{p.port}" if p.port else "")))


def url_publica(url: str) -> str:
    p = urlparse(url)
    if p.scheme.startswith("http") and p.hostname:
        return urlunparse(p._replace(netloc=p.hostname + (f":{p.port}" if p.port else "")))
    return url


# ---------------------------------------------------------------------------
# Preparación del repositorio
# ---------------------------------------------------------------------------
def preparar_repo(repo: str, rama: str, base: str | None, trabajo: Path) -> Path:
    """Devuelve la ruta de un repo local con la rama y la base disponibles."""
    if os.path.isdir(repo):
        root = Path(git(["rev-parse", "--show-toplevel"], cwd=repo).strip())
        try:
            git(["fetch", "--quiet", "origin", rama] + ([base] if base else []), cwd=root)
        except ErrorGit:
            pass  # sin remoto o sin red: se usan las referencias locales
        return root
    destino = trabajo / "repo"
    print(f"[oravalidator] Clonando {url_publica(repo)} (rama {rama})…", file=sys.stderr)
    git(["clone", "--quiet", "--filter=blob:none", "--no-checkout", url_con_token(repo), str(destino)])
    refs = [f"+refs/heads/{rama}:refs/remotes/origin/{rama}"]
    if base:
        refs.append(f"+refs/heads/{base}:refs/remotes/origin/{base}")
    git(["fetch", "--quiet", "origin", *refs], cwd=destino)
    # el token no debe quedar en .git/config
    git(["remote", "set-url", "origin", url_publica(repo)], cwd=destino)
    return destino


def resolver(ref: str, root: Path) -> str:
    for cand in (ref, f"origin/{ref}", f"refs/remotes/origin/{ref}"):
        try:
            return git(["rev-parse", "--verify", "--quiet", f"{cand}^{{commit}}"], cwd=root).strip()
        except ErrorGit:
            continue
    raise ErrorGit(f"No se encontró la referencia '{ref}' en el repositorio.")


def rama_base_por_defecto(root: Path) -> str | None:
    try:
        head = git(["symbolic-ref", "--quiet", "refs/remotes/origin/HEAD"], cwd=root).strip()
        return head.split("/")[-1]
    except ErrorGit:
        pass
    for b in ("develop", "main", "master"):
        try:
            resolver(b, root)
            return b
        except ErrorGit:
            continue
    return None


def archivos_cambiados(root: Path, desde: str | None, hasta: str) -> list[str]:
    if desde:
        mb = git(["merge-base", desde, hasta], cwd=root, check=False).strip() or desde
        out = git(["diff", "--name-only", "--diff-filter=ACMR", "-z", mb, hasta], cwd=root)
    else:
        out = git(["ls-tree", "-r", "--name-only", "-z", hasta], cwd=root)
    return [f for f in out.split("\0") if f]


def lineas_cambiadas(root: Path, desde: str, hasta: str, rutas: list[str]) -> dict[str, set[int]]:
    mb = git(["merge-base", desde, hasta], cwd=root, check=False).strip() or desde
    res: dict[str, set[int]] = {}
    out = git(["diff", "-U0", "--no-color", mb, hasta, "--", *rutas], cwd=root) if rutas else ""
    actual = None
    for line in out.splitlines():
        if line.startswith("+++ "):
            actual = line[6:] if line.startswith("+++ b/") else None
            if actual:
                res.setdefault(actual, set())
        elif line.startswith("@@") and actual:
            m = re.search(r"\+(\d+)(?:,(\d+))?", line)
            ini, cnt = int(m.group(1)), int(m.group(2) or 1)
            res[actual].update(range(ini, ini + max(cnt, 1)))
    return res


def leer_en_commit(root: Path, commit: str, ruta: str) -> str:
    return ov.leer_texto(git_bytes(["show", f"{commit}:{ruta}"], root))


# ---------------------------------------------------------------------------
# Quality gate
# ---------------------------------------------------------------------------
def evaluar_gate(hallazgos: list, omitidos: dict, cfg: dict, motor: ov.Analizador) -> dict:
    qg = cfg["quality_gate"]
    maximos = qg["max_permitidos"]
    bloquear_heur = qg.get("bloquear_hallazgos_heuristicos", False)
    conteo = {s: 0 for s in ov.SEV_ORDER}
    for h in hallazgos:
        cuenta = (h.confianza == "alta" or bloquear_heur) and ov.regla_bloqueante(motor.reglas, h.regla)
        h.bloquea = False
        if cuenta and h.severidad in conteo:
            conteo[h.severidad] += 1
    # hallazgos omitidos por tope cuentan para el gate
    for k, n in omitidos.items():
        rid = k.split("::")[-1]
        sev = motor.reglas.get(rid, {}).get("severidad")
        if sev in conteo and ov.regla_activa(motor.reglas, rid) and ov.regla_bloqueante(motor.reglas, rid):
            conteo[sev] += n
    motivos = []
    for sev, mx in maximos.items():
        if mx is not None and conteo.get(sev, 0) > mx:
            motivos.append(f"{conteo[sev]} hallazgo(s) {sev} (máximo permitido {mx})")
            for h in hallazgos:
                if h.severidad == sev and (h.confianza == "alta" or bloquear_heur) and ov.regla_bloqueante(motor.reglas, h.regla):
                    h.bloquea = True
    return {"estado": "RECHAZADO" if motivos else "APROBADO", "motivos": motivos,
            "conteo_bloqueante": conteo, "politica": maximos,
            "bloquear_hallazgos_heuristicos": bloquear_heur}


# ---------------------------------------------------------------------------
# Ejecución
# ---------------------------------------------------------------------------
def ejecutar(root: Path, commit: str, base_commit: str | None, contexto: dict, args, cfg) -> int:
    motor = ov.Analizador(cfg, ov.cargar_reglas(args.matriz) if args.matriz else None)
    rutas = [r for r in archivos_cambiados(root, base_commit, commit) if ov.es_archivo_oracle(r, cfg)]
    contexto["archivos_en_alcance"] = len(rutas)
    archivos = {}
    for r in rutas:
        try:
            archivos[r] = leer_en_commit(root, commit, r)
        except ErrorGit:
            continue
    filtro = None
    if args.solo_lineas_cambiadas and base_commit:
        filtro = lineas_cambiadas(root, base_commit, commit, rutas)
    res = motor.analizar(archivos, filtro)
    hallazgos = res["hallazgos"]

    # Hallazgos adicionales (revisión semántica de Claude u otras herramientas)
    for extra in args.hallazgos_extra or []:
        for d in json.loads(Path(extra).read_text(encoding="utf-8")):
            h = ov.Hallazgo(d["regla"].replace("ORA-", ""), d["archivo"], int(d.get("linea", 1)), d["detalle"],
                            d.get("fragmento", ""), d.get("confianza", "media"), d.get("relacionadas", []),
                            origen=d.get("origen", "revision_claude"))
            motor._enriquecer(h)
            hallazgos.append(h)

    # Reglas que requieren Oracle (opcional)
    oracle_info = {"ejecutadas": False, "motivo": "Sin credenciales (ORA_USER/ORA_PASSWORD/ORA_DSN)."}
    if cfg.get("oracle", {}).get("habilitado_si_hay_credenciales") and all(
            os.environ.get(v) for v in ("ORA_USER", "ORA_PASSWORD", "ORA_DSN")):
        try:
            import oracle_metadata
            extra, oracle_info = oracle_metadata.ejecutar(archivos, cfg)
            for h in extra:
                motor._enriquecer(h)
            hallazgos += extra
        except Exception as ex:
            oracle_info = {"ejecutadas": False, "motivo": f"Error al consultar Oracle: {ex}"}

    # Casos de prueba seleccionados (categorías / reglas / severidad mínima)
    omitidos = res["omitidos"]
    sel = seleccion_casos(args, motor)
    if sel:
        hallazgos = [h for h in hallazgos if h.regla in sel["ids"]]
        omitidos = {k: v for k, v in omitidos.items() if f"ORA-{k.split('::')[-1]}" in sel["ids"]}
        contexto["casos_aplicados"] = sel["descripcion"]
        contexto["reglas_aplicadas"] = len(sel["ids"])

    hallazgos.sort(key=lambda h: (ov.SEV_ORDER.get(h.severidad, 9), h.archivo, h.linea))
    gate = evaluar_gate(hallazgos, omitidos, cfg, motor)
    cob = ov.cobertura(motor.reglas)
    cob["oracle_ejecutadas"] = oracle_info

    datos = {
        "herramienta": "oravalidator", "version": ov.VERSION,
        "fecha": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        "contexto": contexto, "quality_gate": gate, "cobertura": cob,
        "archivos": res["archivos"],
        "hallazgos": [asdict(h) for h in hallazgos],
        "suprimidos": [asdict(h) for h in res["suprimidos"]],
        "omitidos_por_tope": omitidos,
        "matriz": args.matriz or "rules/matriz_reglas.json",
        "reglas": {f"ORA-{k}": {"regla": v["regla"], "categoria": v["categoria"], "severidad": v["severidad"],
                               "activa": v.get("activa", True), "quality_gate": v.get("quality_gate", "")}
                   for k, v in motor.reglas.items()},
    }
    salida = Path(args.salida)
    salida.mkdir(parents=True, exist_ok=True)
    rutas_rep = reporte.generar(datos, salida)
    reporte.consola(datos, rutas_rep, sys.stderr)
    return 1 if gate["estado"] == "RECHAZADO" else 0


def _lista(valor) -> list[str]:
    if not valor:
        return []
    return [x.strip() for x in re.split(r"[,;]", valor) if x.strip() and x.strip().lower() not in ("todas", "todos", "all", "auto")]


def seleccion_casos(args, motor: ov.Analizador) -> dict | None:
    """Traduce --categorias / --reglas / --severidad-minima al conjunto de reglas a aplicar."""
    cats, reglas = _lista(args.categorias), _lista(args.reglas)
    sev_min = (args.severidad_minima or "").upper().strip()
    if sev_min in ("", "TODAS", "AUTO", "INFO"):
        sev_min = ""
    if not (cats or reglas or sev_min):
        return None
    validas = {r["categoria"].lower(): r["categoria"] for r in motor.reglas.values()}
    norm = {c.lower().replace("_", " ").replace("-", " "): c for c in validas}
    desconocidas = [c for c in cats if c.lower().replace("_", " ").replace("-", " ") not in norm]
    if desconocidas:
        raise ValueError(f"Categoría(s) no existentes en la matriz: {', '.join(desconocidas)}. "
                         f"Válidas: {', '.join(sorted(validas.values()))}")
    if sev_min and sev_min not in ov.SEV_ORDER:
        raise ValueError(f"Severidad mínima inválida: {sev_min}. Use una de {', '.join(ov.SEV_ORDER)}")
    cats_ok = {norm[c.lower().replace('_', ' ').replace('-', ' ')] for c in cats}
    ids_pedidos = {("ORA-" + re.sub(r"\D", "", r).zfill(3)) for r in reglas}
    ids = set()
    for k, r in motor.reglas.items():
        rid = f"ORA-{k}"
        if (cats_ok or ids_pedidos) and not (r["categoria"].lower() in cats_ok or rid in ids_pedidos):
            continue
        if sev_min and ov.SEV_ORDER[r["severidad"]] > ov.SEV_ORDER[sev_min]:
            continue
        ids.add(rid)
    partes = []
    if cats_ok:
        partes.append("categorías " + ", ".join(validas[c] for c in sorted(cats_ok)))
    if ids_pedidos:
        partes.append("reglas " + ", ".join(sorted(ids_pedidos)))
    if sev_min:
        partes.append(f"severidad ≥ {sev_min}")
    return {"ids": ids, "descripcion": " · ".join(partes) + f" ({len(ids)} reglas)"}


def modo_branch(args, cfg) -> int:
    with tempfile.TemporaryDirectory(prefix="oravalidator-") as tmp:
        root = preparar_repo(args.repo, args.rama, args.base, Path(tmp))
        commit = resolver(args.rama, root)
        base = args.base or (rama_base_por_defecto(root) if args.modo == "diff" else None)
        base_commit = resolver(base, root) if (base and args.modo == "diff") else None
        if args.modo == "diff" and base_commit is None:
            print("[oravalidator] No se encontró rama base: se analiza el branch completo.", file=sys.stderr)
        ctx = {"modo": "branch-" + ("diff" if base_commit else "completo"),
               "repositorio": url_publica(args.repo) if not os.path.isdir(args.repo) else str(root),
               "rama": args.rama, "commit": commit[:12], "base": base if base_commit else None,
               "base_commit": base_commit[:12] if base_commit else None,
               "solo_lineas_cambiadas": bool(args.solo_lineas_cambiadas and base_commit)}
        return ejecutar(root, commit, base_commit, ctx, args, cfg)


def modo_pre_push(args, cfg) -> int:
    root = Path(git(["rev-parse", "--show-toplevel"]).strip())
    entradas = [l.split() for l in sys.stdin.read().splitlines() if l.strip()]
    if not entradas:
        return 0
    codigo = 0
    for local_ref, local_sha, remote_ref, remote_sha in entradas:
        if local_sha == CERO:
            continue  # borrado de rama remota
        if remote_sha != CERO and git(["cat-file", "-t", remote_sha], cwd=root, check=False).strip() == "commit":
            base_commit = remote_sha
        else:
            base_name = rama_base_por_defecto(root)
            base_commit = resolver(base_name, root) if base_name else None
            if base_commit is None:
                # rama nueva sin base conocida: commits que no están en ningún remoto
                previos = git(["rev-list", local_sha, "--not", "--remotes", "--max-count=500"], cwd=root).split()
                base_commit = git(["rev-parse", f"{previos[-1]}^"], cwd=root, check=False).strip() if previos else None
        rama = remote_ref.replace("refs/heads/", "")
        ctx = {"modo": "pre-push", "repositorio": str(root), "rama": rama, "commit": local_sha[:12],
               "base_commit": base_commit[:12] if base_commit else None, "base": None,
               "remoto": args.remoto, "solo_lineas_cambiadas": bool(args.solo_lineas_cambiadas)}
        rc = ejecutar(root, local_sha, base_commit, ctx, args, cfg)
        codigo = max(codigo, rc)
    if codigo == 1:
        print("\n[oravalidator] ✖ PUSH BLOQUEADO: corrige las incidencias del reporte y vuelve a intentar.\n"
              "  Si un hallazgo es un falso positivo, documéntalo en el código con:\n"
              "    -- oravalidator:ignore ORA-XXX <justificación de al menos 10 caracteres>", file=sys.stderr)
    return codigo


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo", help="URL del repositorio o ruta local")
    ap.add_argument("--rama", help="Rama a analizar")
    ap.add_argument("--base", help="Rama base para comparar (por defecto la rama por defecto del remoto)")
    ap.add_argument("--modo", choices=["diff", "completo"], default="diff",
                    help="diff: solo archivos modificados respecto a la base · completo: todo el branch")
    ap.add_argument("--solo-lineas-cambiadas", action="store_true",
                    help="Reporta solo hallazgos en líneas nuevas/modificadas (adopción gradual en código legado)")
    ap.add_argument("--pre-push", action="store_true", help="Modo hook pre-push (lee refs de stdin)")
    ap.add_argument("--remoto", default="", help="Nombre del remoto (lo pasa el hook)")
    ap.add_argument("--url-remoto", default="", help=argparse.SUPPRESS)
    ap.add_argument("--config", help="Ruta de oravalidator.json")
    ap.add_argument("--matriz", help="Ruta de matriz_reglas.json (p. ej. la sincronizada desde el dashboard de reglas)")
    ap.add_argument("--salida", default=None, help="Carpeta de reportes")
    ap.add_argument("--categorias", default=os.environ.get("ORAV_CATEGORIAS"),
                    help="Casos de prueba a aplicar: categorías de la matriz separadas por coma (p. ej. 'Seguridad,DML'). Vacío = todas")
    ap.add_argument("--reglas", default=os.environ.get("ORAV_REGLAS"),
                    help="Reglas puntuales a aplicar, p. ej. 'ORA-056,ORA-057,ORA-160'")
    ap.add_argument("--severidad-minima", default=os.environ.get("ORAV_SEVERIDAD_MINIMA"),
                    help="Aplica solo reglas de esta severidad o superior (BLOCKER, CRITICAL, MAJOR, MINOR)")
    ap.add_argument("--listar-casos", action="store_true", help="Muestra las categorías y cantidad de reglas y termina")
    ap.add_argument("--hallazgos-extra", action="append",
                    help="JSON con hallazgos adicionales (p. ej. revisión semántica) a fusionar en el reporte")
    args = ap.parse_args(argv)

    cfg = ov.cargar_config(args.config)
    if args.listar_casos:
        from collections import Counter
        reglas = ov.cargar_reglas(args.matriz)
        for cat, n in Counter(r["categoria"] for r in reglas.values()).most_common():
            print(f"{cat:20} {n:4} reglas")
        return 0
    try:
        if args.pre_push:
            root = Path(git(["rev-parse", "--show-toplevel"]).strip())
            args.salida = args.salida or str(root / ".oravalidator" / "reportes")
            local_cfg = root / ".oravalidator" / "config" / "oravalidator.json"
            if not args.config and local_cfg.exists():
                cfg = ov.cargar_config(str(local_cfg))
            local_rules = root / ".oravalidator" / "rules" / "matriz_reglas.json"
            if not args.matriz and local_rules.exists():
                args.matriz = str(local_rules)
            return modo_pre_push(args, cfg)
        if not args.repo or not args.rama:
            ap.error("--repo y --rama son obligatorios (o use --pre-push)")
        args.salida = args.salida or "reporte-oravalidator"
        return modo_branch(args, cfg)
    except ErrorGit as ex:
        print(f"[oravalidator] Error de git: {ex}", file=sys.stderr)
        return 2
    except ValueError as ex:
        print(f"[oravalidator] Parámetro inválido: {ex}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
