#!/usr/bin/env python3
"""
Instala oravalidator en un repositorio git para que NINGÚN push con incidencias
bloqueantes llegue al remoto.

    python instalar_hook.py /ruta/al/repo [--ci github|gitlab|bitbucket|azure] [--forzar]

Qué hace:
  1. Copia motor, reglas y configuración a <repo>/.oravalidator/ (se versiona: todo el
     equipo usa las mismas reglas y la misma política).
  2. Crea <repo>/.githooks/pre-push y configura `git config core.hooksPath .githooks`.
  3. Agrega .oravalidator/reportes/ al .gitignore.
  4. Opcional: copia la plantilla de pipeline CI que hace cumplir el gate en el servidor.

Cada desarrollador que clone el repo debe ejecutar una vez:
    git config core.hooksPath .githooks
(o volver a correr este instalador). El paso CI + protección de rama es lo que
garantiza el bloqueo aunque alguien omita el hook con --no-verify.
"""
import argparse
import shutil
import subprocess
import sys
from pathlib import Path

SKILL = Path(__file__).resolve().parent.parent
CI = {
    "github": ("ci/github-actions.yml", ".github/workflows/oravalidator.yml"),
    "gitlab": ("ci/gitlab-ci.yml", ".gitlab/oravalidator.gitlab-ci.yml"),
    "bitbucket": ("ci/bitbucket-pipelines.yml", "bitbucket-pipelines.oravalidator.yml"),
    "azure": ("ci/azure-pipelines.yml", "azure-pipelines.oravalidator.yml"),
}


def git(args, cwd):
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("repo")
    ap.add_argument("--ci", choices=sorted(CI))
    ap.add_argument("--forzar", action="store_true", help="Sobrescribe la configuración existente del repo")
    a = ap.parse_args()

    r = git(["rev-parse", "--show-toplevel"], a.repo)
    if r.returncode != 0:
        sys.exit(f"{a.repo} no es un repositorio git.")
    root = Path(r.stdout.strip())
    dest = root / ".oravalidator"

    # 1. motor y reglas (la config del repo se preserva salvo --forzar)
    for sub in ("scripts", "rules", "assets"):
        if (dest / sub).exists():
            shutil.rmtree(dest / sub)
        shutil.copytree(SKILL / sub, dest / sub, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    cfg_dest = dest / "config" / "oravalidator.json"
    if a.forzar or not cfg_dest.exists():
        cfg_dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(SKILL / "config" / "oravalidator.json", cfg_dest)
    else:
        print(f"  · Se conservó la configuración existente: {cfg_dest.relative_to(root)}")

    # 2. hook versionado
    hooks = root / ".githooks"
    hooks.mkdir(exist_ok=True)
    pre_push = hooks / "pre-push"
    if pre_push.exists() and "oravalidator" not in pre_push.read_text(encoding="utf-8", errors="ignore") and not a.forzar:
        sys.exit(f"Ya existe {pre_push} de otra herramienta. Intégrelo manualmente o use --forzar.")
    shutil.copy2(SKILL / "hooks" / "pre-push", pre_push)
    pre_push.chmod(0o755)
    actual = git(["config", "--get", "core.hooksPath"], root).stdout.strip()
    if actual and actual not in (".githooks", str(hooks)):
        print(f"  ! core.hooksPath apuntaba a '{actual}'; se cambia a .githooks (revise si usa husky u otra herramienta).")
    git(["config", "core.hooksPath", ".githooks"], root)
    git(["update-index", "--chmod=+x", ".githooks/pre-push"], root)

    # 3. .gitignore
    gi = root / ".gitignore"
    linea = ".oravalidator/reportes/"
    contenido = gi.read_text(encoding="utf-8") if gi.exists() else ""
    if linea not in contenido:
        gi.write_text(contenido + ("" if contenido.endswith("\n") or not contenido else "\n") + linea + "\n", encoding="utf-8")

    # 4. CI
    if a.ci:
        src, dst = CI[a.ci]
        d = root / dst
        d.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(SKILL / src, d)
        print(f"  · Pipeline CI copiado en {dst}")

    print(f"""
✔ oravalidator instalado en {root}
  · Motor y reglas:   .oravalidator/   (haga commit de esta carpeta y de .githooks/)
  · Hook pre-push:    .githooks/pre-push   (core.hooksPath = .githooks)
  · Política:         .oravalidator/config/oravalidator.json

Siguiente paso para el equipo:  git config core.hooksPath .githooks
Para garantizar el bloqueo en el servidor: active el pipeline CI y marque el job
'oravalidator' como check obligatorio en la protección de la rama.""")


if __name__ == "__main__":
    main()
