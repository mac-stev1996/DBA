#!/usr/bin/env python3
"""Regenera rules/matriz_reglas.json a partir de la matriz Excel corporativa.

Uso:
    python scripts/actualizar_reglas.py Matriz_Oracle_200_Reglas.xlsx

Ejecútalo cada vez que arquitectura actualice la matriz, para que el motor
(oravalidator.py) use las severidades, mensajes y quality gate vigentes.
"""
import json
import sys
from pathlib import Path

try:
    import openpyxl
except ImportError:
    sys.exit("Falta openpyxl: pip install openpyxl")

COLS = {
    "ID": "id", "Categoría": "categoria", "Regla": "regla", "Descripción": "descripcion",
    "Ejemplo incorrecto": "ejemplo_incorrecto", "Ejemplo correcto": "ejemplo_correcto",
    "Severidad": "severidad", "Automatizable": "automatizable",
    "Tipo de análisis": "tipo_analisis", "Herramienta": "herramienta",
    "Quality Gate": "quality_gate", "Mensaje de error": "mensaje",
    "Prioridad": "prioridad", "Complejidad": "complejidad", "Requiere Oracle": "requiere_oracle",
}


def main(xlsx: str) -> None:
    wb = openpyxl.load_workbook(xlsx, data_only=True)
    ws = wb[wb.sheetnames[0]]
    rows = list(ws.iter_rows(values_only=True))
    header = [COLS.get(str(h).strip(), str(h)) for h in rows[0]]
    reglas = []
    for r in rows[1:]:
        if not r or not r[0]:
            continue
        d = {header[i]: (r[i] if r[i] is not None else "") for i in range(len(header))}
        for k in ("ejemplo_incorrecto", "ejemplo_correcto"):
            d[k] = str(d[k]).replace("\\n", "\n")
        d["requiere_oracle"] = str(d["requiere_oracle"]).strip().lower().startswith("s")
        reglas.append(d)

    config = {}
    for name in wb.sheetnames:
        if name.lower().startswith("config"):
            for r in list(wb[name].iter_rows(values_only=True))[1:]:
                if r and r[0]:
                    config[str(r[0])] = r[1]

    out = Path(__file__).resolve().parent.parent / "rules" / "matriz_reglas.json"
    out.write_text(json.dumps({"origen": Path(xlsx).name, "parametros_matriz": config,
                               "reglas": reglas}, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"{len(reglas)} reglas exportadas a {out}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
