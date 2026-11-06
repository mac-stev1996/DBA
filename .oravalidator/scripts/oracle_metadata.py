"""
Reglas que requieren conexión a Oracle (diccionario de datos). SOLO LECTURA.

Se activa si existen las variables de entorno ORA_USER, ORA_PASSWORD y ORA_DSN
(ej. ORA_DSN=dbhost:1521/SERVICIO). Requiere: pip install oracledb  (modo thin, sin cliente Oracle).

Usa una base de desarrollo/QA donde ya esté desplegada la versión anterior del código.
Nunca ejecuta DDL, DML ni compila objetos.

Reglas cubiertas:
  ORA-193/198  objetos inválidos entre los objetos tocados por el cambio
  ORA-194      objetos tocados que dependen de objetos inválidos
  ORA-195      procedimientos/funciones sin ninguna referencia en el esquema
  ORA-197      errores de compilación vigentes (USER_ERRORS) de los objetos tocados
  ORA-104/105  dependencias circulares entre paquetes del esquema
  ORA-188      tablas con varios triggers del mismo evento y momento
  ORA-142      columnas filtradas en WHERE con '=' sin índice (heurístico)
"""
from __future__ import annotations

import os
import re

import oravalidator as ov


def _objetos(archivos: dict) -> dict[str, tuple[str, str, int]]:
    objs = {}
    for ruta, txt in archivos.items():
        src = ov.Fuente(ruta, txt)
        for m in re.finditer(r"\bCREATE\s+(?:OR\s+REPLACE\s+)?(?:EDITIONABLE\s+|NONEDITIONABLE\s+)?"
                             r"(PACKAGE\s+BODY|PACKAGE|PROCEDURE|FUNCTION|TRIGGER|VIEW|TYPE\s+BODY|TYPE|TABLE)\s+([\w$#.\"]+)",
                             src.code, re.I):
            objs[ov.bare(m.group(2))] = (re.sub(r"\s+", " ", m.group(1).upper()), ruta, src.line(m.start()))
    return objs


def ejecutar(archivos: dict, cfg: dict):
    import oracledb  # noqa: import tardío: dependencia opcional

    hallazgos: list[ov.Hallazgo] = []
    con = oracledb.connect(user=os.environ["ORA_USER"], password=os.environ["ORA_PASSWORD"], dsn=os.environ["ORA_DSN"])
    con.call_timeout = 30000
    cur = con.cursor()
    objs = _objetos(archivos)
    nombres = list(objs)

    def H(rid, nombre, detalle, conf="alta"):
        tipo, ruta, linea = objs.get(nombre, ("", next(iter(archivos), ""), 1))
        hallazgos.append(ov.Hallazgo(rid, ruta, linea, detalle, confianza=conf, origen="oracle"))

    def binds(lst):
        return ",".join(f":b{i}" for i in range(len(lst))), {f"b{i}": v for i, v in enumerate(lst)}

    if nombres:
        ph, bv = binds(nombres)
        cur.execute(f"SELECT OBJECT_NAME, OBJECT_TYPE FROM USER_OBJECTS WHERE STATUS='INVALID' AND OBJECT_NAME IN ({ph})", bv)
        for n, t in cur:
            hallazgos.append(ov.Hallazgo("193", objs[n][1], objs[n][2], f"{t} {n} está INVALID en la base de referencia: "
                                         "no debe desplegarse en ese estado.", relacionadas=["198"], origen="oracle"))
        cur.execute(f"""SELECT D.NAME, D.REFERENCED_NAME, O.OBJECT_TYPE FROM USER_DEPENDENCIES D
                        JOIN USER_OBJECTS O ON O.OBJECT_NAME = D.REFERENCED_NAME AND O.OBJECT_TYPE = D.REFERENCED_TYPE
                        WHERE O.STATUS = 'INVALID' AND D.NAME IN ({ph})""", bv)
        for n, ref, t in cur:
            H("194", n, f"{n} depende de {t} {ref}, que está INVALID.")
        cur.execute(f"""SELECT NAME, TYPE, LINE, TEXT FROM USER_ERRORS WHERE ATTRIBUTE='ERROR' AND NAME IN ({ph})
                        ORDER BY NAME, SEQUENCE FETCH FIRST 50 ROWS ONLY""", bv)
        for n, t, line, text in cur:
            H("197", n, f"{t} {n} línea {line}: {text.strip()[:200]}")
        cur.execute(f"""SELECT O.OBJECT_NAME FROM USER_OBJECTS O WHERE O.OBJECT_TYPE IN ('PROCEDURE','FUNCTION')
                        AND O.OBJECT_NAME IN ({ph})
                        AND NOT EXISTS (SELECT 1 FROM ALL_DEPENDENCIES D WHERE D.REFERENCED_NAME = O.OBJECT_NAME
                                        AND D.REFERENCED_OWNER = USER AND D.NAME <> O.OBJECT_NAME)""", bv)
        for (n,) in cur:
            H("195", n, f"{n} no es referenciado por ningún objeto (verifique uso externo antes de mantenerlo).", "media")

    cur.execute("""SELECT A.NAME, A.REFERENCED_NAME FROM USER_DEPENDENCIES A
                   JOIN USER_DEPENDENCIES B ON B.NAME = A.REFERENCED_NAME AND B.REFERENCED_NAME = A.NAME
                   WHERE A.TYPE = 'PACKAGE BODY' AND A.REFERENCED_TYPE = 'PACKAGE' AND B.TYPE = 'PACKAGE BODY'
                     AND A.NAME < A.REFERENCED_NAME""")
    for a, b in cur:
        if a in objs or b in objs:
            hallazgos.append(ov.Hallazgo("104", objs.get(a, objs.get(b))[1], objs.get(a, objs.get(b))[2],
                                         f"Dependencia circular entre {a} y {b} (USER_DEPENDENCIES).", relacionadas=["105"], origen="oracle"))

    tablas = [n for n, (t, _, _) in objs.items() if t == "TRIGGER"]
    if tablas:
        ph, bv = binds(tablas)
        cur.execute(f"""SELECT T.TABLE_NAME, T.TRIGGERING_EVENT, T.TRIGGER_TYPE, COUNT(*)
                        FROM USER_TRIGGERS T WHERE T.TABLE_NAME IN (SELECT TABLE_NAME FROM USER_TRIGGERS WHERE TRIGGER_NAME IN ({ph}))
                        GROUP BY T.TABLE_NAME, T.TRIGGERING_EVENT, T.TRIGGER_TYPE HAVING COUNT(*) > 1""", bv)
        for tabla, ev, tt, n in cur:
            H("188", tablas[0], f"La tabla {tabla} ya tiene {n} triggers {tt} {ev} en la base.", "media")

    # ORA-063: literales de texto no numéricos insertados en columnas NUMBER/DATE
    for ruta, txt in archivos.items():
        src = ov.Fuente(ruta, txt)
        for m in re.finditer(r"\bINSERT\s+INTO\s+([\w$#.]+)\s*\(([^()]*)\)\s*VALUES\s*\(", src.nocomm, re.I):
            cl = ov.match_paren(src.nocomm, m.end() - 1)
            cols = [c.strip().upper() for _, c in ov.split_top(m.group(2))]
            vals = [v.strip() for _, v in ov.split_top(src.nocomm[m.end():cl])]
            for col, val in zip(cols, vals):
                if not re.fullmatch(r"'[^']*'", val):
                    continue
                cur.execute("SELECT DATA_TYPE FROM USER_TAB_COLUMNS WHERE TABLE_NAME=:t AND COLUMN_NAME=:c",
                            t=ov.bare(m.group(1)), c=col)
                row = cur.fetchone()
                lit = val.strip("'")
                if row and row[0] in ("NUMBER", "FLOAT", "INTEGER") and not re.fullmatch(r"-?\d+([.,]\d+)?", lit):
                    hallazgos.append(ov.Hallazgo("063", ruta, src.line(m.start()),
                                                 f"Se inserta '{lit}' en {ov.bare(m.group(1))}.{col} de tipo {row[0]}.", origen="oracle"))
                elif row and row[0] == "DATE":
                    hallazgos.append(ov.Hallazgo("063", ruta, src.line(m.start()),
                                                 f"Literal de texto en la columna DATE {col}: use TO_DATE con máscara o literal DATE.",
                                                 confianza="media", origen="oracle"))

    # ORA-142: columnas filtradas por igualdad sin índice que las encabece
    filtros = set()
    for txt in archivos.values():
        code = ov.Fuente("x", txt).code
        for m in re.finditer(r"\bFROM\s+([\w$#]+)\s+([\w$#]+)?[^;]*?\bWHERE\b([^;]*)", code, re.I):
            tabla, alias, cond = m.group(1).upper(), (m.group(2) or "").upper(), m.group(3)
            for c in re.finditer(rf"\b(?:{re.escape(alias)}\.)?([A-Z_][\w$#]*)\s*=\s*[:\w']", cond, re.I):
                filtros.add((tabla, c.group(1).upper()))
    for tabla, col in list(filtros)[:200]:
        cur.execute("""SELECT (SELECT COUNT(*) FROM USER_TAB_COLUMNS WHERE TABLE_NAME=:t AND COLUMN_NAME=:c),
                              (SELECT COUNT(*) FROM USER_IND_COLUMNS WHERE TABLE_NAME=:t AND COLUMN_NAME=:c AND COLUMN_POSITION=1),
                              (SELECT NUM_ROWS FROM USER_TABLES WHERE TABLE_NAME=:t) FROM DUAL""", t=tabla, c=col)
        existe, indexada, filas = cur.fetchone()
        if existe and not indexada and (filas or 0) > 10000:
            H("142", next(iter(objs), ""), f"{tabla}.{col} se filtra por igualdad y no encabeza ningún índice ({filas} filas).", "media")

    con.close()
    return hallazgos, {"ejecutadas": True, "motivo": f"Conectado a {os.environ['ORA_DSN']} como {os.environ['ORA_USER']}",
                       "objetos_consultados": len(nombres)}
