#!/usr/bin/env python3
"""
oravalidator — Motor de análisis estático para código Oracle (SQL / PL/SQL)
basado en la Matriz Oracle de 200 reglas.

Uso directo (sin git):
    python oravalidator.py archivo1.sql carpeta/ --json salida.json

Normalmente lo invoca analizar_branch.py, que se encarga de git, reportes y quality gate.

Diseño:
  * El código se pre-procesa en tres vistas con las mismas posiciones:
      raw     -> texto original
      nocomm  -> comentarios reemplazados por espacios (strings intactos)
      code    -> comentarios y contenido de strings reemplazados por espacios
    Así ninguna regla se confunde con texto dentro de comentarios o literales.
  * Un tokenizador ligero construye la estructura de bloques (BEGIN/IF/LOOP/CASE),
    las unidades de programa (procedure, function, package, trigger) y las
    secciones de excepción con sus manejadores.
  * Cada hallazgo lleva 'confianza': 'alta' (patrón determinístico) o 'media'
    (heurística: requiere revisión humana o de Claude). El quality gate decide
    según config cómo trata cada nivel.
"""
from __future__ import annotations

import bisect
import fnmatch
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path

VERSION = "1.0.0"
BASE_DIR = Path(__file__).resolve().parent.parent
SEV_ORDER = {"BLOCKER": 0, "CRITICAL": 1, "MAJOR": 2, "MINOR": 3, "INFO": 4}

# Reglas que solo pueden evaluarse con conexión a Oracle (diccionario de datos / planes)
REGLAS_ORACLE = {"063", "104", "105", "142", "193", "194", "195", "197", "198"}
# Reglas que requieren plan de ejecución (EXPLAIN PLAN en un ambiente de pruebas): revisión con DBA
REGLAS_PLAN = {"141", "151", "154", "155"}
# Reglas semánticas que el motor no puede decidir: las revisa Claude (ver references/revision_semantica.md)
REGLAS_CLAUDE = {"024", "029", "033", "034", "049", "058", "059", "071", "072",
                 "080", "081", "083", "089", "094", "114", "117", "187"}

RESERVADAS = set("""ACCESS ADD ALL ALTER AND ANY AS ASC AUDIT BETWEEN BY CHAR CHECK CLUSTER COLUMN
COMMENT COMPRESS CONNECT CREATE CURRENT DATE DECIMAL DEFAULT DELETE DESC DISTINCT DROP ELSE
EXCLUSIVE EXISTS FILE FLOAT FOR FROM GRANT GROUP HAVING IDENTIFIED IMMEDIATE IN INCREMENT INDEX
INITIAL INSERT INTEGER INTERSECT INTO IS LEVEL LIKE LOCK LONG MAXEXTENTS MINUS MLSLABEL MODE
MODIFY NOAUDIT NOCOMPRESS NOT NOWAIT NULL NUMBER OF OFFLINE ON ONLINE OPTION OR ORDER PCTFREE
PRIOR PUBLIC RAW RENAME RESOURCE REVOKE ROW ROWID ROWNUM ROWS SELECT SESSION SET SHARE SIZE
SMALLINT START SUCCESSFUL SYNONYM SYSDATE TABLE THEN TO TRIGGER UID UNION UNIQUE UPDATE USER
VALIDATE VALUES VARCHAR VARCHAR2 VIEW WHENEVER WHERE WITH""".split())

KEYWORDS_FORMATO = set("""SELECT FROM WHERE INSERT INTO UPDATE DELETE MERGE VALUES SET BEGIN END IF
THEN ELSE ELSIF LOOP WHILE EXCEPTION WHEN DECLARE CREATE REPLACE PROCEDURE FUNCTION PACKAGE BODY
RETURN IS AS AND OR NOT NULL JOIN INNER LEFT RIGHT OUTER ON GROUP BY ORDER HAVING COMMIT ROLLBACK
CURSOR OPEN FETCH CLOSE EXIT RAISE TRIGGER TABLE INDEX DISTINCT UNION EXISTS BETWEEN LIKE CASE
EXECUTE IMMEDIATE BULK COLLECT FORALL LIMIT""".split())

AGREGADAS = r"\b(COUNT|SUM|AVG|MIN|MAX|LISTAGG|STDDEV|VARIANCE|MEDIAN|XMLAGG|JSON_ARRAYAGG|COLLECT)\s*\("
SENSIBLES = r"(PASS|PWD|CLAVE|CONTRASE|SECRET|TOKEN|CVV|PIN_|TARJETA|CARD_NUM|API_?KEY)"
TIPOS_NUM = {"NUMBER", "INTEGER", "INT", "PLS_INTEGER", "BINARY_INTEGER", "NUMERIC", "DECIMAL",
             "FLOAT", "SIMPLE_INTEGER", "NATURAL", "POSITIVE", "BINARY_DOUBLE", "BINARY_FLOAT", "SMALLINT"}
TIPOS_CHAR = {"VARCHAR2", "VARCHAR", "CHAR", "NVARCHAR2", "NCHAR", "CLOB", "NCLOB", "LONG"}
TIPOS_DATE = {"DATE", "TIMESTAMP"}
OBJ_KINDS = {"TABLE", "INDEX", "VIEW", "SEQUENCE", "SYNONYM", "USER", "TYPE", "PACKAGE",
             "PROCEDURE", "FUNCTION", "TRIGGER", "MATERIALIZED", "EXISTS", "DROP", "CREATE"}

WORD_RE = re.compile(r'[A-Za-z_][A-Za-z0-9_$#]*(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_$#]*)*|"[^"\n]*"|;|\(|\)|,|:=')
SQLPLUS_LINE = re.compile(
    r"^[ \t]*(PROMPT|PRO|REM|REMARK|SPOOL|WHENEVER|DEFINE|UNDEFINE|COLUMN|COL|TTITLE|BTITLE|EXIT|QUIT|"
    r"SET\s+(DEFINE|SERVEROUTPUT|ECHO|FEEDBACK|VERIFY|TERMOUT|LINESIZE|PAGESIZE|HEADING|TIMING|"
    r"SQLBLANKLINES|SCAN|TRIMSPOOL|LONG|ARRAYSIZE|AUTOCOMMIT|CONCAT|ESCAPE|NEWPAGE|SQLPROMPT)|@)\b.*$",
    re.IGNORECASE | re.MULTILINE)


# ---------------------------------------------------------------------------
# Modelo
# ---------------------------------------------------------------------------
@dataclass
class Hallazgo:
    regla: str
    archivo: str
    linea: int
    detalle: str
    fragmento: str = ""
    confianza: str = "alta"
    relacionadas: list = field(default_factory=list)
    severidad: str = ""
    categoria: str = ""
    titulo: str = ""
    mensaje: str = ""
    ejemplo_correcto: str = ""
    bloquea: bool = False
    origen: str = "motor"
    justificacion: str = ""


@dataclass
class Token:
    w: str          # texto en mayúsculas (palabras) o símbolo
    pos: int
    end: int
    depth: int = 0


@dataclass
class Bloque:
    kind: str       # BEGIN | IF | LOOP | CASE
    start: int
    end: int
    tok_start: int
    tok_end: int
    exc_tok: int = -1


@dataclass
class Handler:
    nombres: list
    start: int      # inicio del cuerpo (después de THEN)
    end: int
    when_pos: int


@dataclass
class Unidad:
    kind: str       # PROCEDURE | FUNCTION | PACKAGE | PACKAGE BODY | TRIGGER
    name: str
    start: int
    end: int
    tok_header: int
    tok_is: int
    tok_begin: int = -1
    tok_end: int = -1
    standalone: bool = False
    params: list = field(default_factory=list)   # [(name, mode, type, pos)]
    decls: list = field(default_factory=list)    # [(name, kind, type, pos)] kind: var|const
    parent: "Unidad | None" = None


# ---------------------------------------------------------------------------
# Pre-procesamiento
# ---------------------------------------------------------------------------
class Fuente:
    def __init__(self, ruta: str, texto: str):
        self.ruta = ruta
        self.raw = texto.replace("\r\n", "\n").replace("\r", "\n")
        self.lines = self.raw.split("\n")
        self._nl = [i for i, c in enumerate(self.raw) if c == "\n"]
        self.comments: list[tuple[int, str]] = []       # (linea, texto)
        self.literals: list[tuple[int, int, str]] = []  # (start, end, contenido)
        self.nocomm, self.code = self._mask()
        self.tokens = self._tokenize()

    def line(self, pos: int) -> int:
        return bisect.bisect_left(self._nl, pos) + 1

    def line_text(self, n: int) -> str:
        return self.lines[n - 1] if 0 < n <= len(self.lines) else ""

    def _mask(self):
        s = self.raw
        n = len(s)
        nocomm = list(s)
        code = list(s)

        def blank(buf, a, b):
            for k in range(a, b):
                if buf[k] != "\n":
                    buf[k] = " "

        # Líneas de SQL*Plus (PROMPT, SET DEFINE...) se tratan como comentarios
        sqlplus = set()
        for m in SQLPLUS_LINE.finditer(s):
            sqlplus.update(range(m.start(), m.end()))
            self.comments.append((self.line(m.start()), ""))

        i = 0
        while i < n:
            if i in sqlplus:
                j = s.find("\n", i)
                j = n if j < 0 else j
                blank(nocomm, i, j); blank(code, i, j)
                i = max(j, i + 1)  # nunca quedarse en la misma posición
                continue
            c = s[i]
            if c == "-" and s.startswith("--", i):
                j = s.find("\n", i)
                j = n if j < 0 else j
                self.comments.append((self.line(i), s[i + 2:j]))
                blank(nocomm, i, j); blank(code, i, j)
                i = j
            elif c == "/" and s.startswith("/*", i):
                j = s.find("*/", i + 2)
                j = n if j < 0 else j + 2
                body = s[i + 2:j - 2]
                for k, ln in enumerate(body.split("\n")):
                    self.comments.append((self.line(i) + k, ln))
                blank(nocomm, i, j); blank(code, i, j)
                i = j
            elif c in "qQ" and i + 2 < n and s[i + 1] == "'" and (i == 0 or not (s[i - 1].isalnum() or s[i - 1] == "_")) \
                    or (c in "nN" and s[i + 1:i + 3].lower() == "q'"):
                q = i + 1 if c in "qQ" else i + 2
                d = s[q + 1] if q + 1 < n else "'"
                close = {"[": "]", "{": "}", "(": ")", "<": ">"}.get(d, d)
                j = s.find(close + "'", q + 2)
                j = n if j < 0 else j + 2
                self.literals.append((q, j, s[q + 2:j - 2]))
                blank(code, q + 2, j - 2)
                i = j
            elif c == "'":
                j = i + 1
                while j < n:
                    if s[j] == "'":
                        if j + 1 < n and s[j + 1] == "'":
                            j += 2
                            continue
                        break
                    j += 1
                j = min(j + 1, n)
                self.literals.append((i, j, s[i + 1:j - 1]))
                blank(code, i + 1, j - 1)
                i = j
            else:
                i += 1
        return "".join(nocomm), "".join(code)

    def _tokenize(self) -> list[Token]:
        toks = []
        for m in WORD_RE.finditer(self.code):
            w = m.group(0)
            if w[0] != '"':
                w = re.sub(r"\s+", "", w).upper()
            toks.append(Token(w, m.start(), m.end()))
        return toks


def strip_parens(text: str) -> str:
    """Reemplaza el contenido de paréntesis anidados por espacios (conserva longitudes)."""
    out = list(text)
    depth = 0
    for i, c in enumerate(text):
        if c == "(":
            depth += 1
            if depth > 1:
                out[i] = " "
        elif c == ")":
            if depth > 1:
                out[i] = " "
            depth = max(0, depth - 1)
        elif depth >= 1 and c != "\n":
            out[i] = " "
    return "".join(out)


def split_top(text: str, sep: str = ",") -> list[tuple[int, str]]:
    """Divide por separador a nivel 0 de paréntesis. Devuelve (offset, trozo)."""
    parts, depth, last = [], 0, 0
    for i, c in enumerate(text):
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        elif c == sep and depth == 0:
            parts.append((last, text[last:i]))
            last = i + 1
    parts.append((last, text[last:]))
    return parts


def match_paren(text: str, open_pos: int) -> int:
    depth = 0
    for i in range(open_pos, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return i
    return len(text) - 1


def bare(name: str) -> str:
    return name.split(".")[-1].strip('"').upper()


# ---------------------------------------------------------------------------
# Estructura: bloques, unidades, excepciones
# ---------------------------------------------------------------------------
class Estructura:
    def __init__(self, src: Fuente):
        self.src = src
        t = src.tokens
        self.bloques: list[Bloque] = []
        self.handlers: list[tuple[Bloque, list[Handler]]] = []
        stack: list[dict] = []
        n = len(t)
        for i, tk in enumerate(t):
            tk.depth = len(stack)
            w = tk.w
            prev = t[i - 1].w if i else ""
            nxt = t[i + 1].w if i + 1 < n else ""
            if w == "BEGIN":
                stack.append({"k": "BEGIN", "i": i, "exc": -1})
            elif w == "IF" and prev != "END" and not (prev in OBJ_KINDS and nxt in ("NOT", "EXISTS")):
                stack.append({"k": "IF", "i": i, "exc": -1})
            elif w == "LOOP" and prev != "END":
                stack.append({"k": "LOOP", "i": i, "exc": -1})
            elif w == "CASE" and prev != "END":
                stack.append({"k": "CASE", "i": i, "exc": -1})
            elif w == "EXCEPTION" and nxt == "WHEN" and stack and stack[-1]["k"] == "BEGIN":
                stack[-1]["exc"] = i
            elif w == "END" and stack:
                kind = nxt if nxt in ("IF", "LOOP", "CASE") else None
                if kind:
                    while stack and stack[-1]["k"] != kind and stack[-1]["k"] != "BEGIN":
                        stack.pop()
                    if stack and stack[-1]["k"] == kind:
                        b = stack.pop()
                        self._close(b, i + 1)
                else:
                    while stack and stack[-1]["k"] in ("IF", "LOOP"):
                        stack.pop()
                    if stack:
                        b = stack.pop()
                        self._close(b, i)
        self.unidades = self._unidades()

    def _close(self, b: dict, tok_end: int):
        t = self.src.tokens
        end_pos = t[tok_end].end
        # incluye ';' final
        semi = self.src.code.find(";", end_pos)
        gap = self.src.code[end_pos:semi].strip() if semi >= 0 else "x x"
        if semi >= 0 and re.fullmatch(r'[\w$#."]*', gap):
            end_pos = semi + 1
        blk = Bloque(b["k"], t[b["i"]].pos, end_pos, b["i"], tok_end, b["exc"])
        self.bloques.append(blk)
        if b["exc"] >= 0:
            self.handlers.append((blk, self._handlers(b["exc"], tok_end)))

    def _handlers(self, exc_i: int, end_i: int) -> list[Handler]:
        t = self.src.tokens
        d = t[exc_i].depth
        whens = [k for k in range(exc_i + 1, end_i) if t[k].w == "WHEN" and t[k].depth == d]
        hs = []
        for idx, k in enumerate(whens):
            j = k + 1
            names = []
            while j < end_i and t[j].w != "THEN":
                if t[j].w not in ("OR",):
                    names.append(t[j].w)
                j += 1
            body_start = t[j].end if j < end_i else t[k].end
            body_end = t[whens[idx + 1]].pos if idx + 1 < len(whens) else t[end_i].pos
            hs.append(Handler(names, body_start, body_end, t[k].pos))
        return hs

    # --- unidades ---------------------------------------------------------
    def _is_body_header(self, i: int) -> int:
        """Si el token i (PROCEDURE/FUNCTION) inicia un cuerpo, devuelve el índice del IS/AS; si no, -1."""
        t = self.src.tokens
        depth = 0
        for j in range(i + 1, min(len(t), i + 400)):
            w = t[j].w
            if w == "(":
                depth += 1
            elif w == ")":
                depth -= 1
            elif depth == 0 and w == ";":
                return -1
            elif depth == 0 and w in ("IS", "AS"):
                nx = t[j + 1].w if j + 1 < len(t) else ""
                if nx in ("LANGUAGE", "EXTERNAL"):
                    return -1
                return j
        return -1

    def _created(self, i: int) -> bool:
        t = self.src.tokens
        back = [t[k].w for k in range(max(0, i - 5), i)]
        return "CREATE" in back

    def _scan_end(self, start: int, mode: str) -> tuple[int, int]:
        """Devuelve (tok_begin_principal, tok_end) usando conteo relativo."""
        t = self.src.tokens
        depth = pending = 0
        init_seen = False
        main_begin = -1
        n = len(t)
        j = start
        while j < n:
            w = t[j].w
            prev = t[j - 1].w if j else ""
            if w in ("PROCEDURE", "FUNCTION") and depth == 0 and self._is_body_header(j) >= 0:
                pending += 1
            elif w == "IS" and prev in ("STATEMENT", "ROW") and mode == "package":
                pending += 1   # secciones de trigger compuesto
            elif w == "BEGIN":
                if depth == 0 and pending == 0:
                    main_begin = j
                    if mode == "package":
                        init_seen = True
                depth += 1
            elif w in ("IF", "LOOP", "CASE") and prev != "END":
                nxt = t[j + 1].w if j + 1 < n else ""
                if not (w == "IF" and prev in OBJ_KINDS and nxt in ("NOT", "EXISTS")):
                    depth += 1
            elif w == "END":
                nxt = t[j + 1].w if j + 1 < n else ""
                if nxt in ("IF", "LOOP", "CASE"):
                    depth -= 1
                    j += 2
                    continue
                if depth == 0:
                    return main_begin, j
                depth -= 1
                if depth == 0:
                    if pending > 0:
                        pending -= 1
                    elif mode == "block" or init_seen:
                        return main_begin, j
            j += 1
        return main_begin, n - 1

    def _unidades(self) -> list[Unidad]:
        t = self.src.tokens
        units: list[Unidad] = []
        for i, tk in enumerate(t):
            w = tk.w
            if w in ("PROCEDURE", "FUNCTION"):
                if i and t[i - 1].w in ("DROP", "ALTER", "ON", "EXECUTE", "ANY"):
                    continue
                is_i = self._is_body_header(i)
                if is_i < 0 or i + 1 >= len(t):
                    continue
                name = t[i + 1].w
                b, e = self._scan_end(is_i + 1, "block")
                u = Unidad(w, bare(name), tk.pos, t[e].end, i, is_i, b, e, self._created(i))
                u.params = self._params(i + 2, is_i)
                units.append(u)
            elif w == "PACKAGE" and self._created(i) and i + 1 < len(t):
                body = t[i + 1].w == "BODY"
                ni = i + 2 if body else i + 1
                if ni >= len(t):
                    continue
                name = t[ni].w
                is_i = next((k for k in range(ni, min(len(t), ni + 30)) if t[k].w in ("IS", "AS")), -1)
                if is_i < 0:
                    continue
                b, e = self._scan_end(is_i + 1, "package")
                units.append(Unidad("PACKAGE BODY" if body else "PACKAGE", bare(name), tk.pos,
                                    t[e].end, i, is_i, b, e, True))
            elif w == "TRIGGER" and self._created(i) and i + 1 < len(t):
                name = t[i + 1].w
                compound = any(t[k].w == "COMPOUND" for k in range(i, min(len(t), i + 60)))
                b, e = self._scan_end(i + 2, "package" if compound else "block")
                units.append(Unidad("TRIGGER", bare(name), tk.pos, t[e].end, i, i + 1, b, e, True))
        # Ajusta fin (incluye 'END nombre;') e inicio (desde CREATE) y define jerarquía
        code = self.src.code
        for u in units:
            mm = re.match(r'\s*[\w$#."]*\s*;', code[u.end:])
            if mm:
                u.end += mm.end()
        for u in units:
            k = u.tok_header
            while k > 0 and t[k - 1].w in ("CREATE", "OR", "REPLACE", "EDITIONABLE", "NONEDITIONABLE", "EDITIONING"):
                k -= 1
            u.start = t[k].pos
        for u in units:
            enclosing = [p for p in units if p is not u and p.start <= u.start and u.end <= p.end]
            u.parent = min(enclosing, key=lambda p: p.end - p.start) if enclosing else None
        for u in units:
            u.decls = self._decls(u, units)
        return units

    def _params(self, from_i: int, to_i: int) -> list:
        t = self.src.tokens
        if from_i >= to_i or t[from_i].w != "(":
            return []
        code = self.src.code
        op = t[from_i].pos
        cl = match_paren(code, op)
        res = []
        for off, piece in split_top(code[op + 1:cl]):
            words = re.findall(r"[A-Za-z_][\w$#%.]*(?:\s*\(\s*\d+[^)]*\))?", piece)
            if not words:
                continue
            name = words[0].upper()
            rest = [x.upper() for x in words[1:]]
            mode = "IN"
            if rest[:2] == ["IN", "OUT"]:
                mode, rest = "IN OUT", rest[2:]
            elif rest[:1] == ["OUT"]:
                mode, rest = "OUT", rest[1:]
            elif rest[:1] == ["IN"]:
                rest = rest[1:]
            if rest[:1] == ["NOCOPY"]:
                rest = rest[1:]
            typ = rest[0] if rest else ""
            lead = len(piece) - len(piece.lstrip())
            res.append((name, mode, typ, op + 1 + off + lead))
        return res

    def _decl_section(self, u: Unidad, units: list[Unidad]) -> tuple[int, int]:
        t = self.src.tokens
        if u.kind in ("PACKAGE", "PACKAGE BODY"):
            a = t[u.tok_is].end
            b = t[u.tok_begin].pos if u.tok_begin >= 0 else t[u.tok_end].pos
        elif u.kind == "TRIGGER":
            dec = next((k for k in range(u.tok_header, u.tok_begin if u.tok_begin > 0 else u.tok_end)
                        if t[k].w == "DECLARE"), -1)
            if dec < 0:
                return (0, 0)
            a, b = t[dec].end, t[u.tok_begin].pos
        else:
            if u.tok_begin < 0:
                return (0, 0)
            a, b = t[u.tok_is].end, t[u.tok_begin].pos
        return a, b

    def _decls(self, u: Unidad, units: list[Unidad]) -> list:
        a, b = self._decl_section(u, units)
        if b <= a:
            return []
        seg = list(self.src.code[a:b])
        for o in units:   # excluye subprogramas anidados
            if o is not u and a <= o.start and o.end <= b + 1:
                for k in range(o.start - a, min(len(seg), o.end - a)):
                    if seg[k] != "\n":
                        seg[k] = " "
        seg = "".join(seg)
        # excluye declaraciones forward de subprogramas (en specs)
        seg = re.sub(r"\b(PROCEDURE|FUNCTION)\b[^;]*;", lambda m: " " * len(m.group(0)), seg, flags=re.I | re.S)
        res = []
        for off, piece in split_top(seg, ";"):
            p = piece.strip()
            if not p:
                continue
            m = re.match(r"([A-Za-z_][\w$#]*)\s+(CONSTANT\s+)?([A-Za-z_][\w$#.%]*)", p, re.I)
            if not m:
                continue
            name, const, typ = m.group(1).upper(), m.group(2), m.group(3).upper()
            if name in ("CURSOR", "TYPE", "SUBTYPE", "PRAGMA", "PROCEDURE", "FUNCTION") or typ == "EXCEPTION":
                continue
            lead = len(piece) - len(piece.lstrip())
            res.append((name, "const" if const else "var", typ, p, a + off + lead))
        return res

    # --- utilidades -------------------------------------------------------
    def loops_containing(self, pos: int) -> list[Bloque]:
        return [b for b in self.bloques if b.kind == "LOOP" and b.start < pos < b.end]

    def unit_at(self, pos: int) -> Unidad | None:
        cands = [u for u in self.unidades if u.start <= pos <= u.end]
        return min(cands, key=lambda u: u.end - u.start) if cands else None

    def in_handler(self, pos: int) -> Handler | None:
        for _, hs in self.handlers:
            for h in hs:
                if h.start <= pos < h.end:
                    return h
        return None

    def enclosing_begins(self, pos: int) -> list[tuple[Bloque, list[Handler]]]:
        res = []
        for blk, hs in self.handlers:
            exc_pos = self.src.tokens[blk.exc_tok].pos
            if blk.start < pos < exc_pos:
                res.append((blk, hs))
        return res


# ---------------------------------------------------------------------------
# Motor
# ---------------------------------------------------------------------------
class Analizador:
    def __init__(self, config: dict | None = None, reglas: dict | None = None):
        self.cfg = config or cargar_config()
        self.reglas = reglas or cargar_reglas()
        self.um = self.cfg["umbrales"]
        self.nom = {k: (re.compile(v, re.I) if isinstance(v, str) else v)
                    for k, v in self.cfg["nomenclatura"].items() if not k.startswith("_")}
        self.max_por_regla = self.cfg.get("max_hallazgos_por_regla_archivo", 25)
        self.indice_global: dict = {"specs": {}, "pkg_refs": {}, "triggers": []}

    # ---- API ---------------------------------------------------------------
    def analizar(self, archivos: dict[str, str], lineas_cambiadas: dict | None = None) -> dict:
        """archivos: {ruta: contenido}. lineas_cambiadas: {ruta: set(lineas)} para filtrar."""
        hallazgos, suprimidos, omitidos, info_archivos = [], [], {}, []
        fuentes = {}
        for ruta, txt in archivos.items():
            src = Fuente(ruta, txt)
            est = Estructura(src)
            fuentes[ruta] = (src, est)
            self._indexar(src, est)
        for ruta, (src, est) in fuentes.items():
            ctx = Contexto(self, src, est)
            try:
                ctx.ejecutar()
            except Exception as ex:  # una regla defectuosa no debe tumbar el análisis
                ctx.add("000", 1, f"Error interno del analizador: {ex!r}", confianza="media")
            hs = ctx.hallazgos
            if lineas_cambiadas is not None and ruta in lineas_cambiadas:
                hs = [h for h in hs if h.linea in lineas_cambiadas[ruta]]
            h_ok, h_sup = ctx.aplicar_supresiones(hs)
            hallazgos += h_ok
            suprimidos += h_sup
            for k, v in ctx.omitidos.items():
                omitidos[f"{ruta}::{k}"] = v
            info_archivos.append({"ruta": ruta, "lineas": len(src.lines),
                                  "unidades": [f"{u.kind} {u.name}" for u in est.unidades
                                               if u.parent is None or u.parent.kind.startswith("PACKAGE")][:50],
                                  "hallazgos": len(h_ok), "supresiones_invalidas": ctx.supresiones_invalidas})
        hallazgos += self._reglas_globales(fuentes)
        for h in hallazgos + suprimidos:
            self._enriquecer(h)
        # Reglas desactivadas desde el dashboard de reglas no generan hallazgos
        hallazgos = [h for h in hallazgos if regla_activa(self.reglas, h.regla)]
        suprimidos = [h for h in suprimidos if regla_activa(self.reglas, h.regla)]
        hallazgos.sort(key=lambda h: (SEV_ORDER.get(h.severidad, 9), h.archivo, h.linea))
        return {"hallazgos": hallazgos, "suprimidos": suprimidos, "omitidos": omitidos, "archivos": info_archivos}

    def _enriquecer(self, h: Hallazgo):
        r = self.reglas.get(h.regla)
        if r:
            h.severidad = h.severidad or r["severidad"]
            h.categoria = r["categoria"]
            h.titulo = r["regla"]
            h.mensaje = r["mensaje"]
            h.ejemplo_correcto = r["ejemplo_correcto"]
        else:
            h.severidad = h.severidad or "INFO"
            h.titulo = h.titulo or "Hallazgo del analizador"
        h.regla = h.regla if h.regla.startswith("ORA-") else f"ORA-{h.regla}"
        h.relacionadas = [r if r.startswith("ORA-") else f"ORA-{r}" for r in h.relacionadas]

    # ---- índice global (reglas multi-archivo) -----------------------------
    def _indexar(self, src: Fuente, est: Estructura):
        for u in est.unidades:
            if u.kind == "PACKAGE":
                body = src.code[src.tokens[u.tok_is].end:u.end]
                pub = {m.group(2).upper() for m in re.finditer(r"\b(PROCEDURE|FUNCTION)\s+([\w$#]+)", body, re.I)}
                self.indice_global["specs"][u.name] = pub
            if u.kind in ("PACKAGE BODY", "PACKAGE"):
                refs = {bare(m.group(1)) for m in re.finditer(r"\b([A-Za-z_][\w$#]*)\s*\.\s*[A-Za-z_]", src.code[u.start:u.end])}
                self.indice_global["pkg_refs"].setdefault(u.name, set()).update(refs - {u.name})
            if u.kind == "TRIGGER":
                hdr = src.code[u.start:src.tokens[u.tok_begin].pos if u.tok_begin > 0 else u.end]
                m = re.search(r"\b(BEFORE|AFTER|INSTEAD\s+OF)\s+(.*?)\s+ON\s+([\w$#.\"]+)", hdr, re.I | re.S)
                if m:
                    eventos = set(re.findall(r"INSERT|UPDATE|DELETE", m.group(2).upper()))
                    nivel = "ROW" if re.search(r"FOR\s+EACH\s+ROW", hdr, re.I) else "STATEMENT"
                    self.indice_global["triggers"].append(
                        (bare(m.group(3)), m.group(1).upper(), nivel, eventos, src.ruta, src.line(u.start), u.name))

    def _reglas_globales(self, fuentes) -> list[Hallazgo]:
        res = []
        refs = self.indice_global["pkg_refs"]
        vistos = set()
        for a, deps in refs.items():
            for b in deps:
                if b in refs and a in refs[b] and (b, a) not in vistos:
                    vistos.add((a, b))
                    ruta, linea = self._ubicar(fuentes, a)
                    res.append(Hallazgo("182", ruta, linea, f"Dependencia circular entre paquetes {a} ⇄ {b}.",
                                        confianza="media", relacionadas=["104"]))
        grupos: dict = {}
        for (tabla, momento, nivel, eventos, ruta, linea, nombre) in self.indice_global["triggers"]:
            for ev in eventos:
                grupos.setdefault((tabla, momento, nivel, ev), []).append((ruta, linea, nombre))
        for (tabla, momento, nivel, ev), lst in grupos.items():
            if len(lst) > 1:
                ruta, linea, _ = lst[0]
                res.append(Hallazgo("188", ruta, linea,
                                    f"{len(lst)} triggers {momento} {ev} {nivel} sobre {tabla}: "
                                    + ", ".join(x[2] for x in lst) + ". El orden de ejecución no está garantizado.",
                                    confianza="media"))
        return res

    def _ubicar(self, fuentes, pkg):
        for ruta, (src, est) in fuentes.items():
            for u in est.unidades:
                if u.name == pkg and u.kind == "PACKAGE BODY":
                    return ruta, src.line(u.start)
        return "", 1


class Contexto:
    """Ejecuta todas las reglas sobre un archivo."""

    def __init__(self, motor: Analizador, src: Fuente, est: Estructura):
        self.m, self.src, self.est = motor, src, est
        self.code, self.nocomm = src.code, src.nocomm
        self.hallazgos: list[Hallazgo] = []
        self.omitidos: dict[str, int] = {}
        self._conteo: dict[str, int] = {}
        self._vistos: set = set()
        self.supresiones_invalidas: list = []

    # ---- registro ---------------------------------------------------------
    def add(self, regla, donde, detalle, confianza="alta", relacionadas=()):
        linea = donde[0] if isinstance(donde, tuple) else self.src.line(donde)
        key = (regla, linea, detalle)
        if key in self._vistos:
            return
        self._vistos.add(key)
        c = self._conteo.get(regla, 0) + 1
        self._conteo[regla] = c
        if c > self.m.max_por_regla:
            self.omitidos[regla] = self.omitidos.get(regla, 0) + 1
            return
        frag = self.src.line_text(linea).strip()[:220]
        self.hallazgos.append(Hallazgo(regla, self.src.ruta, linea, detalle, frag, confianza, list(relacionadas)))

    def L(self, n: int):
        """Marca un número de línea explícito para add()."""
        return (n,)

    # ---- supresiones ------------------------------------------------------
    def aplicar_supresiones(self, hs: list[Hallazgo]):
        qg = self.m.cfg["quality_gate"]
        if not qg.get("permitir_supresiones", True):
            return hs, []
        linea_sup: dict[int, dict] = {}
        archivo_sup: dict[str, str] = {}
        for ln, txt in self.src.comments:
            m = re.search(r"oravalidator\s*:\s*(ignore-file|ignore)\s+((?:ORA-\d{3}\s*,?\s*)+)(.*)", txt, re.I)
            if not m:
                continue
            ids = re.findall(r"ORA-\d{3}", m.group(2).upper())
            just = m.group(3).strip(" -:*/")
            if qg.get("supresion_requiere_justificacion", True) and len(just) < 10:
                self.supresiones_invalidas.append({"linea": ln, "reglas": ids,
                                                   "motivo": "Supresión sin justificación (mín. 10 caracteres): no se aplicó."})
                continue
            for i in ids:
                if m.group(1).lower() == "ignore-file":
                    archivo_sup[i] = just
                else:
                    for target in (ln, ln + 1):
                        linea_sup.setdefault(target, {})[i] = just
        ok, sup = [], []
        for h in hs:
            rid = h.regla if h.regla.startswith("ORA-") else f"ORA-{h.regla}"
            just = archivo_sup.get(rid) or linea_sup.get(h.linea, {}).get(rid)
            if just:
                h.justificacion = just
                sup.append(h)
            else:
                ok.append(h)
        return ok, sup

    # ---- orquestación -----------------------------------------------------
    def ejecutar(self):
        for nombre in sorted(dir(self)):
            if nombre.startswith("r_"):
                getattr(self, nombre)()

    # ---- utilidades -------------------------------------------------------
    def find(self, pattern, text=None, flags=re.I):
        return re.finditer(pattern, self.code if text is None else text, flags)

    def stmt(self, pos: int) -> tuple[int, int]:
        end = self.code.find(";", pos)
        return pos, (len(self.code) if end < 0 else end)

    def unidades(self, *kinds):
        return [u for u in self.est.unidades if not kinds or u.kind in kinds]

    def unit_text(self, u: Unidad, view="code"):
        return getattr(self, view)[u.start:u.end]

    def body_span(self, u: Unidad) -> tuple[int, int]:
        t = self.src.tokens
        a = t[u.tok_begin].pos if u.tok_begin >= 0 else t[u.tok_is].end
        return a, u.end

    def mask_nested(self, u: Unidad, a: int, b: int) -> str:
        seg = list(self.code[a:b])
        for o in self.est.unidades:
            if o is not u and o.start >= a and o.end <= b and o.start > u.start:
                for k in range(o.start - a, o.end - a):
                    if seg[k] != "\n":
                        seg[k] = " "
        return "".join(seg)

    def es_variable_nombre(self, w: str) -> bool:
        return bool(re.match(r"^(P|V|L|G|LV|GV|PI|PO|PIO|C|K)_", w, re.I))

    def dml_statements(self):
        """Yield (kind, start, end, texto) de sentencias DML reales."""
        code = self.code
        for m in self.find(r"\bUPDATE\s+(?!OF\b)([\w$#.\"]+)(\s+(?!SET\b)[A-Za-z_]\w*)?\s+SET\b"):
            prev = re.findall(r"[A-Za-z_]+", code[max(0, m.start() - 20):m.start()])
            if prev and prev[-1].upper() in ("FOR", "BEFORE", "AFTER", "OR", "ON", "GRANT", "OF"):
                continue
            a, b = self.stmt(m.start())
            yield "UPDATE", a, b, code[a:b], bare(m.group(1))
        for m in self.find(r"\bDELETE\s+(FROM\s+)?([\w$#.\"]+)"):
            nm = m.group(2).upper()
            if nm in ("ON", "OR", "WHERE", "CASCADE", "ANY") or nm.endswith(".DELETE"):
                continue
            prev = re.findall(r"[A-Za-z_]+|,", code[max(0, m.start() - 25):m.start()])
            if prev and prev[-1].upper() in ("BEFORE", "AFTER", "OR", "ON", "GRANT", ",", "THEN", "OF"):
                if prev[-1].upper() != "THEN":
                    continue
            if code[m.start() - 1:m.start()] == ".":
                continue
            a, b = self.stmt(m.start())
            if prev and prev[-1].upper() == "THEN" and "MATCHED" in code[max(0, m.start() - 200):m.start()].upper():
                continue  # rama DELETE de MERGE
            yield "DELETE", a, b, code[a:b], bare(nm)
        for m in self.find(r"\bINSERT\s+INTO\s+([\w$#.\"]+)"):
            a, b = self.stmt(m.start())
            yield "INSERT", a, b, code[a:b], bare(m.group(1))
        for m in self.find(r"\bMERGE\s+INTO\s+([\w$#.\"]+)"):
            a, b = self.stmt(m.start())
            yield "MERGE", a, b, code[a:b], bare(m.group(1))

    def selects(self):
        for m in self.find(r"\bSELECT\b"):
            a, b = self.stmt(m.start())
            yield m.start(), b, self.code[m.start():b]

    # =====================================================================
    # NAMING CONVENTION (ORA-001 a ORA-015)
    # =====================================================================
    def r_001_tablas_columnas(self):
        nom = self.m.nom
        for m in self.find(r"\bCREATE\s+(?:(?:GLOBAL|PRIVATE)\s+TEMPORARY\s+|SHARDED\s+|DUPLICATED\s+|BLOCKCHAIN\s+|IMMUTABLE\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([\w$#.\"]+)"):
            nombre = bare(m.group(1))
            if not nom["tabla"].match(nombre):
                self.add("001", m.start(1), f"Tabla '{nombre}' no cumple el patrón {nom['tabla'].pattern}.")
            if nombre in RESERVADAS:
                self.add("015", m.start(1), f"La tabla usa la palabra reservada '{nombre}'.")
            p = self.code.find("(", m.end())
            if p < 0 or self.code[m.end():p].strip().upper().startswith("AS"):
                continue
            if re.match(r"\s*(AS|OF)\b", self.code[m.end():p], re.I):
                continue
            cl = match_paren(self.code, p)
            cols_case = set()
            for off, piece in split_top(self.code[p + 1:cl]):
                pz = piece.strip()
                w = re.match(r'("?[A-Za-z_][\w$#]*"?)', pz)
                if not w or w.group(1).upper() in ("CONSTRAINT", "PRIMARY", "FOREIGN", "UNIQUE", "CHECK",
                                                    "SUPPLEMENTAL", "PERIOD", "SCOPE", "REF"):
                    continue
                col = w.group(1)
                pos = p + 1 + off + (len(piece) - len(piece.lstrip()))
                cname = col.strip('"')
                cols_case.add("lower" if cname.islower() else "upper" if cname.isupper() else "mixed")
                if not nom["columna"].match(cname) or not cname.isupper():
                    self.add("002", pos, f"Columna '{cname}' no cumple la convención (mayúsculas, patrón {nom['columna'].pattern}).")
                elif len(cname) < self.m.um["MinIdentifierLength"]:
                    self.add("013", pos, f"Columna '{cname}' tiene un nombre demasiado corto.")
                if cname.upper() in RESERVADAS:
                    self.add("015", pos, f"La columna usa la palabra reservada '{cname.upper()}'.")

    def r_201_longitud_identificadores(self):
        """ORA-201: ningún identificador (tabla, columna, restricción, índice, vista, secuencia, sinónimo, tipo,
        paquete, procedimiento, función, trigger, variable, constante o parámetro) supera MaxIdentifierLength."""
        mx = self.m.um.get("MaxIdentifierLength")
        if not mx:
            return
        vistos = set()

        def chk(nombre, tipo, pos):
            n = str(nombre).strip('"')
            if not n:
                return
            nb = len(n.encode("utf-8"))
            if nb > mx and (n.upper(), pos) not in vistos:
                vistos.add((n.upper(), pos))
                unidad = "caracteres" if nb == len(n) else "bytes"
                self.add("201", pos, f"{tipo} '{n}' tiene {nb} {unidad} (máximo {mx}).")

        tipos = {"TABLE": "Tabla", "VIEW": "Vista", "SEQUENCE": "Secuencia", "SYNONYM": "Sinónimo", "TYPE": "Tipo",
                 "TYPE BODY": "Tipo", "INDEX": "Índice", "PACKAGE": "Paquete", "PACKAGE BODY": "Paquete",
                 "PROCEDURE": "Procedimiento", "FUNCTION": "Función", "TRIGGER": "Trigger", "MATERIALIZED VIEW": "Vista materializada"}
        for m in self.find(r"\bCREATE\s+(?:OR\s+REPLACE\s+)?(?:(?:EDITIONABLE|NONEDITIONABLE|EDITIONING|FORCE|NO\s+FORCE|GLOBAL\s+TEMPORARY|PRIVATE\s+TEMPORARY|PUBLIC|UNIQUE|BITMAP|SHARDED|DUPLICATED|BLOCKCHAIN|IMMUTABLE)\s+)*"
                           r"(MATERIALIZED\s+VIEW|TABLE|VIEW|SEQUENCE|SYNONYM|TYPE\s+BODY|TYPE|INDEX|PACKAGE\s+BODY|PACKAGE|PROCEDURE|FUNCTION|TRIGGER)\s+(?:IF\s+NOT\s+EXISTS\s+)?([\w$#.\"]+)"):
            chk(bare(m.group(2)), tipos[re.sub(r"\s+", " ", m.group(1).upper())], m.start(2))
        for m in self.find(r"\bCONSTRAINT\s+([\w$#\"]+)"):
            chk(bare(m.group(1)), "Restricción", m.start(1))
        for cname, pos in self._columnas_tablas():
            chk(cname, "Columna", pos)
        t = self.src.tokens
        for u in self.est.unidades:
            if u.kind in ("PROCEDURE", "FUNCTION") and (u.parent is not None or not u.standalone):
                chk(u.name, "Procedimiento" if u.kind == "PROCEDURE" else "Función", t[u.tok_header + 1].pos)
            for name, kind, typ, txt, pos in u.decls:
                chk(name, "Constante" if kind == "const" else "Variable", pos)
            for name, mode, typ, pos in u.params:
                chk(name, "Parámetro", pos)

    def _columnas_tablas(self):
        """(nombre, posición) de cada columna declarada en CREATE TABLE ... ( ... )."""
        for m in self.find(r"\bCREATE\s+(?:(?:GLOBAL|PRIVATE)\s+TEMPORARY\s+|SHARDED\s+|DUPLICATED\s+|BLOCKCHAIN\s+|IMMUTABLE\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([\w$#.\"]+)"):
            p = self.code.find("(", m.end())
            if p < 0 or re.match(r"\s*(AS|OF)\b", self.code[m.end():p], re.I):
                continue
            cl = match_paren(self.code, p)
            for off, piece in split_top(self.code[p + 1:cl]):
                w = re.match(r'("?[A-Za-z_][\w$#]*"?)', piece.strip())
                if not w or w.group(1).upper() in ("CONSTRAINT", "PRIMARY", "FOREIGN", "UNIQUE", "CHECK", "SUPPLEMENTAL", "PERIOD", "SCOPE", "REF"):
                    continue
                yield w.group(1).strip('"'), p + 1 + off + (len(piece) - len(piece.lstrip()))

    def r_003_constraints(self):
        nom = self.m.nom
        for m in self.find(r"\bCONSTRAINT\s+([\w$#\"]+)\s+(PRIMARY\s+KEY|FOREIGN\s+KEY|REFERENCES)"):
            nombre, tipo = bare(m.group(1)), m.group(2).upper()
            if tipo.startswith("PRIMARY") and not nom["primary_key"].match(nombre):
                self.add("003", m.start(1), f"Primary Key '{nombre}' no cumple el patrón {nom['primary_key'].pattern}.")
            elif not tipo.startswith("PRIMARY") and not nom["foreign_key"].match(nombre):
                self.add("004", m.start(1), f"Foreign Key '{nombre}' no cumple el patrón {nom['foreign_key'].pattern}.")
        for m in self.find(r"\bCREATE\s+(?:UNIQUE\s+|BITMAP\s+)?INDEX\s+(?:IF\s+NOT\s+EXISTS\s+)?([\w$#.\"]+)"):
            nombre = bare(m.group(1))
            if not nom["indice"].match(nombre):
                self.add("005", m.start(1), f"Índice '{nombre}' no cumple el patrón {nom['indice'].pattern}.")

    def r_006_unidades(self):
        nom = self.m.nom
        mapa = {"PROCEDURE": ("006", "procedimiento"), "FUNCTION": ("007", "funcion"),
                "PACKAGE": ("008", "paquete"), "TRIGGER": ("009", "trigger")}
        for u in self.est.unidades:
            if u.kind == "PACKAGE BODY":
                if u.name in self.m.indice_global["specs"]:
                    continue
                u = Unidad("PACKAGE", u.name, u.start, u.end, u.tok_header, u.tok_is)
            rid, key = mapa[u.kind]
            if not nom[key].match(u.name):
                self.add(rid, self.src.tokens[u.tok_header].pos,
                         f"{u.kind.title()} '{u.name}' no cumple el patrón {nom[key].pattern}.")

    def r_010_variables_parametros(self):
        nom, um = self.m.nom, self.m.um
        ambiguos = {x.upper() for x in nom.get("nombres_ambiguos", [])}

        def base(n):
            return n.split("_", 1)[1] if "_" in n and re.match(r"^[A-Z]{1,3}_", n) else n

        for u in self.est.unidades:
            pkg_level = u.kind in ("PACKAGE", "PACKAGE BODY")
            for name, kind, typ, txt, pos in u.decls:
                if kind == "const":
                    if not nom["constante"].match(name):
                        self.add("012", pos, f"Constante '{name}' no cumple el patrón {nom['constante'].pattern}.")
                else:
                    pat = nom["variable_global"] if pkg_level else nom["variable_local"]
                    if not pat.match(name):
                        self.add("010", pos, f"Variable {'global' if pkg_level else 'local'} '{name}' no cumple el patrón {pat.pattern}.")
                self._nombre_calidad(name, base(name), pos, ambiguos, um)
            for name, mode, typ, pos in u.params:
                if not nom["parametro"].match(name):
                    self.add("011", pos, f"Parámetro '{name}' no cumple el patrón {nom['parametro'].pattern}.")
                self._nombre_calidad(name, base(name), pos, ambiguos, um)

    def _nombre_calidad(self, name, b, pos, ambiguos, um):
        if len(name) < um["MinIdentifierLength"] or len(b) < 2:
            self.add("013", pos, f"Identificador '{name}' es demasiado corto para ser descriptivo.")
        if b in ambiguos or name in ambiguos:
            self.add("014", pos, f"Identificador '{name}' es ambiguo: no describe su contenido.")
        if name in RESERVADAS:
            self.add("015", pos, f"Identificador '{name}' es palabra reservada de Oracle.")

    # =====================================================================
    # FORMATO (ORA-016 a ORA-025)
    # =====================================================================
    def r_016_formato_lineas(self):
        um = self.m.um
        code_lines = self.code.split("\n")
        tab_lines, space_lines = [], []
        blanks = 0
        for n, raw in enumerate(self.src.lines, 1):
            ind = raw[:len(raw) - len(raw.lstrip())]
            if "\t" in ind and " " in ind:
                self.add("016", self.L(n), "Indentación mezcla tabuladores y espacios.")
            elif "\t" in ind:
                tab_lines.append(n)
            elif ind:
                space_lines.append(n)
            if len(raw) > um["MaxLineLength"]:
                self.add("019", self.L(n), f"Línea de {len(raw)} caracteres (máximo {um['MaxLineLength']}).")
            if raw.strip() == "":
                blanks += 1
                if blanks == um["MaxBlankLines"] + 1:
                    self.add("022", self.L(n), f"Más de {um['MaxBlankLines']} líneas vacías consecutivas.")
            else:
                blanks = 0
            cl = code_lines[n - 1] if n - 1 < len(code_lines) else ""
            # 017 keywords en minúsculas
            for w in re.findall(r"\b[A-Za-z_]+\b", cl):
                if w.upper() in KEYWORDS_FORMATO and w != w.upper():
                    self.add("017", self.L(n), f"Palabra clave '{w}' debe escribirse en mayúsculas.")
                    break
            # 018 varias instrucciones por línea
            partes = [p for p in cl.split(";")[:-1] if p.strip()]
            if len(partes) >= 2 and not re.match(r"^\s*(END\b.*;\s*)+$", cl, re.I):
                self.add("018", self.L(n), "Hay más de una instrucción en la misma línea.")
            # 021 espacios innecesarios
            if re.search(r"\S {2,}(?=\b(FROM|WHERE|AND|OR|SET|INTO|JOIN|ON|VALUES)\b)|\b(SELECT|FROM|WHERE|AND|OR|SET|INTO|JOIN|ON|UPDATE|DELETE|INSERT) {2,}\S",
                         cl.strip(), re.I):
                self.add("021", self.L(n), "Espacios múltiples innecesarios entre elementos de la sentencia.")
        if tab_lines and space_lines:
            menor = tab_lines if len(tab_lines) < len(space_lines) else space_lines
            self.add("016", self.L(menor[0]),
                     f"Indentación inconsistente: {len(tab_lines)} líneas con tabuladores y {len(space_lines)} con espacios.")

    def r_020_terminacion(self):
        code = self.code
        last_semi = code.rfind(";")
        tail = code[last_semi + 1:] if last_semi >= 0 else code
        tail_clean = re.sub(r"^\s*/\s*$", "", tail, flags=re.M).strip()
        if tail_clean and re.search(r"[A-Za-z]", tail_clean):
            pos = (last_semi + 1) + tail.find(tail_clean[:5])
            self.add("020", pos, "La última sentencia del archivo no termina con ';'.")
        # Unidades PL/SQL CREATE sin '/' antes de la siguiente sentencia (SQL*Plus)
        for u in self.est.unidades:
            if not u.standalone or (u.parent is not None):
                continue
            after = code[u.end:]
            m = re.match(r"(\s*)(\S)", after)
            if m and m.group(2) != "/":
                self.add("020", u.end - 1, f"{u.kind} {u.name}: falta la línea '/' después del bloque; "
                                           "en SQL*Plus/SQLcl la siguiente sentencia quedará dentro del objeto.")

    def r_023_comentarios(self):
        vagos = {"HACER", "TODO", "FIXME", "XXX", "OK", "?", "PRUEBA", "TEST", "TEMPORAL", "AQUI", "REVISAR",
                 "CAMBIO", "NUEVO", "COMENTARIO", "ARREGLAR", "HACK", "TMP", "FIX"}
        code_kw = re.compile(
            r"^\s*(SELECT\b.*\bFROM\b|INSERT\s+INTO\b|UPDATE\s+\S+\s+SET\b|DELETE\s+(FROM\s+)?\S+|MERGE\s+INTO\b|COMMIT\s*;|ROLLBACK\s*;|"
            r"IF\b.*\bTHEN\b|END\s+(IF|LOOP)\s*;|EXECUTE\s+IMMEDIATE\b|DBMS_OUTPUT\.|[A-Za-z_][\w.]*\s*:=.*;|"
            r"RAISE\b.*;|OPEN\s+\w+|FETCH\s+\w+|CLOSE\s+\w+\s*;|RETURN\b.*;|NULL\s*;)", re.I)
        for ln, txt in self.src.comments:
            t = txt.strip(" -*/\t")
            if not t or "oravalidator" in t.lower():
                continue
            if code_kw.match(t):
                self.add("025", self.L(ln), "Código comentado: elimínelo (el historial queda en git).")
                continue
            letras = re.sub(r"[^A-Za-zÁÉÍÓÚáéíóúñÑ ]", "", t).strip()
            palabras = letras.upper().split()
            if not letras:
                continue
            if (len(palabras) <= 2 and (palabras[0] in vagos or len(letras) < 4)) or re.match(r"^(TODO|FIXME|HACK|XXX)\b", t, re.I):
                self.add("023", self.L(ln), f"Comentario poco descriptivo o pendiente: «{t[:60]}».", confianza="media")

    # =====================================================================
    # MANTENIBILIDAD / PL-SQL estructural
    # =====================================================================
    def r_026_tamanos(self):
        um = self.m.um
        for u in self.est.unidades:
            n = self.src.line(u.end) - self.src.line(u.start) + 1
            pos = self.src.tokens[u.tok_header].pos
            if u.kind == "PROCEDURE" and n > um["MaxProcedureLines"]:
                self.add("027", pos, f"Procedimiento {u.name} tiene {n} líneas (máximo {um['MaxProcedureLines']}).", relacionadas=["100"])
            elif u.kind == "FUNCTION" and n > um["MaxFunctionLines"]:
                self.add("101", pos, f"Función {u.name} tiene {n} líneas (máximo {um['MaxFunctionLines']}).")
            elif u.kind in ("PACKAGE", "PACKAGE BODY") and n > um["MaxPackageLines"]:
                self.add("181", pos, f"{u.kind} {u.name} tiene {n} líneas (máximo {um['MaxPackageLines']}).")
            elif u.kind == "TRIGGER" and n > um["MaxTriggerLines"]:
                self.add("186", pos, f"Trigger {u.name} tiene {n} líneas (máximo {um['MaxTriggerLines']}).")
            if u.kind not in ("PACKAGE", "PACKAGE BODY") and n > um["MaxBlockLines"]:
                self.add("026", pos, f"Bloque {u.name} de {n} líneas supera el máximo de {um['MaxBlockLines']}.")

    def r_028_complejidad_anidamiento(self):
        um = self.m.um
        t = self.src.tokens
        for u in self.unidades("PROCEDURE", "FUNCTION", "TRIGGER"):
            if u.tok_begin < 0:
                continue
            txt = self.mask_nested(u, t[u.tok_begin].pos, u.end)
            cc = 1 + len(re.findall(r"\b(IF|ELSIF|WHEN|WHILE)\b", txt, re.I)) \
                + len(re.findall(r"(?<!END )\bLOOP\b", txt, re.I)) - len(re.findall(r"\bEND\s+IF\b", txt, re.I))
            if cc > um["MaxCyclomaticComplexity"]:
                self.add("102", t[u.tok_header].pos,
                         f"{u.name}: complejidad ciclomática estimada {cc} (máximo {um['MaxCyclomaticComplexity']}).",
                         relacionadas=["028"])
            # anidamiento IF/LOOP/CASE
            base = None
            maxd, maxpos, loopd, looppos = 0, 0, 0, 0
            for b in self.est.bloques:
                if not (u.start <= b.start <= u.end) or b.kind == "BEGIN":
                    continue
                inner = self.est.unit_at(b.start)
                if inner is not u:
                    continue
                d = sum(1 for o in self.est.bloques if o.kind in ("IF", "LOOP", "CASE")
                        and o.start <= b.start and b.end <= o.end and u.start <= o.start)
                if d > maxd:
                    maxd, maxpos = d, b.start
                if b.kind == "LOOP":
                    ld = sum(1 for o in self.est.bloques if o.kind == "LOOP" and o.start <= b.start and b.end <= o.end and u.start <= o.start)
                    if ld > loopd:
                        loopd, looppos = ld, b.start
                if b.kind == "CASE":
                    nw = len(re.findall(r"\bWHEN\b", strip_parens(self.code[b.start:b.end]), re.I))
                    if nw > um["MaxCaseWhen"]:
                        self.add("085", b.start, f"CASE con {nw} ramas WHEN (máximo {um['MaxCaseWhen']}).")
            if maxd > um["MaxNestingDepth"]:
                self.add("103", maxpos, f"{u.name}: {maxd} niveles de anidamiento IF/LOOP/CASE (máximo {um['MaxNestingDepth']}).",
                         relacionadas=["084"])
            if loopd > 2:
                self.add("086", looppos, f"{u.name}: {loopd} loops anidados; extraiga la lógica o use operaciones de conjunto.")

    def r_030_duplicados(self):
        um = self.m.um
        win, rep = um["DuplicateBlockLines"], um["DuplicateBlockRepeats"]
        norm = [re.sub(r"\s+", " ", l.strip().upper()) for l in self.code.split("\n")]
        idx = [(i + 1, l) for i, l in enumerate(norm) if l]
        hashes: dict[str, list[int]] = {}
        for k in range(len(idx) - win + 1):
            chunk = [l for _, l in idx[k:k + win]]
            if sum(1 for l in chunk if len(l) > 15) < 3:
                continue
            h = hashlib.md5("\n".join(chunk).encode()).hexdigest()
            hashes.setdefault(h, []).append(idx[k][0])
        usados = set()
        for h, lines in hashes.items():
            if len(lines) >= rep and lines[0] not in usados:
                self.add("030", self.L(lines[0]),
                         f"Bloque de {win}+ líneas repetido {len(lines)} veces (líneas {', '.join(map(str, lines[:6]))}). Extráigalo a una rutina.")
                for l in lines:
                    usados.update(range(l, l + win))

    def r_076_variables(self):
        """077 no usadas, 079 VARCHAR2 grandes, 090/091/092 parámetros, 095 conversiones implícitas, 076 no declaradas."""
        um = self.m.um
        declarados_archivo = set()
        for u in self.est.unidades:
            declarados_archivo.update(d[0] for d in u.decls)
            declarados_archivo.update(p[0] for p in u.params)
        declarados_archivo.update(m.group(1).upper() for m in self.find(r"\bFOR\s+([A-Za-z_]\w*)\s+IN\b"))
        tiene_pkg = any(u.kind.startswith("PACKAGE") for u in self.est.unidades)

        for u in self.est.unidades:
            if u.kind in ("PACKAGE", "PACKAGE BODY"):
                continue
            utext = self.unit_text(u).upper()
            a, b = self.body_span(u)
            body = self.code[a:b].upper()
            tipos = {}
            for name, kind, typ, txt, pos in u.decls:
                tipos[name] = typ.split("(")[0]
                usos = len(re.findall(rf"(?<![\w$#.]){re.escape(name)}(?![\w$#])", utext))
                if usos <= 1:
                    self.add("077", pos, f"{'Constante' if kind == 'const' else 'Variable'} '{name}' declarada y no utilizada.")
                mv = re.search(r"VARCHAR2\s*\(\s*(\d+)", txt, re.I)
                if mv and int(mv.group(1)) > um["MaxLocalVarchar2"]:
                    self.add("079", pos, f"'{name}' declarada como VARCHAR2({mv.group(1)}); dimensione según el dato real o use %TYPE.")
            for name, mode, typ, pos in u.params:
                tipos[name] = typ.split("(")[0]
                occ = len(re.findall(rf"(?<![\w$#.]){re.escape(name)}(?![\w$#])", body))
                if occ == 0:
                    self.add("090", pos, f"Parámetro '{name}' no se utiliza en el cuerpo de {u.name}.")
                    continue
                if mode in ("OUT", "IN OUT") and not self._modificado(name, body):
                    if mode == "OUT":
                        self.add("091", pos, f"Parámetro OUT '{name}' nunca se asigna: siempre devolverá NULL.", confianza="media")
                    else:
                        self.add("092", pos, f"Parámetro IN OUT '{name}' solo se lee; decláralo IN.", confianza="media")
            # 095 asignaciones con conversión implícita
            for m in re.finditer(r"(?<![\w$#.])([A-Z_][\w$#]*)\s*:=\s*([A-Z_][\w$#]*)\s*;", body):
                l, r = m.group(1), m.group(2)
                fl, fr = self._familia(tipos.get(l)), self._familia(tipos.get(r))
                if fl and fr and fl != fr:
                    self.add("095", a + m.start(), f"Asignación {l} ({tipos[l]}) := {r} ({tipos[r]}) provoca conversión implícita.")
            # 076 variables con prefijo de convención usadas sin declarar
            for m in re.finditer(r"(?<![\w$#.:'])((?:V|L|LV)_[A-Z0-9_$#]+)(?![\w$#.(])", body):
                nm = m.group(1)
                if nm not in declarados_archivo and nm not in tipos:
                    self.add("076", a + m.start(), f"'{nm}' se usa en {u.name} pero no está declarada en el archivo.",
                             confianza="media" if tiene_pkg else "alta")
                    declarados_archivo.add(nm)

    def _modificado(self, name: str, body: str) -> bool:
        n = re.escape(name)
        if re.search(rf"(?<![\w$#.]){n}(\s*\([^;]*?\))?(\.[\w$#]+)*\s*:=", body):
            return True
        if re.search(rf"\bINTO\b[^;]*?(?<![\w$#.]){n}(?![\w$#])", body):
            return True
        if re.search(rf"\b(FETCH|OPEN)\b[^;]*(?<![\w$#.]){n}(?![\w$#])", body):
            return True
        if re.search(rf"(?<![\w$#.]){n}\s*\.\s*(EXTEND|DELETE|TRIM)\b", body):
            return True
        # pasado como argumento a otra rutina (podría ser OUT) -> se considera modificado
        if re.search(rf"[\w$#.]+\s*\([^;]*(?<![\w$#.]){n}(?![\w$#])[^;]*\)\s*;", body):
            return True
        return False

    @staticmethod
    def _familia(t):
        if not t:
            return None
        t = t.upper()
        if "%" in t:
            return None
        if t in TIPOS_NUM:
            return "NUM"
        if t in TIPOS_CHAR:
            return "CHAR"
        if t in TIPOS_DATE or t.startswith("TIMESTAMP"):
            return "DATE"
        return None

    def r_078_globales_packages(self):
        nom = self.m.nom
        t = self.src.tokens
        for u in self.unidades("PACKAGE", "PACKAGE BODY"):
            spec = u.kind == "PACKAGE"
            for name, kind, typ, txt, pos in u.decls:
                if kind == "var":
                    if spec:
                        self.add("178", pos, f"Variable pública '{name}' en la especificación de {u.name}: exponga getters/setters.",
                                 relacionadas=["078", "184"])
                    else:
                        self.add("078", pos, f"Variable global '{name}' en el body de {u.name}: mantiene estado de sesión; justifique o elimínela.",
                                 confianza="media")
            dec_a = t[u.tok_is].end
            dec_b = t[u.tok_begin].pos if u.tok_begin >= 0 else u.end
            for m in re.finditer(r"\bCURSOR\s+([\w$#]+)[^;]*?\bIS\s+SELECT\b", self.code[dec_a:dec_b], re.I | re.S):
                inner = self.est.unit_at(dec_a + m.start())
                if inner is u:
                    self.add("135", dec_a + m.start(), f"Cursor '{m.group(1).upper()}' declarado a nivel de paquete.",
                             relacionadas=["176"] if spec else [])
            if spec:
                body = self.code[dec_a:u.end]
                if re.search(r"\bBEGIN\b", body, re.I):
                    self.add("176", u.start, f"La especificación {u.name} contiene implementación (BEGIN); muévala al body.")
                for m in re.finditer(r"\b(PROCEDURE|FUNCTION)\s+([\w$#]+)", body, re.I):
                    nm = m.group(2).upper()
                    if re.search(r"(INTERN|PRIV|AUX|HELPER|_INT$|_TMP$)", nm):
                        self.add("177", dec_a + m.start(), f"'{nm}' parece de uso interno y está expuesto en la especificación.",
                                 confianza="media")
                    ln = self.src.line(dec_a + m.start())
                    com = {c[0] for c in self.src.comments}
                    if not ({ln - 1, ln, ln + 1} & com):
                        self.add("183", dec_a + m.start(), f"API pública '{nm}' sin comentario de documentación.")
            elif u.tok_begin >= 0:
                self.add("179", t[u.tok_begin].pos, f"El body {u.name} tiene sección de inicialización; se ejecuta en cada sesión.",
                         confianza="media")
                # 180: subprogramas privados no referenciados
            if not spec:
                pub = self.m.indice_global["specs"].get(u.name)
                if pub is not None:
                    utext = self.unit_text(u).upper()
                    for sub in self.est.unidades:
                        if sub.parent is u and sub.name not in pub:
                            refs = len(re.findall(rf"(?<![\w$#]){re.escape(sub.name)}(?![\w$#])", utext))
                            # definición + END nombre (+ forward) = 2-3 ocurrencias sin uso
                            uses = refs - 1 - len(re.findall(rf"\bEND\s+{re.escape(sub.name)}\b", utext)) \
                                - len(re.findall(rf"\b(?:PROCEDURE|FUNCTION)\s+{re.escape(sub.name)}\b(?:(?!\b(?:IS|AS)\b)[^;])*;", utext))
                            if uses <= 0:
                                self.add("180", t[sub.tok_header].pos, f"Subprograma privado {sub.name} no se invoca en el paquete (código muerto).",
                                         confianza="media")

    def r_082_plsql_varios(self):
        for m in self.find(r"\b(TO_CHAR|TO_NUMBER|TO_DATE)\s*\(\s*\1\s*\("):
            self.add("082", m.start(), f"Conversión redundante {m.group(1).upper()}({m.group(1).upper()}(...)).")
        for m in self.find(r"\b(THEN|ELSE)\s+NULL\s*;"):
            if self.est.in_handler(m.end() - 2):
                continue
            self.add("088", m.start(), f"Rama '{m.group(1).upper()} NULL;' sin efecto: elimine la rama o la condición.")
        for m in self.find(r"\b(IF|ELSIF|WHILE)\s+(FALSE|1\s*=\s*0|0\s*=\s*1|1\s*=\s*2|1\s*<>\s*1)\b"):
            self.add("099", m.start(), "Condición siempre falsa: el bloque es código muerto.")
        for m in self.find(r"\b(RETURN|RAISE|GOTO)\b[^;]*;\s*(?!END\b|ELSE\b|ELSIF\b|WHEN\b|EXCEPTION\b|<<)([A-Za-z_]\w*)"):
            nxt = m.group(2).upper()
            if nxt in ("END", "ELSE", "ELSIF", "WHEN", "EXCEPTION", "PROCEDURE", "FUNCTION", "CREATE", "SHOW", "GRANT"):
                continue
            if self.est.unit_at(m.start()) is None or re.search(r"\b(IS|AS)\b", m.group(0), re.I) \
                    or not any(b.kind == "BEGIN" and b.start < m.start() < b.end for b in self.est.bloques):
                continue
            self.add("099", m.end(2) - len(nxt), f"Sentencias después de {m.group(1).upper()}: nunca se ejecutan.", confianza="media")
        for m in self.find(r"\bLOOP\s+NULL\s*;\s*END\s+LOOP"):
            self.add("134", m.start(), "Loop vacío (LOOP NULL; END LOOP).")
        for u in self.unidades("PROCEDURE", "FUNCTION"):
            a, b = self.body_span(u)
            body = self.mask_nested(u, a, b)
            body_no_end = re.sub(rf"\bEND\s+{re.escape(u.name)}\b", "", body, flags=re.I)
            mrec = re.search(rf"(?<![\w$#.]){re.escape(u.name)}\s*(\(|;)", body_no_end, re.I)
            if mrec:
                self.add("087", a + mrec.start(), f"{u.name} se invoca a sí mismo (recursividad).")
            if u.kind == "PROCEDURE" and re.search(r"\bRETURN\s*;\s*END\b[^;]*;\s*$", body.strip(), re.I) \
                    and not re.search(r"\bEXCEPTION\s+WHEN\b", body, re.I):
                self.add("093", u.end - 1, f"RETURN; innecesario al final de {u.name}.")
        # 096/097 literales mágicos en condiciones
        for m in self.find(r"\b(IF|ELSIF|WHEN)\b(.*?)\bTHEN\b", text=self.nocomm, flags=re.I | re.S):
            cond = m.group(2)
            if len(cond) > 300 or self.est.in_handler(m.start()) or m.group(1).upper() == "WHEN" and re.match(r"\s*[A-Z_]+\s*$", cond, re.I):
                continue
            lit = re.search(r"(=|<>|!=|<|>)\s*('[^']{1,20}'|\b(?!0\b|1\b)\d+\b)", cond)
            if lit:
                self.add("096", m.start(), f"Literal mágico {lit.group(2)} en condición: defínalo como constante con nombre.",
                         relacionadas=["097"])
        # 098 bloques anónimos
        for tk in self.src.tokens:
            if tk.w in ("DECLARE", "BEGIN") and tk.depth == 0 and self.est.unit_at(tk.pos) is None:
                self.add("098", tk.pos, "Bloque anónimo en script: en producción el código debe vivir en objetos versionados "
                                        "(o justificar si es script de migración).", confianza="media")

    # =====================================================================
    # SQL (ORA-031 a ORA-055)
    # =====================================================================
    def r_031_select(self):
        code = self.code
        for pos, end, s in self.selects():
            flat = strip_parens(s)
            sel_list = re.split(r"\bFROM\b", flat, 1, flags=re.I)[0]
            m = re.match(r"SELECT\s+(?:(?:DISTINCT|UNIQUE|ALL)\s+)?((?:[\w$#\"]+\.)?\*)", s, re.I)
            if m or re.search(r",\s*(?:[\w$#\"]+\.)?\*\s*(,|$)", sel_list):
                ctx = code[max(0, pos - 15):pos].upper()
                conf = "media" if "EXISTS" in ctx else "alta"
                self.add("031", pos, "SELECT * : liste explícitamente las columnas" + (" (en EXISTS use SELECT 1)." if conf == "media" else "."),
                         confianza=conf)
            if re.match(r"SELECT\s+(DISTINCT|UNIQUE)\b", s, re.I):
                self.add("036", pos, "DISTINCT: confirme que no oculta un JOIN incorrecto o duplicados de origen.",
                         confianza="media", relacionadas=["146"])
            if re.search(r"\bGROUP\s+BY\b", flat, re.I) and not re.search(AGREGADAS, s, re.I):
                self.add("038", pos, "GROUP BY sin funciones de agregación.", confianza="media")
            mh = re.search(r"\bHAVING\b(.*?)(\bORDER\b|\bUNION\b|\bMINUS\b|\bINTERSECT\b|$)", flat, re.I | re.S)
            if mh:
                full_having = s[mh.start(1):mh.end(1)]
                if not re.search(AGREGADAS, full_having, re.I):
                    self.add("039", pos, "Condición en HAVING sin agregación: muévala al WHERE.")
            if re.search(r"\bUNION\b(?!\s+ALL)", flat, re.I):
                self.add("147", pos, "UNION elimina duplicados con un ordenamiento; si no se requiere use UNION ALL.", confianza="media")
            # 050/153 funciones PL/SQL en la lista de SELECT
            sel_full = re.split(r"\bFROM\b", s, 1, flags=re.I)[0]
            fn = re.search(r"(?<![\w$#.])((?:PKG_[\w$#]+\.)?(?:FNC|FN|F)_[\w$#]+)\s*\(", sel_full, re.I)
            if fn and re.search(r"\bFROM\b", s, re.I):
                self.add("050", pos, f"Función PL/SQL {fn.group(1).upper()} invocada por cada fila del SELECT (cambios de contexto SQL↔PL/SQL).",
                         confianza="media", relacionadas=["153"])
            self._from_clause(pos, s)
        # 145 ORDER BY en subconsulta
        for m in self.find(r"\(\s*SELECT\b"):
            cl = match_paren(code, m.start())
            sub = strip_parens(code[m.start():cl + 1][1:-1])
            if re.search(r"\bORDER\s+BY\b", sub, re.I) and not re.search(r"\bROWNUM\b|\bFETCH\s+FIRST\b|\bOFFSET\b", code[cl:cl + 120] + sub, re.I):
                self.add("145", m.start(), "ORDER BY dentro de una subconsulta no aporta al resultado.", confianza="media", relacionadas=["037"])

    def _from_clause(self, pos, s):
        flat = strip_parens(s)
        mf = re.search(r"\bFROM\b(.*?)(\bWHERE\b|\bGROUP\b|\bORDER\b|\bCONNECT\b|\bSTART\b|\bUNION\b|\bMINUS\b|\bINTERSECT\b|\bHAVING\b|\bFETCH\b|\bFOR\s+UPDATE\b|$)",
                       flat, re.I | re.S)
        if not mf:
            return
        fc = mf.group(1)
        if re.match(r"\s*(DUAL)\s*$", fc, re.I):
            return
        no_kw = r"(?!(?:WHERE|INNER|LEFT|RIGHT|FULL|CROSS|NATURAL|JOIN|ON|USING|GROUP|ORDER|PARTITION|SAMPLE|AS|PIVOT|UNPIVOT|OUTER|CONNECT|START|UNION|MINUS)\b)"
        aliases = []
        for m in re.finditer(rf"(?:^|,|\bJOIN\b)\s*([\w$#.\"]+|\(\s*\))\s+(?:AS\s+)?{no_kw}([A-Za-z_][\w$#]*)", fc, re.I):
            al = m.group(2).upper()
            aliases.append(al)
            if len(al) <= 1:
                self.add("052", pos + mf.start(1) + m.start(2), f"Alias '{m.group(2)}' de una letra: use un alias descriptivo.")
        dup = {a for a in aliases if aliases.count(a) > 1}
        for a in dup:
            self.add("053", pos, f"Alias '{a}' repetido en la misma consulta.")
        # 048 JOIN sin condición
        for m in re.finditer(r"(?<!CROSS )(?<!NATURAL )\bJOIN\s+([\w$#.\"]+|\(\s*\))(\s+(?:AS\s+)?" + no_kw + r"[A-Za-z_][\w$#]*)?\s*(\S+)?", fc + " ;", re.I):
            if (m.group(3) or "").upper() not in ("ON", "USING"):
                prev = fc[max(0, m.start() - 10):m.start()].upper()
                if "CROSS" in prev or "NATURAL" in prev:
                    continue
                self.add("048", pos + mf.start(1) + m.start(), "JOIN sin cláusula ON/USING: producto cartesiano.")
        # 047 cartesiano con comas
        tablas = [p for _, p in split_top(fc) if p.strip()]
        if len(tablas) > 1 and not re.search(r"\bJOIN\b", fc, re.I):
            where = re.search(r"\bWHERE\b(.*)", flat, re.I | re.S)
            if not where:
                self.add("047", pos, f"FROM con {len(tablas)} tablas separadas por coma y sin WHERE: producto cartesiano.")
            else:
                cond = s[where.start(1):]
                als = []
                for p in tablas:
                    w = p.split()
                    als.append((w[-1] if len(w) > 1 else w[0]).split(".")[-1].upper())
                conectados = {als[0]}
                cambios = True
                while cambios:
                    cambios = False
                    for a in als:
                        if a in conectados:
                            continue
                        for c in list(conectados):
                            if re.search(rf"\b{re.escape(a)}\.\w+(\s*\(\+\))?\s*=\s*{re.escape(c)}\.\w+|\b{re.escape(c)}\.\w+(\s*\(\+\))?\s*=\s*{re.escape(a)}\.\w+",
                                         cond, re.I):
                                conectados.add(a)
                                cambios = True
                                break
                faltan = [a for a in als if a not in conectados]
                if faltan:
                    self.add("047", pos, f"Posible producto cartesiano: {', '.join(faltan)} no se relaciona con las demás tablas en el WHERE.",
                             confianza="media")

    def r_040_filtros(self):
        txt = self.nocomm
        for m in re.finditer(r"\b(WHERE|AND|OR|ON)\s+(UPPER|LOWER|TRUNC|TO_CHAR|SUBSTR|NVL|TRIM|LTRIM|RTRIM|TO_NUMBER|REPLACE|COALESCE)\s*\(\s*([A-Za-z_][\w$#.]*)\s*(,[^()]*)?\)\s*(=|<|>|<=|>=|LIKE|IN|BETWEEN|!=|<>)",
                             txt, re.I):
            col = m.group(3)
            if self.es_variable_nombre(bare(col)):
                continue
            fn = m.group(2).upper()
            rhs = txt[m.end():m.end() + 40]
            if fn == "TO_CHAR" and re.match(r"\s*'", rhs):
                self.add("042", m.start(2), f"TO_CHAR({col}) comparado con literal: compare con el tipo nativo de la columna.")
            else:
                self.add("040", m.start(2), f"Función {fn} sobre la columna {col} en el filtro impide usar su índice.",
                         confianza="media", relacionadas=["143"])
        for m in re.finditer(r"\b(WHERE|AND|OR|ON)\s+([A-Za-z_][\w$#.]*)\s*(=|<>|!=|<|>|<=|>=)\s*'(\d+)'", txt, re.I):
            col = bare(m.group(2))
            if self.es_variable_nombre(col):
                continue
            if re.search(r"(^ID|_ID$|^ID_|NUM|NRO|CANT|SEC|CODIGO_NUM|MONTO|VALOR|ANIO|MES)", col):
                self.add("041", m.start(2), f"Columna {col} (posiblemente numérica) comparada con texto '{m.group(4)}': conversión implícita.",
                         confianza="media", relacionadas=["144"])
        for m in self.find(r"\bTO_DATE\s*\("):
            cl = match_paren(self.code, m.end() - 1)
            args = split_top(self.code[m.end():cl])
            if len(args) == 1:
                self.add("043", m.start(), "TO_DATE sin máscara de formato: depende de NLS_DATE_FORMAT de la sesión.")
        for m in self.find(r"\bTO_NUMBER\s*\("):
            cl = match_paren(self.code, m.end() - 1)
            inner = self.code[m.end():cl]
            if len(split_top(inner)) == 1 and not re.search(r"ON\s+CONVERSION\s+ERROR", inner, re.I) \
                    and not re.match(r"\s*'\s*'\s*$", inner):
                u = self.est.unit_at(m.start())
                if u is None or not re.search(r"\bWHEN\s+(VALUE_ERROR|INVALID_NUMBER|OTHERS)\b", self.unit_text(u), re.I):
                    self.add("044", m.start(), "TO_NUMBER sin validar: use DEFAULT ... ON CONVERSION ERROR o capture VALUE_ERROR.",
                             confianza="media")
        for m in self.find(r"\bNOT\s+IN\s*\(\s*SELECT\b"):
            self.add("045", m.start(), "NOT IN con subconsulta: si devuelve algún NULL el resultado es vacío. Use NOT EXISTS.",
                     confianza="media")
        for m in self.find(r"(?<!NOT )\bIN\s*\(\s*SELECT\b"):
            if re.search(r"\bFOR\s+[\w$#]+\s+$", self.code[max(0, m.start() - 60):m.start()], re.I):
                continue
            self.add("046", m.start(), "IN (SELECT ...): evalúe EXISTS o un JOIN.", confianza="media", relacionadas=["035"])

    def r_054_sql_dinamico(self):
        code, nc = self.code, self.nocomm
        ddl = r"^\s*(CREATE|ALTER|DROP|TRUNCATE|GRANT|REVOKE|ANALYZE|PURGE|RENAME|COMMENT|FLASHBACK|SET\s+ROLE|BEGIN|DECLARE)\b"
        for m in self.find(r"\bEXECUTE\s+IMMEDIATE\s+"):
            a, b = self.stmt(m.end())
            expr_nc = nc[m.end():b]
            expr = code[m.end():b]
            main = re.split(r"\b(INTO|USING|BULK|RETURNING|RETURN)\b", expr, 1, flags=re.I)[0].strip()
            main_nc = nc[m.end():m.end() + len(expr.split(main[:10])[0]) + len(main)] if main else ""
            if re.fullmatch(r"'[^']*'(\s*\|\|\s*'[^']*')*", main.strip()):
                lit = re.sub(r"'\s*\|\|\s*'", "", main_nc.strip()).strip("'")
                if not re.match(ddl, lit, re.I):
                    self.add("054", m.start(), "EXECUTE IMMEDIATE con SQL fijo: escriba la sentencia estática.")
                continue
            ident = re.fullmatch(r"([A-Za-z_][\w$#]*)", main.strip())
            u = self.est.unit_at(m.start())
            params = {p[0] for p in u.params} if u else set()
            if ident:
                nm = ident.group(1).upper()
                if nm in params or self.m.nom["parametro"].match(nm):
                    self.add("168", m.start(), f"EXECUTE IMMEDIATE ejecuta directamente el parámetro {nm}: cualquier SQL del invocador se ejecuta.")
                elif u and not re.search(r"DBMS_ASSERT", self.unit_text(u), re.I) and \
                        re.search(rf"\b{re.escape(nm)}\s*:=[^;]*\|\|", self.unit_text(u), re.I):
                    self.add("161", m.start(), f"SQL dinámico armado por concatenación en {nm} sin validación (DBMS_ASSERT).",
                             confianza="media")
        # Concatenaciones dentro de SQL dinámico (055/159/160/162/163)
        sqlkw = re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE|MERGE|WHERE|FROM|VALUES|SET|AND|OR|ORDER\s+BY|INTO|JOIN)\b", re.I)
        lit_by_end = {e: (s, c) for s, e, c in self.src.literals}
        for m in re.finditer(r"\|\|\s*", code):
            left = code[:m.start()].rstrip()
            if not left.endswith("'"):
                continue
            lit = lit_by_end.get(len(left))
            if not lit:
                continue
            content = lit[1]
            chain_start = code.rfind(";", 0, m.start()) + 1
            chain_end = self.stmt(m.end())[1]
            chain_nc = nc[chain_start:chain_end]
            if not re.search(r"\b(SELECT\b[\s\S]*\bFROM|INSERT\s+INTO|UPDATE\s+[\w$#.]+\s+SET|DELETE\s+FROM|MERGE\s+INTO)\b", chain_nc, re.I):
                continue
            if re.search(r"\b(DBMS_OUTPUT|RAISE_APPLICATION_ERROR|LOG\w*|REGISTR\w*)\s*\(", nc[chain_start:m.start()], re.I) \
                    and not re.search(r"EXECUTE\s+IMMEDIATE|OPEN\s+\w+\s+FOR|DBMS_SQL", chain_nc, re.I):
                continue
            rhs = re.match(r"([A-Za-z_][\w$#.]*)(\s*\()?", code[m.end():])
            if not rhs or not sqlkw.search(content):
                continue
            op = rhs.group(1).upper()
            if op.startswith("DBMS_ASSERT") or op in ("CHR", "SYSDATE"):
                continue
            arg = op
            if rhs.group(2):  # función envolvente (TO_CHAR(p_id))
                inner = re.match(r"\s*\(\s*([A-Za-z_][\w$#.]*)", code[m.end() + len(rhs.group(1)):])
                arg = inner.group(1).upper() if inner else op
                if arg.startswith("DBMS_ASSERT"):
                    continue
            u = self.est.unit_at(m.start())
            params = {p[0] for p in u.params} if u else set()
            es_param = bare(arg) in params or bool(self.m.nom["parametro"].match(bare(arg)))
            objeto = re.search(r"\b(FROM|JOIN|UPDATE|INTO|TABLE|DELETE\s+FROM)\s*$", content.rstrip(), re.I)
            if objeto:
                self.add("162", m.start(), f"Nombre de objeto concatenado ({arg}) sin DBMS_ASSERT.SQL_OBJECT_NAME/ENQUOTE_NAME.",
                         relacionadas=["169"])
            elif es_param:
                self.add("160", m.start(), f"SQL Injection: el parámetro {arg} se concatena en la sentencia. Use bind variables (USING :x).",
                         relacionadas=["159", "163", "055"])
            else:
                self.add("055", m.start(), f"Valor {arg} concatenado en SQL dinámico: use bind variables.", relacionadas=["159"])

    # =====================================================================
    # DML (ORA-056 a ORA-075) y Performance relacionados
    # =====================================================================
    def r_056_dml(self):
        vistos = {}
        for kind, a, b, s, tabla in self.dml_statements():
            flat = strip_parens(s)
            if kind in ("UPDATE", "DELETE") and not re.search(r"\bWHERE\b", flat, re.I):
                if kind == "UPDATE":
                    self.add("056", a, f"UPDATE sobre {tabla} sin WHERE: actualiza toda la tabla.")
                else:
                    self.add("057", a, f"DELETE sobre {tabla} sin WHERE: borra toda la tabla (use TRUNCATE si es intencional).")
            if kind == "INSERT":
                rest = s[re.search(r"INTO\s+[\w$#.\"]+", s, re.I).end():]
                malias = re.match(r"\s+(?!VALUES\b|SELECT\b|WITH\b)([A-Za-z_]\w*)(?=\s*[(VSW])", rest, re.I)
                if malias:
                    rest = rest[malias.end():]
                st = rest.lstrip()
                if st.startswith("("):
                    p = a + (len(s) - len(rest)) + (len(rest) - len(st))
                    cl = match_paren(self.code, p)
                    cols_txt = self.code[p + 1:cl]
                    if re.match(r"\s*(SELECT|WITH)\b", cols_txt, re.I):
                        self.add("060", a, f"INSERT INTO {tabla} sin lista de columnas.", relacionadas=["032", "061"])
                    else:
                        ncols = len(split_top(cols_txt))
                        mv = re.match(r"\s*VALUES\s*\(", self.code[cl + 1:b], re.I)
                        if mv:
                            vp = cl + 1 + mv.end() - 1
                            nvals = len(split_top(self.code[vp + 1:match_paren(self.code, vp)]))
                            if nvals != ncols:
                                self.add("062", a, f"INSERT INTO {tabla}: {ncols} columnas y {nvals} valores.")
                elif re.match(r"(VALUES|SELECT|WITH)\b", st, re.I):
                    rec = re.match(r"VALUES\s+[A-Za-z_]", st, re.I)
                    self.add("060", a, f"INSERT INTO {tabla} sin lista de columnas" + (" (inserción de registro)." if rec else "."),
                             confianza="media" if rec else "alta", relacionadas=["032", "061"])
            # 073 DML duplicado en la misma unidad
            u = self.est.unit_at(a)
            key = (id(u), re.sub(r"\s+", " ", s.strip().upper()))
            if key in vistos:
                self.add("073", a, f"{kind} idéntico al de la línea {self.src.line(vistos[key])}.")
            else:
                vistos[key] = a
            # Dentro de loops
            loops = self.est.loops_containing(a)
            if loops and kind != "MERGE" or (loops and kind == "MERGE"):
                if not re.search(r"\bFORALL\b", self.code[max(0, a - 200):a], re.I):
                    self.add("137", a, f"{kind} dentro de un loop: procesamiento fila a fila. Use SQL de conjunto o FORALL.",
                             relacionadas=["064", "127", "139", "065", "129", "150"])
            # 069 DML sin manejo de excepciones
            if u and u.kind in ("PROCEDURE", "FUNCTION") and not self.est.enclosing_begins(a) and not self.est.in_handler(a):
                self.add("069", a, f"{kind} sin bloque EXCEPTION que controle errores de la operación.", confianza="media")
            # 070 SQL%ROWCOUNT
            if kind in ("UPDATE", "DELETE") and u and not re.search(r"SQL%(ROWCOUNT|FOUND|NOTFOUND)", self.code[b:min(u.end, b + 400)], re.I):
                self.add("070", a, f"No se verifica SQL%ROWCOUNT después del {kind}.", confianza="media")

    def r_066_transacciones(self):
        for u in self.unidades("PROCEDURE", "FUNCTION", "TRIGGER"):
            a, b = self.body_span(u)
            body = self.mask_nested(u, a, b)
            commits = [a + m.start() for m in re.finditer(r"\bCOMMIT\b", body, re.I)]
            rollbacks = [a + m.start() for m in re.finditer(r"\bROLLBACK\b(?!\s+TO\b)", body, re.I)]
            fuera = [p for p in commits if not self.est.in_handler(p)]
            if len(fuera) > 1:
                self.add("066", fuera[1], f"{u.name} ejecuta {len(fuera)} COMMIT: el control transaccional debe estar en un solo punto.",
                         relacionadas=["075"])
            if u.kind == "TRIGGER" and (commits or rollbacks) and "AUTONOMOUS_TRANSACTION" not in body.upper():
                self.add("075", (commits + rollbacks)[0], "COMMIT/ROLLBACK dentro de un trigger.")
            if u.parent is not None and u.parent.kind == "PACKAGE BODY":
                for p in rollbacks:
                    if not self.est.in_handler(p):
                        self.add("068", p, f"ROLLBACK en rutina reutilizable {u.name}: deshace trabajo del invocador.", confianza="media")
        for m in self.find(r"\bCOMMIT\b"):
            if self.est.loops_containing(m.start()):
                self.add("138", m.start(), "COMMIT dentro de un loop (fetch across commit, ORA-01555, pérdida de atomicidad).",
                         relacionadas=["067"])
            if self.est.in_handler(m.start()):
                self.add("119", m.start(), "COMMIT en el bloque de excepción: confirma trabajo parcial tras un error.")

    def r_074_funciones_dml(self):
        for u in self.unidades("FUNCTION"):
            a, b = self.body_span(u)
            body = self.mask_nested(u, a, b)
            m = re.search(r"\b(INSERT\s+INTO|UPDATE\s+[\w$#.\"]+\s+SET|DELETE\s+FROM|MERGE\s+INTO)\b", body, re.I)
            if m:
                self.add("185", a + m.start(), f"La función {u.name} modifica datos ({m.group(1).split()[0].upper()}): efecto colateral, "
                                               "no podrá usarse en SQL.", relacionadas=["074"])

    # =====================================================================
    # CURSORES / SQL en loops
    # =====================================================================
    def r_121_cursores(self):
        for u in self.unidades("PROCEDURE", "FUNCTION", "TRIGGER"):
            utxt = self.unit_text(u)
            params = {p[0]: p for p in u.params}
            for m in re.finditer(r"\bOPEN\s+([A-Za-z_][\w$#.]*)(\s+FOR\b)?", utxt, re.I):
                c = m.group(1).upper()
                pos = u.start + m.start()
                if params.get(c, ("", "IN"))[1] in ("OUT", "IN OUT") or re.search(rf"\bRETURN\s+{re.escape(c)}\s*;", utxt, re.I):
                    continue
                if not re.search(rf"\bCLOSE\s+{re.escape(c)}\b", utxt, re.I):
                    self.add("123", pos, f"Cursor {c} se abre y nunca se cierra (fuga de cursores, ORA-01000).")
                elif not m.group(2) and not re.search(rf"\bFETCH\s+{re.escape(c)}\s+BULK\b", utxt, re.I):
                    self.add("122", pos, f"Cursor explícito {c} con OPEN/FETCH/CLOSE: un cursor FOR LOOP es más simple y seguro.",
                             relacionadas=["121"])
                if self.est.in_handler(pos) is None and not re.search(rf"WHEN\s+OTHERS[\s\S]*?CLOSE\s+{re.escape(c)}|%ISOPEN", utxt, re.I) \
                        and re.search(rf"\bCLOSE\s+{re.escape(c)}\b", utxt, re.I) and re.search(r"\bEXCEPTION\s+WHEN\b", utxt, re.I):
                    self.add("123", pos, f"Cursor {c} no se cierra en el manejador de excepciones.", confianza="media")
            for m in re.finditer(r"\bFETCH\s+([A-Za-z_][\w$#.]*)\s+(BULK\s+COLLECT\s+)?INTO\b([^;]*);", utxt, re.I):
                c = m.group(1).upper()
                pos = u.start + m.start()
                if m.group(2):
                    if not re.search(r"\bLIMIT\b", m.group(3), re.I):
                        self.add("130", pos, f"FETCH {c} BULK COLLECT sin LIMIT: carga todo el resultado en memoria (PGA).")
                    after = utxt[m.end():m.end() + 600]
                    if not re.search(rf"{re.escape(c)}%NOTFOUND|\.COUNT|{re.escape(c)}%FOUND|EXIT\s+WHEN", after, re.I):
                        self.add("124", pos, f"Después de FETCH {c} BULK COLLECT no se controla el fin del cursor.")
                else:
                    if not re.search(rf"{re.escape(c)}\s*%\s*(NOTFOUND|FOUND|ROWCOUNT)", utxt, re.I):
                        self.add("124", pos, f"FETCH {c} sin verificar {c}%NOTFOUND.")
                    if self.est.loops_containing(pos):
                        self.add("128", pos, f"FETCH {c} fila por fila dentro de loop: use BULK COLLECT ... LIMIT.", confianza="media")
        for pos, end, s in self.selects():
            flat = strip_parens(s)
            if re.search(r"\bBULK\s+COLLECT\s+INTO\b", flat, re.I) and not re.search(r"\bFETCH\s+FIRST\b|\bROWNUM\b", s, re.I):
                self.add("131", pos, "SELECT BULK COLLECT sin límite: con volúmenes grandes agota la memoria.", confianza="media")
            elif re.search(r"\bINTO\b", flat, re.I) and self.est.unit_at(pos) is not None:
                self._select_into(pos, s, flat)
            loops = self.est.loops_containing(pos)
            prefix = self.code[max(0, pos - 30):pos].upper()
            if loops and not re.search(r"\bIN\s*\(\s*$|\bFOR\b[^;]*$", prefix) and not re.search(r"\bCURSOR\b", prefix):
                self.add("136", pos, "SELECT dentro de un loop: una consulta por iteración. Use JOIN o carga previa en colección.",
                         relacionadas=["126", "051", "148"])
        # 125 cursores anidados
        fors = [m for m in self.find(r"\bFOR\s+\w+\s+IN\s*(\(\s*SELECT\b|[A-Za-z_][\w$#.]*\s*(\(|LOOP))")]
        for m in fors:
            loops = self.est.loops_containing(m.start())
            if any(re.search(r"\bFOR\s+\w+\s+IN\b(?!\s+(REVERSE\s+)?[\w$#.]+\s*\.\.)", self.code[max(0, l.start - 400):l.start + 10], re.I) for l in loops):
                if not re.search(r"\.\.", self.code[m.start():m.start() + 80]):
                    self.add("125", m.start(), "Cursor anidado dentro de otro cursor loop: use un JOIN.", confianza="media")
        # 140 funciones de usuario en loop
        for m in self.find(r"(?<![\w$#.])((?:PKG_[\w$#]+\.)?(?:FNC|FN)_[\w$#]+)\s*\("):
            if self.est.loops_containing(m.start()):
                self.add("140", m.start(), f"Función {m.group(1).upper()} invocada en cada iteración: evalúe cachear o resolver con SQL.",
                         confianza="media")
        # 149 COUNT(*) para verificar existencia
        for m in self.find(r"SELECT\s+COUNT\s*\(\s*(\*|1)\s*\)\s+INTO\s+([\w$#]+)[^;]*;\s*IF\s+\2\s*(>|>=|!=|<>)\s*[01]\b"):
            self.add("149", m.start(), "COUNT(*) solo para verificar existencia: use EXISTS o ROWNUM = 1.", confianza="media")

    def _select_into(self, pos, s, flat):
        sel = re.split(r"\bINTO\b", flat, 1, flags=re.I)[0]
        if re.search(AGREGADAS, s.split("INTO")[0] if "INTO" in s else s, re.I) and not re.search(r"\bGROUP\s+BY\b", flat, re.I):
            return
        unico = re.search(r"\bROWNUM\s*(=|<=?)\s*1\b|\bFETCH\s+FIRST\s+1\b", s, re.I)
        nombres = set()
        for blk, hs in self.est.enclosing_begins(pos):
            for h in hs:
                nombres.update(h.nombres)
        if not ({"NO_DATA_FOUND", "OTHERS"} & nombres):
            self.add("132", pos, "SELECT ... INTO sin manejar NO_DATA_FOUND.", confianza="media")
        if not unico and not ({"TOO_MANY_ROWS", "OTHERS"} & nombres):
            self.add("133", pos, "SELECT ... INTO sin manejar TOO_MANY_ROWS (o sin garantizar una sola fila).", confianza="media")

    # =====================================================================
    # EXCEPCIONES (ORA-106 a ORA-120)
    # =====================================================================
    def r_106_excepciones(self):
        logf = "|".join(re.escape(x) for x in self.m.cfg.get("funciones_log", []))
        for blk, hs in self.est.handlers:
            names_all = [n for h in hs for n in h.nombres]
            for h in hs:
                body = self.code[h.start:h.end]
                body_nc = self.nocomm[h.start:h.end]
                b = re.sub(r"\s+", " ", body).strip().upper()
                others = "OTHERS" in h.nombres
                tiene_raise = re.search(r"\bRAISE(_APPLICATION_ERROR)?\b", b) is not None
                if b in ("NULL;", "NULL ;"):
                    if others:
                        self.add("106", h.when_pos, "WHEN OTHERS THEN NULL: el error se pierde silenciosamente.", relacionadas=["110"])
                    else:
                        self.add("110", h.when_pos, f"WHEN {'/'.join(h.nombres)} THEN NULL: confirme que ignorar el error es intencional.",
                                 confianza="media")
                    continue
                if b in ("RAISE;", "RAISE ;"):
                    if others:
                        self.add("108", h.when_pos, "WHEN OTHERS THEN RAISE sin registrar el error: o regístrelo o elimine el manejador.")
                    else:
                        self.add("109", h.when_pos, f"WHEN {'/'.join(h.nombres)} THEN RAISE: capturar para relanzar sin hacer nada es innecesario.",
                                 relacionadas=["112"])
                    continue
                if others:
                    if not tiene_raise:
                        self.add("107", h.when_pos, "WHEN OTHERS no relanza el error: el invocador no se entera del fallo.")
                    logea = re.search(rf"\b(SQLERRM|SQLCODE|FORMAT_ERROR_STACK|FORMAT_ERROR_BACKTRACE|UTL_CALL_STACK)\b|[\w$#]*({logf})[\w$#]*\s*[.(]", b) if logf else None
                    if not logea:
                        self.add("108", h.when_pos, "WHEN OTHERS no registra el error (log con SQLCODE/SQLERRM y contexto).")
                    else:
                        if "SQLCODE" not in b and "FORMAT_ERROR_STACK" not in b:
                            self.add("115", h.when_pos, "WHEN OTHERS no conserva SQLCODE.")
                        if "SQLERRM" not in b and "FORMAT_ERROR_STACK" not in b:
                            self.add("116", h.when_pos, "WHEN OTHERS no conserva SQLERRM / FORMAT_ERROR_STACK.")
                    for mr in re.finditer(r"RAISE_APPLICATION_ERROR\s*\(", body, re.I):
                        cl = match_paren(body, mr.end() - 1)
                        args = split_top(body[mr.end():cl])
                        args_nc = body_nc[mr.end():cl].upper()
                        if len(args) < 3 or "TRUE" not in args[2][1].upper():
                            if not re.search(r"SQLERRM|FORMAT_ERROR_(STACK|BACKTRACE)", args_nc):
                                self.add("113", h.start + mr.start(), "RAISE_APPLICATION_ERROR en WHEN OTHERS sin TRUE ni SQLERRM: se pierde el error original.")
                    if re.search(r"\bROLLBACK\b(?!\s+TO\b)", b) and not tiene_raise:
                        self.add("120", h.when_pos, "ROLLBACK en WHEN OTHERS sin relanzar: deshace todo y oculta el error.", confianza="media")
                    elif re.search(r"\bROLLBACK\b(?!\s+TO\b)", b):
                        u = self.est.unit_at(h.start)
                        if u and u.parent is not None and u.parent.kind == "PACKAGE BODY":
                            self.add("120", h.when_pos, "ROLLBACK total en rutina reutilizable: prefiera SAVEPOINT / ROLLBACK TO.", confianza="media")
            if names_all == ["OTHERS"]:
                protegido = self.code[blk.start:self.src.tokens[blk.exc_tok].pos]
                sel_into = [x for x in re.findall(r"\bSELECT\b([^;]*?)\bINTO\b", protegido, re.I | re.S)
                            if not re.match(r"\s*(COUNT|SUM|AVG|MIN|MAX)\s*\(", x, re.I)]
                if sel_into or re.search(r"\bTO_NUMBER\s*\(|\bTO_DATE\s*\(", protegido, re.I):
                    self.add("111", self.src.tokens[blk.exc_tok].pos,
                             "Solo WHEN OTHERS: capture primero las excepciones esperadas (NO_DATA_FOUND, VALUE_ERROR...).",
                             confianza="media", relacionadas=["118"])

    # =====================================================================
    # SEGURIDAD (ORA-156 a ORA-175)
    # =====================================================================
    def r_156_seguridad(self):
        nc, raw = self.nocomm, self.src.raw
        for m in re.finditer(rf"([\w$#]*{SENSIBLES}[\w$#]*)\s*(?:CONSTANT\s+)?(?:[\w$#.%]+(?:\s*\([^)]*\))?\s*)?(?::=|DEFAULT)\s*'([^']{{3,}})'",
                             nc, re.I):
            nombre = m.group(1).upper()
            if re.search(r"TOKEN|API_?KEY", nombre):
                self.add("157", m.start(), f"Token/API key embebido en el código ({nombre}).")
            else:
                self.add("156", m.start(), f"Contraseña embebida en el código ({nombre}). Use Oracle Wallet / vault.")
        for s, e, c in self.src.literals:
            if re.search(r"eyJ[\w-]{10,}\.[\w-]{10,}|\bBearer\s+[\w\-.=]{16,}|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY", c):
                self.add("157", s, "Token o llave secreta embebida en un literal.")
            if re.search(r"^[\w$#]+/[^\s/@']{3,}@[\w.:/\-]+$|://[^/\s:@]+:[^/\s@]+@", c.strip()):
                self.add("170", s, "Credenciales hardcodeadas en cadena de conexión.")
        for m in re.finditer(r"^\s*(CONN|CONNECT)\s+[\w$#]+/[^\s@]+", raw, re.I | re.M):
            self.add("158", m.start(), "Credenciales en sentencia CONNECT del script.")
        for m in self.find(r"\bIDENTIFIED\s+BY\s+(\"?[^\s;\"]+\"?)"):
            if not m.group(1).startswith("&") and not m.group(1).upper().startswith("VALUES"):
                self.add("158", m.start(), "Contraseña literal en IDENTIFIED BY (usuario o DB link).")
        for m in self.find(r"\bRAISE_APPLICATION_ERROR\s*\(([^;]*)\)\s*;"):
            if re.search(SENSIBLES, m.group(1), re.I):
                self.add("164", m.start(), "El mensaje de error incluye un dato sensible.")
        for m in self.find(r"\bDBMS_OUTPUT\s*\.\s*PUT(_LINE)?\s*\(([^;]*)\)"):
            self.add("165", m.start(), "DBMS_OUTPUT en código productivo: use el framework de log.")
            if re.search(SENSIBLES, m.group(2), re.I):
                self.add("171", m.start(), "Se imprime un dato sensible.")
        logf = "|".join(re.escape(x) for x in self.m.cfg.get("funciones_log", []))
        if logf:
            for m in self.find(rf"\b(?:[\w$#]+\.)?({logf})\w*\s*\(([^;]*)\)\s*;"):
                if re.search(SENSIBLES, m.group(2), re.I):
                    self.add("171", m.start(), "Dato sensible enviado al log.")
        # GRANTs
        for m in self.find(r"\bGRANT\s+([^;]*?)\s+TO\s+([\w$#\",\s]+?)(\s+WITH\s+(ADMIN|GRANT)\s+OPTION)?\s*;"):
            privs, quien = m.group(1).upper(), m.group(2).upper()
            if re.search(r"\b(DBA|SYSDBA|SYSOPER|ANY|EXEMPT|BECOME\s+USER|ALTER\s+SYSTEM)\b", privs):
                self.add("166", m.start(), f"Privilegio excesivo otorgado: GRANT {privs.strip()[:60]}.")
            if re.search(r"\bALL\b", privs) or "PUBLIC" in quien:
                self.add("167", m.start(), "GRANT ALL / TO PUBLIC viola el principio de mínimo privilegio.")
            if m.group(3):
                self.add("166", m.start(), f"GRANT {m.group(3).strip()} permite re-otorgar el privilegio.")
            if " ON " in f" {privs} " and "PUBLIC" not in quien:
                destinos = [q.strip() for q in quien.split(",")]
                if not all(re.match(r"^(ROL|ROLE|R)_", d) for d in destinos):
                    rid = "173" if privs.startswith("EXECUTE") else "172"
                    self.add(rid, m.start(), f"Privilegio directo a {', '.join(destinos)}: otórguelo a un rol.", confianza="media")
        # AUTHID
        for u in self.est.unidades:
            if not u.standalone or u.kind == "PACKAGE BODY" or u.kind == "TRIGGER":
                continue
            hdr = self.code[u.start:self.src.tokens[u.tok_is].end]
            ma = re.search(r"\bAUTHID\s+DEFINER\b", hdr, re.I)
            ln = self.src.line(u.start)
            justif = any(re.search(r"justific|definer", c[1], re.I) for c in self.src.comments if ln - 3 <= c[0] <= self.src.line(u.end))
            if ma and not justif:
                self.add("175", u.start + ma.start(), f"{u.name} declara AUTHID DEFINER sin justificación documentada.")
            if not re.search(r"\bAUTHID\b", hdr, re.I):
                cuerpo = self.unit_text(u)
                if u.kind == "PACKAGE":
                    cuerpo = ""
                    for o in self.est.unidades:
                        if o.kind == "PACKAGE BODY" and o.name == u.name:
                            cuerpo = self.unit_text(o)
                if re.search(r"EXECUTE\s+IMMEDIATE|DBMS_SQL\.", cuerpo, re.I):
                    self.add("174", u.start, f"{u.name} ejecuta SQL dinámico con derechos del definidor (sin AUTHID explícito).",
                             confianza="media")

    # =====================================================================
    # TRIGGERS / OBJETOS / DESPLIEGUE
    # =====================================================================
    def r_186_triggers(self):
        for u in self.unidades("TRIGGER"):
            hdr_end = self.src.tokens[u.tok_begin].pos if u.tok_begin > 0 else u.end
            hdr = self.code[u.start:hdr_end]
            mt = re.search(r"\bON\s+([\w$#.\"]+)", hdr, re.I)
            tabla = bare(mt.group(1)) if mt else ""
            row = re.search(r"FOR\s+EACH\s+ROW", hdr, re.I)
            a, b = self.body_span(u)
            body = self.code[a:b]
            if tabla and row and not re.search(r"\bCOMPOUND\b", hdr, re.I):
                if re.search(rf"\bFROM\s+(?:[\w$#]+\.)?{re.escape(tabla)}\b", body, re.I):
                    self.add("190", a, f"Trigger de fila {u.name} consulta su propia tabla {tabla}: ORA-04091 (mutating table).")
            if tabla and re.search(rf"\b(UPDATE|INSERT\s+INTO|DELETE\s+FROM)\s+(?:[\w$#]+\.)?{re.escape(tabla)}\b", body, re.I):
                self.add("189", a, f"Trigger {u.name} modifica su propia tabla {tabla}: riesgo de disparo recursivo.", confianza="media")
            dml = len(re.findall(r"\b(INSERT\s+INTO|UPDATE\s+[\w$#.]+\s+SET|DELETE\s+FROM|MERGE\s+INTO)\b", body, re.I))
            if re.search(r"\bLOOP\b|EXECUTE\s+IMMEDIATE", body, re.I) or dml > 3:
                self.add("191", a, f"Trigger {u.name} contiene lógica de negocio compleja (loops/SQL dinámico/{dml} DML).", confianza="media")
            ln0, ln1 = self.src.line(u.start), self.src.line(u.end)
            if not any(ln0 - 3 <= c[0] <= ln1 and c[1].strip(" -*/") for c in self.src.comments):
                self.add("192", u.start, f"Trigger {u.name} sin comentario que documente su propósito.")

    def r_196_despliegue(self):
        for m in self.find(r"\bDROP\s+(TABLE|VIEW|PACKAGE|PROCEDURE|FUNCTION|SYNONYM|TYPE|SEQUENCE|INDEX)\s+([\w$#.\"]+)"):
            if self.est.unit_at(m.start()) is None:
                self.add("196", m.start(), f"DROP {m.group(1).upper()} {bare(m.group(2))}: valide objetos dependientes antes del despliegue.",
                         confianza="media")
        for m in self.find(r"\bALTER\s+TABLE\s+([\w$#.\"]+)\s+(DROP|RENAME)\s+(COLUMN|CONSTRAINT|TO)?"):
            self.add("196", m.start(), f"ALTER TABLE {bare(m.group(1))} {m.group(2).upper()}: valide dependencias (vistas, paquetes, ETL).",
                     confianza="media")
        for m in self.find(r"\bCREATE\s+(?:GLOBAL\s+TEMPORARY\s+|PRIVATE\s+TEMPORARY\s+)?(TABLE|SEQUENCE|INDEX|UNIQUE\s+INDEX)\s+(?!IF\s+NOT\s+EXISTS)([\w$#.\"]+)"):
            if self.est.unit_at(m.start()) is None and not any(b.kind == "BEGIN" and b.start < m.start() < b.end for b in self.est.bloques):
                self.add("199", m.start(), f"CREATE {m.group(1).upper()} {bare(m.group(2))} sin control de existencia: el script no es re-ejecutable.",
                         confianza="media")
        for m in self.find(r"\bCREATE\s+(GLOBAL|PRIVATE)\s+TEMPORARY\s+TABLE\b"):
            self.add("152", m.start(), "Tabla temporal: confirme que no puede resolverse con SQL de conjunto o colecciones.", confianza="media")
        for s, e, c in self.src.literals:
            if re.match(r"\s*CREATE\s+(GLOBAL\s+TEMPORARY\s+)?TABLE\b", c, re.I) and self.est.unit_at(s):
                self.add("152", s, "Creación dinámica de tablas en tiempo de ejecución.", confianza="media")


# ---------------------------------------------------------------------------
# Configuración / reglas
# ---------------------------------------------------------------------------
def cargar_config(ruta: str | None = None) -> dict:
    p = Path(ruta) if ruta else BASE_DIR / "config" / "oravalidator.json"
    return json.loads(p.read_text(encoding="utf-8"))


def cargar_reglas(ruta: str | None = None) -> dict:
    p = Path(ruta) if ruta else BASE_DIR / "rules" / "matriz_reglas.json"
    data = json.loads(p.read_text(encoding="utf-8"))
    return {r["id"].replace("ORA-", ""): r for r in data["reglas"]}


def regla_activa(reglas: dict, rid: str) -> bool:
    r = reglas.get(rid.replace("ORA-", ""))
    return r is None or r.get("activa", True) is not False


def regla_bloqueante(reglas: dict, rid: str) -> bool:
    """La columna 'Quality Gate' de la matriz: solo las reglas marcadas 'Bloquea' detienen el push."""
    r = reglas.get(rid.replace("ORA-", ""))
    if r is None or not r.get("quality_gate"):
        return True
    return str(r["quality_gate"]).strip().lower().startswith("bloq")


def es_archivo_oracle(ruta: str, cfg: dict) -> bool:
    ext = os.path.splitext(ruta)[1].lower()
    if ext not in cfg["extensiones"]:
        return False
    norm = ruta.replace("\\", "/")
    return not any(fnmatch.fnmatch(norm, pat) or fnmatch.fnmatch("/" + norm, pat) for pat in cfg.get("excluir_rutas", []))


def leer_texto(data: bytes) -> str:
    for enc in ("utf-8-sig", "cp1252", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", "replace")


def cobertura(reglas: dict) -> dict:
    ids = sorted(reglas)
    return {
        "total": len(ids),
        "oracle": [f"ORA-{i}" for i in ids if i in REGLAS_ORACLE],
        "revision_claude": [f"ORA-{i}" for i in ids if i in REGLAS_CLAUDE],
        "plan_ejecucion": [f"ORA-{i}" for i in ids if i in REGLAS_PLAN],
        "automaticas": [f"ORA-{i}" for i in ids if i not in REGLAS_ORACLE | REGLAS_CLAUDE | REGLAS_PLAN and i != "200"],
    }


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description="Analizador estático Oracle basado en la matriz de 200 reglas")
    ap.add_argument("rutas", nargs="+")
    ap.add_argument("--config")
    ap.add_argument("--json", help="Archivo de salida JSON")
    a = ap.parse_args(argv)
    cfg = cargar_config(a.config)
    archivos = {}
    for r in a.rutas:
        p = Path(r)
        files = [p] if p.is_file() else [f for f in p.rglob("*") if f.is_file()]
        for f in files:
            rel = str(f)
            if es_archivo_oracle(rel, cfg):
                archivos[rel] = leer_texto(f.read_bytes())
    res = Analizador(cfg).analizar(archivos)
    out = {"hallazgos": [asdict(h) for h in res["hallazgos"]], "suprimidos": [asdict(h) for h in res["suprimidos"]],
           "archivos": res["archivos"], "omitidos": res["omitidos"]}
    if a.json:
        Path(a.json).write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
    for h in res["hallazgos"]:
        print(f"{h.archivo}:{h.linea}  [{h.severidad:8}] {h.regla} {h.detalle}")
    print(f"\n{len(res['hallazgos'])} hallazgos en {len(archivos)} archivos")


if __name__ == "__main__":
    main()
