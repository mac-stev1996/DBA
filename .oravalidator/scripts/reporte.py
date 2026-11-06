"""Generación de reportes de novedades: HTML (Centric), Markdown (PR/MR), JSON y consola."""
from __future__ import annotations

import base64
import html
import json
from collections import Counter, defaultdict
from pathlib import Path

ASSETS = Path(__file__).resolve().parent.parent / "assets"
SEVS = ["BLOCKER", "CRITICAL", "MAJOR", "MINOR", "INFO"]
COLOR = {"BLOCKER": "#B42318", "CRITICAL": "#D9480F", "MAJOR": "#B7791F", "MINOR": "#2B6CB0", "INFO": "#4A5568"}


def generar(datos: dict, salida: Path) -> dict:
    salida.mkdir(parents=True, exist_ok=True)
    p_json = salida / "reporte_oravalidator.json"
    p_md = salida / "reporte_oravalidator.md"
    p_html = salida / "reporte_oravalidator.html"
    p_json.write_text(json.dumps(datos, ensure_ascii=False, indent=1), encoding="utf-8")
    p_md.write_text(markdown(datos), encoding="utf-8")
    p_html.write_text(html_report(datos), encoding="utf-8")
    return {"json": str(p_json), "md": str(p_md), "html": str(p_html)}


def _ctx_linea(c: dict) -> str:
    partes = [f"Rama **{c.get('rama')}** @ `{c.get('commit')}`"]
    if c.get("base") or c.get("base_commit"):
        partes.append(f"comparada con **{c.get('base') or c.get('base_commit')}**")
    partes.append(f"modo `{c.get('modo')}`")
    if c.get("solo_lineas_cambiadas"):
        partes.append("solo líneas modificadas")
    partes.append("casos: " + (c.get("casos_aplicados") or "todas las reglas de la matriz"))
    return " · ".join(partes)


# ---------------------------------------------------------------------------
def consola(d: dict, rutas: dict, f) -> None:
    g = d["quality_gate"]
    hs = d["hallazgos"]
    cnt = Counter(h["severidad"] for h in hs)
    ok = g["estado"] == "APROBADO"
    print("\n" + "═" * 78, file=f)
    print(f" ORAVALIDATOR · Quality Gate: {'✔ APROBADO' if ok else '✖ RECHAZADO'}", file=f)
    print(f" Rama {d['contexto'].get('rama')} @ {d['contexto'].get('commit')} · "
          f"{d['contexto'].get('archivos_en_alcance', 0)} archivo(s) Oracle analizados", file=f)
    print(f" Casos aplicados: {d['contexto'].get('casos_aplicados') or 'todas las reglas de la matriz'}", file=f)
    print(" " + " · ".join(f"{s}: {cnt.get(s, 0)}" for s in SEVS), file=f)
    print("═" * 78, file=f)
    bloq = [h for h in hs if h["bloquea"]]
    for h in bloq[:40]:
        print(f"  ✖ {h['archivo']}:{h['linea']}  {h['regla']} [{h['severidad']}] {h['detalle']}", file=f)
    if len(bloq) > 40:
        print(f"  … y {len(bloq) - 40} incidencia(s) bloqueante(s) más (ver reporte).", file=f)
    rev = [h for h in hs if not h["bloquea"] and h["severidad"] in ("BLOCKER", "CRITICAL", "MAJOR")]
    if rev:
        print(f"\n  ⚠ {len(rev)} hallazgo(s) heurístico(s) para revisar (no bloquean).", file=f)
    for m in g["motivos"]:
        print(f"  Motivo: {m}", file=f)
    print(f"\n  Reporte: {rutas['html']}", file=f)
    print("═" * 78 + "\n", file=f)


# ---------------------------------------------------------------------------
def markdown(d: dict) -> str:
    g = d["quality_gate"]
    hs = d["hallazgos"]
    cnt = Counter(h["severidad"] for h in hs)
    ok = g["estado"] == "APROBADO"
    out = [f"## {'✅' if ok else '⛔'} Quality Gate Oracle: **{g['estado']}**", "",
           _ctx_linea(d["contexto"]), "",
           "| Severidad | Hallazgos | Bloqueantes | Máximo permitido |", "|---|---:|---:|---:|"]
    nbloq = Counter(h["severidad"] for h in hs if h["bloquea"])
    for s in SEVS:
        mx = g["politica"].get(s)
        out.append(f"| {s} | {cnt.get(s, 0)} | {nbloq.get(s, 0)} | {'no bloquea' if mx is None else mx} |")
    if g["motivos"]:
        out += ["", "**Motivos del rechazo:** " + "; ".join(g["motivos"])]
    out.append("")
    porarch = defaultdict(list)
    for h in hs:
        porarch[h["archivo"]].append(h)
    if hs:
        out.append("### Novedades por archivo")
    for arch, lst in porarch.items():
        out += ["", f"<details{' open' if any(x['bloquea'] for x in lst) else ''}><summary><code>{arch}</code> — {len(lst)} hallazgo(s)</summary>", "",
                "| Línea | Regla | Sev. | Estado | Detalle | Corrección sugerida |", "|---:|---|---|---|---|---|"]
        for h in lst:
            est = "⛔ Bloquea" if h["bloquea"] else ("🔎 Revisar" if h["confianza"] == "media" else "⚠ Advertencia")
            fix = (h.get("ejemplo_correcto") or "").replace("\n", " ").replace("|", "\\|")[:90]
            det = h["detalle"].replace("|", "\\|")
            out.append(f"| {h['linea']} | {h['regla']} | {h['severidad']} | {est} | {det} | `{fix}` |" if fix
                       else f"| {h['linea']} | {h['regla']} | {h['severidad']} | {est} | {det} | |")
        out.append("</details>")
    if d["suprimidos"]:
        out += ["", "### Excepciones justificadas en el código", "", "| Archivo | Línea | Regla | Justificación |", "|---|---:|---|---|"]
        for h in d["suprimidos"]:
            out.append(f"| `{h['archivo']}` | {h['linea']} | {h['regla']} | {h['justificacion']} |")
    cob = d["cobertura"]
    out += ["", f"<sub>Cobertura: {len(cob['automaticas'])} reglas automáticas · {len(cob['revision_claude'])} de revisión semántica · "
                f"{len(cob['oracle'])} requieren conexión Oracle ({'ejecutadas' if cob['oracle_ejecutadas'].get('ejecutadas') else 'no ejecutadas'}) · "
                f"{len(cob.get('plan_ejecucion', []))} de plan de ejecución (revisión DBA). "
                f"oravalidator {d['version']} · {d['fecha']}</sub>"]
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
def _logo() -> str:
    p = ASSETS / "logo-white.png"
    if p.exists():
        return f'<img class="logo" alt="centric" src="data:image/png;base64,{base64.b64encode(p.read_bytes()).decode()}">'
    return '<span class="logo-txt">centric</span>'


def html_report(d: dict) -> str:
    e = html.escape
    g = d["quality_gate"]
    hs = d["hallazgos"]
    cnt = Counter(h["severidad"] for h in hs)
    ok = g["estado"] == "APROBADO"
    c = d["contexto"]
    porarch = defaultdict(list)
    for h in hs:
        porarch[h["archivo"]].append(h)
    cat = Counter(h["categoria"] or "Otros" for h in hs)

    nbloq = Counter(h["severidad"] for h in hs if h["bloquea"])

    def sub(s):
        mx = g["politica"].get(s)
        return "no bloquea el push" if mx is None else f"bloquean: {nbloq.get(s, 0)} · máx permitido {mx}"
    cards = "".join(
        f'<div class="card" style="border-top-color:{COLOR[s]}"><div class="n">{cnt.get(s, 0)}</div>'
        f'<div class="l">{s}</div><div class="s">{sub(s)}</div></div>' for s in SEVS)

    filas = []
    for arch, lst in porarch.items():
        nb = sum(1 for x in lst if x["bloquea"])
        filas.append(f'<section class="file"><h3><code>{e(arch)}</code><span class="pill">{len(lst)} hallazgos</span>'
                     + (f'<span class="pill red">{nb} bloquean</span>' if nb else "") + "</h3><table><thead><tr>"
                     "<th>Línea</th><th>Regla</th><th>Severidad</th><th>Estado</th><th>Novedad</th><th>Cómo corregir</th></tr></thead><tbody>")
        for h in lst:
            est = ('<span class="st b">Bloquea</span>' if h["bloquea"] else
                   '<span class="st r">Revisar</span>' if h["confianza"] == "media" else '<span class="st w">Advertencia</span>')
            rel = f'<div class="rel">También: {", ".join(h["relacionadas"])}</div>' if h["relacionadas"] else ""
            org = '<span class="org">revisión semántica</span>' if h.get("origen") not in (None, "motor") else ""
            frag = f"<pre>{e(h['fragmento'])}</pre>" if h["fragmento"] else ""
            fix = f"<pre class='ok'>{e(h['ejemplo_correcto'])}</pre>" if h["ejemplo_correcto"] else ""
            color = COLOR.get(h["severidad"], "#666")
            filas.append(
                f'<tr data-sev="{h["severidad"]}" data-bloq="{int(h["bloquea"])}"><td class="ln">{h["linea"]}</td>'
                f'<td><b>{e(h["regla"])}</b><div class="cat">{e(h["categoria"])}</div></td>'
                f'<td><span class="sev" style="background:{color}">{h["severidad"]}</span></td>'
                f'<td>{est}</td><td><div class="tit">{e(h["titulo"])}</div>{e(h["detalle"])} {org}{frag}{rel}</td>'
                f'<td>{e(h["mensaje"])}{fix}</td></tr>')
        filas.append("</tbody></table></section>")

    sup = ""
    if d["suprimidos"]:
        sup = ('<h2>Excepciones justificadas</h2><p class="muted">Hallazgos marcados en el código con '
               '<code>-- oravalidator:ignore ORA-XXX justificación</code>. Quedan registrados para auditoría.</p><table><thead><tr>'
               '<th>Archivo</th><th>Línea</th><th>Regla</th><th>Justificación</th></tr></thead><tbody>'
               + "".join(f"<tr><td><code>{e(h['archivo'])}</code></td><td>{h['linea']}</td><td>{h['regla']}</td><td>{e(h['justificacion'])}</td></tr>"
                         for h in d["suprimidos"]) + "</tbody></table>")
    inval = [(a["ruta"], s) for a in d["archivos"] for s in a.get("supresiones_invalidas", [])]
    if inval:
        sup += ('<h2>Supresiones rechazadas</h2><table><tbody>'
                + "".join(f"<tr><td><code>{e(r)}</code></td><td>{s['linea']}</td><td>{', '.join(s['reglas'])}</td><td>{e(s['motivo'])}</td></tr>"
                          for r, s in inval) + "</tbody></table>")

    cob = d["cobertura"]
    ora = cob["oracle_ejecutadas"]
    cobertura = (f'<div class="cov"><div><b>{len(cob["automaticas"])}</b> reglas evaluadas automáticamente</div>'
                 f'<div><b>{len(cob["revision_claude"])}</b> reglas de revisión semántica'
                 f'<span class="muted"> ({", ".join(cob["revision_claude"])})</span></div>'
                 f'<div><b>{len(cob["oracle"])}</b> reglas que requieren conexión Oracle: '
                 f'{"ejecutadas" if ora.get("ejecutadas") else "no ejecutadas — " + e(ora.get("motivo", ""))}'
                 f'<span class="muted"> ({", ".join(cob["oracle"])})</span></div>'
                 f'<div><b>{len(cob.get("plan_ejecucion", []))}</b> reglas de plan de ejecución, a revisar con DBA sobre EXPLAIN PLAN'
                 f'<span class="muted"> ({", ".join(cob.get("plan_ejecucion", []))})</span></div></div>')
    archivos_tbl = "".join(f"<tr><td><code>{e(a['ruta'])}</code></td><td>{a['lineas']}</td><td>{a['hallazgos']}</td>"
                           f"<td class='muted'>{e(', '.join(a['unidades'][:6]))}</td></tr>" for a in d["archivos"])
    cats = "".join(f"<li>{e(k)} <b>{v}</b></li>" for k, v in cat.most_common())
    base = c.get("base") or c.get("base_commit") or "—"

    return f"""<!DOCTYPE html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Reporte de novedades Oracle · {e(str(c.get('rama')))}</title>
<link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root{{--navy:#1B2D55;--teal:#40C4AA;--gris:#F5F6F8;--txt:#4A5568;--suave:#E8ECF4}}
*{{box-sizing:border-box}} body{{margin:0;font-family:Montserrat,Calibri,Arial,sans-serif;color:#1f2937;background:#fff;font-size:14px}}
header{{background:var(--navy);color:#fff;padding:22px 32px;display:flex;align-items:center;gap:24px;flex-wrap:wrap;border-bottom:4px solid var(--teal)}}
.logo{{height:34px}} .logo-txt{{font-weight:700;font-size:26px}}
header h1{{font-size:20px;margin:0;font-weight:600}} header .meta{{font-size:12px;opacity:.85;margin-top:4px}}
.gate{{margin-left:auto;padding:10px 18px;border-radius:8px;font-weight:700;font-size:16px;background:{'#40C4AA' if ok else '#B42318'};color:#fff}}
main{{max-width:1280px;margin:0 auto;padding:24px 32px 60px}}
h2{{color:var(--navy);font-size:18px;margin:32px 0 12px;font-weight:600}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px}}
.card{{background:var(--gris);border-radius:8px;padding:14px 16px;border-top:4px solid}}
.card .n{{font-size:28px;font-weight:700;color:var(--navy)}} .card .l{{font-weight:600}} .card .s{{font-size:11px;color:var(--txt)}}
.motivos{{background:#FDECEA;border-left:4px solid #B42318;padding:12px 16px;border-radius:4px;margin-top:16px}}
.okmsg{{background:#E7F8F3;border-left:4px solid var(--teal);padding:12px 16px;border-radius:4px;margin-top:16px}}
.grid2{{display:grid;grid-template-columns:2fr 1fr;gap:24px}} @media(max-width:800px){{.grid2{{grid-template-columns:1fr}}}}
table{{width:100%;border-collapse:collapse;font-size:13px}} th{{background:var(--navy);color:#fff;text-align:left;padding:8px;font-weight:500}}
td{{padding:8px;border-bottom:1px solid var(--suave);vertical-align:top}} tr:nth-child(even) td{{background:#FAFBFC}}
.file{{margin-top:22px;overflow-x:auto}} .file h3{{font-size:14px;color:var(--navy);display:flex;gap:10px;align-items:center;flex-wrap:wrap}}
.pill{{background:var(--suave);color:var(--navy);border-radius:12px;padding:2px 10px;font-size:11px}} .pill.red{{background:#FDECEA;color:#B42318}}
.sev{{color:#fff;border-radius:4px;padding:2px 6px;font-size:11px;font-weight:600}}
.st{{font-size:11px;font-weight:600;border-radius:4px;padding:2px 6px;white-space:nowrap}} .st.b{{background:#FDECEA;color:#B42318}}
.st.r{{background:#FFF4E5;color:#B7791F}} .st.w{{background:var(--suave);color:var(--navy)}}
.ln{{font-family:Consolas,monospace;color:var(--txt)}} .cat,.rel,.muted{{color:var(--txt);font-size:11px}} .tit{{font-weight:600;color:var(--navy)}}
pre{{background:#F1F3F7;padding:6px 8px;border-radius:4px;white-space:pre-wrap;font-size:12px;margin:6px 0 0}} pre.ok{{background:#E7F8F3}}
.org{{background:var(--teal);color:#fff;border-radius:4px;font-size:10px;padding:1px 5px}}
.filtros{{display:flex;gap:8px;flex-wrap:wrap;margin:8px 0}} .filtros button{{font-family:inherit;border:1px solid var(--navy);background:#fff;color:var(--navy);border-radius:16px;padding:4px 12px;cursor:pointer}}
.filtros button.on{{background:var(--navy);color:#fff}} .cov div{{margin:6px 0}} ul.cats{{columns:2;padding-left:18px}}
footer{{color:var(--txt);font-size:11px;text-align:center;padding:20px}}
</style></head><body>
<header>{_logo()}<div><h1>Reporte de novedades · Código Oracle</h1>
<div class="meta">Rama <b>{e(str(c.get('rama')))}</b> @ {e(str(c.get('commit')))} · base {e(str(base))} · modo {e(str(c.get('modo')))}
{' · solo líneas modificadas' if c.get('solo_lineas_cambiadas') else ''} · {e(d['fecha'])}</div>
<div class="meta">{e(str(c.get('repositorio', '')))} · Casos aplicados: {e(c.get('casos_aplicados') or 'todas las reglas de la matriz')}</div></div>
<div class="gate">Quality Gate: {g['estado']}</div></header>
<main>
<div class="cards">{cards}</div>
{('<div class="motivos"><b>Push bloqueado.</b> ' + '; '.join(e(m) for m in g['motivos']) + '. Corrige las incidencias marcadas como <b>Bloquea</b>.</div>') if not ok else '<div class="okmsg"><b>El código cumple el quality gate.</b> Revisa igualmente las advertencias y los hallazgos marcados como <i>Revisar</i>.</div>'}
<div class="grid2"><div><h2>Archivos analizados ({len(d['archivos'])})</h2>
<table><thead><tr><th>Archivo</th><th>Líneas</th><th>Hallazgos</th><th>Objetos</th></tr></thead><tbody>{archivos_tbl or '<tr><td colspan=4>No hay archivos Oracle en el alcance.</td></tr>'}</tbody></table></div>
<div><h2>Por categoría</h2><ul class="cats">{cats or '<li>Sin hallazgos</li>'}</ul></div></div>
<h2>Novedades ({len(hs)})</h2>
<div class="filtros"><button class="on" data-f="all">Todas</button><button data-f="bloq">Solo bloqueantes</button>
{''.join(f'<button data-f="{s}">{s}</button>' for s in SEVS)}</div>
{''.join(filas) or '<p>Sin novedades.</p>'}
{sup}
<h2>Cobertura de la matriz</h2>{cobertura}
</main><footer>Generado por oravalidator {e(d['version'])} · Matriz Oracle de {cob['total']} reglas</footer>
<script>
document.querySelectorAll('.filtros button').forEach(b=>b.onclick=()=>{{
 document.querySelectorAll('.filtros button').forEach(x=>x.classList.remove('on'));b.classList.add('on');const f=b.dataset.f;
 document.querySelectorAll('tr[data-sev]').forEach(tr=>{{tr.style.display=(f==='all'||(f==='bloq'&&tr.dataset.bloq==='1')||tr.dataset.sev===f)?'':'none'}});
 document.querySelectorAll('section.file').forEach(s=>{{s.style.display=[...s.querySelectorAll('tr[data-sev]')].some(t=>t.style.display!=='none')?'':'none'}});
}});
</script></body></html>"""
