# -*- coding: utf-8 -*-
"""Poster do Adamastor SOC: uma imagem que explica cada serviço, o que faz e como se liga."""
from html import escape
from pathlib import Path

W, H = 1720, 1280
INK = "#1b2733"; QUIET = "#5c6b7a"; PAPER = "#ffffff"
BANDS = {
    "ver":      ("#e9f4f2", "#1f7a6b", "VER", "descoberta"),
    "saber":    ("#eaf1fc", "#2554a8", "SABER", "priorizar"),
    "decidir":  ("#f1ecfb", "#5a3db0", "DECIDIR", "acompanhar"),
    "responder":("#fdefeb", "#b5452f", "RESPONDER", "agir e avisar"),
    "sustentar":("#eaf5ec", "#2f7d43", "SUSTENTAR", "manter seguro"),
}
ARROW = "#2c69cf"; ARROW2 = "#8a93a0"; EXT = "#9aa7b4"

boxes = {}   # id -> dict
def box(id, x, y, w, h, title, desc, kind="our", band="ver"):
    boxes[id] = dict(x=x, y=y, w=w, h=h, title=title, desc=desc, kind=kind, band=band)

# ---- bandas (y) ----
BY = {"ver": (120, 360), "saber": (380, 560), "decidir": (580, 740),
      "responder": (760, 1010), "sustentar": (1030, 1200)}
LX = 170  # fim da faixa de rótulos à esquerda

# ---------- VER ----------
box("alvos", 185, 175, 230, 160,
    "Alvos de teste",
    "Apache 2.4.49 e Metasploitable, propositadamente vulneráveis, para testar e confirmar que os scans detetam o que devem.",
    "lab", "ver")
box("greenbone", 440, 175, 255, 160,
    "Greenbone + sonda nmap",
    "Varre a rede. A sonda (nmap) encontra as portas abertas; o Greenbone testa-as e aponta as vulnerabilidades.",
    "our", "ver")
box("wpscan", 720, 175, 230, 160,
    "WPScan",
    "Procura vulnerabilidades conhecidas em plugins e temas dos sites WordPress.",
    "our", "ver")
box("servidores", 975, 175, 230, 160,
    "Servidores (SSH)",
    "Liga-se aos servidores sem agente: saúde, hardening e atualizações de segurança em falta.",
    "our", "ver")
box("atalaia", 1230, 175, 250, 160,
    "Atalaia · certificados",
    "Vigia os certificados TLS: quando expiram, o que está na CMDB e o que foi emitido na Internet (CT).",
    "our", "ver")
box("cmdb", 1500, 175, 205, 160,
    "CMDB",
    "A CMDB da organização: inventário, donos e criticidade de cada ativo.",
    "ext", "ver")

# ---------- SABER ----------
box("vulnflux", 560, 400, 600, 140,
    "VulnFlux — motor de risco",
    "O cérebro do SOC. Orquestra todos os scans e calcula o risco real de cada vulnerabilidade: KEV (já explorada no terreno), EPSS (probabilidade de exploração) e o contexto do ativo (criticidade e exposição).",
    "our", "saber")
box("feeds", 185, 400, 320, 140,
    "Feeds de risco",
    "Sinais externos atualizados todos os dias sobre cada CVE: CISA KEV, EPSS, Exploit-DB, Metasploit e Nuclei.",
    "ext", "saber")
box("siem_ctx", 1215, 400, 300, 140,
    "Watchlist de exposição → SIEM",
    "A lista host × CVE × prioridade que o SIEM importa para cruzar com os alertas de WAF, IDS e EDR.",
    "our", "saber")

# ---------- DECIDIR ----------
box("defectdojo", 560, 600, 290, 120,
    "DefectDojo",
    "Guarda todos os findings, define prazos e SLA por prioridade e evita duplicados.",
    "our", "decidir")
box("portal", 870, 600, 290, 120,
    "Portal Adamastor",
    "Inventário vivo do SOC: que serviços existem, como se ligam, se estão saudáveis e atualizados.",
    "our", "decidir")

# ---------- RESPONDER ----------
box("eventos", 560, 790, 290, 120,
    "Eventos e alertas",
    "Quando aparece um P1 ou KEV novo, um servidor crítico ou um scan falhado, gera um evento — uma só vez.",
    "our", "responder")
box("siem", 905, 820, 300, 150,
    "SIEM",
    "Centro de deteção: junta logs e alertas de todas as fontes, correlaciona e abre incidentes. Continua a ser o centro — o Adamastor dá-lhe a exposição.",
    "ext", "responder")
box("sensores", 905, 790, 300, 0, "", "", "ext", "responder")  # placeholder (remove)
del boxes["sensores"]
box("sensores2", 560, 915, 290, 92,
    "EDR · Firewalls · WAF",
    "Sensores que já tens: enviam alertas ao SIEM e bloqueiam ataques.",
    "ext", "responder")
box("teams", 1255, 790, 220, 95,
    "Webhook → Teams",
    "Avisa as pessoas, no imediato, quando há algo urgente.",
    "our", "responder")
box("tickets", 1255, 900, 220, 95,
    "Tickets (SMAX)",
    "Abre pedidos de correção e de renovação de certificados.",
    "ext", "responder")
box("nis2", 905, 790, 300, 0, "", "", "todo", "responder"); del boxes["nis2"]

# ---------- SUSTENTAR ----------
box("backups", 235, 1065, 330, 110,
    "Backups diários",
    "DefectDojo, Atalaia e o estado do VulnFlux e do portal, com restauro testado automaticamente.",
    "our", "sustentar")
box("redes", 613, 1065, 330, 110,
    "Redes segmentadas",
    "Oito redes por função; bases de dados isoladas; os alvos só são alcançáveis pelo scanner e pela sonda.",
    "our", "sustentar")
box("versoes", 991, 1065, 330, 110,
    "Versões fixas + Dependabot",
    "Imagens travadas por digest; o Dependabot propõe as subidas e o CI testa-as antes de entrarem.",
    "our", "sustentar")
box("trivy", 1369, 1065, 330, 110,
    "Trivy + SBOM",
    "Analisa as nossas imagens à procura de vulnerabilidades e lista todos os componentes (CycloneDX).",
    "our", "sustentar")

# ---------------- arrows ----------------
# (from_id, from_side, to_id, to_side, label, color, dashed, bend)
A = []
def arr(a, asd, b, bsd, label="", color=ARROW2, dash=False, off_a=0.0, off_b=0.0):
    A.append((a, asd, b, bsd, label, color, dash, off_a, off_b))

arr("alvos", "b", "greenbone", "b", "", ARROW2, False)  # not shown well; replace below
A.pop()
arr("cmdb", "b", "vulnflux", "t", "ativos e criticidade", ARROW2, True, 0.0, 0.42)
arr("feeds", "b", "vulnflux", "t", "", ARROW2, True, 0.0, -0.42)
arr("greenbone", "b", "vulnflux", "t", "", ARROW, False, 0.0, -0.18)
arr("wpscan", "b", "vulnflux", "t", "resultados", ARROW, False, 0.0, 0.0)
arr("servidores", "b", "vulnflux", "t", "", ARROW, False, 0.0, 0.18)
arr("atalaia", "b", "vulnflux", "t", "", ARROW, False, 0.0, 0.33)
arr("vulnflux", "b", "defectdojo", "t", "findings e prazos", ARROW, False, -0.33, 0.0)
arr("vulnflux", "b", "portal", "t", "estado e frescura", ARROW2, False, 0.33, 0.0)
arr("defectdojo", "b", "eventos", "t", "", ARROW, False)
arr("vulnflux", "r", "siem_ctx", "l", "exposição", ARROW, False)
arr("eventos", "r", "siem", "l", "eventos P1/KEV", ARROW, False, 0.0, -0.2)
arr("sensores2", "r", "siem", "l", "alertas", ARROW2, True, 0.0, 0.3)
arr("siem_ctx", "b", "siem", "t", "watchlist", ARROW2, True)
arr("eventos", "r", "teams", "l", "", ARROW2, False, 0.0, 0.0)
arr("siem", "r", "tickets", "l", "incidente", ARROW2, True)

# --------- geometria das setas ----------
def anchor(b, side, off):
    x, y, w, h = b["x"], b["y"], b["w"], b["h"]
    if side == "t": return (x + w/2 + off*w, y)
    if side == "b": return (x + w/2 + off*w, y + h)
    if side == "l": return (x, y + h/2 + off*h)
    if side == "r": return (x + w, y + h/2 + off*h)

def path(a, asd, b, bsd, off_a, off_b):
    ax, ay = anchor(boxes[a], asd, off_a); bx, by = anchor(boxes[b], bsd, off_b)
    if asd in "tb" and bsd in "tb":
        my = (ay + by) / 2
        d = f"M{ax:.1f},{ay:.1f} C{ax:.1f},{my:.1f} {bx:.1f},{my:.1f} {bx:.1f},{by:.1f}"
    elif asd in "lr" and bsd in "lr":
        mx = (ax + bx) / 2
        d = f"M{ax:.1f},{ay:.1f} C{mx:.1f},{ay:.1f} {mx:.1f},{by:.1f} {bx:.1f},{by:.1f}"
    else:
        d = f"M{ax:.1f},{ay:.1f} C{bx:.1f},{ay:.1f} {ax:.1f},{by:.1f} {bx:.1f},{by:.1f}"
    return d, (ax+bx)/2, (ay+by)/2

svg = []
svg.append(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" font-family="-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif">')
svg.append(f'<rect x="0" y="0" width="{W}" height="{H}" fill="{PAPER}"/>')
# título
svg.append(f'<text x="48" y="60" font-size="34" font-weight="700" fill="{INK}">Adamastor SOC — o que temos e como se liga</text>')
svg.append(f'<text x="48" y="92" font-size="17" fill="{QUIET}">Centro de operações de segurança · cada caixa é um serviço e o que faz · as setas mostram o que passa de um para o outro</text>')

# bandas
for key, (y0, y1) in BY.items():
    fill, strong, name, sub = BANDS[key]
    svg.append(f'<rect x="40" y="{y0}" width="{W-80}" height="{y1-y0}" rx="14" fill="{fill}"/>')
    svg.append(f'<text x="64" y="{y0+42}" font-size="22" font-weight="700" fill="{strong}">{name}</text>')
    svg.append(f'<text x="64" y="{y0+66}" font-size="13.5" fill="{strong}" opacity="0.85">{escape(sub)}</text>')

# defs marcadores
svg.append('<defs>')
for name, col in [("a", ARROW), ("b", ARROW2), ("e", EXT)]:
    svg.append(f'<marker id="m{name}" viewBox="0 0 10 10" refX="8.5" refY="5" markerWidth="7.5" markerHeight="7.5" orient="auto-start-reverse"><path d="M0,1 L10,5 L0,9 z" fill="{col}"/></marker>')
svg.append('</defs>')

# setas (por baixo das caixas)
labels = []
for a, asd, b, bsd, label, color, dash, oa, ob in A:
    if a not in boxes or b not in boxes: continue
    d, mx, my = path(a, asd, b, bsd, oa, ob)
    mk = "ma" if color == ARROW else ("me" if dash else "mb")
    da = ' stroke-dasharray="6 5"' if dash else ''
    svg.append(f'<path d="{d}" fill="none" stroke="{color}" stroke-width="2.2"{da} marker-end="url(#{mk})"/>')
    if label:
        labels.append((mx, my, label, color))

# caixas
for id, b in boxes.items():
    if b["h"] == 0: continue
    x, y, w, h = b["x"], b["y"], b["w"], b["h"]
    if b["kind"] == "ext":
        bg, stroke, dash, tag = "#ffffff", EXT, ' stroke-dasharray="6 5"', "externo"
    elif b["kind"] == "lab":
        bg, stroke, dash, tag = "#fff7f4", "#c9704f", ' stroke-dasharray="6 5"', "laboratório"
    elif b["kind"] == "todo":
        bg, stroke, dash, tag = "#f6f7f9", "#9aa7b4", ' stroke-dasharray="3 5"', "por fazer"
    else:
        bg, stroke, dash, tag = "#ffffff", "#33495c", '', ""
    svg.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="12" fill="{bg}" stroke="{stroke}" stroke-width="1.8"{dash}/>')
    big = w > 400
    ts = 20 if big else 16.5
    svg.append(f'<text x="{x+18}" y="{y+30}" font-size="{ts}" font-weight="700" fill="{INK}">{escape(b["title"])}</text>')
    if tag:
        tw = len(tag)*7.2 + 14
        svg.append(f'<rect x="{x+w-tw-14}" y="{y+13}" width="{tw}" height="20" rx="10" fill="{stroke}" opacity="0.14"/>')
        svg.append(f'<text x="{x+w-tw-14+tw/2}" y="{y+27}" font-size="11.5" fill="{stroke}" text-anchor="middle">{escape(tag)}</text>')
    # descrição com quebra de linha
    desc = b["desc"]; fs = 14.5 if big else 13
    cpl = int((w-36) / (fs*0.52))
    words = desc.split(); line = ""; lines = []
    for wd in words:
        if len(line)+len(wd)+1 <= cpl: line = (line+" "+wd).strip()
        else: lines.append(line); line = wd
    if line: lines.append(line)
    ly = y + (56 if big else 52)
    for ln in lines:
        svg.append(f'<text x="{x+18}" y="{ly:.0f}" font-size="{fs}" fill="{QUIET}">{escape(ln)}</text>')
        ly += fs + 5

# rótulos das setas (por cima)
for mx, my, label, color in labels:
    tw = len(label)*6.8 + 12
    svg.append(f'<rect x="{mx-tw/2:.1f}" y="{my-11:.1f}" width="{tw:.1f}" height="19" rx="6" fill="#ffffff" stroke="{color}" stroke-width="0.8" opacity="0.96"/>')
    svg.append(f'<text x="{mx:.1f}" y="{my+3:.1f}" font-size="12" fill="{color}" text-anchor="middle" font-weight="600">{escape(label)}</text>')

# legenda (rodapé)
ly = H - 46
items = [("#33495c", "solid", "serviço nosso"), (EXT, "dash", "sistema externo (já existe)"),
         ("#c9704f", "dash", "alvo de laboratório"), (ARROW, "arrow", "o que criámos de novo"),
         (ARROW2, "arrowd", "integração / fluxo existente")]
lx = 48
svg.append(f'<text x="{lx}" y="{ly-24}" font-size="13" font-weight="700" fill="{INK}">Legenda</text>')
for col, style, txt in items:
    if style == "solid":
        svg.append(f'<rect x="{lx}" y="{ly-11}" width="26" height="15" rx="4" fill="#fff" stroke="{col}" stroke-width="1.8"/>')
    elif style == "dash":
        svg.append(f'<rect x="{lx}" y="{ly-11}" width="26" height="15" rx="4" fill="#fff" stroke="{col}" stroke-width="1.8" stroke-dasharray="4 3"/>')
    elif style == "arrow":
        svg.append(f'<line x1="{lx}" y1="{ly-3}" x2="{lx+26}" y2="{ly-3}" stroke="{col}" stroke-width="2.4" marker-end="url(#ma)"/>')
    else:
        svg.append(f'<line x1="{lx}" y1="{ly-3}" x2="{lx+26}" y2="{ly-3}" stroke="{col}" stroke-width="2.4" stroke-dasharray="6 5" marker-end="url(#mb)"/>')
    svg.append(f'<text x="{lx+34}" y="{ly}" font-size="13" fill="{QUIET}">{escape(txt)}</text>')
    lx += 60 + len(txt)*7.4

svg.append('</svg>')
out = "<!doctype html><meta charset='utf-8'><style>body{margin:0;background:#fff}</style>" + "".join(svg)
Path(__file__).with_name("poster.html").write_text(out, encoding="utf-8")
print("ok", len(boxes), "caixas", len(A), "setas")
