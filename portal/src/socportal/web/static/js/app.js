/* VulnFlux — comportamento da interface. Sem eval nem scripts inline (CSP estrita). */
(function () {
  "use strict";

  const csrf = () => document.querySelector('meta[name="csrf-token"]')?.content || "";

  // CSRF em todos os pedidos HTMX
  document.addEventListener("htmx:configRequest", (e) => {
    e.detail.headers["X-CSRF-Token"] = csrf();
  });

  // ---------------- Toasts ----------------
  function toast(message, level) {
    const box = document.getElementById("toasts");
    if (!box || !message) return;
    const el = document.createElement("div");
    el.className = "toast" + (level && level !== "ok" ? " toast-" + level : "");
    el.setAttribute("role", "status");
    el.textContent = message;
    box.appendChild(el);
    setTimeout(() => el.remove(), level === "error" ? 8000 : 4500);
  }
  document.body.addEventListener("toast", (e) => toast(e.detail.message, e.detail.level));
  document.body.addEventListener("htmx:responseError", (e) => {
    // Erros com HX-Trigger já mostram o seu próprio toast
    if (e.detail.xhr.getResponseHeader("HX-Trigger")) return;
    toast("Erro " + e.detail.xhr.status + " ao comunicar com o servidor.", "error");
  });
  document.body.addEventListener("htmx:sendError", () => toast("Sem ligação ao servidor.", "error"));

  // ---------------- Modal ----------------
  const modal = () => document.getElementById("modal");
  document.body.addEventListener("htmx:afterSwap", (e) => {
    if (e.detail.target && e.detail.target.id === "modal-body") {
      const m = modal();
      if (m && !m.open) m.showModal();
      const first = m && m.querySelector("[autofocus], input:not([type=hidden]), textarea");
      if (first) first.focus();
    }
    applyAllFilters();
  });
  document.addEventListener("click", (e) => {
    if (e.target.closest("[data-close-modal]")) {
      modal()?.close();
      return;
    }
    // clicar no fundo fecha o modal
    const m = modal();
    if (m && e.target === m) m.close();
  });
  document.addEventListener("close", (e) => {
    if (e.target.id === "modal") document.getElementById("modal-body").innerHTML = "";
  }, true);

  // ---------------- Linhas clicáveis ----------------
  document.addEventListener("click", (e) => {
    const row = e.target.closest("tr[data-href]");
    if (!row || e.target.closest("a, button, input, select, label")) return;
    window.location.href = row.dataset.href;
  });

  // ---------------- Filtro de tabelas ----------------
  function applyFilter(input) {
    const table = document.querySelector(input.dataset.filter);
    if (!table) return;
    const terms = input.value.trim().toLowerCase().split(/\s+/).filter(Boolean);
    table.querySelectorAll("tbody tr").forEach((tr) => {
      const hay = (tr.dataset.search || tr.textContent).toLowerCase();
      tr.hidden = terms.length > 0 && !terms.every((t) => hay.includes(t));
    });
  }
  function applyAllFilters() {
    document.querySelectorAll("input[data-filter]").forEach(applyFilter);
  }
  document.addEventListener("input", (e) => {
    if (e.target.matches("input[data-filter]")) applyFilter(e.target);
  });

  // Atalho: "/" foca a pesquisa
  document.addEventListener("keydown", (e) => {
    if (e.key === "/" && !e.target.closest("input, textarea, select")) {
      const s = document.querySelector("input[data-filter]");
      if (s) { e.preventDefault(); s.focus(); }
    }
  });

  // Flashes do servidor desaparecem sozinhos
  setTimeout(() => document.querySelectorAll(".content ~ .flash, .main > .flash.flash-ok").forEach((f) => f.remove()), 6000);
  // ---------------- Mapa: clicar numa função realça as ligadas ----------------
  document.addEventListener("click", (e) => {
    const fn = e.target.closest("[data-map] .fn");
    const map = document.querySelector("[data-map]");
    if (!map) return;
    if (!fn || e.target.closest("a")) {
      if (!fn && !e.target.closest("[data-map]")) {
        map.classList.remove("focus");
        map.querySelectorAll(".fn").forEach((x) => x.classList.remove("is-focus", "is-linked"));
      }
      return;
    }
    const was = fn.classList.contains("is-focus");
    map.querySelectorAll(".fn").forEach((x) => x.classList.remove("is-focus", "is-linked"));
    if (was) { map.classList.remove("focus"); return; }
    map.classList.add("focus");
    fn.classList.add("is-focus");
    (fn.dataset.links || "").split(" ").filter(Boolean).forEach((id) => {
      document.getElementById("fn-" + id)?.classList.add("is-linked");
    });
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && e.target.matches && e.target.matches("[data-map] .fn")) e.target.click();
  });
  // ---------------- Inventário: linhas entre aplicações e painel de detalhe ----------------
  const SVGNS = "http://www.w3.org/2000/svg";
  let selected = null;
  let hovered = null;
  let selectedEdge = null; // "origem|destino" da ligação aberta no painel

  function drawLines() {
    const stage = document.querySelector(".inv-stage");
    if (!stage) return;
    const svg = stage.querySelector(".inv-lines");
    let edges = [];
    try { edges = JSON.parse(stage.dataset.edges || "[]"); } catch (_) { edges = []; }
    // No mapa, as linhas vivem dentro da tela, que pode estar à escala: medidas em unidades da tela.
    const scale = parseFloat(stage.dataset.scale || "1") || 1;
    const host = svg.parentElement;
    const box = host.getBoundingClientRect();
    const W = box.width / scale, H = box.height / scale;
    svg.setAttribute("width", W);
    svg.setAttribute("height", H);
    svg.setAttribute("viewBox", "0 0 " + W + " " + H);
    svg.replaceChildren();
    const rel = (r) => ({ left: (r.left - box.left) / scale, top: (r.top - box.top) / scale, width: r.width / scale, height: r.height / scale });
    const at = (id) => stage.querySelector('[data-node="' + CSS.escape(id) + '"]');
    edges.forEach((e) => {
      const a = at(e.from), b = at(e.to);
      if (!a || !b) return;
      const ra = rel(a.getBoundingClientRect()), rb = rel(b.getBoundingClientRect());
      const ax = ra.left + ra.width / 2, ay = ra.top + ra.height / 2;
      const bx = rb.left + rb.width / 2, by = rb.top + rb.height / 2;
      const external = e.to.startsWith("ext-");
      const path = document.createElementNS(SVGNS, "path");
      // Na mesma camada (linha): arco por cima, de borda a borda. Entre camadas: curva vertical.
      const sameRow = Math.abs(by - ay) < 12;
      let d;
      if (sameRow) {
        const x1 = bx > ax ? ax + ra.width / 2 : ax - ra.width / 2, x2 = bx > ax ? bx - rb.width / 2 : bx + rb.width / 2;
        const y = ay - ra.height / 2, lift = Math.min(60, 18 + Math.abs(x2 - x1) / 6);
        d = `M${ax},${y} C${ax},${y - lift} ${bx},${y - lift} ${bx},${y}`;
        void x1; void x2;
      } else {
        const down = by > ay;
        const y1 = down ? ay + ra.height / 2 : ay - ra.height / 2, y2 = down ? by - rb.height / 2 : by + rb.height / 2;
        const dy = Math.max(30, Math.abs(y2 - y1) / 2) * (down ? 1 : -1);
        d = `M${ax},${y1} C${ax},${y1 + dy} ${bx},${y2 - dy} ${bx},${y2}`;
      }
      path.setAttribute("d", d);
      path.setAttribute("class", "ln ln-" + (external ? "ext" : e.status));
      path.dataset.from = e.from; path.dataset.to = e.to;
      // Traço largo e invisível por baixo: a ligação é fácil de apanhar com o rato
      const hit = document.createElementNS(SVGNS, "path");
      hit.setAttribute("d", d);
      hit.setAttribute("class", "hit");
      hit.dataset.edge = e.from + "|" + e.to;
      const title = document.createElementNS(SVGNS, "title");
      title.textContent = e.via + (e.what ? ": " + e.what : "") + " (carrega para ver e alterar)";
      hit.appendChild(title);
      const focus = selected || hovered;
      const on = (selectedEdge === e.from + "|" + e.to) || (!selectedEdge && focus && (e.from === focus || e.to === focus));
      if (!external || selected === e.from || selectedEdge === e.from + "|" + e.to) svg.appendChild(hit); // as externas só aparecem (e só se apanham) com o serviço em foco
      svg.appendChild(path);
      if (on) {
        path.classList.add("ln-on");
        const mx = (ax + bx) / 2, my = (ay + by) / 2;
        const t = document.createElementNS(SVGNS, "text");
        t.setAttribute("x", mx); t.setAttribute("y", my - 4);
        t.setAttribute("text-anchor", "middle");
        t.setAttribute("class", "ln-label");
        t.textContent = e.via;
        svg.appendChild(t);
        const bb = t.getBBox();
        const bg = document.createElementNS(SVGNS, "rect");
        bg.setAttribute("x", bb.x - 5); bg.setAttribute("y", bb.y - 2);
        bg.setAttribute("width", bb.width + 10); bg.setAttribute("height", bb.height + 4);
        bg.setAttribute("rx", 5); bg.setAttribute("class", "ln-label-bg");
        svg.insertBefore(bg, t);
      }
    });
    const focus = selected || hovered;
    stage.classList.toggle("has-sel", !!focus);
    stage.querySelectorAll("[data-node]").forEach((el) => {
      const id = el.dataset.node;
      const linked = focus && edges.some((e) => (e.from === focus && e.to === id) || (e.to === focus && e.from === id));
      el.classList.toggle("is-sel", id === focus);
      el.classList.toggle("is-linked", !!linked);
    });
  }

  function openDrawer(id) {
    const drawer = document.getElementById("inv-drawer");
    if (!drawer || !window.htmx) return;
    selected = id;
    drawLines();
    htmx.ajax("GET", "/inventory/" + encodeURIComponent(id), { target: "#inv-drawer", swap: "innerHTML" }).then(() => {
      drawer.hidden = false;
    });
  }
  function closeDrawer() {
    const drawer = document.getElementById("inv-drawer");
    if (drawer) { drawer.hidden = true; drawer.replaceChildren(); }
    selected = null;
    selectedEdge = null;
    drawLines();
  }
  function openPanel(url, sel, edgeKey) {
    const drawer = document.getElementById("inv-drawer");
    if (!drawer || !window.htmx) return;
    selected = sel; selectedEdge = edgeKey;
    drawLines();
    htmx.ajax("GET", url, { target: "#inv-drawer", swap: "innerHTML" }).then(() => {
      drawer.hidden = false;
      const first = drawer.querySelector("input:not([type=hidden]), select, button");
      if (first) first.focus({ preventScroll: true });
    });
  }
  function openEdge(edgeKey) {
    const [a, b] = edgeKey.split("|");
    openPanel("/ligacao?de=" + encodeURIComponent(a) + "&para=" + encodeURIComponent(b), a, edgeKey);
  }
  document.addEventListener("click", (e) => {
    const edge = e.target.closest && e.target.closest("[data-edge]");
    if (edge) { e.preventDefault(); openEdge(edge.dataset.edge); return; }
    if (e.target.closest && e.target.closest("[data-new-edge]")) { e.preventDefault(); openPanel("/ligacao/nova" + (selected ? "?de=" + encodeURIComponent(selected) : ""), selected, null); return; }
    const open = e.target.closest("[data-open]");
    if (open) { e.preventDefault(); selectedEdge = null; if (selected === open.dataset.open && !document.getElementById("inv-drawer").hidden && !e.target.closest(".drawer")) closeDrawer(); else openDrawer(open.dataset.open); return; }
    if (e.target.closest("[data-close-drawer]")) closeDrawer();
  });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape" && selected) closeDrawer(); });
  // Passar o rato (ou o foco do teclado) por um serviço destaca as suas ligações, sem abrir nada.
  const hoverOn = (e) => {
    const hit = e.target.classList && e.target.classList.contains("hit") ? e.target : null;
    if (hit) { const k = hit.dataset.edge; if (hovered !== k) { hovered = null; drawLines(); const vis = hit.nextSibling; if (vis) vis.classList.add("ln-hover"); } return; }
    const card = e.target.closest && e.target.closest(".inv-stage article[data-node]");
    const id = card ? card.dataset.node : null;
    if (id !== hovered) { hovered = id; drawLines(); }
  };
  document.addEventListener("mouseover", hoverOn);
  document.addEventListener("focusin", hoverOn);
  document.body.addEventListener("htmx:afterSwap", (e) => { if (e.detail.target && e.detail.target.id === "inventory") drawLines(); });
  document.body.addEventListener("htmx:afterSettle", () => drawLines());
  window.addEventListener("resize", () => { fitMap(); drawLines(); });

  // ---------------- Mapa: nós arrastáveis, ligar arrastando, zoom ----------------
  const postLayout = (body) => fetch("/layout", {
    method: "POST", credentials: "same-origin",
    headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf() },
    body: JSON.stringify(body),
  });
  let userZoom = 1;
  try { userZoom = parseFloat(sessionStorage.getItem("mapZoom") || "1") || 1; } catch (_) { userZoom = 1; }
  let dragging = null;

  function fitMap() {
    const stage = document.querySelector(".inv-map");
    if (!stage) return;
    const viewport = stage.querySelector(".map-viewport"), canvas = stage.querySelector(".map-canvas");
    let w = 0, h = 0;
    canvas.querySelectorAll(".map-node").forEach((el) => {
      const x = parseFloat(el.dataset.x) || 0, y = parseFloat(el.dataset.y) || 0;
      el.style.left = x + "px"; el.style.top = y + "px";
      w = Math.max(w, x + el.offsetWidth); h = Math.max(h, y + el.offsetHeight);
    });
    w += 24; h += 24;
    canvas.style.width = w + "px"; canvas.style.height = h + "px";
    // Cabe no ecrã: na largura do painel e na altura que sobra até ao fundo da janela
    const availW = viewport.clientWidth;
    // O que fica por baixo do mapa (legenda, rodapé da página) também tem de caber
    const vr = viewport.getBoundingClientRect();
    const docBottom = document.documentElement.scrollHeight - window.scrollY;
    const below = Math.max(0, docBottom - vr.bottom);
    const availH = Math.max(260, window.innerHeight - vr.top - below - 8);
    const small = window.innerWidth < 760;
    // No telemóvel o mapa inteiro ficaria ilegível: escala fixa e desliza-se dentro do mapa
    const fit = small ? 0.6 : Math.min(1.1, availW / w, availH / h);
    const s = Math.max(0.25, Math.min(2.5, fit * userZoom));
    stage.dataset.scale = String(s);
    canvas.style.transform = "scale(" + s + ")";
    viewport.style.height = Math.ceil(small ? Math.min(h * s, window.innerHeight * 0.7) : h * s) + "px";
    viewport.classList.toggle("is-zoomed", small || userZoom > 1.001);
  }

  function nodeAt(x, y, except) {
    const el = document.elementFromPoint(x, y);
    const n = el && el.closest(".map-canvas [data-node]");
    return n && n !== except ? n : null;
  }

  document.addEventListener("pointerdown", (e) => {
    const stage = e.target.closest && e.target.closest(".inv-map");
    if (!stage || e.button !== 0) return;
    const scale = parseFloat(stage.dataset.scale || "1") || 1;
    const port = e.target.closest("[data-port]");
    const node = e.target.closest(".map-node");
    if (port) {
      e.preventDefault();
      const src = port.closest(".map-node");
      dragging = { kind: "link", src, scale, stage, startX: e.clientX, startY: e.clientY };
    } else if (node && !e.target.closest("button, a, input, select")) {
      e.preventDefault();
      dragging = { kind: "move", node, scale, stage, startX: e.clientX, startY: e.clientY,
        x0: parseFloat(node.dataset.x) || 0, y0: parseFloat(node.dataset.y) || 0, moved: false };
      node.classList.add("is-dragging");
    } else {
      return;
    }
    stage.setPointerCapture && stage.setPointerCapture(e.pointerId);
  });

  let raf = 0;
  document.addEventListener("pointermove", (e) => {
    if (!dragging) return;
    const d = dragging;
    const dx = (e.clientX - d.startX) / d.scale, dy = (e.clientY - d.startY) / d.scale;
    if (d.kind === "move") {
      if (Math.abs(dx) + Math.abs(dy) > 3) d.moved = true;
      const x = Math.max(0, Math.round(d.x0 + dx)), y = Math.max(0, Math.round(d.y0 + dy));
      d.node.dataset.x = x; d.node.dataset.y = y;
      d.node.style.left = x + "px"; d.node.style.top = y + "px";
      if (!raf) raf = requestAnimationFrame(() => { raf = 0; drawLines(); });
    } else {
      // Linha provisória do + até ao cursor
      const svg = d.stage.querySelector(".inv-lines");
      const box = svg.parentElement.getBoundingClientRect();
      const r = d.src.getBoundingClientRect();
      const ax = (r.right - box.left) / d.scale, ay = (r.top + r.height / 2 - box.top) / d.scale;
      const bx = (e.clientX - box.left) / d.scale, by = (e.clientY - box.top) / d.scale;
      let tmp = svg.querySelector(".ln-temp");
      if (!tmp) { tmp = document.createElementNS(SVGNS, "path"); tmp.setAttribute("class", "ln ln-temp"); svg.appendChild(tmp); }
      tmp.setAttribute("d", `M${ax},${ay} C${ax + 60},${ay} ${bx - 60},${by} ${bx},${by}`);
      d.stage.querySelectorAll(".is-target").forEach((n) => n.classList.remove("is-target"));
      const t = nodeAt(e.clientX, e.clientY, d.src);
      if (t) t.classList.add("is-target");
    }
  });

  document.addEventListener("pointerup", (e) => {
    if (!dragging) return;
    const d = dragging;
    dragging = null;
    if (d.kind === "move") {
      d.node.classList.remove("is-dragging");
      if (d.moved) {
        d.node.dataset.justDragged = "1";
        setTimeout(() => { delete d.node.dataset.justDragged; }, 0);
        postLayout({ positions: { [d.node.dataset.node]: { x: +d.node.dataset.x, y: +d.node.dataset.y } } });
        fitMap(); drawLines();
      }
    } else {
      d.stage.querySelectorAll(".is-target").forEach((n) => n.classList.remove("is-target"));
      const tmp = d.stage.querySelector(".ln-temp"); if (tmp) tmp.remove();
      const t = nodeAt(e.clientX, e.clientY, d.src);
      if (t) {
        const para = t.dataset.name || t.dataset.node;
        openPanel("/ligacao/nova?de=" + encodeURIComponent(d.src.dataset.node) + "&para=" + encodeURIComponent(para), d.src.dataset.node, null);
      }
    }
  });
  // Um arrasto não conta como clique no nome do serviço
  document.addEventListener("click", (e) => {
    const n = e.target.closest && e.target.closest(".map-node");
    if (n && n.dataset.justDragged) { e.stopPropagation(); e.preventDefault(); }
  }, true);

  // Teclado: Alt + setas move o serviço com o foco (20 px; com Shift, 5 px)
  document.addEventListener("keydown", (e) => {
    if (!e.altKey || !e.key.startsWith("Arrow")) return;
    const node = e.target.closest && e.target.closest(".inv-map .map-node");
    if (!node) return;
    e.preventDefault();
    const step = e.shiftKey ? 5 : 20;
    const x = Math.max(0, (+node.dataset.x || 0) + (e.key === "ArrowRight" ? step : e.key === "ArrowLeft" ? -step : 0));
    const y = Math.max(0, (+node.dataset.y || 0) + (e.key === "ArrowDown" ? step : e.key === "ArrowUp" ? -step : 0));
    node.dataset.x = x; node.dataset.y = y;
    fitMap(); drawLines();
    clearTimeout(node._save);
    node._save = setTimeout(() => postLayout({ positions: { [node.dataset.node]: { x, y } } }), 400);
  });

  document.addEventListener("click", (e) => {
    const z = e.target.closest && e.target.closest("[data-zoom]");
    if (z) {
      const k = z.dataset.zoom;
      userZoom = k === "fit" ? 1 : Math.max(0.4, Math.min(3, userZoom * (k === "in" ? 1.2 : 1 / 1.2)));
      try { sessionStorage.setItem("mapZoom", String(userZoom)); } catch (_) { /* sem armazenamento */ }
      fitMap(); drawLines();
      return;
    }
    if (e.target.closest && e.target.closest("[data-layout-reset]")) {
      postLayout({ reset: true }).then(() => window.location.reload());
    }
  });

  // A atualização automática (30 s) não interrompe um arrasto
  document.body.addEventListener("htmx:beforeRequest", (e) => {
    if (dragging && e.detail.elt && e.detail.elt.id === "inventory") e.preventDefault();
  });
  document.body.addEventListener("htmx:afterSettle", () => { fitMap(); drawLines(); });
  fitMap(); drawLines();
  document.addEventListener("DOMContentLoaded", drawLines);
  if (document.readyState !== "loading") setTimeout(drawLines, 0);
  // ---------------- Tabelas no telemóvel e teclado ----------------
  // O nome de cada coluna vai para data-label (o CSS mostra-o ao lado do valor quando a tabela
  // vira cartões) e as linhas clicáveis sem link próprio passam a receber foco.
  function prepareTables(root) {
    (root || document).querySelectorAll("table.stack").forEach((table) => {
      const heads = [...table.querySelectorAll("thead th")].map((th) => th.textContent.trim());
      if (!heads.length) return;
      table.querySelectorAll("tbody tr").forEach((tr) => {
        [...tr.children].forEach((td, i) => { if (heads[i] && !td.hasAttribute("data-label")) td.setAttribute("data-label", heads[i]); });
      });
    });
    (root || document).querySelectorAll("tr[data-href]").forEach((tr) => {
      if (!tr.querySelector("a") && !tr.hasAttribute("tabindex")) { tr.tabIndex = 0; tr.setAttribute("role", "link"); }
    });
  }
  document.addEventListener("keydown", (e) => {
    const row = e.target.matches && e.target.matches("tr[data-href]") ? e.target : null;
    if (row && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); window.location.href = row.dataset.href; }
  });
  document.body.addEventListener("htmx:afterSwap", (e) => prepareTables(e.detail.target));
  if (document.readyState !== "loading") prepareTables(); else document.addEventListener("DOMContentLoaded", () => prepareTables());
})();
