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

  function drawLines() {
    const stage = document.querySelector(".inv-stage");
    if (!stage) return;
    const svg = stage.querySelector(".inv-lines");
    let edges = [];
    try { edges = JSON.parse(stage.dataset.edges || "[]"); } catch (_) { edges = []; }
    const box = stage.getBoundingClientRect();
    svg.setAttribute("width", box.width);
    svg.setAttribute("height", box.height);
    svg.setAttribute("viewBox", "0 0 " + box.width + " " + box.height);
    svg.replaceChildren();
    const at = (id) => stage.querySelector('[data-node="' + CSS.escape(id) + '"]');
    edges.forEach((e) => {
      const a = at(e.from), b = at(e.to);
      if (!a || !b) return;
      const ra = a.getBoundingClientRect(), rb = b.getBoundingClientRect();
      const ax = ra.left + ra.width / 2 - box.left, ay = ra.top + ra.height / 2 - box.top;
      const bx = rb.left + rb.width / 2 - box.left, by = rb.top + rb.height / 2 - box.top;
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
      svg.appendChild(path);
      const on = selected && (e.from === selected || e.to === selected);
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
    stage.classList.toggle("has-sel", !!selected);
    stage.querySelectorAll("[data-node]").forEach((el) => {
      const id = el.dataset.node;
      const linked = selected && edges.some((e) => (e.from === selected && e.to === id) || (e.to === selected && e.from === id));
      el.classList.toggle("is-sel", id === selected);
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
    drawLines();
  }
  document.addEventListener("click", (e) => {
    const open = e.target.closest("[data-open]");
    if (open) { e.preventDefault(); if (selected === open.dataset.open) closeDrawer(); else openDrawer(open.dataset.open); return; }
    if (e.target.closest("[data-close-drawer]")) closeDrawer();
  });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape" && selected) closeDrawer(); });
  document.body.addEventListener("htmx:afterSwap", (e) => { if (e.detail.target && e.detail.target.id === "inventory") drawLines(); });
  document.body.addEventListener("htmx:afterSettle", () => drawLines());
  window.addEventListener("resize", () => drawLines());
  document.addEventListener("DOMContentLoaded", drawLines);
  if (document.readyState !== "loading") setTimeout(drawLines, 0);
})();
