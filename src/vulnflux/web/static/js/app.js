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

  // ---------------- Copiar comandos ----------------
  document.addEventListener("click", (e) => {
    const btn = e.target.closest("[data-copy]");
    if (!btn) return;
    const src = document.querySelector(btn.dataset.copy);
    if (!src) return;
    const text = src.textContent.trim();
    const done = () => toast("Copiado.", "ok");
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(done, () => selectText(src));
    } else {
      selectText(src);
    }
  });
  function selectText(el) {
    const r = document.createRange();
    r.selectNodeContents(el);
    const sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(r);
    toast("Selecionado: Ctrl+C para copiar.", "ok");
  }

  // ---------------- Separadores simples (data-tabs / data-tab-panel) ----------------
  document.addEventListener("click", (e) => {
    const btn = e.target.closest("[data-tabs] [data-tab]");
    if (!btn) return;
    const group = btn.closest("[data-tabs]");
    const name = group.dataset.tabs;
    group.querySelectorAll("[data-tab]").forEach((b) => b.classList.toggle("active", b === btn));
    document.querySelectorAll('[data-tab-panel^="' + name + ':"]').forEach((p) => {
      p.hidden = p.dataset.tabPanel !== name + ":" + btn.dataset.tab;
    });
  });

  // ---------------- Filtro de cartões (estado + texto), sobrevive ao refresh automático ----------------
  const cardFilter = { status: "", q: "" };
  function applyCards() {
    document.querySelectorAll("[data-card-filter]").forEach((seg) => {
      seg.querySelectorAll("[data-status]").forEach((b) => b.classList.toggle("active", b.dataset.status === cardFilter.status));
    });
    document.querySelectorAll("input[data-filter-cards]").forEach((inp) => {
      if (document.activeElement !== inp) inp.value = cardFilter.q;
    });
    const terms = cardFilter.q.trim().toLowerCase().split(/\s+/).filter(Boolean);
    document.querySelectorAll(".server-card").forEach((c) => {
      const okStatus = !cardFilter.status || c.dataset.status === cardFilter.status;
      const hay = (c.dataset.search || c.textContent).toLowerCase();
      c.hidden = !(okStatus && terms.every((t) => hay.includes(t)));
    });
  }
  document.addEventListener("click", (e) => {
    const b = e.target.closest("[data-card-filter] [data-status]");
    if (!b) return;
    cardFilter.status = b.dataset.status;
    applyCards();
  });
  document.addEventListener("input", (e) => {
    if (e.target.matches("input[data-filter-cards]")) { cardFilter.q = e.target.value; applyCards(); }
  });
  document.body.addEventListener("htmx:afterSwap", applyCards);

  // Flashes do servidor desaparecem sozinhos
  setTimeout(() => document.querySelectorAll(".content ~ .flash, .main > .flash.flash-ok").forEach((f) => f.remove()), 6000);
})();
