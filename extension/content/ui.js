/* IOC Triage in-page UI: banners and dialogs rendered in closed Shadow DOM so pages can't restyle or read them. */
(function () {
  'use strict';
  if (window.__VSUI) return;

  const CSS = `
  :host { all: initial; }
  .vs { font: 14px/1.45 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; color: #1b1b1f; box-sizing: border-box; }
  .vs * { box-sizing: border-box; }
  .card { border-radius: 10px; padding: 14px 16px; border: 1px solid; display: flex; gap: 12px; align-items: flex-start; }
  .block { background: #fff1f0; border-color: #e5484d; }
  .warn { background: #fff8e6; border-color: #f5a524; }
  .info { background: #eef6ff; border-color: #3b82f6; }
  .ok { background: #effaf2; border-color: #30a46c; }
  .icon { flex: none; width: 28px; height: 28px; border-radius: 50%; display: grid; place-items: center; color: #fff; font-weight: 700; }
  .block .icon { background: #e5484d; } .warn .icon { background: #f5a524; } .info .icon { background: #3b82f6; } .ok .icon { background: #30a46c; }
  .body { flex: 1; min-width: 0; }
  .title { font-weight: 700; font-size: 15px; margin: 2px 0 4px; }
  .text { margin: 0 0 6px; }
  ul { margin: 4px 0 8px; padding-left: 18px; } li { margin: 2px 0; }
  .meta { font: 12px ui-monospace, Consolas, monospace; color: #555; word-break: break-all; background: rgba(0,0,0,.04); padding: 6px 8px; border-radius: 6px; margin: 6px 0; }
  .actions { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 8px; }
  button { font: inherit; font-size: 13px; padding: 6px 12px; border-radius: 6px; border: 1px solid #c9c9cf; background: #fff; color: #1b1b1f; cursor: pointer; }
  button.primary { background: #1b1b1f; color: #fff; border-color: #1b1b1f; }
  button.danger { background: transparent; border-color: transparent; color: #8a1c1f; text-decoration: underline; padding-left: 4px; padding-right: 4px; }
  button:focus-visible { outline: 2px solid #3b82f6; outline-offset: 2px; }
  .brand { font-size: 11px; color: #666; margin-top: 6px; }
  .top { position: fixed; top: 12px; left: 50%; transform: translateX(-50%); width: min(640px, calc(100vw - 24px)); z-index: 2147483647; box-shadow: 0 10px 30px rgba(0,0,0,.18); }
  .overlay { position: fixed; inset: 0; background: rgba(15,15,20,.55); z-index: 2147483647; display: grid; place-items: center; padding: 16px; }
  .dialog { width: min(520px, 100%); box-shadow: 0 20px 50px rgba(0,0,0,.35); }
  .inline { margin: 0 0 12px; }
  `;

  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }

  function makeHost(position) {
    const host = document.createElement('soclens-ui');
    host.style.cssText = position === 'inline' ? 'display:block' : 'position:static';
    const root = host.attachShadow({ mode: 'closed' });
    const style = document.createElement('style');
    style.textContent = CSS;
    root.appendChild(style);
    return { host, root };
  }

  /**
   * opts: { level: 'block'|'warn'|'info'|'ok', title, text, reasons[], meta, actions: [{ label, kind, onClick }] }
   * mode: 'top' (floating banner), 'modal' (blocking dialog), 'inline' (returns host to insert yourself)
   */
  function render(opts, mode) {
    const { host, root } = makeHost(mode);
    const wrap = el('div', 'vs');
    const card = el('div', 'card ' + (opts.level || 'info') + (mode === 'top' ? ' top' : mode === 'modal' ? ' dialog' : ' inline'));
    card.setAttribute('role', mode === 'modal' ? 'alertdialog' : 'alert');
    card.appendChild(el('div', 'icon', opts.level === 'ok' ? '✓' : '!'));
    const body = el('div', 'body');
    body.appendChild(el('div', 'title', opts.title));
    if (opts.text) body.appendChild(el('p', 'text', opts.text));
    if (opts.reasons && opts.reasons.length) {
      const ul = el('ul');
      opts.reasons.slice(0, 6).forEach((r) => ul.appendChild(el('li', null, r)));
      body.appendChild(ul);
    }
    if (opts.meta) body.appendChild(el('div', 'meta', opts.meta));
    const close = () => host.remove();
    if (opts.actions && opts.actions.length) {
      const act = el('div', 'actions');
      for (const a of opts.actions) {
        const b = el('button', a.kind || '', a.label);
        b.addEventListener('click', (ev) => { ev.stopPropagation(); a.onClick && a.onClick(close, b); });
        act.appendChild(b);
      }
      body.appendChild(act);
    }
    body.appendChild(el('div', 'brand', 'IOC Triage'));
    card.appendChild(body);
    if (mode === 'modal') {
      const ov = el('div', 'overlay');
      ov.appendChild(card);
      wrap.appendChild(ov);
    } else wrap.appendChild(card);
    root.appendChild(wrap);
    if (mode !== 'inline') (document.body || document.documentElement).appendChild(host);
    const firstBtn = root.querySelector('button.primary') || root.querySelector('button');
    if (mode === 'modal' && firstBtn) setTimeout(() => firstBtn.focus(), 0);
    host.vsClose = close;
    return host;
  }

  function send(msg) {
    return new Promise((resolve) => {
      try { chrome.runtime.sendMessage(msg, (r) => { void chrome.runtime.lastError; resolve(r); }); } catch (_) { resolve(null); }
    });
  }

  function defang(u) { return String(u || '').replace(/^http/i, 'hxxp').replace(/\./g, '[.]'); }

  window.__VSUI = {
    top: (o) => render(o, 'top'),
    modal: (o) => render(o, 'modal'),
    inline: (o) => render(o, 'inline'),
    send, defang
  };
})();
