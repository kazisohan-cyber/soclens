(async function () {
  'use strict';
  const $ = (id) => document.getElementById(id);

  // Shared by verify.html and the popup: renders pending "was this you?" requests into `box`.
  async function render(box, onEmpty) {
    const s = await chrome.runtime.sendMessage({ type: 'verifyState' });
    box.textContent = '';
    const pending = (s && s.pending) || [];
    if (!pending.length) { if (onEmpty) onEmpty(); return 0; }
    for (const vr of pending) {
      const card = document.createElement('section');
      card.className = 'card';
      const p = document.createElement('p');
      p.className = 'prompt';
      p.textContent = vr.prompt;
      const meta = document.createElement('p');
      meta.className = 'muted';
      meta.textContent = [vr.app, vr.location, vr.ip, vr.signInTime && new Date(vr.signInTime).toLocaleString()].filter(Boolean).join(' · ');
      const row = document.createElement('div');
      row.className = 'row';
      const yes = document.createElement('button');
      yes.className = 'primary';
      yes.textContent = 'Yes, it was me';
      const no = document.createElement('button');
      no.textContent = 'No, not me';
      const answer = async (a) => {
        yes.disabled = no.disabled = true;
        const r = await chrome.runtime.sendMessage({ type: 'verifyAnswer', id: vr.id, answer: a });
        row.textContent = '';
        const done = document.createElement('span');
        done.className = 'done';
        done.textContent = !r || !r.ok ? 'This request has expired or was already answered.'
          : a === 'yes' ? 'Thanks, confirmed.' : 'Thanks. Your security team has been alerted and will secure your account.';
        row.appendChild(done);
      };
      yes.addEventListener('click', () => answer('yes'));
      no.addEventListener('click', () => answer('no'));
      row.append(yes, ' ', no);
      card.append(p, meta, row);
      box.appendChild(card);
    }
    return pending.length;
  }

  window.VSVerifyUI = { render };
  if ($('list')) await render($('list'), () => { $('empty').hidden = false; });
})();
