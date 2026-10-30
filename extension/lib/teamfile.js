/*
 * IOC Triage team memory: an encrypted file a team shares by any channel it trusts. No server is involved.
 * AES-256-GCM with a key derived from a passphrase (PBKDF2-SHA-256). A wrong passphrase or a changed file fails to open.
 */
(function (root) {
  'use strict';
  const FORMAT = 'ioc-triage-team-memory';
  const ITERATIONS = 600000;
  // Limits for files we open, so a crafted file can neither weaken the key nor hang the panel.
  const MIN_ITERATIONS = 100000;
  const MAX_ITERATIONS = 5000000;
  const MIN_PASSPHRASE = 12;

  const b64 = (bytes) => { let s = ''; for (let i = 0; i < bytes.length; i += 32768) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 32768)); return btoa(s); };
  const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

  async function deriveKey(passphrase, salt, iterations) {
    const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }

  /** payload is any JSON value. Returns the file's text. */
  async function encrypt(payload, passphrase, opts) {
    if (String(passphrase || '').length < MIN_PASSPHRASE) throw new Error(`Use a passphrase of at least ${MIN_PASSPHRASE} characters`);
    const iterations = (opts && opts.iterations) || ITERATIONS;
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKey(passphrase, salt, iterations);
    const data = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(JSON.stringify(payload)));
    return JSON.stringify({ format: FORMAT, version: 1, kdf: { name: 'PBKDF2', hash: 'SHA-256', iterations, salt: b64(salt) }, cipher: { name: 'AES-GCM', iv: b64(iv) }, data: b64(new Uint8Array(data)) }, null, 1);
  }

  async function decrypt(text, passphrase) {
    let f;
    try { f = JSON.parse(text); } catch (_) { throw new Error('This is not an IOC Triage team memory file'); }
    if (!f || f.format !== FORMAT || f.version !== 1 || !f.kdf || !f.cipher) throw new Error('This is not an IOC Triage team memory file');
    const iterations = Number(f.kdf.iterations);
    if (!(iterations >= MIN_ITERATIONS && iterations <= MAX_ITERATIONS)) throw new Error('This file has unsafe encryption settings');
    let plain;
    try {
      const key = await deriveKey(String(passphrase || ''), unb64(f.kdf.salt), iterations);
      plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(f.cipher.iv) }, key, unb64(f.data));
    } catch (_) { throw new Error('Wrong passphrase, or the file was changed'); }
    return JSON.parse(new TextDecoder().decode(plain));
  }

  const api = { FORMAT, MIN_PASSPHRASE, MIN_ITERATIONS, encrypt, decrypt };
  root.VSTeamFile = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
