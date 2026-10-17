// challenge/page.js — the interstitial a challenged visitor actually sees.
//
// Deliberately self-contained: inline CSS, no build step, no external assets
// beyond a third-party provider's own script when one is configured. This
// page is served to traffic CatWAF already considers suspicious, so it must
// not depend on anything that could itself be blocked, and it must render
// before any JavaScript runs.

const providers = require('./providers')

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]))
}

const STYLE = `
:root { color-scheme: dark light }
* { box-sizing: border-box }
body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center;
  font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  background:#0d0f14; color:#e6e9ef; padding:24px }
.card { width:100%; max-width:440px; background:#13161d; border:1px solid #232833; border-radius:14px;
  padding:32px; box-shadow:0 24px 48px rgba(0,0,0,.35) }
h1 { margin:0 0 6px; font-size:19px; font-weight:650; letter-spacing:-.01em }
p { margin:0 0 20px; color:#98a2b3; font-size:13.5px }
form { display:flex; flex-direction:column; gap:14px }
.captcha { display:flex; align-items:center; gap:12px; flex-wrap:wrap }
.captcha img, .captcha svg { border-radius:10px; border:1px solid #232833; max-width:100% }
input[type=text] { flex:1; min-width:140px; padding:11px 13px; border-radius:9px; border:1px solid #2b3140;
  background:#0d0f14; color:#e6e9ef; font-size:15px; letter-spacing:.16em; text-transform:uppercase }
input[type=text]:focus { outline:2px solid #4f8ef7; outline-offset:1px; border-color:#4f8ef7 }
button { padding:11px 16px; border-radius:9px; border:0; background:#4f8ef7; color:#fff;
  font-size:14px; font-weight:600; cursor:pointer }
button:hover { background:#3d7ce0 }
.err { color:#f4a4a4; font-size:13px; margin:0 0 14px; padding:9px 12px; border-radius:8px;
  background:rgba(244,164,164,.09); border:1px solid rgba(244,164,164,.2) }
.foot { margin:22px 0 0; padding-top:16px; border-top:1px solid #232833; color:#6b7484; font-size:11.5px }
.spin { width:17px; height:17px; border:2px solid #2b3140; border-top-color:#4f8ef7; border-radius:50%;
  display:inline-block; vertical-align:-3px; margin-right:9px; animation:s .8s linear infinite }
@keyframes s { to { transform:rotate(360deg) } }
@media (prefers-color-scheme: light) {
  body { background:#f4f6fa; color:#161b25 }
  .card { background:#fff; border-color:#e2e6ee; box-shadow:0 20px 40px rgba(15,23,42,.08) }
  p { color:#5b6474 } input[type=text] { background:#fff; border-color:#d8dde7; color:#161b25 }
  .foot { border-color:#e2e6ee; color:#8a93a3 }
}
`

function build({ mode, provider, siteKey, providerUrl, token, returnTo, error, captchaSvg, challengeId }) {
  const spec = provider && provider !== 'none' ? providers.get(provider) : null
  const action = '/catwaf-challenge/verify'

  let bodyInner
  let script = ''

  if (mode === 'cookie') {
    bodyInner = `
      <p><span class="spin" aria-hidden="true"></span>Checking your browser before you continue&hellip;</p>
      <noscript><p>Your browser needs to accept a cookie to continue. Press the button below.</p></noscript>
      <form method="POST" action="${action}">
        <input type="hidden" name="challenge_id" value="${escapeHtml(challengeId)}">
        <input type="hidden" name="return_to" value="${escapeHtml(returnTo)}">
        <input type="hidden" name="token" value="${escapeHtml(token)}">
        <button type="submit">Continue</button>
      </form>`
    // Auto-submits for a real browser; the button is the no-JS path.
    script = `<script>document.addEventListener('DOMContentLoaded',function(){setTimeout(function(){document.forms[0].submit()},700)})</script>`
  } else if (mode === 'javascript') {
    bodyInner = `
      <p><span class="spin" aria-hidden="true"></span>Verifying your browser&hellip;</p>
      <noscript><p><strong>JavaScript is required</strong> to continue to this site.</p></noscript>
      <form method="POST" action="${action}" id="f">
        <input type="hidden" name="challenge_id" value="${escapeHtml(challengeId)}">
        <input type="hidden" name="return_to" value="${escapeHtml(returnTo)}">
        <input type="hidden" name="token" value="${escapeHtml(token)}">
        <input type="hidden" name="proof" id="proof" value="">
      </form>`
    // A small proof-of-work: cheap for one browser, expensive for a client
    // trying thousands of requests a second, and it cannot be satisfied by an
    // HTTP client that does not run scripts.
    script = `<script>
(function(){
  var id=${JSON.stringify(String(challengeId))}, n=0;
  function h(s){var x=5381;for(var i=0;i<s.length;i++){x=((x<<5)+x+s.charCodeAt(i))>>>0}return x}
  while(n<300000){ if(h(id+n)%4096===0){break} n++ }
  document.getElementById('proof').value=String(n);
  document.getElementById('f').submit();
})()
</script>`
  } else if (mode === 'captcha') {
    bodyInner = `
      <p>Type the characters shown below to continue.</p>
      <form method="POST" action="${action}">
        <div class="captcha">${captchaSvg || ''}
          <input type="text" name="answer" autocomplete="off" autocapitalize="characters"
                 spellcheck="false" maxlength="8" required autofocus aria-label="Characters shown in the image">
        </div>
        <input type="hidden" name="challenge_id" value="${escapeHtml(challengeId)}">
        <input type="hidden" name="return_to" value="${escapeHtml(returnTo)}">
        <input type="hidden" name="token" value="${escapeHtml(token)}">
        <button type="submit">Continue</button>
      </form>`
  } else if (mode === 'provider' && provider === 'mcaptcha' && providerUrl) {
    let widget
    try { widget = new URL('/widget/', providerUrl); widget.searchParams.set('sitekey', siteKey) } catch {}
    if (!widget || !['http:', 'https:'].includes(widget.protocol)) {
      bodyInner = '<p>The CAPTCHA provider is not configured. Contact the site administrator.</p>'
    } else {
      bodyInner = `<p>Complete the check below to continue.</p>
        <form method="POST" action="${action}">
        <iframe id="mcaptcha-frame" title="mCaptcha verification" src="${escapeHtml(widget.href)}" style="border:0;width:100%;height:120px" sandbox="allow-scripts allow-same-origin"></iframe>
        <input type="hidden" name="mcaptcha__token" id="mcaptcha-token">
        <input type="hidden" name="challenge_id" value="${escapeHtml(challengeId)}">
        <input type="hidden" name="return_to" value="${escapeHtml(returnTo)}">
        <button type="submit">Continue</button></form>`
      script = `<script>window.addEventListener('message',function(e){var f=document.getElementById('mcaptcha-frame');if(e.source!==f.contentWindow||e.origin!==new URL(f.src).origin||!e.data||typeof e.data.token!=='string'||e.data.token.length>4096)return;document.getElementById('mcaptcha-token').value=e.data.token;});</script>`
    }
  } else {
    bodyInner = `
      <p>Complete the check below to continue.</p>
      <form method="POST" action="${action}">
        ${spec ? spec.widget(escapeHtml(siteKey)) : '<p class="err">No challenge provider is configured.</p>'}
        <input type="hidden" name="challenge_id" value="${escapeHtml(challengeId)}">
        <input type="hidden" name="return_to" value="${escapeHtml(returnTo)}">
        <input type="hidden" name="token" value="${escapeHtml(token)}">
        <button type="submit">Continue</button>
      </form>`
    if (spec && spec.script) script = `<script src="${spec.script}" async defer></script>`
  }

  return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>Verifying your connection</title>
<style>${STYLE}</style>
</head><body>
<main class="card">
<h1>One moment</h1>
${error ? `<p class="err">${escapeHtml(error)}</p>` : ''}
${bodyInner}
<p class="foot">This site is protected by CatWAF. This check runs once and is then remembered for a while.</p>
</main>
${script}
</body></html>`
}

module.exports = { build, escapeHtml }
