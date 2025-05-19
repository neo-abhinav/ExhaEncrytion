const express = require('express');
const crypto = require('crypto');
const app = express();

function esc(s) { return String(s).replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m])); }

const algorithms = [
  "AES-256",
  "DES",
  "RC4",
  "Base64",
  "Caesar",
  "Vigenere",
  "Atbash",
  "ROT13",
  "XOR",
  "RailFence"
];

// --- Cipher Implementations ---

function aes(mode, text, key, bits) {
  key = crypto.createHash('sha256').update(key).digest().slice(0, bits / 8);
  const iv = Buffer.alloc(16, 0);
  if (mode === 'encrypt') {
    const cipher = crypto.createCipheriv(`aes-${bits}-cbc`, key, iv);
    return cipher.update(text, 'utf8', 'base64') + cipher.final('base64');
  } else {
    try {
      const decipher = crypto.createDecipheriv(`aes-${bits}-cbc`, key, iv);
      return decipher.update(text, 'base64', 'utf8') + decipher.final('utf8');
    } catch (e) { return 'Invalid key or input'; }
  }
}
function des(mode, text, key) {
  key = crypto.createHash('md5').update(key).digest().slice(0, 8);
  const iv = Buffer.alloc(8, 0);
  if (mode === 'encrypt') {
    const cipher = crypto.createCipheriv('des-cbc', key, iv);
    return cipher.update(text, 'utf8', 'base64') + cipher.final('base64');
  } else {
    try {
      const decipher = crypto.createDecipheriv('des-cbc', key, iv);
      return decipher.update(text, 'base64', 'utf8') + decipher.final('utf8');
    } catch (e) { return 'Invalid key or input'; }
  }
}
function rc4(mode, text, key) {
  if (mode === 'encrypt') {
    const cipher = crypto.createCipheriv('rc4', Buffer.from(key), null);
    return cipher.update(text, 'utf8', 'base64') + cipher.final('base64');
  } else {
    try {
      const decipher = crypto.createDecipheriv('rc4', Buffer.from(key), null);
      return decipher.update(text, 'base64', 'utf8') + decipher.final('utf8');
    } catch (e) { return 'Invalid key or input'; }
  }
}
function base64(mode, text) {
  return mode === 'encrypt'
    ? Buffer.from(text).toString('base64')
    : Buffer.from(text, 'base64').toString('utf8');
}
function caesar(mode, text, key) {
  key = parseInt(key) || 3;
  if (mode === 'decrypt') key = 26 - key;
  return text.replace(/[a-z]/gi, c =>
    String.fromCharCode(((c = c.charCodeAt(0)) >= 97 ?
      (c - 97 + key) % 26 + 97 :
      (c - 65 + key) % 26 + 65)));
}
function vigenere(mode, text, key) {
  key = key.replace(/[^a-z]/gi, '').toUpperCase();
  if (!key) return 'Key required';
  let res = '', ki = 0;
  for (let i = 0; i < text.length; i++) {
    let c = text[i];
    if (/[a-z]/i.test(c)) {
      let base = c >= 'a' ? 97 : 65;
      let off = (c.charCodeAt(0) - base) + (mode === 'encrypt' ? 1 : -1) * ((key[ki % key.length].charCodeAt(0) - 65));
      if (off < 0) off += 26;
      res += String.fromCharCode(base + (off % 26));
      ki++;
    } else res += c;
  }
  return res;
}
function rot13(_, text) { return caesar('encrypt', text, 13); }
function xor(mode, text, key) {
  if (!key) return 'Key required';
  let k = Buffer.from(key);
  let buf = Buffer.from(mode === 'encrypt' ? text : Buffer.from(text, 'base64'));
  let out = Buffer.alloc(buf.length);
  for (let i = 0; i < buf.length; i++) out[i] = buf[i] ^ k[i % k.length];
  return mode === 'encrypt' ? out.toString('base64') : out.toString();
}
function atbash(_, text) {
  return text.replace(/[a-z]/gi, c =>
    String.fromCharCode((c <= 'Z' ? 90 : 122) - (c.charCodeAt(0) - (c <= 'Z' ? 65 : 97))));
}
function railfence(mode, text, key) {
  let rails = parseInt(key) || 2;
  if (rails < 2) return "Key must be >=2";
  if (mode === "encrypt") {
    let arr = Array.from({ length: rails }, () => []);
    let rail = 0, dir = 1;
    for (let c of text) {
      arr[rail].push(c);
      rail += dir;
      if (rail == rails - 1 || rail == 0) dir *= -1;
    }
    return arr.map(a => a.join("")).join("");
  } else {
    let pat = [];
    let rail = 0, dir = 1;
    for (let i = 0; i < text.length; i++) {
      pat.push(rail);
      rail += dir;
      if (rail == rails - 1 || rail == 0) dir *= -1;
    }
    let pos = Array(rails).fill(0), idxs = [];
    for (let r = 0, c = 0; r < rails; r++) for (let i = 0; i < text.length; i++) if (pat[i] == r) idxs[i] = c++;
    let ret = new Array(text.length);
    for (let i = 0; i < text.length; i++) ret[i] = text[idxs[i]];
    return ret.join('');
  }
}

// --- Algorithm Selector ---
function process(mode, algo, text, key) {
  try {
    switch (algo) {
      case "AES-256": return aes(mode, text, key, 256);
      case "DES": return des(mode, text, key);
      case "RC4": return rc4(mode, text, key);
      case "Base64": return base64(mode, text);
      case "Caesar": return caesar(mode, text, key);
      case "Vigenere": return vigenere(mode, text, key);
      case "Atbash": return atbash(mode, text);
      case "ROT13": return rot13(mode, text);
      case "XOR": return xor(mode, text, key);
      case "RailFence": return railfence(mode, text, key);
      default: return "Unrecognized algorithm.";
    }
  } catch (e) { return "Error: " + e.message; }
}

// --- HTML Frontend ---
function renderPage(result, mode, algo, text, key) {
  return `<!DOCTYPE html>
  <html lang="en"><head><title>ExhaEncryption (OGS)</title>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <style>
    :root {
      --bg: #0f172a;
      --panel: #1e293b;
      --accent: #8b5cf6;
      --accent2: #06b6d4;
      --danger: #f43f5e;
      --field: #1f2937;
      --border: #334155;
      --text: #f1f5f9;
      --text2: #cbd5e1;
      --shadow: 0 8px 32px #0004;
    }
    body{font-family:sans-serif;background:var(--bg);margin:0;padding:0;}
    .ct{max-width:700px;margin:30px auto;background:var(--panel);padding:2em 2em 2.5em 2em;border-radius:20px;box-shadow:var(--shadow);}
    h1{font-size:2.5em;text-align:center;color:var(--accent);margin-bottom:.7em;letter-spacing:-1px;}
    label{font-weight:600;color:var(--text2);}
    .row{margin-bottom:1.3em;}
    textarea,input[type="text"]{width:100%;background:var(--field);color:var(--text);padding:.75em;border-radius:10px;border:1px solid var(--border);margin-top:.3em;font-size:1.1em;}
    textarea:focus,input[type="text"]:focus{outline:2px solid var(--accent);}
    select{padding:.6em;background:var(--field);color:var(--text);border-radius:10px;margin-top:.3em;font-size:1.08em;border:1px solid var(--border);}
    button{background:var(--accent);color:#fff;font-weight:600;border:none;padding:.8em 1.4em;border-radius:10px;cursor:pointer;transition:background 0.2s;}
    button:hover{background:#4338ca;}
    .flex{display:flex;gap:1em;}
    .outbox{position:relative;margin-top:1.5em;}
    .copybtn{position:absolute;top:8px;right:12px;font-size:.97em;background:#9333ea;}
    .copybtn:hover{background:#6d28d9;}
    .dlbtn{margin-left:1em;background:var(--accent2);}
    .dlbtn:hover{background:#065f46;}
    .footer{text-align:center;font-size:.98em;color:var(--text2);margin-top:2em;}
    @media (max-width: 750px) {
      .ct{padding:1em;max-width:96vw;}
      .flex{flex-direction:column;gap:.7em;}
      button,select,textarea,input{font-size:1em;}
    }
    .algosel{width:100%;}
    .form-actions{justify-content:center;}
    .info-tip{background:#202336;color:var(--accent);padding:.65em 1em;border-radius:8px;margin-bottom:1.2em;border-left:4px solid var(--accent);font-size:.99em;}
    .algoinfo{color:var(--accent);margin:0 0 .4em 0;padding:0;font-size:.98em;}
    a{color:var(--accent);}
    input[type="radio"] { accent-color: var(--accent);}
  </style>
  </head>
  <body>
    <div class="ct">
      <h1>ExhaEncryption (OGS)</h1>
      <div class="info-tip">
        <b>Encrypt or decrypt</b> text using 10 classic &amp; modern ciphers.
      </div>
      <form method="POST" autocomplete="off">
        <div class="row">
          <label>Input Text</label>
          <textarea name="text" rows=6 placeholder="Paste or type your message here...">${esc(text||'')}</textarea>
        </div>
        <div class="flex row">
          <div style="flex:2">
            <label>Algorithm</label>
            <select name="algorithm" class="algosel" required>
              ${algorithms.map(a=>`<option${algo===a?' selected':''}>${a}</option>`).join('')}
            </select>
            <div class="algoinfo" id="algoinfo"></div>
          </div>
          <div style="flex:1">
            <label>Key / Password</label>
            <input type="text" name="key" value="${esc(key||'')}" placeholder="If needed"/>
          </div>
        </div>
        <div class="flex row form-actions" style="margin-top:.6em;">
          <button type="submit" name="mode" value="encrypt" style="background:var(--accent2);">Encrypt</button>
          <button type="submit" name="mode" value="decrypt" style="background:var(--danger);">Decrypt</button>
        </div>
      </form>
      ${result!==undefined ? `
        <div class="row outbox">
          <label style="display:block;margin-bottom:.5em;color:var(--accent);">Output (${esc(algo)} ${esc(mode)}):</label>
          <textarea id="output" rows=6 readonly>${esc(result)}</textarea>
          <button class="copybtn" onclick="copyToClipboard()">Copy</button>
        </div>
        <script>
          function copyToClipboard() {
            var t = document.getElementById('output');
            t.select(); t.setSelectionRange(0,99999);
            document.execCommand('copy');
            t.blur();
            let btn = document.querySelector('.copybtn');
            btn.textContent = 'Copied!';
            btn.style.background = '#06b6d4';
            setTimeout(()=>{
            btn.textContent = 'Copy';
            btn.style.background = '#8b5cf6';
          }, 1200);
          }
        </script>
      ` : ''}
      <div class="footer">Supports 10 ciphers • Made by Abhinav Kumar • <a href="https://github.com/neo-abhinav" target="_blank">@neo-abhinav</a></div>
    </div>
    <script>
      const algoInfos = {
        "AES-256":"AES (Advanced Encryption Standard), 256-bit key.",
        "DES":"DES (Data Encryption Standard), legacy 56-bit key.",
        "RC4":"RC4, stream cipher.",
        "Base64":"Base64 encoding (not encryption!).",
        "Caesar":"Caesar cipher (classic shift).",
        "Vigenere":"Vigenère cipher, polyalphabetic.",
        "Atbash":"Atbash cipher (reversal).",
        "ROT13":"ROT13 (special Caesar, shift 13).",
        "XOR":"XOR, symmetric stream.",
        "RailFence":"Rail Fence (transposition)."
      };
      function updateAlgoInfo() {
        const sel = document.querySelector('select[name="algorithm"]');
        const info = document.getElementById('algoinfo');
        info.textContent = algoInfos[sel.value] || '';
      }
      document.querySelector('select[name="algorithm"]').addEventListener('change', updateAlgoInfo);
      updateAlgoInfo();
    </script>
  </body>
  </html>`;
}

// --- Routes ---
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use(express.json());

app.get('/', (req, res) => {
  res.send(renderPage(undefined, 'encrypt', 'AES-256', '', ''));
});

app.post('/', (req, res) => {
  try {
    const algo = req.body?.algorithm || 'AES-256';
    const mode = req.body?.mode || 'encrypt';
    const key = req.body?.key || '';
    const text = req.body?.text || '';
    const result = process(mode, algo, text, key);
    res.send(renderPage(result, mode, algo, text, key));
  } catch (error) {
    console.error('Form processing error:', error);
    res.status(400).send(renderPage('Error processing request', 'encrypt', 'AES-256', '', ''));
  }
});

const PORT = 3000;
app.listen(PORT, () => console.log('ExhaEncryption running at http://localhost:' + PORT));