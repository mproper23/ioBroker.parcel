/**
 * Verifiziert den neuen DHL-Login-Flow (v2 CIAM):
 *   Browser greift Code aus dhllogin://-Redirect ab → Token-Exchange via TLS-Client.
 * Aufruf: node test-dhl-newflow.js <email> <passwort>
 */
const puppeteer = require('puppeteer-extra');
const StealthPlugin = require('puppeteer-extra-plugin-stealth');
puppeteer.use(StealthPlugin());
const crypto = require('crypto');
const qs = require('qs');
const { Session: TlsSession, ClientIdentifier, initTLS, destroyTLS } = require('node-tls-client');

const DHL_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
const DHL_CLIENT_ID = '83471082-5c13-4fce-8dcb-19d2a3fca413';
const DHL_BASIC_AUTH = 'Basic ' + Buffer.from(DHL_CLIENT_ID + ':').toString('base64');

function gcc() {
  const c = '0123456789abcdef';
  let r = '';
  for (let i = 64; i > 0; --i) r += c[Math.floor(Math.random() * c.length)];
  return [r, crypto.createHash('sha256').update(r).digest('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')];
}

(async () => {
  const [user, pass] = process.argv.slice(2);
  if (!user || !pass) { console.error('Aufruf: node test-dhl-newflow.js <email> <pass>'); process.exit(1); }
  const [code_verifier, codeChallenge] = gcc();

  const browser = await puppeteer.launch({
    headless: false,
    args: ['--no-sandbox', '--disable-blink-features=AutomationControlled', '--lang=de-DE'],
    defaultViewport: { width: 1280, height: 900 },
  });
  const page = await browser.newPage();

  let capturedCode = null;
  page.on('request', (req) => {
    const u = req.url();
    if (u.startsWith('dhllogin://') && u.includes('code=')) {
      try {
        const params = qs.parse(u.split('?')[1] || '');
        if (params.code && !capturedCode) capturedCode = String(params.code);
      } catch {}
    }
  });

  const params = new URLSearchParams({
    redirect_uri: 'dhllogin://de.deutschepost.dhl/login',
    state: 'eyJycyI6dHJ1ZSwicnYiOmZhbHNlLCJmaWQiOiJhcHAtbG9naW4tbWVoci1mb290ZXIiLCJoaWQiOiJhcHAtbG9naW4tbWVoci1oZWFkZXIiLCJycCI6ZmFsc2V9',
    client_id: DHL_CLIENT_ID,
    response_type: 'code',
    scope: 'openid offline_access',
    claims: '{"id_token":{"email":null,"post_number":null,"twofa":null,"service_mask":null,"deactivate_account":null,"last_login":null,"customer_type":null,"display_name":null}}',
    nonce: '',
    login_hint: '',
    prompt: 'login',
    ui_locales: 'de-DE',
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
  });

  console.log('[1] Navigate');
  try { await page.goto('https://login.dhl.de/af5f9bb6-27ad-4af4-9445-008e7a5cddb8/login/authorize?' + params.toString(), { waitUntil: 'networkidle2', timeout: 30000 }); } catch (e) { console.log('  nav: ' + e.message.substring(0, 80)); }

  console.log('[2] Fill credentials');
  await new Promise((r) => setTimeout(r, 2500));
  // Wait for any text input that's not the 2FA code field
  let emailInput = null;
  for (let i = 0; i < 10 && !emailInput; i++) {
    emailInput = await page.evaluateHandle(() => {
      return document.querySelector('input[type=email]') ||
             document.querySelector('input[name=signInEmailAddress]') ||
             Array.from(document.querySelectorAll('input[type=text]')).find((el) => !el.id.includes('secondFactor') && el.offsetParent !== null);
    });
    if (await emailInput.evaluate((el) => !el)) { emailInput = null; await new Promise((r) => setTimeout(r, 500)); }
  }
  if (!emailInput) { console.error('No email input'); await browser.close(); process.exit(1); }
  await emailInput.click({ clickCount: 3 });
  await emailInput.type(user, { delay: 30 });
  const pwdInput = await page.$('input[type=password]');
  await pwdInput.click({ clickCount: 3 });
  await pwdInput.type(pass, { delay: 30 });

  console.log('[3] Submit');
  const btn = await page.$('button[type=submit]');
  if (btn) await btn.click(); else await page.keyboard.press('Enter');

  console.log('[4] Warte auf dhllogin://-Code...');
  const start = Date.now();
  while (!capturedCode && Date.now() - start < 45000) {
    await new Promise((r) => setTimeout(r, 500));
  }
  await browser.close();
  if (!capturedCode) { console.error('Kein Code erhalten'); process.exit(1); }
  console.log('  Code: ' + capturedCode.substring(0, 30) + '...');

  console.log('[5] Token-Exchange');
  await initTLS();
  const tls = new TlsSession({ clientIdentifier: ClientIdentifier.chrome_131, timeout: 30000, insecureSkipVerify: true });
  const tokenResp = await tls.post('https://login.dhl.de/af5f9bb6-27ad-4af4-9445-008e7a5cddb8/login/token', {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json, text/plain, */*',
      Origin: 'https://login.dhl.de',
      Authorization: DHL_BASIC_AUTH,
      'User-Agent': DHL_UA,
      'Accept-Language': 'de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7',
    },
    body: new URLSearchParams({
      redirect_uri: 'dhllogin://de.deutschepost.dhl/login',
      grant_type: 'authorization_code',
      code_verifier: code_verifier,
      code: capturedCode,
    }).toString(),
    followRedirects: true,
  });
  console.log('  Status: ' + tokenResp.status);
  const tokenData = await tokenResp.json();
  if (tokenData.id_token) {
    console.log('  ✓ id_token: ' + tokenData.id_token.substring(0, 50) + '...');
    console.log('  ✓ refresh_token: ' + (tokenData.refresh_token || '').substring(0, 30) + '...');
    console.log('  ✓ expires_in: ' + tokenData.expires_in);
    console.log('\nLOGIN ERFOLGREICH');
  } else {
    console.error('  Tokens fehlen: ' + JSON.stringify(tokenData).substring(0, 300));
  }
  await tls.close();
  await destroyTLS();
})().catch((e) => { console.error('FATAL: ' + e.stack); process.exit(1); });
