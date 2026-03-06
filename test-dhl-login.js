/**
 * Standalone DHL Login Test mit Puppeteer
 * Nutzt einen echten Chrome-Browser um Akamai Bot-Erkennung zu umgehen.
 *
 * Aufruf: node test-dhl-login.js <email> <passwort> [--visible]
 *
 * --visible zeigt den Browser sichtbar an (empfohlen fuer MFA)
 */

const puppeteer = require('puppeteer-extra');
const StealthPlugin = require('puppeteer-extra-plugin-stealth');
puppeteer.use(StealthPlugin());
const crypto = require('crypto');

function getCodeChallenge() {
  const chars = '0123456789abcdef';
  let result = '';
  for (let i = 64; i > 0; --i) result += chars[Math.floor(Math.random() * chars.length)];
  let hash = crypto.createHash('sha256').update(result).digest('base64');
  hash = hash.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  return [result, hash];
}

async function testDhlLogin(username, password, headless) {
  console.log('=== DHL Login Test mit Puppeteer ===\n');

  const [code_verifier, codeChallenge] = getCodeChallenge();

  // Step 1: Launch Browser
  console.log('[1/6] Starte Chrome Browser' + (headless ? ' (headless)' : ' (sichtbar)') + '...');
  const browser = await puppeteer.launch({
    headless: headless ? 'new' : false,
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-blink-features=AutomationControlled',
      '--lang=de-DE',
    ],
    defaultViewport: { width: 1280, height: 900 },
  });
  const page = await browser.newPage();

  // Stealth plugin handles webdriver, user-agent, etc. automatically

  // We'll enable request interception LATER (after Janrain login)
  // to avoid interfering with Janrain's JSONP calls
  let capturedCode = null;

  // Capture console messages for debugging
  const consoleLogs = [];
  page.on('console', (msg) => consoleLogs.push(msg.type() + ': ' + msg.text()));

  console.log('  -> OK\n');

  // Step 2: Navigate to the authorize URL with dhllogin:// redirect
  console.log('[2/6] Navigiere zur DHL Login-Seite...');
  const authorizeParams = new URLSearchParams({
    redirect_uri: 'dhllogin://de.deutschepost.dhl/login',
    state: 'eyJycyI6dHJ1ZSwicnYiOmZhbHNlLCJmaWQiOiJhcHAtbG9naW4tbWVoci1mb290ZXIiLCJoaWQiOiJhcHAtbG9naW4tbWVoci1oZWFkZXIiLCJycCI6ZmFsc2V9',
    client_id: '83471082-5c13-4fce-8dcb-19d2a3fca413',
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
  const authorizeUrl =
    'https://login.dhl.de/af5f9bb6-27ad-4af4-9445-008e7a5cddb8/login/authorize?' + authorizeParams.toString();

  try {
    await page.goto(authorizeUrl, { waitUntil: 'networkidle2', timeout: 30000 });
  } catch (e) {
    // Navigation might fail due to dhllogin:// redirect interception - that's OK
    if (!e.message.includes('net::ERR_ABORTED') && !e.message.includes('net::ERR_FAILED')) {
      console.log('  Navigation Warnung: ' + e.message.substring(0, 100));
    }
  }

  console.log('  URL: ' + page.url().substring(0, 100));
  await page.screenshot({ path: 'dhl-step2.png' });
  console.log('  Screenshot: dhl-step2.png');
  console.log('  -> OK\n');

  // Step 3: Fill in credentials
  console.log('[3/6] Gebe Credentials ein...');
  try {
    // Wait for any email/username input field
    const emailSelectors = [
      'input[name="emailOrPostNumber"]',
      '#emailOrPostNumber',
      'input[name="signInName"]',
      'input[name="email"]',
      'input[type="email"]',
      'input[name="username"]',
      'input[name="loginfmt"]',
      'input[id*="email"]',
      'input[id*="signIn"]',
    ];

    let emailInput = null;
    // First try main page
    for (const sel of emailSelectors) {
      try {
        emailInput = await page.waitForSelector(sel, { timeout: 2000, visible: true });
        if (emailInput) {
          console.log('  E-Mail Feld gefunden: ' + sel);
          break;
        }
      } catch {}
    }

    // If not found, check all frames
    if (!emailInput) {
      const frames = page.frames();
      console.log('  Suche in ' + frames.length + ' Frames...');
      for (const frame of frames) {
        for (const sel of emailSelectors) {
          try {
            emailInput = await frame.waitForSelector(sel, { timeout: 2000, visible: true });
            if (emailInput) {
              console.log('  E-Mail Feld in Frame gefunden: ' + sel);
              console.log('  Frame URL: ' + frame.url().substring(0, 80));
              break;
            }
          } catch {}
        }
        if (emailInput) break;
      }
    }

    // If still not found, try generic approach
    if (!emailInput) {
      console.log('  Versuche generische Input-Suche...');
      await new Promise((r) => setTimeout(r, 3000));
      // Get all visible input fields
      const inputs = await page.$$('input:not([type="hidden"])');
      console.log('  Sichtbare Input-Felder: ' + inputs.length);
      for (let i = 0; i < inputs.length; i++) {
        const attrs = await page.evaluate((el) => {
          return {
            type: el.type,
            name: el.name,
            id: el.id,
            placeholder: el.placeholder,
            className: el.className,
            visible: el.offsetParent !== null,
          };
        }, inputs[i]);
        console.log('    [' + i + '] type=' + attrs.type + ' name=' + attrs.name + ' id=' + attrs.id + ' placeholder=' + attrs.placeholder + ' visible=' + attrs.visible);
        if (!emailInput && attrs.visible && (attrs.type === 'text' || attrs.type === 'email' || attrs.name.toLowerCase().includes('email'))) {
          emailInput = inputs[i];
          console.log('  -> Verwende Input [' + i + '] als E-Mail Feld');
        }
      }
    }

    if (!emailInput) {
      console.error('  FEHLER: Kein E-Mail Feld gefunden!');
      // Dump page HTML for debugging
      const html = await page.content();
      console.log('  Page title: ' + (await page.title()));
      console.log('  HTML snippet: ' + html.substring(0, 500));
      await page.screenshot({ path: 'dhl-login-error.png' });
      await browser.close();
      return;
    }

    // Use Puppeteer keyboard to fill fields (real key events for Janrain)
    await emailInput.click({ clickCount: 3 });
    await new Promise((r) => setTimeout(r, 100));
    await emailInput.type(username, { delay: 50 });
    console.log('  E-Mail eingegeben.');

    // Find password field
    let pwdInput = await page.$('input[type="password"]');
    if (!pwdInput) {
      for (const frame of page.frames()) {
        pwdInput = await frame.$('input[type="password"]');
        if (pwdInput) break;
      }
    }

    if (pwdInput) {
      await pwdInput.click({ clickCount: 3 });
      await new Promise((r) => setTimeout(r, 100));
      await pwdInput.type(password, { delay: 50 });
      console.log('  Passwort eingegeben.');
    } else {
      console.error('  FEHLER: Passwort-Feld nicht gefunden!');
      await page.screenshot({ path: 'dhl-login-error.png' });
      await browser.close();
      return;
    }

    // Verify values are in DOM before submit
    const emailVal = await emailInput.evaluate((el) => el.value);
    const pwdVal = await pwdInput.evaluate((el) => el.value);
    console.log('  Werte vor Submit: email="' + emailVal.substring(0, 5) + '..." (' + emailVal.length + '), pwd=(' + pwdVal.length + ' Zeichen)');

    await page.screenshot({ path: 'dhl-step3.png' });
    console.log('  Screenshot: dhl-step3.png');
  } catch (e) {
    console.error('  FEHLER: ' + e.message);
    await page.screenshot({ path: 'dhl-login-error.png' });
    await browser.close();
    return;
  }
  console.log('  -> OK\n');

  // Step 4: Submit and handle token-url intermediate page
  console.log('[4/6] Sende Login ab...');
  try {
    // Monitor network responses for JSONP and redirects
    const networkLogs = [];
    page.on('response', (resp) => {
      const url = resp.url();
      if (url.includes('login-api.dhl') || url.includes('token-url') || url.includes('signin')) {
        networkLogs.push(resp.status() + ' ' + url.substring(0, 120));
      }
    });

    // Submit via Janrain's own form mechanism
    // The form is: capture_signIn_signInForm -> login-api.dhl.de/widget/traditional_signin.jsonp
    console.log('  Submitte ueber Janrain capture form...');

    // Use Janrain's built-in form submission (this ensures Janrain reads the values correctly)
    const submitResult = await page.evaluate(() => {
      try {
        // Check what Janrain APIs are available
        const info = {
          hasJanrain: !!window.janrain,
          hasCapture: !!(window.janrain && window.janrain.capture),
          hasCaptureUi: !!(window.janrain && window.janrain.capture && window.janrain.capture.ui),
        };

        if (window.janrain && window.janrain.capture && window.janrain.capture.ui) {
          const methods = Object.keys(window.janrain.capture.ui).filter(k => typeof window.janrain.capture.ui[k] === 'function');
          info.uiMethods = methods.join(', ');
        }

        // Check the form values as Janrain would see them
        const form = document.getElementById('capture_signIn_signInForm');
        if (form) {
          const formData = new FormData(form);
          info.formFields = {};
          for (const [k, v] of formData.entries()) {
            info.formFields[k] = typeof v === 'string' ? v.substring(0, 30) : 'blob';
          }
        }
        return info;
      } catch (e) {
        return { error: e.message };
      }
    });
    console.log('  Janrain Info: ' + JSON.stringify(submitResult).substring(0, 500));

    // Now click submit with proper wait
    const submitBtn = await page.$('button[type="submit"]') || await page.$('input[type="submit"]');
    if (submitBtn) {
      // Click submit and wait for either navigation or network response
      submitBtn.click();
      console.log('  Anmelden geklickt.');
    } else {
      await page.keyboard.press('Enter');
      console.log('  Enter gedrueckt.');
    }

    // Wait for response (Janrain uses JSONP, so watch for page changes)
    console.log('  Warte auf Antwort...');
    let pageUrl = page.url();
    for (let i = 0; i < 30; i++) {
      await new Promise((r) => setTimeout(r, 1000));
      pageUrl = page.url();
      if (pageUrl.includes('token-url') || capturedCode) {
        console.log('  Weiterleitung nach ' + (i + 1) + 's erkannt!');
        break;
      }
      // Check if there were network responses
      if (networkLogs.length > 0 && i === 3) {
        console.log('  Network: ' + networkLogs.join('\n           '));
      }
    }

    await page.screenshot({ path: 'dhl-step4.png' });
    console.log('  Screenshot: dhl-step4.png');
    console.log('  URL nach Submit: ' + pageUrl.substring(0, 120));

    // Print captured console logs
    if (consoleLogs.length > 0) {
      console.log('  Browser Console (' + consoleLogs.length + ' Eintraege):');
      for (const log of consoleLogs.slice(-30)) console.log('    ' + log.substring(0, 200));
    }
    // Print network logs
    if (networkLogs.length > 0) {
      console.log('  Network Logs (' + networkLogs.length + ' Eintraege):');
      for (const log of networkLogs) console.log('    ' + log);
    }

    // Check for error messages
    const errorMsgs = await page.evaluate(() => {
      const msgs = [];
      // Check visible error messages only
      for (const el of document.querySelectorAll('[class*="error"], [role="alert"]')) {
        if (el.offsetParent !== null || el.style.display !== 'none') {
          const text = el.textContent.trim();
          if (text && text.length > 3 && text.length < 500 && !text.includes('{*')) msgs.push(text);
        }
      }
      return [...new Set(msgs)];
    });
    if (errorMsgs.length > 0) {
      console.log('  Sichtbare Fehlermeldungen:');
      for (const m of errorMsgs) console.log('    -> ' + m.substring(0, 150));
    }
    if (pageUrl.includes('token-url') && !capturedCode) {
      console.log('  Auf token-url Zwischenseite - extrahiere existingToken...');

      // Get page HTML to find existingToken
      const html = await page.content();
      let existingToken = '';
      let csrfToken = '';

      // Try to find existingToken in the HTML
      const tokenMatch = html.match(/existingToken:\s*'([^']+)'/);
      if (tokenMatch) {
        existingToken = tokenMatch[1];
        console.log('  existingToken: ' + existingToken.substring(0, 30) + '...');
      }

      // Try to find _csrf_token
      const csrfMatch = html.match(/_csrf_token['"]\s*value=['"](.*?)['"]/);
      if (csrfMatch) {
        csrfToken = csrfMatch[1];
      }
      // Also check cookies
      if (!csrfToken) {
        const cookies = await page.cookies();
        const csrfCookie = cookies.find((c) => c.name === '_csrf_token');
        if (csrfCookie) csrfToken = csrfCookie.value;
      }
      if (csrfToken) {
        console.log('  _csrf_token: ' + csrfToken.substring(0, 20) + '...');
      }

      // Use node-tls-client to complete the remaining steps outside the browser
      // Browser handled: authorize → login page → credentials → token-url (existingToken)
      // TLS client handles: loginSuccess POST → follow redirects → get code → exchange for tokens
      console.log('\n  Wechsle zu TLS-Client fuer restliche Schritte...');

      const { Session: TlsSession, ClientIdentifier: TlsCI, initTLS: initTLS2, destroyTLS: destroyTLS2 } = require('node-tls-client');
      await initTLS2();
      const tlsSession = new TlsSession({
        clientIdentifier: TlsCI.chrome_131,
        timeout: 30000,
        insecureSkipVerify: true,
      });

      const DHL_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';

      // Transfer browser cookies to TLS session
      const browserCookies = await page.cookies();
      const cookieObj = {};
      for (const c of browserCookies.filter((c) => c.domain.includes('login.dhl'))) {
        cookieObj[c.name] = c.value;
      }
      console.log('  Browser-Cookies uebertragen: ' + Object.keys(cookieObj).length);

      // Get the token-url with query params
      const tokenUrlBase = 'https://login.dhl.de/af5f9bb6-27ad-4af4-9445-008e7a5cddb8/auth-ui/token-url';
      const currentUrl = page.url();
      const queryString = currentUrl.includes('?') ? currentUrl.split('?')[1] : '';

      // POST loginSuccess (without following redirects to capture the location)
      console.log('  POST loginSuccess via TLS-Client...');
      const loginSuccessResp = await tlsSession.post(tokenUrlBase + '?' + queryString, {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Origin: 'https://login.dhl.de',
          Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'User-Agent': DHL_UA,
          Referer: 'https://login.dhl.de/',
          'sec-fetch-site': 'same-origin',
          'sec-fetch-mode': 'navigate',
          'sec-fetch-dest': 'document',
        },
        cookies: cookieObj,
        body: new URLSearchParams({
          screen: 'loginSuccess',
          accessToken: existingToken,
          _csrf_token: csrfToken,
        }).toString(),
        followRedirects: false,
      });
      console.log('  loginSuccess Status: ' + loginSuccessResp.status);

      let idTokenHint = '';
      if (loginSuccessResp.status >= 300 && loginSuccessResp.status < 400) {
        let location = loginSuccessResp.headers['location'] || loginSuccessResp.headers['Location'] || '';
        if (Array.isArray(location)) location = location[0];
        console.log('  Redirect: ' + String(location).substring(0, 100) + '...');

        // Extract id_token_hint from the redirect URL
        if (location.includes('id_token_hint=')) {
          idTokenHint = location.split('id_token_hint=')[1].split('&')[0];
          console.log('  id_token_hint: ' + idTokenHint.substring(0, 30) + '...');
        }
      } else {
        const respText = await loginSuccessResp.text();
        console.log('  Kein Redirect. Body: ' + respText.substring(0, 200));
      }

      if (idTokenHint) {
        // Follow the authorize chain to get the code
        console.log('  GET /authorize mit id_token_hint...');
        const authorizeUrl2 = 'https://login.dhl.de/af5f9bb6-27ad-4af4-9445-008e7a5cddb8/login/authorize?' +
          new URLSearchParams({
            claims: '{"id_token":{"customer_type":null,"deactivate_account":null,"display_name":null,"email":null,"last_login":null,"post_number":null,"service_mask":null,"twofa":null}}',
            client_id: '83471082-5c13-4fce-8dcb-19d2a3fca413',
            code_challenge: codeChallenge,
            code_challenge_method: 'S256',
            prompt: 'none',
            redirect_uri: 'dhllogin://de.deutschepost.dhl/login',
            response_type: 'code',
            scope: 'openid',
            state: 'eyJycyI6dHJ1ZSwicnYiOmZhbHNlLCJmaWQiOiJhcHAtbG9naW4tbWVoci1mb290ZXIiLCJoaWQiOiJhcHAtbG9naW4tbWVoci1oZWFkZXIiLCJycCI6ZmFsc2V9',
            ui_locales: 'de-DE',
            id_token_hint: idTokenHint,
          }).toString();

        let redirectUrl = authorizeUrl2;
        for (let i = 0; i < 10; i++) {
          const resp = await tlsSession.get(redirectUrl, {
            headers: { 'User-Agent': DHL_UA, Accept: '*/*' },
            cookies: cookieObj,
            followRedirects: false,
          });
          console.log('  Redirect ' + (i + 1) + ': ' + resp.status);
          if (resp.status >= 300 && resp.status < 400) {
            let loc = resp.headers['location'] || resp.headers['Location'] || '';
            if (Array.isArray(loc)) loc = loc[0];
            if (loc.startsWith('dhllogin://')) {
              const qs = require('qs');
              const codeParams = qs.parse(loc.split('?')[1]);
              capturedCode = codeParams.code;
              console.log('  Code erhalten: ' + capturedCode.substring(0, 30) + '...');
              break;
            }
            redirectUrl = loc.startsWith('http') ? loc : 'https://login.dhl.de' + loc;
          } else {
            break;
          }
        }
      }

      // Close browser - no longer needed
      await browser.close();
      console.log('  Browser geschlossen.');
      console.log('  -> OK\n');

      // Step 5+6: Exchange code for tokens
      if (!capturedCode) {
        console.log('[5/6] FEHLER: Kein Authorization Code erhalten.\n');
        await tlsSession.close();
        await destroyTLS2();
        return;
      }

      console.log('[5/6] Tausche Code gegen Tokens...');
      const tokenResponse = await tlsSession.post(
        'https://login.dhl.de/af5f9bb6-27ad-4af4-9445-008e7a5cddb8/login/token',
        {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            Accept: 'application/json, text/plain, */*',
            Authorization: 'Basic ODM0NzEwODItNWMxMy00ZmNlLThkY2ItMTlkMmEzZmNhNDEzOg==',
            'User-Agent': DHL_UA,
          },
          body: new URLSearchParams({
            redirect_uri: 'dhllogin://de.deutschepost.dhl/login',
            grant_type: 'authorization_code',
            code_verifier: code_verifier,
            code: capturedCode,
          }).toString(),
          followRedirects: true,
        },
      );

      const tokenData = await tokenResponse.json();
      console.log('  Token Status: ' + tokenResponse.status);

      if (tokenData.id_token) {
        console.log('\n========================================');
        console.log('  LOGIN ERFOLGREICH!');
        console.log('========================================');
        console.log('  id_token: ' + tokenData.id_token.substring(0, 50) + '...');
        console.log('  refresh_token: ' + (tokenData.refresh_token ? tokenData.refresh_token.substring(0, 30) + '...' : 'nicht vorhanden'));
        console.log('  token_type: ' + tokenData.token_type);
        console.log('  expires_in: ' + tokenData.expires_in);

        // Test tracking
        console.log('\n  Teste Tracking...');
        const trackingResponse = await tlsSession.get(
          'https://www.dhl.de/int-verfolgen/data/search?noRedirect=true&language=de&cid=app',
          {
            headers: {
              Accept: 'application/json',
              'Content-Type': 'application/json',
              'User-Agent':
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
            },
            cookies: { dhli: tokenData.id_token },
            followRedirects: true,
          },
        );
        const trackingData = await trackingResponse.json();
        console.log('  Tracking Status: ' + trackingResponse.status);
        if (trackingData && trackingData.sendungen) {
          console.log('  Sendungen: ' + trackingData.sendungen.length);
          for (const s of trackingData.sendungen.slice(0, 5)) {
            console.log('    - ' + s.id + ': ' + (s.sendungsdetails?.sendungsverlauf?.kurzStatus || '?'));
          }
        } else {
          console.log('  Response: ' + JSON.stringify(trackingData).substring(0, 300));
        }
      } else {
        console.log('  Token Response: ' + JSON.stringify(tokenData).substring(0, 300));
      }

      await tlsSession.close();
      await destroyTLS2();
      return;
    }
  } catch (e) {
    console.error('  Fehler: ' + e.message);
    await page.screenshot({ path: 'dhl-login-error.png' }).catch(() => {});
    await browser.close().catch(() => {});
    return;
  }

  // Fallback: existingToken not found
  console.log('  existingToken nicht gefunden auf token-url Seite.');
  const dbgHtml = await page.content();
  console.log('  HTML (' + dbgHtml.length + ' chars): ' + dbgHtml.substring(0, 500));
  await page.screenshot({ path: 'dhl-login-error.png' });
  await browser.close();
  console.log('\nTest abgeschlossen (ohne Token).');
}

// Main
const args = process.argv.slice(2);
const visibleFlag = args.includes('--visible');
const cleanArgs = args.filter((a) => a !== '--visible');

if (cleanArgs.length < 2) {
  console.log('Aufruf: node test-dhl-login.js <email> <passwort> [--visible]');
  console.log('');
  console.log('Optionen:');
  console.log('  --visible  Browser sichtbar (empfohlen fuer MFA-Eingabe)');
  console.log('');
  console.log('Beispiel: node test-dhl-login.js meine@email.de meinPasswort --visible');
  process.exit(1);
}

testDhlLogin(cleanArgs[0], cleanArgs[1], !visibleFlag).catch((err) => {
  console.error('\nUnerwarteter Fehler:', err);
  process.exit(1);
});
