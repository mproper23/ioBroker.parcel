/**
 * Standalone Amazon Login Test mit Puppeteer
 * Testet den Login-Flow und ruft die Bestelluebersicht ab.
 *
 * Aufruf: node test-amazon-login.js <email> <passwort> [--visible] [--otp <code>]
 *
 * --visible  zeigt den Browser sichtbar an (empfohlen fuer MFA/Captcha)
 * --otp      MFA/OTP Code aus der Authenticator-App
 */

const puppeteer = require('puppeteer-extra');
const StealthPlugin = require('puppeteer-extra-plugin-stealth');
puppeteer.use(StealthPlugin());
const { JSDOM } = require('jsdom');

async function testAmazonLogin(username, password, headless, otpCode) {
  console.log('=== Amazon Login Test mit Puppeteer ===\n');

  // Step 1: Launch Browser
  console.log('[1/5] Starte Chrome Browser' + (headless ? ' (headless)' : ' (sichtbar)') + '...');
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

  // Capture console + network for debugging
  const consoleLogs = [];
  page.on('console', (msg) => consoleLogs.push(msg.type() + ': ' + msg.text()));

  const networkLogs = [];
  page.on('response', (resp) => {
    const url = resp.url();
    if (url.includes('amazon.de/ap/') || url.includes('captcha') || url.includes('auth') || url.includes('order')) {
      networkLogs.push(resp.status() + ' ' + url.substring(0, 150));
    }
  });

  console.log('  -> OK\n');

  // Step 2: Navigate to Amazon Signin
  console.log('[2/5] Navigiere zur Amazon Login-Seite...');
  const signinUrl =
    'https://www.amazon.de/ap/signin?_encoding=UTF8&accountStatusPolicy=P1&openid.assoc_handle=deflex' +
    '&openid.claimed_id=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select' +
    '&openid.identity=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select' +
    '&openid.mode=checkid_setup&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0' +
    '&openid.ns.pape=http%3A%2F%2Fspecs.openid.net%2Fextensions%2Fpape%2F1.0' +
    '&openid.pape.max_auth_age=0' +
    '&openid.return_to=https%3A%2F%2Fwww.amazon.de%2Fgp%2Fcss%2Forder-history%3Fie%3DUTF8%26ref_%3Dnav_orders_first' +
    '&pageId=webcs-yourorder&showRmrMe=1';

  try {
    await page.goto(signinUrl, { waitUntil: 'networkidle2', timeout: 30000 });
  } catch (e) {
    console.log('  Navigation Warnung: ' + e.message.substring(0, 100));
  }

  console.log('  URL: ' + page.url().substring(0, 100));
  await page.screenshot({ path: 'amz-step2.png' });
  console.log('  Screenshot: amz-step2.png');

  // Check for untrusted app warning
  const pageContent = await page.content();
  if (pageContent.includes('untrusted-app-sign-in-continue-button-announce')) {
    console.log('  Untrusted App Warning erkannt - klicke Weiter...');
    const continueBtn = await page.$('#continue');
    if (continueBtn) {
      await Promise.all([page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 15000 }).catch(() => {}), continueBtn.click()]);
    }
    console.log('  -> Weiter geklickt');
  }

  console.log('  -> OK\n');

  // Step 3: Enter credentials
  console.log('[3/5] Gebe Credentials ein...');
  try {
    // Check if we need to enter email first (split login flow)
    const emailInput = await page.$('#ap_email');
    if (emailInput) {
      await emailInput.click({ clickCount: 3 });
      await new Promise((r) => setTimeout(r, 100));
      await emailInput.type(username, { delay: 50 });
      console.log('  E-Mail eingegeben.');

      // Check if there's a "Continue" button (split flow: email first, then password)
      const continueBtn = await page.$('#continue');
      if (continueBtn) {
        console.log('  Split-Login erkannt - klicke Weiter...');
        await Promise.all([
          page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 15000 }).catch(() => {}),
          continueBtn.click(),
        ]);
        await new Promise((r) => setTimeout(r, 1000));
        console.log('  URL: ' + page.url().substring(0, 100));
      }
    }

    // Enter password
    const pwdInput = await page.$('#ap_password');
    if (pwdInput) {
      await pwdInput.click({ clickCount: 3 });
      await new Promise((r) => setTimeout(r, 100));
      await pwdInput.type(password, { delay: 50 });
      console.log('  Passwort eingegeben.');
    } else {
      console.error('  FEHLER: Passwort-Feld nicht gefunden!');
      await page.screenshot({ path: 'amz-login-error.png' });
      console.log('  Screenshot: amz-login-error.png');
      await browser.close();
      return;
    }

    // Check "Remember me"
    const rememberMe = await page.$('input[name="rememberMe"]');
    if (rememberMe) {
      const checked = await rememberMe.evaluate((el) => el.checked);
      if (!checked) await rememberMe.click();
    }

    await page.screenshot({ path: 'amz-step3.png' });
    console.log('  Screenshot: amz-step3.png');
  } catch (e) {
    console.error('  FEHLER: ' + e.message);
    await page.screenshot({ path: 'amz-login-error.png' });
    await browser.close();
    return;
  }
  console.log('  -> OK\n');

  // Step 4: Submit login and handle MFA/Captcha
  console.log('[4/5] Sende Login ab...');
  try {
    // Click signin button
    const signInBtn = await page.$('#signInSubmit');
    if (signInBtn) {
      await Promise.all([
        page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 30000 }).catch(() => {}),
        signInBtn.click(),
      ]);
    } else {
      await page.keyboard.press('Enter');
      await page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 30000 }).catch(() => {});
    }

    console.log('  URL nach Submit: ' + page.url().substring(0, 100));
    await page.screenshot({ path: 'amz-step4.png' });
    console.log('  Screenshot: amz-step4.png');

    let html = await page.content();

    // Check for captcha
    if (html.includes('captcha') || html.includes('Löse das Rätsel') || html.includes('/errors/validateCaptcha')) {
      console.log('\n  *** CAPTCHA ERKANNT ***');
      console.log('  Amazon verlangt eine Captcha-Loesung.');
      if (!headless) {
        console.log('  Bitte loese das Captcha im Browser-Fenster...');
        console.log('  Warte bis zu 120s...');
        for (let i = 0; i < 120; i++) {
          await new Promise((r) => setTimeout(r, 1000));
          html = await page.content();
          if (!html.includes('captcha') && !html.includes('Löse das Rätsel') && !html.includes('/errors/validateCaptcha')) {
            console.log('  Captcha geloest nach ' + (i + 1) + 's!');
            break;
          }
        }
      } else {
        console.log('  Im Headless-Modus kann kein Captcha geloest werden.');
        console.log('  Starte mit --visible erneut: node test-amazon-login.js <email> <pw> --visible');
        await browser.close();
        return;
      }
    }

    // Check for password reset required
    if (html.includes('Zurücksetzen des Passworts erforderlich') || html.includes('ap_change_login_claim')) {
      console.log('  *** PASSWORT-RESET ERFORDERLICH ***');
      console.log('  Amazon verlangt ein neues Passwort. Bitte manuell zuruecksetzen.');
      await page.screenshot({ path: 'amz-password-reset.png' });
      await browser.close();
      return;
    }

    // Check for MFA
    if (html.includes('auth-mfa-otpcode') || html.includes('auth-mfa-form')) {
      console.log('  MFA/2FA erkannt.');
      if (otpCode) {
        console.log('  Gebe OTP Code ein: ' + otpCode);
        const otpInput = await page.$('#auth-mfa-otpcode');
        if (otpInput) {
          await otpInput.click({ clickCount: 3 });
          await otpInput.type(otpCode, { delay: 50 });

          // Check "Remember device"
          const rememberDevice = await page.$('#auth-mfa-remember-device');
          if (rememberDevice) {
            const checked = await rememberDevice.evaluate((el) => el.checked);
            if (!checked) await rememberDevice.click();
          }

          const submitOtp = await page.$('#auth-signin-button');
          if (submitOtp) {
            await Promise.all([
              page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 30000 }).catch(() => {}),
              submitOtp.click(),
            ]);
          }
          console.log('  OTP gesendet.');
          html = await page.content();
        }
      } else if (!headless) {
        console.log('  Bitte gib den MFA-Code im Browser-Fenster ein...');
        console.log('  Oder starte mit --otp <code> erneut.');
        console.log('  Warte bis zu 120s...');
        for (let i = 0; i < 120; i++) {
          await new Promise((r) => setTimeout(r, 1000));
          const currentUrl = page.url();
          if (currentUrl.includes('order-history') || currentUrl.includes('gp/css') || currentUrl.includes('gp/yourstore')) {
            console.log('  MFA erfolgreich nach ' + (i + 1) + 's!');
            break;
          }
        }
        html = await page.content();
      } else {
        console.log('  Im Headless-Modus kein MFA moeglich ohne --otp.');
        console.log('  Starte mit: node test-amazon-login.js <email> <pw> --otp <code>');
        console.log('  Oder mit: node test-amazon-login.js <email> <pw> --visible');
        await browser.close();
        return;
      }
    }

    // Check for SMS/Call device selection
    if (html.includes('auth-select-device-form')) {
      console.log('  SMS/Anruf-Auswahl erkannt.');
      if (!headless) {
        console.log('  Bitte waehle im Browser-Fenster die Verifizierungs-Methode...');
        console.log('  Warte bis zu 120s...');
        for (let i = 0; i < 120; i++) {
          await new Promise((r) => setTimeout(r, 1000));
          const currentUrl = page.url();
          if (currentUrl.includes('order-history') || currentUrl.includes('gp/css')) {
            console.log('  Verifizierung erfolgreich nach ' + (i + 1) + 's!');
            break;
          }
        }
        html = await page.content();
      } else {
        console.log('  Im Headless-Modus nicht moeglich. Starte mit --visible.');
        await browser.close();
        return;
      }
    }

    // Check for approval notification (new device)
    if (html.includes('auth-approve-notification') || html.includes('cvf-widget-form-approve-notification')) {
      console.log('  Push-Benachrichtigung zur Genehmigung gesendet.');
      console.log('  Bitte bestaetigen auf deinem Handy/anderem Geraet...');
      console.log('  Warte bis zu 120s...');
      for (let i = 0; i < 120; i++) {
        await new Promise((r) => setTimeout(r, 1000));
        const currentUrl = page.url();
        html = await page.content();
        if (
          currentUrl.includes('order-history') ||
          currentUrl.includes('gp/css') ||
          html.includes('js-yo-main-content')
        ) {
          console.log('  Genehmigung erhalten nach ' + (i + 1) + 's!');
          break;
        }
      }
    }

    // Final check: are we logged in?
    await page.screenshot({ path: 'amz-step4-final.png' });
    console.log('  Screenshot: amz-step4-final.png');

    html = await page.content();
    const currentUrl = page.url();

    if (
      html.includes('js-yo-main-content') ||
      currentUrl.includes('order-history') ||
      currentUrl.includes('gp/css') ||
      html.includes('nav-link-accountList')
    ) {
      console.log('\n========================================');
      console.log('  LOGIN ERFOLGREICH!');
      console.log('========================================');
    } else if (html.includes('Amazon Anmelden') || html.includes('ap_email')) {
      console.log('  FEHLER: Login fehlgeschlagen. Noch auf der Login-Seite.');

      // Check for specific errors
      const errorMsgs = await page.evaluate(() => {
        const msgs = [];
        for (const el of document.querySelectorAll(
          '.a-alert-content, #auth-error-message-box .a-list-item, .a-box-inner .a-alert-content',
        )) {
          const text = el.textContent.trim();
          if (text && text.length > 3 && text.length < 500) msgs.push(text);
        }
        return [...new Set(msgs)];
      });
      if (errorMsgs.length > 0) {
        console.log('  Fehlermeldungen:');
        for (const m of errorMsgs) console.log('    -> ' + m.substring(0, 200));
      }

      await browser.close();
      return;
    } else {
      console.log('  Unbekannter Status. URL: ' + currentUrl.substring(0, 100));
      console.log('  Pruefe ob eingeloggt...');
    }
  } catch (e) {
    console.error('  FEHLER: ' + e.message);
    await page.screenshot({ path: 'amz-login-error.png' }).catch(() => {});
    await browser.close();
    return;
  }
  console.log('  -> OK\n');

  // Step 5: Read orders
  console.log('[5/5] Lese Bestellungen...');
  try {
    // Navigate to order history (might already be there after login redirect)
    const currentUrl = page.url();
    if (!currentUrl.includes('order-history') && !currentUrl.includes('gp/css')) {
      await page.goto('https://www.amazon.de/gp/css/order-history?ref_=nav_orders_first', {
        waitUntil: 'networkidle2',
        timeout: 30000,
      });
    }

    await new Promise((r) => setTimeout(r, 2000));
    await page.screenshot({ path: 'amz-step5.png' });
    console.log('  Screenshot: amz-step5.png');

    const html = await page.content();

    // Check if we need to re-login
    if (html.includes('auth-workflow') || html.includes('ap_email')) {
      console.log('  Session ungueltig - Login erforderlich.');
      await browser.close();
      return;
    }

    // Parse orders using JSDOM (same approach as the adapter)
    const dom = new JSDOM(html);
    const document = dom.window.document;
    const orders = document.querySelectorAll('.order-card.js-order-card');

    console.log('  Bestellungen gefunden: ' + orders.length);

    const elements = [];
    for (const order of orders) {
      const descHandle = order.querySelector(
        '.a-fixed-right-grid-col.a-col-left .a-fixed-left-grid-col.a-col-right div:first-child .a-link-normal',
      );
      const desc = descHandle ? descHandle.textContent.replace(/\n */g, '').trim() : '(kein Titel)';

      let url = '';
      const trackBtn = order.querySelector('.track-package-button a');
      if (trackBtn) {
        url = trackBtn.getAttribute('href');
      }
      if (!url) {
        const allLinks = order.querySelectorAll('.a-button-inner a');
        for (const link of allLinks) {
          if (link.textContent.includes('Lieferung verfolgen')) {
            url = link.getAttribute('href');
          }
        }
      }
      if (!url) {
        const shipmentLink = order.querySelector('.yohtmlc-shipment-level-connections .a-button-inner a');
        if (shipmentLink) url = shipmentLink.getAttribute('href');
      }

      elements.push({ desc: desc.substring(0, 80), url: url ? 'https://www.amazon.de' + url : '' });
    }

    if (elements.length > 0) {
      console.log('\n  Bestellungen mit Tracking:');
      for (const el of elements) {
        const hasTracking = el.url ? 'JA' : 'NEIN';
        console.log('    [' + hasTracking + '] ' + el.desc);
      }

      // Try to get tracking details for the first order with tracking
      const trackable = elements.find((e) => e.url);
      if (trackable) {
        console.log('\n  Teste Tracking fuer: ' + trackable.desc.substring(0, 50) + '...');
        await page.goto(trackable.url, { waitUntil: 'networkidle2', timeout: 30000 });
        await new Promise((r) => setTimeout(r, 2000));

        const trackHtml = await page.content();
        const trackDom = new JSDOM(trackHtml);
        const trackDoc = trackDom.window.document;

        // Try to find tracking status
        const statusEl =
          trackDoc.querySelector('.milestone-primaryMessage') ||
          trackDoc.querySelector('.pt-status-main-heading-msg-text') ||
          trackDoc.querySelector('#primaryStatus');
        const carrierEl =
          trackDoc.querySelector('.carrierRelatedInfo-trackingId-text') ||
          trackDoc.querySelector('.pt-delivery-card-trackingId');

        if (statusEl) console.log('  Status: ' + statusEl.textContent.trim());
        if (carrierEl) console.log('  Carrier/Tracking: ' + carrierEl.textContent.trim());

        await page.screenshot({ path: 'amz-tracking.png' });
        console.log('  Screenshot: amz-tracking.png');
      }
    } else {
      console.log('  Keine Bestellungen mit Tracking gefunden.');
      console.log('  (Moeglicherweise keine aktiven Lieferungen)');
    }

    // Export cookies for potential reuse
    const cookies = await page.cookies();
    const amazonCookies = cookies.filter((c) => c.domain.includes('amazon'));
    console.log('\n  Amazon Cookies: ' + amazonCookies.length);
    console.log(
      '  Session-Cookies: ' +
        amazonCookies
          .filter((c) => c.name.startsWith('session') || c.name.startsWith('x-') || c.name === 'at-acbde')
          .map((c) => c.name)
          .join(', '),
    );
  } catch (e) {
    console.error('  FEHLER: ' + e.message);
    await page.screenshot({ path: 'amz-order-error.png' }).catch(() => {});
  }

  // Print debug info
  if (networkLogs.length > 0) {
    console.log('\n  Network Logs (' + networkLogs.length + '):');
    for (const log of networkLogs.slice(-15)) console.log('    ' + log);
  }

  await browser.close();
  console.log('\n  Browser geschlossen.');
  console.log('\nTest abgeschlossen.');
}

// Main
const args = process.argv.slice(2);
const visibleFlag = args.includes('--visible');
const otpIndex = args.indexOf('--otp');
const otpCode = otpIndex !== -1 && args[otpIndex + 1] ? args[otpIndex + 1] : null;
const cleanArgs = args.filter((a, i) => a !== '--visible' && a !== '--otp' && (otpIndex === -1 || i !== otpIndex + 1));

if (cleanArgs.length < 2) {
  console.log('Aufruf: node test-amazon-login.js <email> <passwort> [--visible] [--otp <code>]');
  console.log('');
  console.log('Optionen:');
  console.log('  --visible  Browser sichtbar (empfohlen fuer MFA/Captcha)');
  console.log('  --otp      MFA/OTP Code aus der Authenticator-App');
  console.log('');
  console.log('Beispiele:');
  console.log('  node test-amazon-login.js meine@email.de meinPasswort');
  console.log('  node test-amazon-login.js meine@email.de meinPasswort --visible');
  console.log('  node test-amazon-login.js meine@email.de meinPasswort --otp 123456');
  console.log('  node test-amazon-login.js meine@email.de meinPasswort --visible --otp 123456');
  process.exit(1);
}

testAmazonLogin(cleanArgs[0], cleanArgs[1], !visibleFlag, otpCode).catch((err) => {
  console.error('\nUnerwarteter Fehler:', err);
  process.exit(1);
});
