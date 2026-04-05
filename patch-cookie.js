/**
 * Patcht Cookie.js fuer tough-cookie v5 Kompatibilitaet
 * Aufruf: node patch-cookie.js [pfad-zu-iobroker]
 * Beispiel: node patch-cookie.js C:\ioBroker
 * Wird auch automatisch als postinstall ausgefuehrt.
 */
const fs = require('fs');
const path = require('path');

// Wenn als postinstall aufgerufen: Cookie.js liegt relativ zum Adapter-Verzeichnis
// Wenn manuell mit ioBroker-Pfad aufgerufen: Cookie.js liegt unter node_modules/iobroker.parcel/...
const iobrokerDir = process.argv[2];
const localPath = path.join(__dirname, 'node_modules', 'node-tls-client', 'dist', 'lib', 'Cookie.js');
const globalPath = iobrokerDir
  ? path.join(iobrokerDir, 'node_modules', 'iobroker.parcel', 'node_modules', 'node-tls-client', 'dist', 'lib', 'Cookie.js')
  : null;
const cookiePath = (globalPath && fs.existsSync(globalPath)) ? globalPath : localPath;

if (!fs.existsSync(cookiePath)) {
  console.error('Cookie.js nicht gefunden: ' + cookiePath);
  process.exit(1);
}

const patched = `"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Cookies = void 0;
const tough_cookie_1 = require("tough-cookie");
class Cookies extends tough_cookie_1.CookieJar {
    constructor() {
        super();
    }
    async fetchAllCookies() {
        return (await this.serialize()).cookies;
    }
    async syncCookies(cookies, url) {
        if (!cookies)
            return {};
        const result = {};
        await Promise.all(Object.entries(cookies).map(async ([key, value]) => {
            try {
                const cookie = await this.setCookie(\`\${key}=\${value}\`, url);
                if (cookie && cookie.key) {
                    result[cookie.key] = cookie.value;
                } else {
                    result[key] = value;
                }
            } catch (e) {
                result[key] = value;
            }
        }));
        return result;
    }
    async mergeCookies(cookies, url) {
        return Promise.all(Object.entries(cookies).map(async ([key, value]) => {
            try {
                const cookie = await this.setCookie(\`\${key}=\${value}\`, url);
                if (cookie && cookie.key) {
                    return { name: cookie.key, value: cookie.value };
                }
                return { name: key, value: value };
            } catch (e) {
                return { name: key, value: value };
            }
        }));
    }
}
exports.Cookies = Cookies;
`;

fs.writeFileSync(cookiePath, patched);
console.log('Cookie.js erfolgreich gepatcht: ' + cookiePath);
