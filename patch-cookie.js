/**
 * Patcht Cookie.js fuer tough-cookie v5 Kompatibilitaet
 * Aufruf: node patch-cookie.js [pfad-zu-iobroker]
 * Beispiel: node patch-cookie.js C:\ioBroker
 */
const fs = require('fs');
const path = require('path');

const iobrokerDir = process.argv[2] || '.';
const cookiePath = path.join(iobrokerDir, 'node_modules', 'iobroker.parcel', 'node_modules', 'node-tls-client', 'dist', 'lib', 'Cookie.js');

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
