# SecureStep — aplicație web pentru iPhone

SecureStep este un autentificator TOTP în format PWA. Se instalează de pe un URL HTTPS pe ecranul principal al iPhone-ului, rulează și offline după prima încărcare și nu are nevoie de Mac, domeniu cumpărat, cont Google sau server propriu.

## Publică gratuit cu GitHub Pages

GitHub Pages oferă hosting HTTPS gratuit pentru acest proiect static:

1. Creează un repository GitHub nou. Un repository public este cel mai simplu pentru Pages pe planul gratuit; proiectul nu conține secrete sau chei personale.
2. Încarcă în directorul rădăcină fișierele proiectului: `index.html`, `app.js`, `style.css`, `manifest.webmanifest`, `service-worker.js`, `icon.svg`, `icon-180.png`, `icon-192.png`, `icon-512.png` și folderul `lib`.
3. În GitHub, deschide repository-ul → **Settings → Pages**. La **Build and deployment**, alege **Deploy from a branch**, selectează `main` și folderul `/ (root)`, apoi apasă **Save**.
4. Așteaptă publicarea și deschide adresa HTTPS afișată de GitHub Pages, de tipul `https://utilizator.github.io/nume-repository/`, direct în **Safari** pe iPhone.
5. Apasă **Share → Add to Home Screen**. Dacă apare opțiunea **Open as Web App**, activeaz-o, apoi apasă **Add**. Deschide SecureStep de pe ecranul principal și configurează seiful acolo.

Nu deschide aplicația prin `file://`: criptografia browserului, camera și instalarea PWA necesită HTTPS. Nu introduce coduri 2FA reale înainte să publici o versiune pe un URL HTTPS și să verifici că seiful se blochează/deblochează corect.

## Cum funcționează

- Scanează QR-ul `otpauth://` cu camera sau importă o captură de ecran. Dacă scanarea QR nu pornește, poți introduce cheia TOTP oferită de site.
- Codurile TOTP sunt generate local, fără a trimite conturile către un server.
- La prima pornire este generat un cod aleator de recuperare de 256 de biți. Fără codul de recuperare nu poți debloca seiful.
- Seiful salvat în browser este criptat cu AES-256-GCM; cheia este derivată din codul de recuperare folosind HKDF-SHA-256.
- **Backup-ul nu este sincronizat în cloud.** Exportă fișierul `.sstep` din aplicație și păstrează-l separat de codul de recuperare. Pentru restaurare după ștergerea aplicației, ai nevoie de ambele.
- La redeschidere, aplicația cere codul de recuperare pentru a decripta seiful. Un browser nu poate păstra o cheie secretă deblocată în sistemul iOS Keychain; aplicația web nu oferă protecția Face ID disponibilă unei aplicații native.
- Păstrează și codurile de recuperare furnizate de fiecare site. Nu șterge conturile din SecureStep până când ai confirmat o metodă de recuperare pe serviciul respectiv.

Codul QR este decodat local folosind biblioteca open-source `jsQR` 1.4.0 inclusă în `lib/`. Vezi `lib/jsQR.LICENSE` pentru licența Apache 2.0.
