"use strict";

const STORAGE_KEY = "securestep-vault-v1";
const BACKUP_FORMAT = "securestep-encrypted-backup";
const VAULT_INFO = new TextEncoder().encode("SecureStep encrypted vault v1");
const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const TOTP_ALGORITHMS = new Set(["SHA1", "SHA256", "SHA512"]);
const elements = {
    status: document.querySelector("#status-message"),
    setupScreen: document.querySelector("#setup-screen"),
    setupForm: document.querySelector("#setup-form"),
    username: document.querySelector("#username"),
    recoveryCode: document.querySelector("#recovery-code"),
    recoveryConfirm: document.querySelector("#recovery-confirm"),
    setupError: document.querySelector("#setup-error"),
    copyRecoveryCode: document.querySelector("#copy-recovery-code"),
    restoreScreen: document.querySelector("#restore-screen"),
    restoreForm: document.querySelector("#restore-form"),
    backupFile: document.querySelector("#backup-file"),
    restoreCode: document.querySelector("#restore-code"),
    restoreError: document.querySelector("#restore-error"),
    unlockScreen: document.querySelector("#unlock-screen"),
    unlockForm: document.querySelector("#unlock-form"),
    unlockCode: document.querySelector("#unlock-code"),
    unlockError: document.querySelector("#unlock-error"),
    showRestore: document.querySelector("#show-restore"),
    homeScreen: document.querySelector("#home-screen"),
    greeting: document.querySelector("#greeting"),
    homeNotice: document.querySelector("#home-notice"),
    accountList: document.querySelector("#account-list"),
    emptyState: document.querySelector("#empty-state"),
    accountTemplate: document.querySelector("#account-template"),
    addDialog: document.querySelector("#add-dialog"),
    accountForm: document.querySelector("#account-form"),
    closeDialog: document.querySelector("#close-dialog"),
    scanTab: document.querySelector("#scan-tab"),
    manualTab: document.querySelector("#manual-tab"),
    scanPanel: document.querySelector("#scan-panel"),
    manualPanel: document.querySelector("#manual-panel"),
    cameraPreview: document.querySelector("#camera-preview"),
    startCamera: document.querySelector("#start-camera"),
    qrImage: document.querySelector("#qr-image"),
    retryCamera: document.querySelector("#retry-camera"),
    scanMessage: document.querySelector("#scan-message"),
    cameraUnsupported: document.querySelector("#camera-unsupported"),
    accountFields: document.querySelector("#account-fields"),
    issuer: document.querySelector("#issuer"),
    accountName: document.querySelector("#account-name"),
    secret: document.querySelector("#secret"),
    formError: document.querySelector("#form-error"),
    settingsDialog: document.querySelector("#settings-dialog"),
    closeSettings: document.querySelector("#close-settings"),
    settingsUsername: document.querySelector("#settings-username"),
    saveUsername: document.querySelector("#save-username"),
    settingsExport: document.querySelector("#settings-export"),
    settingsImportFile: document.querySelector("#settings-import-file"),
    settingsMessage: document.querySelector("#settings-message")
};

let vault;
let recoveryKey;
let cameraStream;
let scanFrame;
let lastScanTime = 0;
let lockTimer;

function showScreen(screen) {
    for (const [name, element] of Object.entries({
        setup: elements.setupScreen,
        restore: elements.restoreScreen,
        unlock: elements.unlockScreen,
        home: elements.homeScreen
    })) {
        element.hidden = name !== screen;
    }
}

function showStatus(message, type = "error") {
    elements.status.textContent = message;
    elements.status.className = `notice notice-${type}`;
    elements.status.hidden = false;
}

function showFormMessage(element, message, type = "error") {
    element.textContent = message;
    element.className = `form-message ${type === "success" ? "message-success" : "message-error"}`;
}

function normalizeBase32(value) {
    return value.toUpperCase().replace(/[\s=-]/g, "");
}

function decodeBase32(value) {
    const secret = normalizeBase32(value);
    if (!/^[A-Z2-7]{16,128}$/.test(secret)) {
        throw new Error("Cheia secretă nu este Base32 validă.");
    }

    let bitBuffer = 0;
    let bitCount = 0;
    const bytes = [];
    for (const character of secret) {
        bitBuffer = (bitBuffer << 5) | BASE32_ALPHABET.indexOf(character);
        bitCount += 5;
        if (bitCount >= 8) {
            bytes.push((bitBuffer >>> (bitCount - 8)) & 255);
            bitCount -= 8;
        }
    }
    return new Uint8Array(bytes);
}

function encodeBase32(bytes) {
    let bitBuffer = 0;
    let bitCount = 0;
    let encoded = "";
    for (const byte of bytes) {
        bitBuffer = (bitBuffer << 8) | byte;
        bitCount += 8;
        while (bitCount >= 5) {
            encoded += BASE32_ALPHABET[(bitBuffer >>> (bitCount - 5)) & 31];
            bitCount -= 5;
        }
    }
    if (bitCount) {
        encoded += BASE32_ALPHABET[(bitBuffer << (5 - bitCount)) & 31];
    }
    return encoded.match(/.{1,4}/g).join("-");
}

function decodeRecoveryCode(value) {
    const key = decodeBase32(value);
    if (key.length !== 32) {
        throw new Error("Codul de recuperare nu este valid. Verifică-l și încearcă din nou.");
    }
    return key;
}

function toBase64(bytes) {
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary);
}

function fromBase64(value) {
    if (typeof value !== "string" || value.length > 2_000_000) {
        throw new Error("Fișierul backup este invalid sau prea mare.");
    }
    let binary;
    try {
        binary = atob(value);
    } catch {
        throw new Error("Fișierul backup nu conține date valide.");
    }
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function randomBytes(length) {
    if (!globalThis.crypto?.getRandomValues || !globalThis.crypto?.subtle) {
        throw new Error("Criptografia nu este disponibilă. Deschide aplicația de pe un URL HTTPS.");
    }
    return globalThis.crypto.getRandomValues(new Uint8Array(length));
}

async function deriveEncryptionKey(code, salt) {
    const material = await crypto.subtle.importKey("raw", code, "HKDF", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
        { name: "HKDF", hash: "SHA-256", salt, info: VAULT_INFO },
        material,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
}

async function encryptVault(value, code) {
    const salt = randomBytes(16);
    const iv = randomBytes(12);
    const key = await deriveEncryptionKey(code, salt);
    const plaintext = new TextEncoder().encode(JSON.stringify(value));
    const ciphertext = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv, additionalData: VAULT_INFO, tagLength: 128 },
        key,
        plaintext
    );
    return {
        format: BACKUP_FORMAT,
        version: 1,
        salt: toBase64(salt),
        iv: toBase64(iv),
        ciphertext: toBase64(new Uint8Array(ciphertext))
    };
}

async function decryptVault(envelope, code) {
    if (!envelope || envelope.format !== BACKUP_FORMAT || envelope.version !== 1) {
        throw new Error("Fișierul selectat nu este un backup SecureStep acceptat.");
    }
    const salt = fromBase64(envelope.salt);
    const iv = fromBase64(envelope.iv);
    const ciphertext = fromBase64(envelope.ciphertext);
    if (salt.length !== 16 || iv.length !== 12 || ciphertext.length < 17 || ciphertext.length > 1_000_000) {
        throw new Error("Fișierul backup este incomplet sau invalid.");
    }

    try {
        const key = await deriveEncryptionKey(code, salt);
        const plaintext = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv, additionalData: VAULT_INFO, tagLength: 128 },
            key,
            ciphertext
        );
        const decoded = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(plaintext));
        return validateVault(decoded);
    } catch {
        throw new Error("Codul de recuperare nu este corect sau fișierul backup este deteriorat.");
    }
}

function validateVault(value) {
    if (!value || typeof value !== "object"
        || typeof value.username !== "string"
        || !Array.isArray(value.accounts)
        || value.accounts.length > 500) {
        throw new Error("Structura seifului este invalidă.");
    }

    const accounts = value.accounts.map((account) => {
        if (!account || typeof account !== "object"
            || typeof account.issuer !== "string"
            || typeof account.name !== "string"
            || typeof account.secret !== "string"
            || account.issuer.length > 80
            || account.name.length > 120
            || !TOTP_ALGORITHMS.has(account.algorithm)
            || ![6, 8].includes(account.digits)
            || !Number.isInteger(account.period)
            || account.period < 15
            || account.period > 120) {
            throw new Error("Un cont din backup are câmpuri invalide.");
        }
        decodeBase32(account.secret);
        return {
            id: typeof account.id === "string" ? account.id : crypto.randomUUID(),
            issuer: account.issuer,
            name: account.name,
            secret: normalizeBase32(account.secret),
            algorithm: account.algorithm,
            digits: account.digits,
            period: account.period
        };
    });

    return { username: value.username.slice(0, 60), accounts };
}

async function saveVault() {
    if (!recoveryKey || !vault) throw new Error("Deblochează seiful înainte de a salva modificările.");
    const envelope = await encryptVault(vault, recoveryKey);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(envelope));
}

function formatCode(code) {
    const splitAt = Math.ceil(code.length / 2);
    return `${code.slice(0, splitAt)} ${code.slice(splitAt)}`;
}

async function generateTOTP(account, timestamp = Date.now()) {
    const secret = decodeBase32(account.secret);
    const counter = BigInt(Math.floor(timestamp / 1000 / account.period));
    const counterBytes = new Uint8Array(8);
    const view = new DataView(counterBytes.buffer);
    view.setUint32(0, Number((counter >> 32n) & 0xffffffffn));
    view.setUint32(4, Number(counter & 0xffffffffn));
    const key = await crypto.subtle.importKey(
        "raw",
        secret,
        { name: "HMAC", hash: account.algorithm.replace("SHA", "SHA-") },
        false,
        ["sign"]
    );
    const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, counterBytes));
    const offset = digest[digest.length - 1] & 15;
    const binary = ((digest[offset] & 127) * 0x1000000)
        + ((digest[offset + 1] & 255) << 16)
        + ((digest[offset + 2] & 255) << 8)
        + (digest[offset + 3] & 255);
    const code = String(binary % (10 ** account.digits)).padStart(account.digits, "0");
    const secondsRemaining = account.period - (Math.floor(timestamp / 1000) % account.period);
    return { code, secondsRemaining };
}

function parseOTPURI(value) {
    let url;
    try {
        url = new URL(value.trim());
    } catch {
        throw new Error("Nu am putut citi QR-ul. Scanează codul de configurare 2FA afișat de site.");
    }
    if (url.protocol !== "otpauth:" || url.hostname.toLowerCase() !== "totp") {
        throw new Error("Acesta nu este un QR TOTP compatibil. Scanează QR-ul 2FA furnizat de site.");
    }

    const secret = normalizeBase32(url.searchParams.get("secret") || "");
    decodeBase32(secret);
    const algorithm = (url.searchParams.get("algorithm") || "SHA1").toUpperCase().replaceAll("-", "");
    const digits = Number(url.searchParams.get("digits") || 6);
    const period = Number(url.searchParams.get("period") || 30);
    if (!TOTP_ALGORITHMS.has(algorithm) || ![6, 8].includes(digits) || !Number.isInteger(period) || period < 15 || period > 120) {
        throw new Error("QR-ul folosește parametri TOTP care nu sunt acceptați.");
    }

    let label;
    try {
        label = decodeURIComponent(url.pathname.slice(1));
    } catch {
        throw new Error("Eticheta contului din QR nu este validă.");
    }
    const separator = label.indexOf(":");
    const pathIssuer = separator < 0 ? "" : label.slice(0, separator).trim();
    const accountName = (separator < 0 ? label : label.slice(separator + 1)).trim();
    const issuer = (url.searchParams.get("issuer") || pathIssuer).trim();
    if (!issuer || !accountName) {
        throw new Error("QR-ul nu include numele serviciului și contului.");
    }
    return { id: crypto.randomUUID(), issuer, name: accountName, secret, algorithm, digits, period };
}

function accountCard(account) {
    const card = elements.accountTemplate.content.firstElementChild.cloneNode(true);
    card.querySelector(".account-brand").textContent = account.issuer.trim().charAt(0).toUpperCase();
    card.querySelector(".account-issuer").textContent = account.issuer;
    card.querySelector(".account-name").textContent = account.name;

    const codeElement = card.querySelector(".generated-code");
    const countdown = card.querySelector(".code-countdown");
    const progress = card.querySelector(".code-progress");
    let active = true;
    let lastCode = "";

    const refresh = async () => {
        if (!active || !card.isConnected) return;
        try {
            const result = await generateTOTP(account);
            if (!active || !card.isConnected) return;
            if (lastCode && result.code !== lastCode) {
                codeElement.classList.remove("code-refresh");
                void codeElement.offsetWidth;
                codeElement.classList.add("code-refresh");
            }
            lastCode = result.code;
            codeElement.textContent = formatCode(result.code);
            countdown.textContent = `${result.secondsRemaining}s`;
            progress.max = account.period;
            progress.value = result.secondsRemaining;
        } catch (error) {
            codeElement.textContent = "------";
            showStatus(error.message || "Nu s-a putut genera codul de verificare.");
        }
        window.setTimeout(refresh, 1000);
    };

    window.setTimeout(refresh, 0);
    const copyButton = card.querySelector(".copy-code");
    copyButton.addEventListener("click", async () => {
        try {
            const result = await generateTOTP(account);
            await navigator.clipboard.writeText(result.code);
            copyButton.textContent = "Copiat!";
            window.setTimeout(() => {
                if (copyButton.isConnected) copyButton.textContent = "Copiază";
            }, 1300);
        } catch (error) {
            showStatus(error.message || "Codul nu a putut fi copiat.");
        }
    });
    card.querySelector(".delete-account").addEventListener("click", async () => {
        if (!window.confirm(`Ștergi codurile pentru ${account.issuer} — ${account.name}? Păstrează înainte codurile de recuperare ale site-ului.`)) return;
        const previousAccounts = vault.accounts;
        try {
            vault.accounts = vault.accounts.filter((item) => item.id !== account.id);
            await saveVault();
            renderAccounts();
            showHomeNotice("Contul a fost șters. Păstrează codurile de recuperare ale site-ului.", "success");
        } catch (error) {
            vault.accounts = previousAccounts;
            showStatus(error.message || "Contul nu a putut fi șters.");
        }
    });
    return card;
}

function renderAccounts() {
    elements.accountList.replaceChildren();
    elements.accountList.hidden = vault.accounts.length === 0;
    elements.emptyState.hidden = vault.accounts.length !== 0;
    elements.greeting.textContent = vault.username ? `Salut, ${vault.username}.` : "Codurile tale.";
    vault.accounts.forEach((account) => elements.accountList.append(accountCard(account)));
}

function showHomeNotice(message, type = "info") {
    elements.homeNotice.textContent = message;
    elements.homeNotice.className = `notice notice-${type}`;
    elements.homeNotice.hidden = false;
}

function lockVault() {
    if (!recoveryKey) return;
    recoveryKey.fill(0);
    recoveryKey = undefined;
    vault = undefined;
    elements.accountList.replaceChildren();
    elements.homeScreen.hidden = true;
    elements.unlockScreen.hidden = false;
    elements.unlockCode.value = "";
    elements.unlockError.textContent = "";
    if (elements.addDialog.open) elements.addDialog.close();
    if (elements.settingsDialog.open) elements.settingsDialog.close();
}

function openHome(restoredVault) {
    vault = restoredVault;
    showScreen("home");
    elements.status.hidden = true;
    renderAccounts();
}

async function unlockWithCode(value) {
    const code = decodeRecoveryCode(value);
    const serialized = localStorage.getItem(STORAGE_KEY);
    if (!serialized) throw new Error("Seiful local nu a fost găsit. Importă fișierul backup criptat.");
    const envelope = JSON.parse(serialized);
    const unlockedVault = await decryptVault(envelope, code);
    if (recoveryKey) recoveryKey.fill(0);
    recoveryKey = code;
    openHome(unlockedVault);
}

function exportBackup() {
    const envelope = localStorage.getItem(STORAGE_KEY);
    if (!envelope) throw new Error("Nu există încă un backup. Adaugă un cont sau verifică setările browserului.");
    const data = new Blob([envelope], { type: "application/json" });
    const url = URL.createObjectURL(data);
    const link = document.createElement("a");
    link.href = url;
    link.download = `securestep-backup-${new Date().toISOString().slice(0, 10)}.sstep`;
    document.body.append(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function restoreFromFile(file, codeValue) {
    if (!file || file.size > 1_500_000) {
        throw new Error("Alege un fișier backup SecureStep valid, de cel mult 1,5 MB.");
    }
    const code = decodeRecoveryCode(codeValue);
    let envelope;
    try {
        envelope = JSON.parse(await file.text());
    } catch {
        throw new Error("Fișierul nu conține un backup SecureStep valid.");
    }
    const restoredVault = await decryptVault(envelope, code);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(envelope));
    if (recoveryKey) recoveryKey.fill(0);
    recoveryKey = code;
    openHome(restoredVault);
}

function switchAddMethod(method) {
    const isScan = method === "scan";
    elements.scanTab.classList.toggle("active", isScan);
    elements.scanTab.setAttribute("aria-selected", String(isScan));
    elements.manualTab.classList.toggle("active", !isScan);
    elements.manualTab.setAttribute("aria-selected", String(!isScan));
    elements.scanPanel.hidden = !isScan;
    elements.manualPanel.hidden = isScan;
    elements.accountFields.hidden = isScan;
    stopCamera();
    elements.formError.textContent = "";
}

function stopCamera() {
    if (scanFrame !== undefined) {
        window.cancelAnimationFrame(scanFrame);
        scanFrame = undefined;
    }
    if (cameraStream) {
        cameraStream.getTracks().forEach((track) => track.stop());
        cameraStream = undefined;
    }
    elements.cameraPreview.srcObject = null;
    elements.cameraPreview.hidden = true;
    elements.startCamera.textContent = "Pornește camera";
}

function readQRFromCanvas(canvas) {
    if (typeof window.jsQR !== "function") {
        throw new Error("Cititorul QR local nu s-a încărcat. Reîncarcă pagina când ești conectat la internet.");
    }
    const context = canvas.getContext("2d", { willReadFrequently: true });
    const image = context.getImageData(0, 0, canvas.width, canvas.height);
    return window.jsQR(image.data, image.width, image.height, { inversionAttempts: "attemptBoth" });
}

function handleQRValue(value) {
    stopCamera();
    try {
        const account = parseOTPURI(value);
        setAccountFields(account);
        showFormMessage(elements.scanMessage, "QR-ul a fost citit. Verifică informațiile și salvează contul.", "success");
        elements.retryCamera.hidden = true;
    } catch (error) {
        showFormMessage(elements.scanMessage, error.message);
        elements.retryCamera.hidden = false;
    }
}

function scanFrameLoop() {
    if (!cameraStream) return;
    if (performance.now() - lastScanTime < 130) {
        scanFrame = window.requestAnimationFrame(scanFrameLoop);
        return;
    }
    lastScanTime = performance.now();
    try {
        if (elements.cameraPreview.readyState >= HTMLMediaElement.HAVE_CURRENT_DATA) {
            const scale = Math.min(1, 960 / Math.max(elements.cameraPreview.videoWidth, elements.cameraPreview.videoHeight));
            const canvas = document.createElement("canvas");
            canvas.width = Math.max(1, Math.round(elements.cameraPreview.videoWidth * scale));
            canvas.height = Math.max(1, Math.round(elements.cameraPreview.videoHeight * scale));
            canvas.getContext("2d", { willReadFrequently: true }).drawImage(
                elements.cameraPreview,
                0,
                0,
                canvas.width,
                canvas.height
            );
            const result = readQRFromCanvas(canvas);
            if (result) {
                handleQRValue(result.data);
                return;
            }
        }
    } catch (error) {
        stopCamera();
        showFormMessage(elements.scanMessage, error.message || "Camera nu a putut citi codul QR.");
        elements.retryCamera.hidden = false;
        return;
    }
    scanFrame = window.requestAnimationFrame(scanFrameLoop);
}

async function startCamera() {
    if (cameraStream) {
        stopCamera();
        return;
    }
    try {
        if (typeof window.jsQR !== "function") {
            throw new Error("Cititorul QR local nu s-a încărcat. Reîncarcă pagina când ești conectat la internet.");
        }
        cameraStream = await navigator.mediaDevices.getUserMedia({
            audio: false,
            video: { facingMode: "environment" }
        });
        elements.cameraPreview.srcObject = cameraStream;
        elements.cameraPreview.hidden = false;
        elements.startCamera.textContent = "Oprește camera";
        await elements.cameraPreview.play();
        scanFrame = window.requestAnimationFrame(scanFrameLoop);
    } catch (error) {
        stopCamera();
        showFormMessage(elements.scanMessage, error.message || "Camera nu a putut fi pornită. Verifică permisiunile din Safari.");
    }
}

function setAccountFields(account = {}) {
    elements.issuer.value = account.issuer || "";
    elements.accountName.value = account.name || "";
    elements.secret.value = account.secret || "";
    elements.accountFields.hidden = false;
    elements.formError.textContent = "";
}

function resetAccountForm() {
    stopCamera();
    elements.accountForm.reset();
    elements.cameraUnsupported.hidden = !navigator.mediaDevices?.getUserMedia;
    elements.retryCamera.hidden = true;
    elements.qrImage.value = "";
    elements.scanMessage.textContent = "";
    elements.formError.textContent = "";
    elements.accountFields.hidden = true;
    switchAddMethod("scan");
}

async function scanImageFile(file) {
    if (!file) return;
    let bitmap;
    let objectURL;
    try {
        if (typeof window.jsQR !== "function") {
            throw new Error("Cititorul QR local nu s-a încărcat.");
        }
        let image;
        if ("createImageBitmap" in window) {
            bitmap = await createImageBitmap(file);
            image = bitmap;
        } else {
            objectURL = URL.createObjectURL(file);
            image = new Image();
            image.src = objectURL;
            await image.decode();
        }
        const scale = Math.min(1, 1800 / Math.max(image.width, image.height));
        const canvas = document.createElement("canvas");
        canvas.width = Math.max(1, Math.round(image.width * scale));
        canvas.height = Math.max(1, Math.round(image.height * scale));
        canvas.getContext("2d", { willReadFrequently: true }).drawImage(image, 0, 0, canvas.width, canvas.height);
        const result = readQRFromCanvas(canvas);
        if (!result) {
            throw new Error("Nu am găsit niciun QR în imagine. Alege o captură mai clară.");
        }
        handleQRValue(result.data);
    } catch (error) {
        showFormMessage(elements.scanMessage, error.message || "Imaginea QR nu a putut fi citită.");
        elements.retryCamera.hidden = true;
    } finally {
        bitmap?.close();
        if (objectURL) URL.revokeObjectURL(objectURL);
        elements.qrImage.value = "";
    }
}

function openAddDialog() {
    resetAccountForm();
    elements.addDialog.showModal();
}

function updateLockTimer() {
    window.clearTimeout(lockTimer);
    if (document.visibilityState === "hidden") {
        lockTimer = window.setTimeout(lockVault, 60_000);
    }
}

elements.setupForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    elements.setupError.textContent = "";
    try {
        const code = decodeRecoveryCode(elements.recoveryCode.textContent);
        vault = {
            username: elements.username.value.trim().slice(0, 60),
            accounts: []
        };
        recoveryKey = code;
        await saveVault();
        openHome(vault);
    } catch (error) {
        if (recoveryKey) recoveryKey.fill(0);
        recoveryKey = undefined;
        vault = undefined;
        showFormMessage(elements.setupError, error.message || "Nu s-a putut crea seiful criptat.");
    }
});

elements.copyRecoveryCode.addEventListener("click", async () => {
    try {
        await navigator.clipboard.writeText(elements.recoveryCode.textContent);
        elements.copyRecoveryCode.textContent = "Cod copiat";
        window.setTimeout(() => { elements.copyRecoveryCode.textContent = "Copiază codul"; }, 1500);
    } catch {
        showFormMessage(elements.setupError, "Nu s-a putut copia codul. Selectează-l și copiază-l manual.");
    }
});

elements.unlockForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    elements.unlockError.textContent = "";
    try {
        await unlockWithCode(elements.unlockCode.value);
    } catch (error) {
        showFormMessage(elements.unlockError, error.message || "Seiful nu a putut fi deblocat.");
    }
});

elements.restoreForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    elements.restoreError.textContent = "";
    try {
        await restoreFromFile(elements.backupFile.files[0], elements.restoreCode.value);
        elements.restoreForm.reset();
    } catch (error) {
        showFormMessage(elements.restoreError, error.message || "Backup-ul nu a putut fi restaurat.");
    }
});

elements.showRestore.addEventListener("click", () => {
    showScreen("restore");
    elements.restoreCode.focus();
});
document.querySelector("#go-to-setup").addEventListener("click", () => {
    showScreen("setup");
});
document.querySelector("#add-account").addEventListener("click", openAddDialog);
document.querySelector("#empty-add-account").addEventListener("click", openAddDialog);
elements.closeDialog.addEventListener("click", () => elements.addDialog.close());
elements.addDialog.addEventListener("close", stopCamera);
elements.scanTab.addEventListener("click", () => switchAddMethod("scan"));
elements.manualTab.addEventListener("click", () => switchAddMethod("manual"));
elements.startCamera.addEventListener("click", startCamera);
elements.retryCamera.addEventListener("click", () => {
    elements.retryCamera.hidden = true;
    elements.scanMessage.textContent = "";
    startCamera();
});
elements.qrImage.addEventListener("change", () => scanImageFile(elements.qrImage.files[0]));
document.querySelector("#lock-vault").addEventListener("click", lockVault);
document.querySelector("#export-backup").addEventListener("click", () => {
    try {
        exportBackup();
        showHomeNotice("Backup criptat descărcat. Păstrează-l separat de codul de recuperare.", "success");
    } catch (error) {
        showStatus(error.message || "Backup-ul nu a putut fi exportat.");
    }
});
document.querySelector("#open-settings").addEventListener("click", () => {
    elements.settingsUsername.value = vault.username;
    elements.settingsMessage.textContent = "";
    elements.settingsDialog.showModal();
});
elements.closeSettings.addEventListener("click", () => elements.settingsDialog.close());
elements.settingsExport.addEventListener("click", () => {
    try {
        exportBackup();
        showFormMessage(elements.settingsMessage, "Backup criptat descărcat. Păstrează-l separat de codul de recuperare.", "success");
    } catch (error) {
        showFormMessage(elements.settingsMessage, error.message || "Backup-ul nu a putut fi exportat.");
    }
});
elements.settingsImportFile.addEventListener("change", async () => {
    const file = elements.settingsImportFile.files[0];
    if (!file) return;
    const code = window.prompt("Introdu codul de recuperare pentru backup-ul selectat:");
    if (!code) {
        elements.settingsImportFile.value = "";
        return;
    }
    try {
        await restoreFromFile(file, code);
        elements.settingsDialog.close();
        showHomeNotice("Seiful a fost restaurat din backup.", "success");
    } catch (error) {
        showFormMessage(elements.settingsMessage, error.message || "Backup-ul nu a putut fi importat.");
    } finally {
        elements.settingsImportFile.value = "";
    }
});
elements.saveUsername.addEventListener("click", async () => {
    try {
        vault.username = elements.settingsUsername.value.trim().slice(0, 60);
        await saveVault();
        renderAccounts();
        showFormMessage(elements.settingsMessage, "Numele a fost salvat.", "success");
    } catch (error) {
        showFormMessage(elements.settingsMessage, error.message || "Numele nu a putut fi salvat.");
    }
});

elements.accountForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    elements.formError.textContent = "";
    let account;
    try {
        account = {
            id: crypto.randomUUID(),
            issuer: elements.issuer.value.trim().slice(0, 80),
            name: elements.accountName.value.trim().slice(0, 120),
            secret: normalizeBase32(elements.secret.value),
            algorithm: "SHA1",
            digits: 6,
            period: 30
        };
        decodeBase32(account.secret);
        if (!account.issuer || !account.name) throw new Error("Completează numele serviciului și contului.");
        vault.accounts.push(account);
        await saveVault();
        elements.addDialog.close();
        renderAccounts();
        showHomeNotice(`${account.issuer} a fost adăugat.`, "success");
    } catch (error) {
        if (account) vault.accounts = vault.accounts.filter((item) => item.id !== account.id);
        showFormMessage(elements.formError, error.message || "Contul nu a putut fi salvat.");
    }
});

for (const dialog of [elements.addDialog, elements.settingsDialog]) {
    dialog.addEventListener("click", (event) => {
        if (event.target === dialog) dialog.close();
    });
}

document.addEventListener("visibilitychange", updateLockTimer);
window.addEventListener("pagehide", lockVault);
window.addEventListener("beforeinstallprompt", (event) => event.preventDefault());

async function startApplication() {
    if (!globalThis.crypto?.subtle) {
        showStatus("Web Crypto nu este disponibil. Deschide aplicația de pe un URL HTTPS; nu folosi file://.");
        return;
    }

    try {
        const envelope = localStorage.getItem(STORAGE_KEY);
        if (envelope) {
            showScreen("unlock");
        } else {
            const bytes = randomBytes(32);
            elements.recoveryCode.textContent = encodeBase32(bytes);
            bytes.fill(0);
            showScreen("setup");
        }
        if ("serviceWorker" in navigator && window.isSecureContext) {
            navigator.serviceWorker.register("./service-worker.js").catch((error) => {
                console.error("Service worker registration failed:", error);
            });
        }
    } catch (error) {
        showStatus(error.message || "Aplicația nu a putut porni în acest browser.");
    }
}

startApplication();
