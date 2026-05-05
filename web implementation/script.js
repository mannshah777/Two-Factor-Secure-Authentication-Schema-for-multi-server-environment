// -----------------------------
// GLOBAL VARIABLES
// -----------------------------
let omega = 15;
let x = 5;
let p = 101;

let smartCard = {
    ID: "user1",
    r: "1234"
};

let stored = {};
let cardInserted = false;

// Security
let attempts = parseInt(localStorage.getItem("authAttempts")) || 0;
let maxAttempts = 3;
let locked = false;


// -----------------------------
// SHA-256 (full 64-char hash, NO truncation)
// -----------------------------
async function sha256(message) {
    const msgBuffer = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest("SHA-256", msgBuffer);
    return Array.from(new Uint8Array(hashBuffer))
        .map(b => b.toString(16).padStart(2, "0")).join("");
}


// -----------------------------
// Chebyshev Map
// -----------------------------
function chebyshev(n, x, p) {
    let T0 = 1 % p;
    if (n === 0) return T0;

    let T1 = x % p;
    if (n === 1) return T1;

    for (let i = 2; i <= n; i++) {
        let Tn = (2 * x * T1 - T0) % p;
        if (Tn < 0) Tn += p;
        T0 = T1;
        T1 = Tn;
    }
    return T1;
}


// -----------------------------
// INIT SYSTEM (PERSIST PASSWORD)
// -----------------------------
// On every page load, read the current V from localStorage.
// Only generate default credentials if no V exists at all.
async function initSystem() {
    let savedV = localStorage.getItem("V");

    // Migration: if stored V is not a valid 64-char SHA-256 hex hash
    // (e.g. old truncated 8-char value from previous buggy code), discard it
    if (savedV && (savedV.length !== 64 || !/^[0-9a-f]{64}$/.test(savedV))) {
        console.warn("Detected corrupted/truncated V — resetting credentials");
        localStorage.removeItem("V");
        savedV = null;
    }

    if (savedV) {
        // Always use the latest value from localStorage
        stored = { V: savedV };
    } else {
        // First-time setup: hash the default password "pass123"
        let RPW = await sha256("pass123" + smartCard.r);
        let V = await sha256(smartCard.ID + RPW);

        stored = { V };
        localStorage.setItem("V", V);
    }
}

initSystem();


// -----------------------------
// INSERT CARD
// -----------------------------
window.insertCard = function () {

    if (locked) {
        document.getElementById("errorText").innerText = "System Locked";
        return;
    }

    cardInserted = true;

    let authSection = document.getElementById("authSection");
    let statusText = document.getElementById("statusText");

    if (authSection && statusText) {
        authSection.classList.remove("hidden");
        statusText.innerText = "Card Inserted";
    }

    // Hide the Insert Smart Card button after successful insertion
    let insertBtn = document.getElementById("insertCardBtn");
    if (insertBtn) insertBtn.classList.add("hidden");

    let err = document.getElementById("errorText");
    if (err) err.innerText = "";
};


// -----------------------------
// RESET CARD
// -----------------------------
function resetToCardState() {
    cardInserted = false;

    document.getElementById("password").value = "";

    let authSection = document.getElementById("authSection");
    let statusText = document.getElementById("statusText");

    if (authSection && statusText) {
        authSection.classList.add("hidden");
        statusText.innerText = "Insert Smart Card";
    }

    // Re-show the Insert Smart Card button so user can re-insert
    let insertBtn = document.getElementById("insertCardBtn");
    if (insertBtn) insertBtn.classList.remove("hidden");
}


// -----------------------------
// LOCK SYSTEM
// -----------------------------
function lockSystem() {
    locked = true;
    let time = 60;

    let errEl = document.getElementById("errorText");

    let interval = setInterval(() => {
        if (errEl) errEl.innerText = "System Locked: " + time + "s";
        time--;

        if (time <= 0) {
            clearInterval(interval);
            locked = false;
            attempts = 0;
            localStorage.removeItem("authAttempts");
            if (errEl) errEl.innerText = "";
        }
    }, 1000);
}


// -----------------------------
// LOGIN
// -----------------------------
async function login() {

    if (!cardInserted) {
        document.getElementById("errorText").innerText =
            "Insert Smart Card First";
        return;
    }

    let id = document.getElementById("userId").value;
    let pw = document.getElementById("password").value;

    // Hash input password using FULL hash (no substring)
    let RPW_input = await sha256(pw + smartCard.r);
    let checkV = await sha256(smartCard.ID + RPW_input);

    // Always re-read from localStorage to get the latest V
    let savedV = localStorage.getItem("V");
    stored = { V: savedV };

    // ❌ Failed
    if (checkV !== stored.V) {
        attempts++;
        localStorage.setItem("authAttempts", attempts);
        resetToCardState();

        if (attempts >= maxAttempts) {
            lockSystem();
            return;
        }

        document.getElementById("errorText").innerText =
            "Authentication Failed\nAttempts: " +
            attempts + "/" + maxAttempts +
            "\nInsert Smart Card again";

        return;
    }

    // ✅ Success
    attempts = 0;
    localStorage.removeItem("authAttempts");

    let timestamp = Date.now();

    let ru = Math.floor(Math.random() * 40) + 10;
    let rs = Math.floor(Math.random() * 40) + 10;

    let C = chebyshev(ru, x, p);
    let L = chebyshev(rs * ru, x, p);

    let SK = await sha256(L + timestamp);

    localStorage.setItem("sessionKey", SK);
    localStorage.setItem("loginTime", timestamp);

    window.location.href = "dashboard.html";
}


// -----------------------------
// LOGOUT (preserve credentials!)
// -----------------------------
function logout() {
    // Only remove session data, NOT the password verifier V
    localStorage.removeItem("sessionKey");
    localStorage.removeItem("loginTime");
    localStorage.removeItem("cardInsertedTemp");
    window.location.href = "index.html";
}


// -----------------------------
// CHANGE PASSWORD (used by change_password.html)
// These are the SINGLE authoritative definitions.
// change_password.html must NOT redefine these.
// -----------------------------
window.verifyOld = async function () {

    if (locked) {
        let errEl = document.getElementById("errorText");
        if (errEl) errEl.innerText = "System Locked";
        return;
    }

    let pw = document.getElementById("oldPw").value;

    // Use FULL hash — must match how initSystem stored V
    let RPW = await sha256(pw + smartCard.r);
    let checkV = await sha256(smartCard.ID + RPW);

    // Re-read latest V from localStorage
    let savedV = localStorage.getItem("V");
    stored = { V: savedV };

    // ❌ Failed — save attempt count and redirect to index.html
    if (checkV !== stored.V) {
        attempts++;
        localStorage.setItem("authAttempts", attempts);
        localStorage.setItem("authFailed", "true");
        window.location.href = "index.html";
        return;
    }

    // ✅ Success
    attempts = 0;
    let errEl = document.getElementById("errorText");
    if (errEl) errEl.innerText = "";

    document.getElementById("authSection").classList.add("hidden");
    document.getElementById("newPwSection").classList.remove("hidden");
};


// -----------------------------
// PASSWORD VALIDATION
// -----------------------------
window.validateNewPassword = function () {
    let pw = document.getElementById("newPw").value;

    let rules = {
        length:  pw.length >= 10,
        upper:   /[A-Z]/.test(pw),
        lower:   /[a-z]/.test(pw),
        digit:   /[0-9]/.test(pw),
        special: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?`~]/.test(pw)
    };

    function mark(id, pass, text) {
        let el = document.getElementById(id);
        if (!el) return;
        el.innerText = (pass ? "✓ " : "✗ ") + text;
        el.style.color = pass ? "#4caf50" : "#ff5252";
    }

    mark("reqLength",  rules.length,  "At least 10 characters");
    mark("reqUpper",   rules.upper,   "At least one uppercase letter");
    mark("reqLower",   rules.lower,   "At least one lowercase letter");
    mark("reqDigit",   rules.digit,   "At least one number");
    mark("reqSpecial", rules.special, "At least one special character (!@#$%^&* etc.)");

    let allPass = Object.values(rules).every(Boolean);
    let btn = document.getElementById("updatePwBtn");
    if (btn) btn.disabled = !allPass;

    return allPass;
};


window.updatePassword = async function () {

    let newPw = document.getElementById("newPw").value;

    if (!newPw || newPw.trim() === "") {
        document.getElementById("msg").innerText = "❌ New password cannot be empty";
        return;
    }

    // Validate password requirements
    if (!validateNewPassword()) {
        document.getElementById("msg").innerText = "❌ Password does not meet requirements";
        return;
    }

    // Use FULL hash — consistent with initSystem and login
    let RPW_new = await sha256(newPw + smartCard.r);
    let newV = await sha256(smartCard.ID + RPW_new);

    // Overwrite both in-memory and localStorage
    stored.V = newV;
    localStorage.removeItem("V");
    localStorage.setItem("V", newV);

    window.location.href = "success.html";
};


// -----------------------------
// AUTO-INSERT CARD ON PAGE LOAD
// -----------------------------
window.onload = function () {

    let temp = localStorage.getItem("cardInsertedTemp");

    if (temp === "true") {
        cardInserted = true;

        let authSection = document.getElementById("authSection");
        let statusText = document.getElementById("statusText");

        if (authSection && statusText) {
            authSection.classList.remove("hidden");
            statusText.innerText = "Card Inserted";
        }

        // Hide the Insert Smart Card button (auto-insert from navigation)
        let insertBtn = document.getElementById("insertCardBtn");
        if (insertBtn) insertBtn.classList.add("hidden");

        localStorage.removeItem("cardInsertedTemp");
    }

    // Handle failed verification redirect from change_password.html
    let authFailed = localStorage.getItem("authFailed");
    if (authFailed === "true") {
        localStorage.removeItem("authFailed");
        attempts = parseInt(localStorage.getItem("authAttempts")) || 0;

        if (attempts >= maxAttempts) {
            lockSystem();
            resetToCardState();
        } else {
            resetToCardState();
            let errEl = document.getElementById("errorText");
            if (errEl) {
                errEl.innerText = "Authentication Failed\nAttempts: " +
                    attempts + "/" + maxAttempts +
                    "\nInsert Smart Card again";
            }
        }
    }
};


// -----------------------------
// NAVIGATION
// -----------------------------
function goToChangePassword() {
    localStorage.setItem("cardInsertedTemp", "true");
    window.location.href = "change_password.html";
}