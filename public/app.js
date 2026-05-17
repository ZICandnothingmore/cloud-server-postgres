const loginTab = document.getElementById("loginTab");
const registerTab = document.getElementById("registerTab");

const loginForm = document.getElementById("loginForm");
const registerForm = document.getElementById("registerForm");

const messageBox = document.getElementById("message");
const resultBox = document.getElementById("resultBox");
const resultPre = document.getElementById("result");

const registerPasswordInput = document.getElementById("registerPassword");
const registerConfirmPasswordInput = document.getElementById("registerConfirmPassword");

function hideResult() {
    if (resultBox) {
        resultBox.classList.add("hidden");
    }
}

function showMessage(text, type) {
    messageBox.textContent = text;
    messageBox.className = `message ${type}`;
    messageBox.style.display = "block";
}

function hideMessage() {
    messageBox.textContent = "";
    messageBox.className = "message";
    messageBox.style.display = "none";
}

function showResult(data) {
    // resultBox.classList.remove("hidden");
    // resultPre.textContent = JSON.stringify(data, null, 2);
    return;
}

function switchTab(tab) {
    hideMessage();
    hideResult();

    if (tab === "login") {
        loginTab.classList.add("active");
        registerTab.classList.remove("active");
        loginForm.classList.remove("hidden");
        registerForm.classList.add("hidden");
    } else {
        registerTab.classList.add("active");
        loginTab.classList.remove("active");
        registerForm.classList.remove("hidden");
        loginForm.classList.add("hidden");
    }
}

function validateConfirmPassword() {
    const password = registerPasswordInput.value;
    const confirmPassword = registerConfirmPasswordInput.value;

    if (!confirmPassword || password === confirmPassword) {
        registerConfirmPasswordInput.setCustomValidity("");
        hideMessage();
        return true;
    }

    registerConfirmPasswordInput.setCustomValidity("Mật khẩu xác nhận không khớp");
    showMessage("Mật khẩu xác nhận không khớp", "error");
    return false;
}

loginTab.addEventListener("click", () => switchTab("login"));
registerTab.addEventListener("click", () => switchTab("register"));

registerPasswordInput.addEventListener("input", validateConfirmPassword);
registerConfirmPasswordInput.addEventListener("input", validateConfirmPassword);

registerForm.addEventListener("submit", async (e) => {
    e.preventDefault();

    const password = document.getElementById("registerPassword").value;
    const confirmPassword = document.getElementById("registerConfirmPassword").value;

    if (password !== confirmPassword) {
        showMessage("Mật khẩu xác nhận không khớp", "error");
        resultBox.classList.add("hidden");
        return;
    }

    const body = {
        email: document.getElementById("registerEmail").value.trim(),
        password: password,
        displayName: document.getElementById("registerDisplayName").value.trim(),
        identity_pk: document.getElementById("registerIdentityPk").value.trim(),
        deviceName: document.getElementById("registerDeviceName").value.trim(),
        fcmToken: "fake_fcm_token_from_web"
    };

    try {
        const res = await fetch("/auth/register", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify(body),
        });

        const data = await res.json();
        // showResult(data);

        if (!res.ok) {
            showMessage(data.error || "Đăng ký thất bại", "error");
            return;
        }

        localStorage.setItem("accessToken", data.accessToken);
        localStorage.setItem("refreshToken", data.refreshToken);

        showMessage("Đăng ký thành công! Token đã được lưu vào localStorage.", "success");
    } catch (err) {
        showMessage("Không gọi được API đăng ký: " + err.message, "error");
    }
});

loginForm.addEventListener("submit", async (e) => {
    e.preventDefault();

    const body = {
        email: document.getElementById("loginEmail").value.trim(),
        password: document.getElementById("loginPassword").value
    };

    try {
        const res = await fetch("/auth/login", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify(body),
        });

        const data = await res.json();
        // showResult(data);

        if (!res.ok) {
            showMessage(data.error || "Đăng nhập thất bại", "error");
            return;
        }

        localStorage.setItem("accessToken", data.accessToken);
        localStorage.setItem("refreshToken", data.refreshToken);

        showMessage("Đăng nhập thành công! Token đã được lưu vào localStorage.", "success");
    } catch (err) {
        showMessage("Không gọi được API đăng nhập: " + err.message, "error");
    }
});