function getRPID() {
  const h = location.hostname;
  if (h === "localhost" || h === "127.0.0.1") return h;
  const p = h.split(".");
  return p.length > 2 ? p.slice(-2).join(".") : h;
}

class FIDO2Decryptor {
  constructor() {
    this.container = null;
    this.data = null;
    this.config = null;
  }

  init() {
    this.container = document.querySelector(".encrypted-post-container");
    if (!this.container) return;

    this.data = {
      ciphertext: this.container.dataset.ciphertext,
      iv: this.container.dataset.iv,
      authTag: this.container.dataset.authTag,
      keyHint: this.container.dataset.keyHint,
    };

    this.config = {
      rpName: this.container.dataset.rpName || "Undefined Blog",
      rpId: getRPID(),
    };

    if (!window.PublicKeyCredential) {
      this.showError("此浏览器不支持 FIDO2/WebAuthn");
      return;
    }

    if (this.checkCache()) return;

    const btn = document.getElementById("fido2-verify-btn");
    if (btn) btn.onclick = () => this.authenticate();
  }

  async authenticate() {
    this.showStatus("请触摸安全密钥...", "info");

    try {
      const challenge = crypto.getRandomValues(new Uint8Array(32));
      const assertion = await navigator.credentials.get({
        publicKey: {
          challenge,
          rpId: this.config.rpId,
          userVerification: "preferred",
          timeout: 60000,
        },
      });

      if (!assertion) throw new Error("验证失败");
      this.showStatus("验证成功", "success");
      setTimeout(() => this.decrypt(), 500);
    } catch (e) {
      if (e.name === "NotAllowedError") {
        this.showError("验证被拒绝或超时");
      } else if (e.name === "InvalidStateError" || e.name === "NotFoundError") {
        this.showError("未找到已注册的安全密钥");
      } else {
        this.showError(`验证失败: ${e.message}`);
      }
    }
  }

  checkCache() {
    try {
      const cacheKey = `fido2_cache_${this.data.keyHint}`;
      const cached = localStorage.getItem(cacheKey);
      if (!cached) return false;

      const { html, timestamp } = JSON.parse(cached);
      const now = Date.now();
      const expiry = 15 * 60 * 1000;

      if (now - timestamp < expiry) {
        this.render(html);
        setTimeout(() => this.hideStatus(), 2000);
        return true;
      } else {
        localStorage.removeItem(cacheKey);
        return false;
      }
    } catch (e) {
      return false;
    }
  }

  saveCache(html) {
    try {
      const cacheKey = `fido2_cache_${this.data.keyHint}`;
      const cacheData = { html, timestamp: Date.now() };
      localStorage.setItem(cacheKey, JSON.stringify(cacheData));
    } catch (e) {
      console.warn(`缓存失败: ${e}`);
    }
  }

  async decrypt() {
    try {
      this.showStatus("正在解密...", "info");

      const keyBuffer = this.b64ToAB(this.data.keyHint);
      const ciphertext = this.b64ToAB(this.data.ciphertext);
      const iv = this.b64ToAB(this.data.iv);
      const authTag = this.b64ToAB(this.data.authTag);

      const encData = new Uint8Array(
        ciphertext.byteLength + authTag.byteLength
      );
      encData.set(new Uint8Array(ciphertext), 0);
      encData.set(new Uint8Array(authTag), ciphertext.byteLength);

      const key = await crypto.subtle.importKey(
        "raw",
        keyBuffer,
        { name: "AES-GCM" },
        false,
        ["decrypt"]
      );
      const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv, tagLength: 128 },
        key,
        encData
      );

      const html = new TextDecoder().decode(decrypted);
      this.saveCache(html);
      this.render(html);
      setTimeout(() => this.hideStatus(), 2000);
    } catch (e) {
      this.showError("解密失败: 密钥不匹配或数据损坏");
    }
  }

  render(html) {
    const content = document.getElementById("decrypted-content");
    const notice = document.querySelector(".encrypted-post-notice");
    if (content && notice) {
      notice.style.display = "none";
      content.innerHTML = html;
      content.style.display = "block";
    }
  }

  showStatus(msg, type = "info") {
    const el = document.getElementById("verification-status");
    if (!el) return;
    const icons = {
      info: "fa-info-circle",
      success: "fa-check-circle",
      error: "fa-times-circle",
    };
    el.style.display = "block";
    el.className = "verification-status " + type;
    el.innerHTML = `<i class="fa ${icons[type]}"></i> ${msg}`;
  }

  showError(msg) {
    this.showStatus(msg, "error");
  }

  hideStatus() {
    const el = document.getElementById("verification-status");
    if (el) el.style.display = "none";
  }

  b64ToAB(b64) {
    const str = atob(b64);
    const bytes = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) bytes[i] = str.charCodeAt(i);
    return bytes.buffer;
  }
}

window.FIDO2Decryptor = new FIDO2Decryptor();
document.addEventListener("DOMContentLoaded", () => {
  if (document.querySelector(".encrypted-post-container")) {
    window.FIDO2Decryptor.init();
  }
});
