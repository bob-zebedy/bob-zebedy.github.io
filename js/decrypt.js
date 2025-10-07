function getRPID() {
  const hostname = location.hostname;
  return hostname === "127.0.0.1" ? "localhost" : hostname;
}

class FIDO2Decryptor {
  constructor() {
    this.container = null;
    this.data = null;
    this.rpId = getRPID();
  }

  init() {
    this.container = document.querySelector(".encrypted-post-container");
    if (!this.container) return;

    this.data = {
      ciphertext: this.container.dataset.ciphertext,
      iv: this.container.dataset.iv,
      authTag: this.container.dataset.authTag,
      abbrlink: this.container.dataset.abbrlink,
      wrappedKeys: JSON.parse(this.container.dataset.wrappedKeys || "[]"),
      prfSalt: this.container.dataset.prfSalt,
    };

    if (!window.PublicKeyCredential) {
      this.showError("浏览器不支持 FIDO2/WebAuthn");
      return;
    }

    if (this.checkCache()) return;

    const btn = document.getElementById("fido2-verify-btn");
    if (!btn) return;

    btn.onclick = () => this.authenticate();
  }

  getCacheKey() {
    return this.data.abbrlink || location.pathname;
  }

  checkCache() {
    try {
      const cached = localStorage.getItem(this.getCacheKey());
      if (!cached) return false;

      const { html, timestamp } = JSON.parse(cached);
      if (Date.now() - timestamp < 10 * 60 * 1000) {
        this.render(html);
        setTimeout(() => this.hideStatus(), 2000);
        return true;
      }
      localStorage.removeItem(this.getCacheKey());
      return false;
    } catch (e) {
      return false;
    }
  }

  saveCache(html) {
    try {
      localStorage.setItem(
        this.getCacheKey(),
        JSON.stringify({ html, timestamp: Date.now() })
      );
    } catch (e) {
      console.warn(`缓存失败: ${e}`);
    }
  }

  async authenticate() {
    this.showStatus("正在验证身份...", "info");

    try {
      const challenge = crypto.getRandomValues(new Uint8Array(32));

      const prfSalt = await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(this.data.prfSalt)
      );

      const assertion = await navigator.credentials.get({
        publicKey: {
          challenge,
          rpId: this.rpId,
          userVerification: "preferred",
          timeout: 60000,
          extensions: { prf: { eval: { first: prfSalt } } },
        },
      });

      const prfResults = assertion.getClientExtensionResults().prf;
      if (!prfResults?.results?.first) throw new Error("PRF 扩展不可用");

      const wrappingKey = prfResults.results.first;

      this.showStatus("验证成功，正在解密...", "success");
      setTimeout(() => this.unwrapAndDecrypt(wrappingKey), 300);
    } catch (e) {
      if (e.name === "NotAllowedError") {
        this.showError("验证被拒绝");
      } else if (e.name === "InvalidStateError" || e.name === "NotFoundError") {
        this.showError("未注册的通行密钥");
      } else {
        this.showError(`验证失败: ${e.message}`);
      }
    }
  }

  async unwrapAndDecrypt(wrappingKey) {
    try {
      this.showStatus("正在解密密钥...", "info");

      const wrapKeyBuffer = await crypto.subtle.importKey(
        "raw",
        wrappingKey,
        { name: "AES-GCM" },
        false,
        ["decrypt"]
      );

      let cek = null;
      for (const wrapped of this.data.wrappedKeys) {
        try {
          const encCEK = this.b64ToAB(wrapped.encryptedCEK);
          const wrapIV = this.b64ToAB(wrapped.iv);
          const wrapAuthTag = this.b64ToAB(wrapped.authTag);

          const wrappedCEK = new Uint8Array(
            encCEK.byteLength + wrapAuthTag.byteLength
          );
          wrappedCEK.set(new Uint8Array(encCEK), 0);
          wrappedCEK.set(new Uint8Array(wrapAuthTag), encCEK.byteLength);

          cek = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: wrapIV, tagLength: 128 },
            wrapKeyBuffer,
            wrappedCEK
          );
          break;
        } catch (e) {}
      }

      if (!cek) throw new Error("通行密钥无权限");

      await this.decryptContent(cek);
    } catch (e) {
      console.error(`解密密钥失败: ${e}`);
      this.showError(`解密失败: ${e.message}`);
    }
  }

  async decryptContent(decryptionKey) {
    try {
      this.showStatus("正在解密...", "info");

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
        decryptionKey,
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
      this.showError(`解密失败: ${e.message}`);
    }
  }

  render(html) {
    const content = document.getElementById("decrypted-content");
    const notice = document.querySelector(".encrypted-post-notice");
    if (!content || !notice) return;

    notice.style.display = "none";
    content.innerHTML = html;
    content.style.display = "block";

    try {
      if (typeof NexT !== "undefined" && NexT.boot?.refresh) {
        NexT.boot.refresh();
      }
    } catch (e) {
      console.warn(`NexT 主题功能初始化失败: ${e}`);
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
    el.className = `verification-status ${type}`;
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

const decryptor = new FIDO2Decryptor();
document.addEventListener("DOMContentLoaded", () => {
  if (document.querySelector(".encrypted-post-container")) decryptor.init();
});
