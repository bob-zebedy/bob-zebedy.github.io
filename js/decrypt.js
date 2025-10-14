const PBKDF2_ITERATIONS = 500000;

function getRPID() {
  const hostname = location.hostname;
  return hostname === "127.0.0.1" ? "localhost" : hostname;
}

class Decryptor {
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
      cache: parseInt(this.container.dataset.cache) || 0,
    };

    if (this.checkCache()) return;

    const fido2Btn = document.getElementById("fido2-verify-btn");
    if (fido2Btn) {
      if (!window.PublicKeyCredential) {
        this.showStatus("浏览器不支持 FIDO2/WebAuthn", "error");
      } else {
        fido2Btn.onclick = () => this.authenticate();
      }
    }

    const showPasswordBtn = document.getElementById("show-password-btn");
    if (showPasswordBtn) {
      showPasswordBtn.onclick = () => this.showPasswordInput();
    }

    const passwordBtn = document.getElementById("password-decrypt-btn");
    if (passwordBtn) {
      passwordBtn.onclick = () => this.decryptWithPassword();
    }

    const passwordInput = document.getElementById("password-input");
    if (passwordInput) {
      passwordInput.addEventListener("keydown", (e) => {
        if (e.key === "Enter") this.decryptWithPassword();
      });
    }
  }

  getCacheKey() {
    return this.data.abbrlink;
  }

  showPasswordInput() {
    const showBtn = document.getElementById("show-password-btn");
    const inputGroup = document.getElementById("password-input-group");
    const passwordInput = document.getElementById("password-input");

    if (showBtn) showBtn.style.display = "none";
    if (inputGroup) inputGroup.style.display = "flex";
    if (passwordInput) {
      passwordInput.focus();
      passwordInput.addEventListener("input", () =>
        this.updatePasswordButtonState()
      );
    }
    this.updatePasswordButtonState();
  }

  updatePasswordButtonState() {
    const passwordInput = document.getElementById("password-input");
    const passwordBtn = document.getElementById("password-decrypt-btn");

    if (!passwordInput || !passwordBtn) return;

    const hasPassword = passwordInput.value.trim().length > 0;
    passwordBtn.disabled = !hasPassword;
    passwordBtn.style.opacity = hasPassword ? "1" : "0.5";
    passwordBtn.style.cursor = hasPassword ? "pointer" : "not-allowed";
  }

  checkCache() {
    if (!this.data.cache) return false;

    try {
      const cached = localStorage.getItem(this.getCacheKey());
      if (!cached) return false;

      const { html, expired } = JSON.parse(cached);
      if (Date.now() < expired) {
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
    if (!this.data.cache) return;

    try {
      const expired = Date.now() + this.data.cache * 60 * 1000;
      localStorage.setItem(
        this.getCacheKey(),
        JSON.stringify({ html, expired })
      );
    } catch (e) {}
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
        this.showStatus("验证被拒绝", "error");
      } else if (e.name === "InvalidStateError" || e.name === "NotFoundError") {
        this.showStatus("未注册的通行密钥", "error");
      } else {
        this.showStatus(`验证失败: ${e.message}`, "error");
      }
    }
  }

  async derivePBKDF2Key(password, salt, iterations = PBKDF2_ITERATIONS) {
    const passwordBuffer = new TextEncoder().encode(password);
    const saltBuffer = new TextEncoder().encode(salt);

    const baseKey = await crypto.subtle.importKey(
      "raw",
      passwordBuffer,
      "PBKDF2",
      false,
      ["deriveBits"]
    );

    const derivedBits = await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt: saltBuffer,
        iterations: iterations,
        hash: "SHA-256",
      },
      baseKey,
      256
    );

    return derivedBits;
  }

  async decryptWithPassword() {
    const passwordInput = document.getElementById("password-input");
    const password = passwordInput?.value.trim();

    if (!password) {
      this.showStatus("未输入密码", "error");
      return;
    }

    this.showStatus("正在解密...", "info");

    try {
      const passwordWrapped = this.data.wrappedKeys.find(
        (k) => k.type === "password"
      );
      if (!passwordWrapped) throw new Error("不支持密码认证");

      const wrappingKey = await this.derivePBKDF2Key(
        password,
        passwordWrapped.salt
      );
      await this.unwrapAndDecrypt(wrappingKey, "password");
    } catch (e) {
      this.showStatus(`解密失败: ${e.message}`, "error");
    }
  }

  combineWithAuthTag(data, authTag) {
    const combined = new Uint8Array(data.byteLength + authTag.byteLength);
    combined.set(new Uint8Array(data), 0);
    combined.set(new Uint8Array(authTag), data.byteLength);
    return combined;
  }

  async unwrapAndDecrypt(wrappingKey, type = "fido2") {
    try {
      const wrapKeyBuffer = await crypto.subtle.importKey(
        "raw",
        wrappingKey,
        { name: "AES-GCM" },
        false,
        ["decrypt"]
      );
      const targetKeys = this.data.wrappedKeys.filter((k) => k.type === type);

      let cek = null;
      for (const wrapped of targetKeys) {
        try {
          const encCEK = this.b64ToAB(wrapped.encryptedCEK);
          const wrapIV = this.b64ToAB(wrapped.iv);
          const wrapAuthTag = this.b64ToAB(wrapped.authTag);
          const wrappedCEK = this.combineWithAuthTag(encCEK, wrapAuthTag);

          cek = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: wrapIV, tagLength: 128 },
            wrapKeyBuffer,
            wrappedCEK
          );
          break;
        } catch (e) {}
      }

      if (!cek)
        throw new Error(type === "password" ? "密码错误" : "通行密钥无权限");
      await this.decryptContent(cek);
    } catch (e) {
      this.showStatus(`解密失败: ${e.message}`, "error");
    }
  }

  async decryptContent(decryptionKey) {
    try {
      this.showStatus("正在解密...", "info");

      const ciphertext = this.b64ToAB(this.data.ciphertext);
      const iv = this.b64ToAB(this.data.iv);
      const authTag = this.b64ToAB(this.data.authTag);
      const encData = this.combineWithAuthTag(ciphertext, authTag);

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
      this.showStatus(`解密失败: ${e.message}`, "error");
    }
  }

  render(html) {
    const content = document.getElementById("decrypted-content");
    const notice = document.querySelector(".encrypted-post-notice");
    if (!content || !notice) return;

    notice.style.display = "none";
    content.innerHTML = html;
    content.style.display = "block";

    this.renderRefresh();
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

  hideStatus() {
    const el = document.getElementById("verification-status");
    if (el) el.style.display = "none";
  }

  rebuildTOC() {
    try {
      const content = document.getElementById("decrypted-content");
      const tocWrap = document.querySelector(".post-toc-wrap");
      const sidebar = document.querySelector(".sidebar-inner");
      const utils = window.NexT?.utils;
      if (!content || !tocWrap) return;

      const headings = content.querySelectorAll("h1,h2,h3,h4,h5,h6");
      const ensureToc = () =>
        tocWrap.querySelector(".post-toc") ||
        (() => {
          const el = document.createElement("div");
          el.className = "post-toc animated";
          tocWrap.appendChild(el);
          return el;
        })();

      if (!headings.length) {
        const exist = tocWrap.querySelector(".post-toc");
        if (exist) exist.innerHTML = "";
        sidebar?.classList.remove("sidebar-nav-active", "sidebar-toc-active");
        sidebar?.classList.add("sidebar-overview-active");
        utils?.registerSidebarTOC?.();
        return;
      }

      const { roots } = Array.from(headings).reduce(
        (acc, h, i) => {
          if (!h.id) h.id = `heading-${i}`;
          const level = parseInt(h.tagName[1], 10);
          const node = {
            level,
            id: h.id,
            text: h.textContent.trim(),
            children: [],
          };
          while (acc.stack.length && acc.stack.at(-1).level >= level)
            acc.stack.pop();
          (acc.stack.length ? acc.stack.at(-1).children : acc.roots).push(node);
          acc.stack.push(node);
          return acc;
        },
        { roots: [], stack: [] }
      );

      const render = (nodes, depth = 1) =>
        nodes
          .map((n) => {
            const link = `<a class="nav-link" href="#${n.id}"><span class="nav-text">${n.text}</span></a>`;
            const kids = n.children.length
              ? `<ol class="nav-child">${render(n.children, depth + 1)}</ol>`
              : "";
            return `<li class="nav-item nav-level-${depth}">${link}${kids}</li>`;
          })
          .join("");

      const toc = ensureToc();
      toc.innerHTML = `<ol class="nav">${render(roots)}</ol>`;

      sidebar?.classList.add("sidebar-nav-active", "sidebar-toc-active");
      sidebar?.classList.remove("sidebar-overview-active");
      utils?.registerSidebarTOC?.();
    } catch (e) {
      console.error(`TOC 重建失败: ${e.message}`);
    }
  }

  renderRefresh() {
    this.rebuildTOC();
    NexT?.boot?.refresh?.();
  }

  b64ToAB(b64) {
    const str = atob(b64);
    const bytes = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) bytes[i] = str.charCodeAt(i);
    return bytes.buffer;
  }
}

const decryptor = new Decryptor();
document.addEventListener("DOMContentLoaded", () => {
  if (document.querySelector(".encrypted-post-container")) decryptor.init();
});
