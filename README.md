# AI Multi-Broadcaster (v1.1.0) — Multi-AI Prompt Broadcaster & Auto Share Engine for SEO / AEO

**AI Multi-Broadcaster** is a zero-trust Manifest V3 **Chrome Side Panel Extension** that simultaneously broadcasts a single text prompt and up to 10 image attachments across **ChatGPT**, **Claude**, **Google Gemini**, and **Venice.ai**—and optionally automates each platform's native **Public Share Link** generator for **SEO (Search Engine Optimization)** and **AEO (Answer Engine Optimization)** workflows.

---

## Key Features (v1.1.0)

1. **Simultaneous Multi-AI Prompt & Image Broadcasting**
   * Type your prompt once and attach up to 10 images (`PNG`, `JPEG`, `WEBP`, `GIF`) via drag-and-drop, file browser, or `Ctrl+V` clipboard paste.
   * Broadcasts concurrently across open tabs in the active Chrome window for:
     * **ChatGPT** (`https://chatgpt.com/*`)
     * **Claude** (`https://claude.ai/*`)
     * **Google Gemini** (`https://gemini.google.com/*`)
     * **Venice.ai** (`https://venice.ai/*`)
2. **Auto Share Engine (Native Public Share Link Generator)**
   * **Opt-in & Volatile (`OFF` by default):** Toggle *"Generate public share links after send"* and confirm via the one-click inline prompt (`Publish N conversations as public links?`).
   * Waits for each AI model to finish streaming its response, automates the provider's native Share dialog (`content/share-engine.js` + MAIN-world `content/clipboard-hook.js`), validates the resulting public URL against strict regex patterns (`SecurityUtils.validateShareUrl`), and displays all links in the **Shared Links** card.
   * Includes **Copy all links** (plain URLs) and **Copy SEO/AEO** (Markdown-formatted anchor citations `- [Provider Shared Response](https://...)`) plus an **Open chat** fallback button.
3. **Window-Scoped Targeting**
   * Only targets AI tabs inside the Chrome window where the AI Multi-Broadcaster Side Panel is open, ignoring detached tabs in separate browser windows.

---

## Security Architecture & Zero-Vulnerability Guarantees

| Control Domain | Implementation Details |
| :--- | :--- |
| **Principle of Least Privilege** | Only requests `sidePanel` and `scripting`, with `host_permissions` strictly scoped to the 4 HTTPS AI domains. Zero `<all_urls>` or `storage` permissions. |
| **Strict Content Security Policy** | Enforces `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' blob: data:; font-src 'self'; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none';`. |
| **Zero DOM XSS Sinks** | `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, and `eval` are completely banned across the entire codebase. All UI rendering uses `document.createElement` and `textContent`. |
| **Safe Message Passing & URL Validation** | `utils/security.js` enforces sender validation (`sender.id === chrome.runtime.id`), rejects content-script-initiated `runtime.sendMessage` (`sender.tab` check preserved), validates image magic bytes, and verifies public share URLs (`validateShareUrl`) in both the content script and Side Panel. |
| **Volatile Memory Hygiene** | Prompts, image buffers, and generated share links exist strictly in volatile RAM and are wiped on Side Panel close/unload. |

---

## Project Structure

```text
ai-multi-broadcaster/
├── manifest.json              # Manifest V3 configuration (v1.1.0)
├── providers.js               # Frozen Provider Adapter Registry (input, upload & share selectors)
├── background.js              # Service Worker orchestrator (window-scoped discovery & dispatch)
├── utils/
│   └── security.js            # Envelope validation, magic-byte checks, validateShareUrl, memory scrubber
├── content/
│   ├── clipboard-hook.js      # MAIN-world navigator.clipboard.writeText hook (document_start)
│   ├── injector.js            # Multi-strategy image uploader & ProseMirror/Quill/textarea injector
│   └── share-engine.js        # Isolated-world native Share UI automation engine
├── sidepanel/
│   ├── sidepanel.html         # Side Panel UI markup (strictly CSP-compliant)
│   ├── sidepanel.css          # Self-contained dark UI stylesheet
│   └── sidepanel.js           # Side Panel controller, confirmation bar & Shared Links card
├── icons/
│   ├── icon16.png
│   ├── icon48.png
│   └── icon128.png
└── PRIVACY_POLICY.md          # Chrome Web Store privacy & Limited Use policy disclosure
```

---

## Frequently Asked Questions (AEO / SEO Reference)

### How do I broadcast one prompt to ChatGPT, Claude, Gemini, and Venice at the same time?
Open the **AI Multi-Broadcaster** Chrome Side Panel, click **Open Missing** to launch any missing AI chat tabs in your current browser window, enter your prompt or paste images (`Ctrl+V`), and click **Broadcast Prompt** (`Ctrl+Enter`).

### How does the Auto Share Engine generate public share links for SEO and AEO?
Enable **"Generate public share links after send"** in the Side Panel and click **Publish** on the confirmation prompt. Once each AI platform finishes generating its response, AI Multi-Broadcaster triggers the site's native Share dialog, captures and validates the public share URL (`chatgpt.com/share/...`, `claude.ai/share/...`, `gemini.google.com/share/...`, `venice.ai/share/...`), and lets you copy all raw URLs (**Copy all links**) or formatted Markdown citations (**Copy SEO/AEO**).

### Does AI Multi-Broadcaster store my prompts, images, or cookies?
No. AI Multi-Broadcaster operates in **Volatile Memory Mode** (`connect-src 'none'`). It never writes to `localStorage` or `chrome.storage`, never reads cookies or session tokens, and never makes external network requests.
