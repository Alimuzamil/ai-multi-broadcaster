# AI Multi-Broadcaster (Manifest V3 Chrome Side Panel Extension)

A production-ready, zero-vulnerability Chrome Extension (Manifest V3) built on the **Chrome Side Panel API** (`chrome.sidePanel`) that broadcasts a single prompt and one or multiple image attachments simultaneously across open tabs for:

1. **ChatGPT** (`https://chatgpt.com/*`)
2. **Claude** (`https://claude.ai/*`)
3. **Gemini** (`https://gemini.google.com/*`)
4. **Venice.ai** (`https://venice.ai/*`)

---

## 1. Security Architecture & Zero-Vulnerability Guarantees

| Control Domain | Implementation Details |
| :--- | :--- |
| **Principle of Least Privilege** | No `<all_urls>`, `storage`, or broad host permissions. `host_permissions` and `content_scripts.matches` are strictly pinned to the 4 HTTPS AI domains. |
| **Strict Content Security Policy** | Enforces `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' blob: data:; font-src 'self'; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none';`. Zero inline scripts, zero inline `style` attributes, and zero external CDNs. |
| **DOM XSS Prevention** | `innerHTML`, `outerHTML`, `insertAdjacentHTML`, and `document.write` are completely banned across the entire codebase. UI rendering and DOM prompt injection use `document.createElement`, `textContent`, `ClipboardEvent`, `DataTransfer`, and `InputEvent`. |
| **Safe Message Passing** | `utils/security.js` enforces sender validation (`sender.id === chrome.runtime.id`), strict action whitelisting, MIME-type whitelisting (`image/png`, `image/jpeg`, `image/webp`, `image/gif`), size bounds, and filename sanitization. |
| **Volatile Memory & Privacy Hygiene** | Prompts and image attachments are **never** written to `localStorage`, `sessionStorage`, `indexedDB`, or `chrome.storage`. Preview thumbnails use `URL.createObjectURL` and are immediately revoked via `URL.revokeObjectURL`. Base64 transfer payloads and `Uint8Array` buffers are explicitly zeroed out (`scrubVolatilePayload`) in `finally` blocks immediately after dispatch. |

---

## 2. Project Structure

```text
ai-multi-broadcaster/
├── manifest.json            # Manifest V3 configuration with strict CSP & scoped host_permissions
├── providers.js             # Frozen Provider Adapter Registry (ChatGPT, Claude, Gemini, Venice.ai)
├── background.js            # Service Worker orchestrator for concurrent multi-tab dispatch
├── utils/
│   └── security.js          # Sender verification, MIME/schema validation, volatile memory scrubber
├── content/
│   └── injector.js          # Multi-strategy image uploader & React/ProseMirror/Quill text injector
├── sidepanel/
│   ├── sidepanel.html       # Side Panel UI markup (strictly CSP-compliant)
│   ├── sidepanel.css        # Self-contained dark UI stylesheet
│   └── sidepanel.js         # Side Panel controller with volatile-only attachment store
└── icons/
    ├── icon16.png
    ├── icon48.png
    └── icon128.png
```

---

## 3. Adding a New AI Platform (`providers.js`)

To add a new AI platform in the future without touching the core injection or orchestration logic:

1. Add the domain pattern to `host_permissions` and `content_scripts.matches` in `manifest.json`.
2. Add an adapter entry to `AI_PROVIDERS` in `providers.js`:

```javascript
perplexity: {
  id: 'perplexity',
  name: 'Perplexity',
  urlMatch: 'https://www.perplexity.ai/*',
  origin: 'https://www.perplexity.ai',
  launchUrl: 'https://www.perplexity.ai/',
  inputSelectors: ['textarea[placeholder*="Ask"]', 'div[contenteditable="true"]'],
  sendButtonSelectors: ['button[aria-label="Submit"]', 'button[type="submit"]'],
  fileInputSelectors: ['input[type="file"]'],
  dropZoneSelectors: ['form', 'main'],
  uploadMethod: 'paste-or-drop',
  uploadSettleDelayMs: 900,
  submitOnEnterFallback: true
}
```

---

## 4. Installation & Usage

1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Enable **Developer mode** (toggle in the top-right corner).
3. Click **Load unpacked** and select the `ai-multi-broadcaster` project folder.
4. Click the **AI Multi-Broadcaster** icon in your Chrome toolbar to open the Side Panel.
5. Click **Open Missing** (or individual **Open** buttons) to launch tabs for ChatGPT, Claude, Gemini, and Venice.ai, then type your prompt, attach one or more images (drag & drop, browse, or `Ctrl+V`), and click **Broadcast Prompt** (`Ctrl+Enter`).

