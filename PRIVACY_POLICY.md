# Privacy Policy for AI Multi-Broadcaster

**Effective Date:** November 6, 2026  
**Extension Name:** AI Multi-Broadcaster  

## 1. Overview & Zero-Data Collection Guarantee
**AI Multi-Broadcaster** is built on a strict zero-trust, volatile-memory architecture. We **do not collect, store, log, transmit, or share** any personal data, browsing history, prompts, images, or usage analytics.

## 2. How Your Data Is Handled
* **Volatile Memory Only:** All text prompts and image attachments you enter into the AI Multi-Broadcaster Side Panel exist strictly in temporary browser memory (RAM) for the sole purpose of transferring them to the AI chat tabs you explicitly select in your own browser.
* **No Persistent Storage:** The extension does not use `chrome.storage`, `localStorage`, `sessionStorage`, `IndexedDB`, or cookies. As soon as a broadcast completes—or when you close the Side Panel—all prompt text, Object URLs, and image buffers are immediately wiped from memory.
* **Zero External Network Requests:** The extension enforces a strict Content Security Policy (`connect-src 'none'`). It cannot and does not make any network requests to external servers, third-party APIs, or telemetry endpoints.

## 3. Permissions Disclosure
AI Multi-Broadcaster requests only the minimum permissions necessary to function:
* **`sidePanel`:** Used solely to display the AI Multi-Broadcaster user interface in Chrome's Side Panel.
* **`scripting`:** Used solely to attach the local prompt-injection script to pre-existing open tabs matching the four supported AI platforms when triggered by the user.
* **`host_permissions` (`https://chatgpt.com/*`, `https://claude.ai/*`, `https://gemini.google.com/*`, `https://venice.ai/*`):** Used solely to detect whether you have open tabs for these four AI platforms and to insert your prompt and attached images directly into their chat input boxes when you click **Broadcast Prompt**.

## 4. Third-Party AI Platforms & Optional Public Share Links
When you broadcast a prompt to ChatGPT (`chatgpt.com`), Claude (`claude.ai`), Gemini (`gemini.google.com`), or Venice (`venice.ai`), your interaction inside those tabs is governed by the respective privacy policies and terms of service of those platforms, using your own existing session in your browser. AI Multi-Broadcaster never reads or intercepts your account credentials, session tokens, or AI responses.

* **Optional Auto Share Engine (Off by Default):** Optional, off by default: creates public share links using each AI site's own Share feature when explicitly enabled and confirmed by the user in the Side Panel. Anyone with a generated public share link can read that shared conversation according to the respective AI platform's sharing settings. Generated links are held strictly in volatile Side Panel memory until cleared or closed.

## 5. Compliance with Google Chrome Web Store Limited Use Policy
The use of information received from Google APIs will adhere to the Chrome Web Store User Data Policy, including the Limited Use requirements.

## 6. Changes to This Privacy Policy
If we update this Privacy Policy, the revised version will be posted at this URL with an updated effective date.

## 7. Contact
If you have any questions regarding this Privacy Policy or the extension's security practices, please contact the developer via the support section on the Chrome Web Store listing.

