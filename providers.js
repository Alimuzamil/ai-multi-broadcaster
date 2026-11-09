/**
 * @file providers.js
 * @description Extensible Provider Adapter Registry for AI Multi-Broadcaster.
 *
 * Adding a new AI platform requires only adding a configuration block below
 * (and declaring its explicit domain in manifest.json -> host_permissions).
 *
 * Supported uploadMethod strategies:
 *  - 'paste-or-drop'       : Synthesizes a ClipboardEvent('paste') with File items first,
 *                            falling back to DragEvent('drop') and finally input[type="file"].
 *  - 'file-input-or-paste' : Assigns DataTransfer files to input[type="file"] first,
 *                            falling back to ClipboardEvent('paste') and DragEvent('drop').
 */

'use strict';

(function initProviders(globalScope) {
  /**
   * Deeply freezes an object graph to prevent prototype or runtime tampering.
   * @param {Object} obj
   * @returns {Object}
   */
  function deepFreeze(obj) {
    if (obj === null || typeof obj !== 'object' || Object.isFrozen(obj)) {
      return obj;
    }
    Object.freeze(obj);
    for (const key of Object.keys(obj)) {
      deepFreeze(obj[key]);
    }
    return obj;
  }

  const AI_PROVIDERS = {
    chatgpt: {
      id: 'chatgpt',
      name: 'ChatGPT',
      urlMatch: 'https://chatgpt.com/*',
      origin: 'https://chatgpt.com',
      launchUrl: 'https://chatgpt.com/',
      inputSelectors: [
        '#prompt-textarea',
        'div#prompt-textarea[contenteditable="true"]',
        'div.ProseMirror[contenteditable="true"]',
        'form textarea',
        'div[contenteditable="true"]'
      ],
      sendButtonSelectors: [
        'button[data-testid="send-button"]',
        'button[aria-label="Send prompt"]',
        'button[aria-label="Send message"]',
        'form button[type="submit"]'
      ],
      fileInputSelectors: [
        'input[type="file"][multiple]',
        'input[type="file"]'
      ],
      dropZoneSelectors: [
        '#prompt-textarea',
        'form',
        'main'
      ],
      uploadMethod: 'paste-or-drop',
      uploadSettleDelayMs: 900,
      submitOnEnterFallback: true
    },

    claude: {
      id: 'claude',
      name: 'Claude',
      urlMatch: 'https://claude.ai/*',
      origin: 'https://claude.ai',
      launchUrl: 'https://claude.ai/new',
      inputSelectors: [
        'div.ProseMirror[contenteditable="true"]',
        'fieldset div[contenteditable="true"]',
        'div[contenteditable="true"][aria-label*="Write"]',
        'div[contenteditable="true"][aria-label*="prompt"]',
        'div[contenteditable="true"]'
      ],
      sendButtonSelectors: [
        'button[aria-label="Send Message"]',
        'button[aria-label="Send message"]',
        'button[data-testid="send-button"]',
        'fieldset button[aria-label*="Send"]'
      ],
      fileInputSelectors: [
        'input[data-testid="file-upload"]',
        'input[type="file"][accept*="image"]',
        'input[type="file"]'
      ],
      dropZoneSelectors: [
        'div.ProseMirror[contenteditable="true"]',
        'fieldset',
        'main'
      ],
      uploadMethod: 'paste-or-drop',
      uploadSettleDelayMs: 900,
      submitOnEnterFallback: true
    },

    gemini: {
      id: 'gemini',
      name: 'Gemini',
      urlMatch: 'https://gemini.google.com/*',
      origin: 'https://gemini.google.com',
      launchUrl: 'https://gemini.google.com/app',
      inputSelectors: [
        'rich-textarea div.ql-editor[contenteditable="true"]',
        'div.ql-editor.textarea[contenteditable="true"]',
        'div.ql-editor[contenteditable="true"]',
        'div[contenteditable="true"][role="textbox"]',
        'rich-textarea [contenteditable="true"]',
        'div[contenteditable="true"]'
      ],
      sendButtonSelectors: [
        'button.send-button',
        'button[aria-label="Send message"]',
        'button[aria-label*="Send message"]',
        'button[mattooltip*="Send"]',
        '.send-button-container button'
      ],
      fileInputSelectors: [
        'input[type="file"][accept*="image"]',
        'input[type="file"]'
      ],
      dropZoneSelectors: [
        'rich-textarea div.ql-editor',
        'rich-textarea',
        'input-area-v2',
        'main'
      ],
      uploadMethod: 'paste-or-drop',
      uploadSettleDelayMs: 1100,
      submitOnEnterFallback: true
    },

    venice: {
      id: 'venice',
      name: 'Venice.ai',
      urlMatch: 'https://venice.ai/*',
      origin: 'https://venice.ai',
      launchUrl: 'https://venice.ai/chat',
      inputSelectors: [
        'textarea[placeholder*="Ask"]',
        'textarea[placeholder*="Message"]',
        'textarea[placeholder*="Type"]',
        'textarea[name="prompt"]',
        'form textarea',
        'div.ProseMirror[contenteditable="true"]',
        'div[contenteditable="true"][role="textbox"]',
        'div[contenteditable="true"]',
        'textarea'
      ],
      sendButtonSelectors: [
        'button[aria-label="Send message"]',
        'button[aria-label="Send"]',
        'button[aria-label*="Send"]',
        'button[data-testid="send-button"]',
        'button[ data-testid="chat-submit" ]',
        'form button[type="submit"]',
        'button[type="submit"]'
      ],
      fileInputSelectors: [
        'input[type="file"][accept*="image"]',
        'input[type="file"]'
      ],
      dropZoneSelectors: [
        'form',
        'textarea',
        'main'
      ],
      uploadMethod: 'file-input-or-paste',
      uploadSettleDelayMs: 800,
      submitOnEnterFallback: true
    }
  };

  /**
   * Resolves a provider key and config from a tab URL string.
   * Performs strict origin & HTTPS protocol checks.
   * @param {string} rawUrl
   * @returns {{ key: string, config: Object } | null}
   */
  function matchProviderByUrl(rawUrl) {
    if (typeof rawUrl !== 'string' || !rawUrl) {
      return null;
    }
    let parsed;
    try {
      parsed = new URL(rawUrl);
    } catch {
      return null;
    }
    if (parsed.protocol !== 'https:') {
      return null;
    }
    for (const [key, config] of Object.entries(AI_PROVIDERS)) {
      if (parsed.origin === config.origin) {
        return { key, config };
      }
    }
    return null;
  }

  /**
   * Returns all allowed urlMatch patterns across registered providers.
   * @returns {string[]}
   */
  function getAllUrlMatchPatterns() {
    return Object.values(AI_PROVIDERS).map((provider) => provider.urlMatch);
  }

  deepFreeze(AI_PROVIDERS);

  globalScope.AI_PROVIDERS = AI_PROVIDERS;
  globalScope.ProviderRegistry = Object.freeze({
    AI_PROVIDERS,
    matchProviderByUrl,
    getAllUrlMatchPatterns
  });
})(typeof globalThis !== 'undefined' ? globalThis : self);
