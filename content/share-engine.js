/**
 * @file content/share-engine.js
 * @description Native Public Share Link Automation Engine for AI Multi-Broadcaster.
 *
 * Security & Architecture Guarantees:
 *  - Isolated-world content script loaded after content/injector.js.
 *  - Zero DOM XSS sinks: never uses innerHTML, outerHTML, insertAdjacentHTML, or eval.
 *  - Never initiates chrome.runtime.sendMessage; responds strictly via long-lived sendResponse
 *    to GENERATE_SHARE_LINK requests initiated by the Side Panel.
 *  - Scans for share links strictly inside the provider's share dialog or validated clipboard hook,
 *    and validates every candidate URL via SecurityUtils.validateShareUrl().
 */

'use strict';

(function initShareEngine(globalScope) {
  const { SecurityUtils, ProviderRegistry } = globalScope;
  if (!SecurityUtils || !ProviderRegistry) {
    return;
  }

  let isShareInProgress = false;
  /** @type {string | null} */
  let lastCapturedClipboardUrl = null;

  /**
   * Returns a Promise that resolves after `ms` milliseconds.
   * @param {number} ms
   * @returns {Promise<void>}
   */
  function delay(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  /**
   * Checks whether an element is attached to the DOM and visible.
   * @param {Element | null} el
   * @returns {boolean}
   */
  function isElementVisible(el) {
    if (!el || !el.isConnected) {
      return false;
    }
    const style = window.getComputedStyle(el);
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') {
      return false;
    }
    return el.getClientRects().length > 0;
  }

  /**
   * Checks whether a button or interactive element is visible and enabled.
   * @param {Element | null} el
   * @returns {boolean}
   */
  function isInteractiveReady(el) {
    if (!(el instanceof HTMLElement) || !isElementVisible(el)) {
      return false;
    }
    if ('disabled' in el && Boolean(el.disabled)) {
      return false;
    }
    if (el.getAttribute('aria-disabled') === 'true' || el.hasAttribute('data-disabled')) {
      return false;
    }
    return true;
  }

  /**
   * Dispatches a full pointer/mouse/click sequence required by Radix UI, Material,
   * and React menu/dialog triggers, then invokes native .click().
   *
   * @param {HTMLElement} el
   */
  function realClick(el) {
    if (!el) {
      return;
    }
    const eventInit = {
      bubbles: true,
      cancelable: true,
      composed: true,
      view: window
    };
    try {
      el.dispatchEvent(new PointerEvent('pointerdown', eventInit));
      el.dispatchEvent(new MouseEvent('mousedown', eventInit));
      el.dispatchEvent(new PointerEvent('pointerup', eventInit));
      el.dispatchEvent(new MouseEvent('mouseup', eventInit));
      el.click();
    } catch {
      try {
        el.click();
      } catch {
        // Ignore fallback click error
      }
    }
  }

  /**
   * Checks whether any busy/streaming indicator selector is currently visible on the page.
   * @param {string[]} busySelectors
   * @returns {boolean}
   */
  function isProviderBusy(busySelectors) {
    if (!Array.isArray(busySelectors) || busySelectors.length === 0) {
      return false;
    }
    for (const selector of busySelectors) {
      try {
        const nodes = document.querySelectorAll(selector);
        for (const node of nodes) {
          if (isElementVisible(node)) {
            return true;
          }
        }
      } catch {
        // Ignore unsupported selector syntax
      }
    }
    return false;
  }

  /**
   * Step 1: Waits up to 10s for a busy selector to appear (generation started),
   * then waits until no busy selector is visible continuously for 2500ms
   * using a MutationObserver + 500ms check loop.
   *
   * @param {Object} shareConfig
   * @returns {Promise<boolean>} true if response completed within timeout, false on timeout.
   */
  async function waitForResponseCompletion(shareConfig) {
    const busySelectors = shareConfig.busySelectors || [];
    const timeoutMs =
      typeof shareConfig.responseTimeoutMs === 'number' && shareConfig.responseTimeoutMs > 0
        ? shareConfig.responseTimeoutMs
        : 240000;

    const overallDeadline = Date.now() + timeoutMs;
    const appearDeadline = Math.min(overallDeadline, Date.now() + 10000);

    // Wait up to 10s for generation stop-button to appear
    while (Date.now() < appearDeadline) {
      if (isProviderBusy(busySelectors)) {
        break;
      }
      await delay(250);
    }

    // Require 2500ms of continuous non-busy state
    const REQUIRED_QUIET_MS = 2500;
    let lastBusyTimestamp = isProviderBusy(busySelectors) ? Date.now() : Date.now() - 500;

    return new Promise((resolve) => {
      let settled = false;
      let intervalId = null;

      const observer = new MutationObserver(() => {
        if (isProviderBusy(busySelectors)) {
          lastBusyTimestamp = Date.now();
        }
      });

      const cleanup = (result) => {
        if (settled) {
          return;
        }
        settled = true;
        observer.disconnect();
        if (intervalId !== null) {
          clearInterval(intervalId);
        }
        resolve(result);
      };

      try {
        if (document.body) {
          observer.observe(document.body, {
            childList: true,
            subtree: true,
            attributes: true
          });
        }
      } catch {
        // Ignore observer attachment errors
      }

      intervalId = setInterval(() => {
        const now = Date.now();
        if (isProviderBusy(busySelectors)) {
          lastBusyTimestamp = now;
        } else if (now - lastBusyTimestamp >= REQUIRED_QUIET_MS) {
          cleanup(true);
          return;
        }

        if (now >= overallDeadline) {
          cleanup(false);
        }
      }, 500);
    });
  }

  /**
   * Waits for DOM mutations inside document.body or until `maxWaitMs` elapses,
   * resolving early if `earlyCheckFn()` returns a truthy value.
   *
   * @param {number} maxWaitMs
   * @param {() => string | null} [earlyCheckFn]
   * @returns {Promise<void>}
   */
  function waitForDomStep(maxWaitMs, earlyCheckFn) {
    return new Promise((resolve) => {
      let finished = false;
      let pollId = null;
      let timerId = null;
      let mutationDebounceId = null;

      const done = () => {
        if (finished) {
          return;
        }
        finished = true;
        observer.disconnect();
        if (pollId !== null) {
          clearInterval(pollId);
        }
        if (timerId !== null) {
          clearTimeout(timerId);
        }
        if (mutationDebounceId !== null) {
          clearTimeout(mutationDebounceId);
        }
        resolve();
      };

      const observer = new MutationObserver(() => {
        if (typeof earlyCheckFn === 'function' && earlyCheckFn()) {
          done();
          return;
        }
        if (mutationDebounceId !== null) {
          clearTimeout(mutationDebounceId);
        }
        mutationDebounceId = setTimeout(done, 450);
      });

      try {
        if (document.body) {
          observer.observe(document.body, {
            childList: true,
            subtree: true,
            attributes: true,
            characterData: true
          });
        }
      } catch {
        // Ignore
      }

      if (typeof earlyCheckFn === 'function') {
        pollId = setInterval(() => {
          if (earlyCheckFn()) {
            done();
          }
        }, 200);
      }

      timerId = setTimeout(done, maxWaitMs);
    });
  }

  /**
   * Returns all currently visible dialog/menu containers matching `shareConfig.dialogSelector`.
   * @param {Object} shareConfig
   * @returns {HTMLElement[]}
   */
  function getVisibleDialogs(shareConfig) {
    const selector =
      typeof shareConfig.dialogSelector === 'string' && shareConfig.dialogSelector
        ? shareConfig.dialogSelector
        : '[role="dialog"]';
    const dialogs = [];
    try {
      const nodes = document.querySelectorAll(selector);
      for (const node of nodes) {
        if (node instanceof HTMLElement && isElementVisible(node)) {
          dialogs.push(node);
        }
      }
    } catch {
      // Ignore selector error
    }
    return dialogs;
  }

  /**
   * Scans for a valid public share URL in strict priority order:
   *  1. Last clipboard capture from MAIN-world clipboard-hook.js.
   *  2. Inside the active share dialog ONLY: input.value, textarea.value, a[href].
   *  3. Inside the active share dialog ONLY: URL tokens within dialog.innerText / textContent.
   *
   * Never scans outside the dialog so sidebar/history links are never matched.
   *
   * @param {string} providerKey
   * @param {Object} shareConfig
   * @returns {string | null}
   */
  function scanForLink(providerKey, shareConfig) {
    if (lastCapturedClipboardUrl) {
      const validatedClip = SecurityUtils.validateShareUrl(providerKey, lastCapturedClipboardUrl);
      if (validatedClip) {
        return validatedClip;
      }
    }

    const dialogs = getVisibleDialogs(shareConfig);
    if (dialogs.length === 0) {
      return null;
    }

    const urlTokenRegex = /https:\/\/[^\s"'<>]+/;

    for (const dialog of dialogs) {
      // Check input.value and textarea.value inside dialog
      const inputs = dialog.querySelectorAll('input, textarea');
      for (const input of inputs) {
        const rawVal =
          input instanceof HTMLInputElement || input instanceof HTMLTextAreaElement
            ? input.value
            : '';
        if (typeof rawVal === 'string' && rawVal.trim()) {
          const directValid = SecurityUtils.validateShareUrl(providerKey, rawVal);
          if (directValid) {
            return directValid;
          }
          const tokenMatch = urlTokenRegex.exec(rawVal);
          if (tokenMatch) {
            const tokenValid = SecurityUtils.validateShareUrl(providerKey, tokenMatch[0]);
            if (tokenValid) {
              return tokenValid;
            }
          }
        }
      }

      // Check a[href] inside dialog
      const anchors = dialog.querySelectorAll('a[href]');
      for (const anchor of anchors) {
        if (anchor instanceof HTMLAnchorElement && anchor.href) {
          const validHref = SecurityUtils.validateShareUrl(providerKey, anchor.href);
          if (validHref) {
            return validHref;
          }
        }
      }

      // Check dialog innerText / textContent
      const rawText = dialog.innerText || dialog.textContent || '';
      if (rawText.includes('https://')) {
        const words = rawText.split(/\s+/);
        for (const word of words) {
          if (word.startsWith('https://')) {
            const cleanedWord = word.replace(/[.,;!?)"'\]]+$/, '');
            const validTextUrl = SecurityUtils.validateShareUrl(providerKey, cleanedWord);
            if (validTextUrl) {
              return validTextUrl;
            }
          }
        }
      }
    }

    return null;
  }

  /**
   * Checks whether an element's visible text or accessible label matches any RegExp in `patterns`.
   * @param {HTMLElement} el
   * @param {RegExp[]} patterns
   * @returns {boolean}
   */
  function matchesAnyTextPattern(el, patterns) {
    if (!Array.isArray(patterns) || patterns.length === 0) {
      return false;
    }
    const candidates = [
      (el.textContent || '').trim(),
      (el.getAttribute('aria-label') || '').trim(),
      (el.getAttribute('title') || '').trim(),
      (el.getAttribute('mattooltip') || '').trim()
    ].filter(Boolean);

    for (const pattern of patterns) {
      if (!(pattern instanceof RegExp)) {
        continue;
      }
      for (const text of candidates) {
        if (pattern.test(text)) {
          return true;
        }
      }
    }
    return false;
  }

  /**
   * Finds the Share trigger button on the page using CSS selectors first,
   * then text/aria-label matchers on button, [role="button"], [role="menuitem"].
   *
   * @param {Object} shareConfig
   * @returns {HTMLElement | null}
   */
  function findShareTriggerElement(shareConfig) {
    const cssSelectors = shareConfig.shareTriggerSelectors || [];
    for (const selector of cssSelectors) {
      try {
        const nodes = document.querySelectorAll(selector);
        for (const node of nodes) {
          if (node instanceof HTMLElement && isInteractiveReady(node)) {
            return node;
          }
        }
      } catch {
        // Ignore invalid selector
      }
    }

    const textPatterns = shareConfig.shareTriggerText || [];
    if (textPatterns.length > 0) {
      const candidates = document.querySelectorAll('button, [role="button"], [role="menuitem"]');
      for (const node of candidates) {
        if (
          node instanceof HTMLElement &&
          isInteractiveReady(node) &&
          matchesAnyTextPattern(node, textPatterns)
        ) {
          return node;
        }
      }
    }

    return null;
  }

  /**
   * Finds an interactive confirm/copy button inside the currently open share dialog(s)
   * matching `stepPattern`.
   *
   * @param {Object} shareConfig
   * @param {RegExp} stepPattern
   * @returns {HTMLElement | null}
   */
  function findDialogStepButton(shareConfig, stepPattern) {
    if (!(stepPattern instanceof RegExp)) {
      return null;
    }
    const dialogs = getVisibleDialogs(shareConfig);
    for (const dialog of dialogs) {
      const candidates = dialog.querySelectorAll(
        'button, [role="button"], [role="menuitem"], [role="radio"], label'
      );
      for (const node of candidates) {
        if (
          node instanceof HTMLElement &&
          isInteractiveReady(node) &&
          matchesAnyTextPattern(node, [stepPattern])
        ) {
          return node;
        }
      }
    }
    return null;
  }

  /**
   * Closes any open share dialog by dispatching Escape keydown events.
   * Always called in `finally`.
   *
   * @param {Object} shareConfig
   */
  function closeShareDialog(shareConfig) {
    const escapeInit = {
      key: 'Escape',
      code: 'Escape',
      keyCode: 27,
      which: 27,
      bubbles: true,
      cancelable: true,
      composed: true
    };
    const dialogs = getVisibleDialogs(shareConfig);
    for (const dialog of dialogs) {
      try {
        dialog.dispatchEvent(new KeyboardEvent('keydown', escapeInit));
        dialog.dispatchEvent(new KeyboardEvent('keyup', escapeInit));
      } catch {
        // Ignore
      }
      const closeBtns = dialog.querySelectorAll(
        'button[data-testid="close-button"], button[aria-label="Close"], button[aria-label*="Close" i]'
      );
      for (const btn of closeBtns) {
        if (btn instanceof HTMLElement && isElementVisible(btn)) {
          try {
            btn.click();
          } catch {
            // Ignore
          }
          break;
        }
      }
    }
    try {
      document.dispatchEvent(new KeyboardEvent('keydown', escapeInit));
    } catch {
      // Ignore
    }
    if (document.activeElement instanceof HTMLElement) {
      try {
        document.activeElement.dispatchEvent(new KeyboardEvent('keydown', escapeInit));
      } catch {
        // Ignore
      }
    }
    if (document.body) {
      try {
        document.body.dispatchEvent(new KeyboardEvent('keydown', escapeInit));
      } catch {
        // Ignore
      }
    }
  }

  /**
   * Executes the end-to-end native Share UI automation flow for the current provider tab.
   *
   * @param {string} providerKey
   * @param {Object} providerConfig
   * @returns {Promise<Object>}
   */
  async function executeShareFlow(providerKey, providerConfig) {
    const shareConfig = providerConfig.share;
    if (!shareConfig || !shareConfig.supported) {
      return {
        ok: false,
        provider: providerKey,
        code: 'UNSUPPORTED',
        message: `Auto-share is not enabled for ${providerConfig.name}.`
      };
    }

    if (isShareInProgress) {
      return {
        ok: false,
        provider: providerKey,
        code: 'BUSY',
        message: `Share link generation is already running on ${providerConfig.name}.`
      };
    }

    isShareInProgress = true;
    lastCapturedClipboardUrl = null;
    let dialogOpened = false;

    // Also listen for document 'copy' events during the share flow
    const onDocumentCopy = (event) => {
      try {
        const text = event.clipboardData && event.clipboardData.getData('text/plain');
        if (typeof text === 'string' && text.startsWith('https://')) {
          const valid = SecurityUtils.validateShareUrl(providerKey, text);
          if (valid) {
            lastCapturedClipboardUrl = valid;
          }
        }
      } catch {
        // Ignore
      }
    };
    document.addEventListener('copy', onDocumentCopy, true);

    try {
      // 1. Wait for AI response generation to complete
      const finishedInTime = await waitForResponseCompletion(shareConfig);
      if (!finishedInTime) {
        return {
          ok: false,
          provider: providerKey,
          code: 'RESPONSE_TIMEOUT',
          message: `Timed out waiting for ${providerConfig.name} response to finish.`
        };
      }

      // If a stale share dialog from a previous run is still open, close it first
      if (getVisibleDialogs(shareConfig).length > 0) {
        closeShareDialog(shareConfig);
        await delay(350);
      }

      // 2. Locate and click the Share trigger (poll up to 4s as UI header buttons settle after stream)
      let shareTrigger = null;
      const triggerDeadline = Date.now() + 4000;
      while (Date.now() < triggerDeadline) {
        shareTrigger = findShareTriggerElement(shareConfig);
        if (shareTrigger) {
          break;
        }
        await delay(250);
      }

      if (!shareTrigger) {
        return {
          ok: false,
          provider: providerKey,
          code: 'SHARE_BUTTON_NOT_FOUND',
          message: `Share button not found on ${providerConfig.name}.`
        };
      }

      realClick(shareTrigger);
      dialogOpened = true;
      await delay(650);
      await waitForDomStep(1800, () => scanForLink(providerKey, shareConfig));

      // 3. Execute confirm steps inside the dialog
      const confirmSteps = Array.isArray(shareConfig.confirmSteps)
        ? shareConfig.confirmSteps
        : [];
      const clickedButtons = new Map();

      for (const stepPattern of confirmSteps) {
        const existingLink = scanForLink(providerKey, shareConfig);
        if (existingLink) {
          return {
            ok: true,
            provider: providerKey,
            shareUrl: existingLink,
            conversationUrl: window.location.href
          };
        }

        const stepBtn = findDialogStepButton(shareConfig, stepPattern);
        if (stepBtn) {
          clickedButtons.set(stepBtn, Date.now());
          realClick(stepBtn);
          await delay(500);
          await waitForDomStep(6000, () => scanForLink(providerKey, shareConfig));
        }
      }

      // 4. Final scan up to 10s (also clicking any confirm/copy button that finished loading asynchronously)
      const finalDeadline = Date.now() + 10000;
      while (Date.now() < finalDeadline) {
        const foundLink = scanForLink(providerKey, shareConfig);
        if (foundLink) {
          return {
            ok: true,
            provider: providerKey,
            shareUrl: foundLink,
            conversationUrl: window.location.href
          };
        }

        for (const stepPattern of confirmSteps) {
          const lateBtn = findDialogStepButton(shareConfig, stepPattern);
          if (lateBtn) {
            const lastClickedAt = clickedButtons.get(lateBtn) || 0;
            if (Date.now() - lastClickedAt > 1800) {
              clickedButtons.set(lateBtn, Date.now());
              realClick(lateBtn);
              await delay(400);
              break;
            }
          }
        }

        await delay(250);
      }

      return {
        ok: false,
        provider: providerKey,
        code: 'LINK_NOT_FOUND',
        message: `Could not extract public share link from ${providerConfig.name} dialog.`
      };
    } catch (err) {
      return {
        ok: false,
        provider: providerKey,
        code: 'LINK_NOT_FOUND',
        message:
          err instanceof Error
            ? err.message
            : `Unexpected error while generating share link on ${providerConfig.name}.`
      };
    } finally {
      document.removeEventListener('copy', onDocumentCopy, true);
      if (dialogOpened) {
        closeShareDialog(shareConfig);
      }
      isShareInProgress = false;
      lastCapturedClipboardUrl = null;
    }
  }

  // Replace any previous window message listener on re-injection
  if (typeof globalScope.__AI_MULTI_BROADCASTER_CLIPBOARD_LISTENER__ === 'function') {
    try {
      window.removeEventListener(
        'message',
        globalScope.__AI_MULTI_BROADCASTER_CLIPBOARD_LISTENER__
      );
    } catch {
      // Ignore
    }
  }

  const clipboardWindowListener = (event) => {
    if (event.source !== window || event.origin !== window.location.origin) {
      return;
    }
    const data = event.data;
    if (
      !data ||
      typeof data !== 'object' ||
      data.type !== '__AMB_SHARE_CLIPBOARD__' ||
      typeof data.text !== 'string'
    ) {
      return;
    }
    const matched = ProviderRegistry.matchProviderByUrl(window.location.href);
    if (!matched) {
      return;
    }
    const validatedUrl = SecurityUtils.validateShareUrl(matched.key, data.text);
    if (validatedUrl) {
      lastCapturedClipboardUrl = validatedUrl;
    }
  };

  globalScope.__AI_MULTI_BROADCASTER_CLIPBOARD_LISTENER__ = clipboardWindowListener;
  window.addEventListener('message', clipboardWindowListener);

  // Replace any previous runtime.onMessage listener on re-injection
  if (
    typeof globalScope.__AI_MULTI_BROADCASTER_SHARE_LISTENER__ === 'function' &&
    chrome.runtime &&
    chrome.runtime.onMessage
  ) {
    try {
      chrome.runtime.onMessage.removeListener(
        globalScope.__AI_MULTI_BROADCASTER_SHARE_LISTENER__
      );
    } catch {
      // Ignore
    }
  }

  const shareMessageListener = (message, sender, sendResponse) => {
    // Handle ONLY GENERATE_SHARE_LINK; return false silently for all other actions
    // so content/injector.js handles PING_PROVIDER and DISPATCH_PROMPT undisturbed.
    if (!message || typeof message !== 'object' || message.action !== 'GENERATE_SHARE_LINK') {
      return false;
    }

    const matched = ProviderRegistry.matchProviderByUrl(window.location.href);
    const providerKey = matched ? matched.key : 'unknown';

    const envelopeCheck = SecurityUtils.validateMessageEnvelope(message, sender);
    if (!envelopeCheck.valid) {
      sendResponse({
        ok: false,
        provider: providerKey,
        code: 'INVALID_ENVELOPE',
        message: envelopeCheck.reason || 'Invalid message envelope.'
      });
      return false;
    }

    if (!matched || !matched.config.share || !matched.config.share.supported) {
      sendResponse({
        ok: false,
        provider: providerKey,
        code: 'UNSUPPORTED',
        message: 'Share link generation is not supported on this tab.'
      });
      return false;
    }

    executeShareFlow(matched.key, matched.config)
      .then((result) => sendResponse(result))
      .catch((err) => {
        sendResponse({
          ok: false,
          provider: matched.key,
          code: 'LINK_NOT_FOUND',
          message: err instanceof Error ? err.message : 'Share engine error.'
        });
      });

    return true; // Keep message channel open for long-lived async response
  };

  globalScope.__AI_MULTI_BROADCASTER_SHARE_LISTENER__ = shareMessageListener;
  chrome.runtime.onMessage.addListener(shareMessageListener);
})(typeof globalThis !== 'undefined' ? globalThis : self);

