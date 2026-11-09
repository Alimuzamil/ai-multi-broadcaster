/**
 * @file content/injector.js
 * @description Zero-XSS Content Script Injection Engine for AI Multi-Broadcaster.
 *
 * Security Guarantees:
 *  - Never uses innerHTML, outerHTML, insertAdjacentHTML, or eval.
 *  - Validates message sender ID and schema via SecurityUtils before acting.
 *  - Reconstructs File blobs strictly in volatile memory and scrubs buffers immediately.
 */

'use strict';

(function initContentInjector(globalScope) {
  const { SecurityUtils, ProviderRegistry } = globalScope;
  if (!SecurityUtils || !ProviderRegistry) {
    return;
  }

  /**
   * Returns a Promise that resolves after `ms` milliseconds.
   * @param {number} ms
   * @returns {Promise<void>}
   */
  function delay(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  /**
   * Checks whether an element is attached and visible in the layout.
   * @param {Element | null} el
   * @returns {boolean}
   */
  function isElementVisible(el) {
    if (!el || !el.isConnected) {
      return false;
    }
    const style = window.getComputedStyle(el);
    if (style.display === 'none' || style.visibility === 'hidden') {
      return false;
    }
    return el.getClientRects().length > 0;
  }

  /**
   * Queries an ordered list of CSS selectors and returns the first visible match.
   * @param {string[]} selectors
   * @returns {HTMLElement | null}
   */
  function findFirstVisibleElement(selectors) {
    if (!Array.isArray(selectors)) {
      return null;
    }
    for (const selector of selectors) {
      try {
        const nodes = document.querySelectorAll(selector);
        for (const node of nodes) {
          if (node instanceof HTMLElement && isElementVisible(node)) {
            return node;
          }
        }
      } catch {
        // Ignore invalid or unsupported selector syntax on older engines
      }
    }
    return null;
  }

  /**
   * Waits for a visible element matching any of `selectors` within `timeoutMs`.
   * @param {string[]} selectors
   * @param {number} timeoutMs
   * @returns {Promise<HTMLElement | null>}
   */
  async function waitForVisibleElement(selectors, timeoutMs = 4000) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const found = findFirstVisibleElement(selectors);
      if (found) {
        return found;
      }
      await delay(120);
    }
    return findFirstVisibleElement(selectors);
  }

  /**
   * Finds the first connected <input type="file"> matching provider selectors.
   * Note: File inputs are commonly hidden via CSS, so visibility is not required.
   * @param {string[]} selectors
   * @returns {HTMLInputElement | null}
   */
  function findFileInputElement(selectors) {
    if (!Array.isArray(selectors)) {
      return null;
    }
    for (const selector of selectors) {
      try {
        const nodes = document.querySelectorAll(selector);
        for (const node of nodes) {
          if (
            node instanceof HTMLInputElement &&
            node.type === 'file' &&
            node.isConnected &&
            !node.disabled
          ) {
            return node;
          }
        }
      } catch {
        // Ignore selector error
      }
    }
    return null;
  }

  /**
   * Checks whether a candidate Send button is enabled and ready to be clicked.
   * @param {HTMLElement | null} btn
   * @returns {boolean}
   */
  function isSendButtonReady(btn) {
    if (!btn || !isElementVisible(btn)) {
      return false;
    }
    if ('disabled' in btn && Boolean(btn.disabled)) {
      return false;
    }
    const ariaDisabled = btn.getAttribute('aria-disabled');
    if (ariaDisabled === 'true') {
      return false;
    }
    if (btn.hasAttribute('data-disabled')) {
      return false;
    }
    return true;
  }

  /**
   * Ensures a contenteditable element has an active collapsed DOM Selection Range
   * inside it so ProseMirror (`claude.ai`) and Quill (`gemini.google.com`) recognize
   * the editor as focused across multi-file pastes.
   *
   * @param {HTMLElement} el
   */
  function focusWithSelectionRange(el) {
    if (!el) {
      return;
    }
    el.focus();
    if (el.isContentEditable || el.getAttribute('contenteditable') === 'true') {
      try {
        const selection = window.getSelection();
        if (selection) {
          const range = document.createRange();
          range.selectNodeContents(el);
          range.collapse(false);
          selection.removeAllRanges();
          selection.addRange(range);
        }
      } catch {
        // Ignore selection error
      }
    }
  }

  /**
   * Strategy A: Dispatches synthetic ClipboardEvent('paste') events per File
   * onto the focused composer element.
   *
   * - For ChatGPT & Venice: preserves the exact original 140ms loop.
   * - For Gemini: re-queries and re-focuses `.ql-editor` before each file with a
   *   600ms interval because Gemini blurs/updates the editor when mounting each image chip.
   * - For Claude: sets ProseMirror selection range before each paste with a 400ms interval.
   *
   * @param {HTMLElement} targetEl
   * @param {File[]} files
   * @param {Object} [providerConfig]
   * @returns {Promise<boolean>}
   */
  async function tryPasteFiles(targetEl, files, providerConfig) {
    if (!targetEl || !files.length) {
      return false;
    }
    try {
      const providerId = providerConfig ? providerConfig.id : '';

      if (providerId === 'gemini' || providerId === 'claude') {
        const perFileDelayMs = providerId === 'gemini' ? 600 : 400;
        for (let i = 0; i < files.length; i += 1) {
          const currentTarget =
            (providerConfig &&
              findFirstVisibleElement(providerConfig.inputSelectors)) ||
            targetEl;
          focusWithSelectionRange(currentTarget);

          const dt = new DataTransfer();
          dt.items.add(files[i]);

          const pasteEvent = new ClipboardEvent('paste', {
            bubbles: true,
            cancelable: true,
            composed: true,
            clipboardData: dt
          });
          currentTarget.dispatchEvent(pasteEvent);

          if (i < files.length - 1) {
            await delay(perFileDelayMs);
          }
        }
        return true;
      }

      // Untouched original flow for ChatGPT and Venice
      targetEl.focus();
      for (let i = 0; i < files.length; i += 1) {
        const dt = new DataTransfer();
        dt.items.add(files[i]);

        const pasteEvent = new ClipboardEvent('paste', {
          bubbles: true,
          cancelable: true,
          composed: true,
          clipboardData: dt
        });
        targetEl.dispatchEvent(pasteEvent);

        if (i < files.length - 1) {
          await delay(140);
        }
      }
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Strategy B: Dispatches synthetic DragEvent sequence (dragenter, dragover, drop)
   * with a populated DataTransfer object onto the drop zone or input element.
   *
   * @param {HTMLElement} dropTarget
   * @param {File[]} files
   * @returns {Promise<boolean>}
   */
  async function tryDropFiles(dropTarget, files) {
    if (!dropTarget || !files.length) {
      return false;
    }
    try {
      const dt = new DataTransfer();
      for (const file of files) {
        dt.items.add(file);
      }

      const eventInit = {
        bubbles: true,
        cancelable: true,
        composed: true,
        dataTransfer: dt
      };

      dropTarget.dispatchEvent(new DragEvent('dragenter', eventInit));
      dropTarget.dispatchEvent(new DragEvent('dragover', eventInit));
      dropTarget.dispatchEvent(new DragEvent('drop', eventInit));
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Strategy C: Assigns File objects directly to an <input type="file"> element
   * and triggers 'input' and 'change' events.
   *
   * @param {Object} providerConfig
   * @param {File[]} files
   * @returns {Promise<boolean>}
   */
  async function tryFileInputUpload(providerConfig, files) {
    const fileInput = findFileInputElement(providerConfig.fileInputSelectors);
    if (!fileInput || !files.length) {
      return false;
    }

    try {
      if (fileInput.multiple || files.length === 1) {
        const dt = new DataTransfer();
        for (const file of files) {
          dt.items.add(file);
        }
        fileInput.files = dt.files;
        fileInput.dispatchEvent(new Event('input', { bubbles: true, composed: true }));
        fileInput.dispatchEvent(new Event('change', { bubbles: true, composed: true }));
      } else {
        for (let i = 0; i < files.length; i += 1) {
          const dt = new DataTransfer();
          dt.items.add(files[i]);
          fileInput.files = dt.files;
          fileInput.dispatchEvent(new Event('input', { bubbles: true, composed: true }));
          fileInput.dispatchEvent(new Event('change', { bubbles: true, composed: true }));
          if (i < files.length - 1) {
            await delay(150);
          }
        }
      }
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Dedicated multi-image uploader for Claude (`claude.ai`).
   * Checks whether the composer DOM (`fieldset`) grows in descendant element count after:
   *  1. `<input type="file">` (`input[data-testid="file-upload"]` / `input[type="file"]`)
   *  2. `ClipboardEvent('paste')` with ProseMirror selection range activation
   *  3. `DragEvent('drop')` on `fieldset`
   * Stops at the first method that adds attachment preview nodes to the composer.
   *
   * @param {Object} providerConfig
   * @param {HTMLElement} inputEl
   * @param {File[]} files
   * @returns {Promise<{ uploaded: boolean, methodUsed: string }>}
   */
  async function injectImagesForClaude(providerConfig, inputEl, files) {
    const composerArea =
      inputEl.closest('fieldset') ||
      inputEl.parentElement?.parentElement?.parentElement ||
      document.body;

    const getComposerNodeCount = () => composerArea.querySelectorAll('*').length;
    const baselineNodes = getComposerNodeCount();

    // 1. Try Claude's hidden <input type="file"> (input[data-testid="file-upload"])
    if (await tryFileInputUpload(providerConfig, files)) {
      await delay(550);
      if (getComposerNodeCount() > baselineNodes) {
        return { uploaded: true, methodUsed: 'file-input' };
      }
    }

    // 2. Fallback: Paste with active ProseMirror Selection Range
    if (await tryPasteFiles(inputEl, files, providerConfig)) {
      await delay(550);
      if (getComposerNodeCount() > baselineNodes) {
        return { uploaded: true, methodUsed: 'paste' };
      }
    }

    // 3. Fallback: Drop onto fieldset
    const dropTarget =
      findFirstVisibleElement(providerConfig.dropZoneSelectors || []) ||
      composerArea ||
      inputEl;
    await tryDropFiles(dropTarget, files);
    await delay(400);

    return { uploaded: true, methodUsed: 'claude-multi-fallback' };
  }

  /**
   * Orchestrates multi-image injection according to the provider's configured `uploadMethod`.
   * Reconstructs File instances in volatile memory and zeroes out source payloads immediately.
   *
   * @param {Object} providerConfig
   * @param {HTMLElement} inputEl
   * @param {Array<{name: string, type: string, size: number, dataUrl: string}>} rawImages
   * @returns {Promise<{ uploaded: boolean, methodUsed: string | null }>}
   */
  async function injectImagesIntoProvider(providerConfig, inputEl, rawImages) {
    if (!Array.isArray(rawImages) || rawImages.length === 0) {
      return { uploaded: true, methodUsed: 'none' };
    }

    /** @type {File[]} */
    let volatileFiles = [];
    try {
      for (let i = 0; i < rawImages.length; i += 1) {
        const file = SecurityUtils.dataUrlToVolatileFile(rawImages[i]);
        volatileFiles.push(file);
        // Immediately scrub the serialized Base64 string after converting to File
        rawImages[i].dataUrl = '';
      }

      // Isolated handler exclusively for Claude
      if (providerConfig.id === 'claude') {
        return await injectImagesForClaude(providerConfig, inputEl, volatileFiles);
      }

      const dropTarget =
        findFirstVisibleElement(providerConfig.dropZoneSelectors || []) || inputEl;

      if (providerConfig.uploadMethod === 'file-input-or-paste') {
        if (await tryFileInputUpload(providerConfig, volatileFiles)) {
          return { uploaded: true, methodUsed: 'file-input' };
        }
        if (await tryPasteFiles(inputEl, volatileFiles, providerConfig)) {
          return { uploaded: true, methodUsed: 'paste' };
        }
        if (await tryDropFiles(dropTarget, volatileFiles)) {
          return { uploaded: true, methodUsed: 'drop' };
        }
      } else {
        // Default: 'paste-or-drop' (ChatGPT & Gemini)
        if (await tryPasteFiles(inputEl, volatileFiles, providerConfig)) {
          return { uploaded: true, methodUsed: 'paste' };
        }
        if (await tryDropFiles(dropTarget, volatileFiles)) {
          return { uploaded: true, methodUsed: 'drop' };
        }
        if (await tryFileInputUpload(providerConfig, volatileFiles)) {
          return { uploaded: true, methodUsed: 'file-input' };
        }
      }

      return { uploaded: false, methodUsed: null };
    } finally {
      // Release File object array references immediately
      volatileFiles.fill(null);
      volatileFiles.length = 0;
    }
  }

  /**
   * Injects prompt text into either a standard <textarea>/<input> or a rich-text
   * contenteditable element (ProseMirror, Quill, Lexical) without ever touching
   * innerHTML or outerHTML.
   *
   * @param {HTMLElement} inputEl
   * @param {string} promptText
   * @returns {Promise<boolean>}
   */
  async function injectPromptText(inputEl, promptText) {
    if (!promptText) {
      return true;
    }

    inputEl.focus();

    // Case 1: Native <textarea> or <input> (e.g., Venice.ai or fallback)
    if (
      inputEl instanceof HTMLTextAreaElement ||
      inputEl instanceof HTMLInputElement
    ) {
      const proto =
        inputEl instanceof HTMLTextAreaElement
          ? window.HTMLTextAreaElement.prototype
          : window.HTMLInputElement.prototype;
      const nativeValueSetter = Object.getOwnPropertyDescriptor(proto, 'value')?.set;

      if (nativeValueSetter) {
        nativeValueSetter.call(inputEl, promptText);
      } else {
        inputEl.value = promptText;
      }

      inputEl.dispatchEvent(
        new InputEvent('input', {
          bubbles: true,
          cancelable: true,
          composed: true,
          data: promptText,
          inputType: 'insertText'
        })
      );
      inputEl.dispatchEvent(new Event('change', { bubbles: true, composed: true }));
      return true;
    }

    // Case 2: Rich-text contenteditable (ProseMirror on ChatGPT/Claude, Quill on Gemini)
    if (inputEl.isContentEditable || inputEl.getAttribute('contenteditable') === 'true') {
      inputEl.focus();

      // Select existing contents so replacement is clean
      const selection = window.getSelection();
      if (selection) {
        const range = document.createRange();
        range.selectNodeContents(inputEl);
        selection.removeAllRanges();
        selection.addRange(range);
      }

      // Attempt 1: Native editor command pipeline (best support for ProseMirror & Quill state)
      let insertedViaCommand = false;
      try {
        insertedViaCommand = document.execCommand('insertText', false, promptText);
      } catch {
        insertedViaCommand = false;
      }

      const currentText = (inputEl.textContent || '').trim();
      const targetSample = promptText.trim().slice(0, 32);

      if (insertedViaCommand && currentText.includes(targetSample)) {
        inputEl.dispatchEvent(
          new InputEvent('input', {
            bubbles: true,
            cancelable: true,
            composed: true,
            inputType: 'insertText',
            data: promptText
          })
        );
        return true;
      }

      // Attempt 2: Safe DOM node construction using createElement + textContent (Zero innerHTML)
      inputEl.dispatchEvent(
        new InputEvent('beforeinput', {
          bubbles: true,
          cancelable: true,
          composed: true,
          inputType: 'insertText',
          data: promptText
        })
      );

      while (inputEl.firstChild) {
        inputEl.removeChild(inputEl.firstChild);
      }

      const lines = promptText.split(/\r?\n/);
      for (const line of lines) {
        const paragraph = document.createElement('p');
        if (line.length > 0) {
          paragraph.textContent = line;
        } else {
          paragraph.appendChild(document.createElement('br'));
        }
        inputEl.appendChild(paragraph);
      }

      inputEl.dispatchEvent(
        new InputEvent('input', {
          bubbles: true,
          cancelable: true,
          composed: true,
          inputType: 'insertText',
          data: promptText
        })
      );
      inputEl.dispatchEvent(new Event('change', { bubbles: true, composed: true }));
      return true;
    }

    // Fallback for generic elements
    inputEl.textContent = promptText;
    inputEl.dispatchEvent(
      new InputEvent('input', {
        bubbles: true,
        cancelable: true,
        composed: true,
        inputType: 'insertText',
        data: promptText
      })
    );
    return true;
  }

  /**
   * Waits for the provider's Send button to become enabled (especially after image upload)
   * and triggers it, with an optional Enter key fallback.
   *
   * @param {Object} providerConfig
   * @param {HTMLElement} inputEl
   * @param {boolean} hasImages
   * @returns {Promise<{ sent: boolean, via: string }>}
   */
  async function triggerSendAction(providerConfig, inputEl, hasImages) {
    const maxWaitMs = hasImages ? 14000 : 4500;
    const deadline = Date.now() + maxWaitMs;

    while (Date.now() < deadline) {
      const sendBtn = findFirstVisibleElement(providerConfig.sendButtonSelectors);
      if (sendBtn && isSendButtonReady(sendBtn)) {
        sendBtn.click();
        return { sent: true, via: 'button-click' };
      }
      await delay(150);
    }

    if (providerConfig.submitOnEnterFallback && inputEl) {
      inputEl.focus();
      const enterEventInit = {
        key: 'Enter',
        code: 'Enter',
        keyCode: 13,
        which: 13,
        bubbles: true,
        cancelable: true,
        composed: true
      };
      inputEl.dispatchEvent(new KeyboardEvent('keydown', enterEventInit));
      inputEl.dispatchEvent(new KeyboardEvent('keypress', enterEventInit));
      inputEl.dispatchEvent(new KeyboardEvent('keyup', enterEventInit));
      return { sent: true, via: 'enter-key-fallback' };
    }

    return { sent: false, via: 'timeout' };
  }

  /**
   * Executes the full injection lifecycle on the current AI provider tab:
   *  1. Verify origin against ProviderRegistry.
   *  2. Locate composer input element.
   *  3. Inject images (if any) and wait for composer settle delay.
   *  4. Inject prompt text safely.
   *  5. Trigger Send button once ready.
   *  6. Scrub all volatile memory references.
   *
   * @param {Object} payload
   * @returns {Promise<Object>}
   */
  async function handleDispatchPrompt(payload) {
    try {
      const matched = ProviderRegistry.matchProviderByUrl(window.location.href);
      if (!matched) {
        return {
          ok: false,
          error: 'Current tab origin is not an authorized AI provider.'
        };
      }

      const validation = SecurityUtils.validateDispatchPayload(payload);
      if (!validation.valid) {
        return {
          ok: false,
          provider: matched.key,
          error: validation.reason || 'Payload validation failed.'
        };
      }

      const providerConfig = matched.config;
      const inputEl = await waitForVisibleElement(providerConfig.inputSelectors, 4500);
      if (!inputEl) {
        return {
          ok: false,
          provider: matched.key,
          error: `Could not locate chat input on ${providerConfig.name}. Ensure you are logged in and on the chat view.`
        };
      }

      const imageCount = Array.isArray(payload.images) ? payload.images.length : 0;
      const hasImages = imageCount > 0;
      const promptText = typeof payload.prompt === 'string' ? payload.prompt : '';

      // Step 1: Inject images first so the host application begins processing attachments
      let uploadInfo = { uploaded: true, methodUsed: 'none' };
      if (hasImages) {
        uploadInfo = await injectImagesIntoProvider(providerConfig, inputEl, payload.images);
        if (!uploadInfo.uploaded) {
          return {
            ok: false,
            provider: matched.key,
            error: `Failed to attach images on ${providerConfig.name}.`
          };
        }

        // For Gemini & Claude, scale settle delay when multiple images are attached
        const baseDelay = providerConfig.uploadSettleDelayMs || 900;
        const extraMultiImageDelay =
          (matched.key === 'gemini' || matched.key === 'claude') && imageCount > 1
            ? (imageCount - 1) * 650
            : 0;
        await delay(baseDelay + extraMultiImageDelay);
      }

      // Step 2: Re-query input element in case the DOM re-rendered after attachment
      const activeInputEl =
        findFirstVisibleElement(providerConfig.inputSelectors) || inputEl;

      if (promptText.trim().length > 0) {
        await injectPromptText(activeInputEl, promptText);
        await delay(220);
      }

      // Step 3: Wait for Send button readiness and click
      const sendResult = await triggerSendAction(
        providerConfig,
        activeInputEl,
        hasImages
      );

      if (!sendResult.sent) {
        return {
          ok: false,
          provider: matched.key,
          error: `Prompt injected on ${providerConfig.name}, but Send button remained disabled or unavailable.`
        };
      }

      return {
        ok: true,
        provider: matched.key,
        providerName: providerConfig.name,
        uploadMethodUsed: uploadInfo.methodUsed,
        sentVia: sendResult.via
      };
    } catch (err) {
      return {
        ok: false,
        error: err instanceof Error ? err.message : 'Unexpected injection error.'
      };
    } finally {
      // Strictly scrub volatile payload buffers immediately after execution
      SecurityUtils.scrubVolatilePayload(payload);
    }
  }

  // Cleanly replace any old listener if content script is re-injected
  if (
    typeof globalScope.__AI_MULTI_BROADCASTER_LISTENER__ === 'function' &&
    chrome.runtime &&
    chrome.runtime.onMessage
  ) {
    try {
      chrome.runtime.onMessage.removeListener(
        globalScope.__AI_MULTI_BROADCASTER_LISTENER__
      );
    } catch {
      // Ignore
    }
  }

  const messageListener = (message, sender, sendResponse) => {
    const envelopeCheck = SecurityUtils.validateMessageEnvelope(message, sender);
    if (!envelopeCheck.valid) {
      sendResponse({ ok: false, error: envelopeCheck.reason });
      return false;
    }

    if (message.action === 'PING_PROVIDER') {
      const matched = ProviderRegistry.matchProviderByUrl(window.location.href);
      if (!matched) {
        sendResponse({ ok: false, ready: false });
        return false;
      }
      const inputEl = findFirstVisibleElement(matched.config.inputSelectors);
      sendResponse({
        ok: true,
        version: '1.3.0',
        ready: Boolean(inputEl),
        provider: matched.key,
        providerName: matched.config.name
      });
      return false;
    }

    if (message.action === 'DISPATCH_PROMPT') {
      handleDispatchPrompt(message.payload)
        .then((result) => sendResponse(result))
        .catch((err) => {
          sendResponse({
            ok: false,
            error: err instanceof Error ? err.message : 'Content script error.'
          });
        });
      return true; // Keep message channel open for async response
    }

    return false;
  };

  globalScope.__AI_MULTI_BROADCASTER_LISTENER__ = messageListener;
  chrome.runtime.onMessage.addListener(messageListener);
})(typeof globalThis !== 'undefined' ? globalThis : self);
