/**
 * @file sidepanel/sidepanel.js
 * @description Zero-XSS, Volatile-Memory Side Panel Controller for AI Multi-Broadcaster.
 *
 * Security & Privacy Invariants:
 *  - Zero DOM XSS sinks: All UI updates use `document.createElement` and `textContent`.
 *  - Zero persistent storage: Never touches `localStorage`, `sessionStorage`, or `chrome.storage`.
 *  - Immediate memory scrubbing: Object URLs are revoked via `URL.revokeObjectURL` and
 *    Base64 transfer strings are scrubbed immediately upon dispatch completion or panel unload.
 */

'use strict';

(function initSidePanel(globalScope) {
  const { SecurityUtils, ProviderRegistry, AI_PROVIDERS } = globalScope;

  /**
   * Volatile in-memory store for attached image files.
   * Each entry: { id: string, file: File, safeName: string, size: number, type: string, previewUrl: string }
   * @type {Array<{ id: string, file: File, safeName: string, size: number, type: string, previewUrl: string }>}
   */
  const volatileAttachments = [];

  /**
   * Volatile in-memory store for generated public share links.
   * @type {Array<{ tabId: number, providerKey: string, providerName: string, state: 'pending' | 'success' | 'error', shareUrl: string | null, code: string | null, message: string }>}
   */
  const volatileSharedLinks = [];

  /**
   * Selected provider keys (all 4 enabled by default in volatile state).
   * @type {Set<string>}
   */
  const selectedProviders = new Set(Object.keys(AI_PROVIDERS));

  /**
   * Latest discovered open tabs per provider key.
   * @type {Record<string, Array<{ tabId: number, title: string, active: boolean }>>}
   */
  let activeProviderTabs = {};

  let isBroadcasting = false;
  let shareRequestCounter = 0;

  // DOM References
  const providerGridEl = document.getElementById('provider-grid');
  const openMissingBtn = document.getElementById('open-missing-btn');
  const refreshTabsBtn = document.getElementById('refresh-tabs-btn');
  const dropzoneEl = document.getElementById('dropzone');
  const fileInputEl = document.getElementById('file-input');
  const attachmentCountBadgeEl = document.getElementById('attachment-count-badge');
  const clearImagesBtn = document.getElementById('clear-images-btn');
  const attachmentListEl = document.getElementById('attachment-list');
  const promptInputEl = document.getElementById('prompt-input');
  const charCounterEl = document.getElementById('char-counter');
  const clearAfterSendCheckbox = document.getElementById('clear-after-send');
  const autoShareToggle = document.getElementById('auto-share-toggle');
  const autoShareWarningEl = document.getElementById('auto-share-warning');
  const shareConfirmContainerEl = document.getElementById('share-confirm-container');
  const sendBtn = document.getElementById('send-btn');
  const sendBtnTextEl = document.getElementById('send-btn-text');
  const statusSectionEl = document.getElementById('status-section');
  const statusListEl = document.getElementById('status-list');
  const dismissStatusBtn = document.getElementById('dismiss-status-btn');
  const sharedLinksSectionEl = document.getElementById('shared-links-section');
  const sharedLinksListEl = document.getElementById('shared-links-list');
  const copyAllLinksBtn = document.getElementById('copy-all-links-btn');
  const copySeoLinksBtn = document.getElementById('copy-seo-links-btn');
  const clearSharedLinksBtn = document.getElementById('clear-shared-links-btn');

  /**
   * Formats byte counts into human-readable KB/MB strings.
   * @param {number} bytes
   * @returns {string}
   */
  function formatByteSize(bytes) {
    if (bytes < 1024) {
      return `${bytes} B`;
    }
    const kb = bytes / 1024;
    if (kb < 1024) {
      return `${kb.toFixed(1)} KB`;
    }
    const mb = kb / 1024;
    return `${mb.toFixed(2)} MB`;
  }

  /**
   * Removes all child nodes from a DOM element safely without innerHTML.
   * @param {HTMLElement | null} element
   */
  function clearChildNodes(element) {
    if (!element) {
      return;
    }
    while (element.firstChild) {
      element.removeChild(element.firstChild);
    }
  }

  /**
   * Renders the 4 AI Provider status cards safely using createElement + textContent.
   */
  function renderProviderGrid() {
    clearChildNodes(providerGridEl);

    for (const [providerKey, config] of Object.entries(AI_PROVIDERS)) {
      const tabs = activeProviderTabs[providerKey] || [];
      const isOnline = tabs.length > 0;
      const isChecked = selectedProviders.has(providerKey);

      const card = document.createElement('div');
      card.className = isOnline
        ? 'provider-item provider-online'
        : 'provider-item';

      // Top row: checkbox + provider name + status dot
      const topRow = document.createElement('div');
      topRow.className = 'provider-top-row';

      const label = document.createElement('label');
      label.className = 'provider-label';

      const checkbox = document.createElement('input');
      checkbox.type = 'checkbox';
      checkbox.className = 'provider-checkbox';
      checkbox.checked = isChecked;
      checkbox.addEventListener('change', () => {
        if (checkbox.checked) {
          selectedProviders.add(providerKey);
        } else {
          selectedProviders.delete(providerKey);
        }
      });

      const nameSpan = document.createElement('span');
      nameSpan.textContent = config.name;

      label.appendChild(checkbox);
      label.appendChild(nameSpan);

      const dot = document.createElement('span');
      dot.className = isOnline ? 'status-dot online' : 'status-dot';
      dot.title = isOnline
        ? `${tabs.length} open tab(s) detected`
        : 'No open tab detected';

      topRow.appendChild(label);
      topRow.appendChild(dot);

      // Bottom row: tab count or quick-open button
      const bottomRow = document.createElement('div');
      bottomRow.className = 'provider-bottom-row';

      const metaSpan = document.createElement('span');
      metaSpan.className = 'provider-tab-meta';
      metaSpan.textContent = isOnline
        ? `${tabs.length} tab${tabs.length > 1 ? 's' : ''} ready`
        : 'Offline';

      bottomRow.appendChild(metaSpan);

      if (!isOnline) {
        const openBtn = document.createElement('button');
        openBtn.type = 'button';
        openBtn.className = 'open-tab-link-btn';
        openBtn.textContent = 'Open';
        openBtn.title = `Open ${config.name} in a new tab`;
        openBtn.addEventListener('click', () => {
          openProviderTab(providerKey);
        });
        bottomRow.appendChild(openBtn);
      }

      card.appendChild(topRow);
      card.appendChild(bottomRow);
      providerGridEl.appendChild(card);
    }
  }

  /**
   * Resolves the Chrome windowId of the browser window where this Side Panel instance is open.
   * Ensures detached tabs in separate browser windows are ignored.
   *
   * @returns {Promise<number | null>}
   */
  async function getCurrentPanelWindowId() {
    try {
      if (chrome.windows && chrome.windows.getCurrent) {
        const currentWin = await chrome.windows.getCurrent();
        if (currentWin && typeof currentWin.id === 'number' && currentWin.id >= 0) {
          return currentWin.id;
        }
      }
    } catch {
      // Fallback to active tab query in current window
    }

    try {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tabs && tabs.length > 0 && typeof tabs[0].windowId === 'number') {
        return tabs[0].windowId;
      }
    } catch {
      // Ignore
    }

    return null;
  }

  /**
   * Queries the background service worker for currently open AI provider tabs
   * strictly within this Side Panel's Chrome window.
   */
  async function refreshActiveProviders() {
    try {
      const windowId = await getCurrentPanelWindowId();
      const response = await chrome.runtime.sendMessage({
        action: 'QUERY_ACTIVE_PROVIDERS',
        payload: { windowId }
      });
      if (response && response.ok && response.providers) {
        activeProviderTabs = response.providers;
      }
    } catch {
      // Ignore transient service worker wake-up error
    }
    renderProviderGrid();
  }

  /**
   * Requests the background script to open a specific whitelisted AI provider tab
   * inside this Side Panel's Chrome window.
   * @param {string} providerKey
   */
  async function openProviderTab(providerKey) {
    try {
      const windowId = await getCurrentPanelWindowId();
      await chrome.runtime.sendMessage({
        action: 'OPEN_PROVIDER_TAB',
        payload: { providerKey, windowId }
      });
      setTimeout(refreshActiveProviders, 450);
    } catch {
      // Ignore error
    }
  }

  /**
   * Opens tabs for all selected providers that do not currently have an open tab.
   */
  async function openMissingSelectedProviders() {
    for (const providerKey of selectedProviders) {
      const tabs = activeProviderTabs[providerKey] || [];
      if (tabs.length === 0) {
        await openProviderTab(providerKey);
      }
    }
  }

  /**
   * Renders the volatile image attachment thumbnails safely.
   */
  function renderAttachmentList() {
    clearChildNodes(attachmentListEl);

    const count = volatileAttachments.length;
    attachmentCountBadgeEl.textContent = `${count} / ${SecurityUtils.MAX_IMAGE_COUNT}`;

    if (count === 0) {
      attachmentListEl.classList.add('hidden');
      clearImagesBtn.classList.add('hidden');
      return;
    }

    attachmentListEl.classList.remove('hidden');
    clearImagesBtn.classList.remove('hidden');

    for (const item of volatileAttachments) {
      const card = document.createElement('div');
      card.className = 'attachment-card';

      const img = document.createElement('img');
      img.className = 'attachment-thumb';
      img.src = item.previewUrl;
      img.alt = item.safeName;

      const info = document.createElement('div');
      info.className = 'attachment-info';

      const nameEl = document.createElement('span');
      nameEl.className = 'attachment-name';
      nameEl.textContent = item.safeName;
      nameEl.title = item.safeName;

      const sizeEl = document.createElement('span');
      sizeEl.className = 'attachment-size';
      sizeEl.textContent = formatByteSize(item.size);

      info.appendChild(nameEl);
      info.appendChild(sizeEl);

      const removeBtn = document.createElement('button');
      removeBtn.type = 'button';
      removeBtn.className = 'attachment-remove-btn';
      removeBtn.textContent = '\u00D7';
      removeBtn.title = `Remove ${item.safeName}`;
      removeBtn.setAttribute('aria-label', `Remove ${item.safeName}`);
      removeBtn.addEventListener('click', () => {
        removeAttachmentById(item.id);
      });

      card.appendChild(img);
      card.appendChild(info);
      card.appendChild(removeBtn);
      attachmentListEl.appendChild(card);
    }
  }

  /**
   * Removes a single volatile attachment and immediately revokes its blob URL.
   * @param {string} id
   */
  function removeAttachmentById(id) {
    const index = volatileAttachments.findIndex((item) => item.id === id);
    if (index === -1) {
      return;
    }
    const [removed] = volatileAttachments.splice(index, 1);
    if (removed && removed.previewUrl) {
      URL.revokeObjectURL(removed.previewUrl);
      removed.previewUrl = '';
    }
    renderAttachmentList();
  }

  /**
   * Immediately revokes all volatile Object URLs and empties the attachment array.
   */
  function clearAllVolatileAttachments() {
    for (let i = 0; i < volatileAttachments.length; i += 1) {
      const item = volatileAttachments[i];
      if (item && item.previewUrl) {
        URL.revokeObjectURL(item.previewUrl);
        item.previewUrl = '';
      }
      volatileAttachments[i] = null;
    }
    volatileAttachments.length = 0;
    if (fileInputEl) {
      fileInputEl.value = '';
    }
    renderAttachmentList();
  }

  /**
   * Validates and ingests File objects from file input, drag-and-drop, or clipboard paste.
   * @param {FileList | File[]} fileList
   */
  function addFilesToVolatileStore(fileList) {
    if (!fileList || fileList.length === 0) {
      return;
    }

    const errors = [];
    let currentBytes = volatileAttachments.reduce((acc, item) => acc + item.size, 0);

    for (const file of Array.from(fileList)) {
      if (volatileAttachments.length >= SecurityUtils.MAX_IMAGE_COUNT) {
        errors.push(`Maximum of ${SecurityUtils.MAX_IMAGE_COUNT} images reached.`);
        break;
      }
      if (!SecurityUtils.ALLOWED_IMAGE_MIME_TYPES.has(file.type)) {
        errors.push(`Skipped "${file.name}": unsupported MIME type (${file.type || 'unknown'}).`);
        continue;
      }
      if (file.size <= 0 || file.size > SecurityUtils.MAX_SINGLE_IMAGE_BYTES) {
        errors.push(`Skipped "${file.name}": exceeds 20 MB per-image limit.`);
        continue;
      }
      if (currentBytes + file.size > SecurityUtils.MAX_TOTAL_IMAGE_BYTES) {
        errors.push(`Skipped "${file.name}": total attachments would exceed 50 MB.`);
        continue;
      }

      const safeName = SecurityUtils.sanitizeFileName(file.name, file.type);
      const previewUrl = URL.createObjectURL(file);
      const uniqueId = `${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;

      volatileAttachments.push({
        id: uniqueId,
        file,
        safeName,
        size: file.size,
        type: file.type,
        previewUrl
      });
      currentBytes += file.size;
    }

    renderAttachmentList();

    if (errors.length > 0) {
      renderStatusReports(
        errors.map((msg) => ({
          providerName: 'Attachment Filter',
          status: 'error',
          message: msg
        }))
      );
    }
  }

  /**
   * Reads a File object into a Base64 DataURL in volatile memory for IPC transfer.
   * @param {File} file
   * @returns {Promise<string>}
   */
  function readFileAsVolatileDataUrl(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => {
        if (typeof reader.result === 'string') {
          resolve(reader.result);
        } else {
          reject(new Error('Failed to encode image attachment.'));
        }
      };
      reader.onerror = () => reject(new Error('FileReader error while reading image.'));
      reader.readAsDataURL(file);
    });
  }

  /**
   * Renders status telemetry items in the Broadcast Status card using safe DOM nodes.
   * @param {Array<{ providerName: string, status: string, message: string }>} reports
   */
  function renderStatusReports(reports) {
    clearChildNodes(statusListEl);

    if (!Array.isArray(reports) || reports.length === 0) {
      statusSectionEl.classList.add('hidden');
      return;
    }

    statusSectionEl.classList.remove('hidden');

    for (const report of reports) {
      const li = document.createElement('li');
      const statusClass =
        report.status === 'success'
          ? 'status-success'
          : report.status === 'skipped'
          ? 'status-skipped'
          : 'status-error';
      li.className = `status-item ${statusClass}`;

      const providerSpan = document.createElement('span');
      providerSpan.className = 'status-provider';
      providerSpan.textContent = report.providerName || 'Provider';

      const messageSpan = document.createElement('span');
      messageSpan.className = 'status-message';
      messageSpan.textContent = report.message || '';

      li.appendChild(providerSpan);
      li.appendChild(messageSpan);
      statusListEl.appendChild(li);
    }
  }

  /**
   * Maps a share-engine failure code to a concise human-readable message.
   * @param {string | undefined} code
   * @param {string | undefined} fallbackMsg
   * @returns {string}
   */
  function formatShareErrorReason(code, fallbackMsg) {
    const map = {
      RESPONSE_TIMEOUT: 'Timed out waiting for AI response to complete.',
      SHARE_BUTTON_NOT_FOUND: 'Share button not found in chat UI.',
      LINK_NOT_FOUND: 'Could not extract public share link from dialog.',
      BUSY: 'Share generation already in progress on this tab.',
      UNSUPPORTED: 'Public share links not supported on this provider.',
      INVALID_ENVELOPE: 'Security validation failed for share request.'
    };
    if (typeof code === 'string' && Object.prototype.hasOwnProperty.call(map, code)) {
      return map[code];
    }
    return fallbackMsg || 'Could not generate public share link.';
  }

  /**
   * Clears all volatile shared links from memory and hides the Shared Links card.
   */
  function clearVolatileSharedLinks() {
    for (let i = 0; i < volatileSharedLinks.length; i += 1) {
      volatileSharedLinks[i] = null;
    }
    volatileSharedLinks.length = 0;
    clearChildNodes(sharedLinksListEl);
    if (sharedLinksSectionEl) {
      sharedLinksSectionEl.classList.add('hidden');
    }
  }

  /**
   * Renders the Shared Links card using createElement + textContent only.
   */
  function renderSharedLinksCard() {
    if (!sharedLinksSectionEl || !sharedLinksListEl) {
      return;
    }
    clearChildNodes(sharedLinksListEl);

    if (volatileSharedLinks.length === 0) {
      sharedLinksSectionEl.classList.add('hidden');
      return;
    }

    sharedLinksSectionEl.classList.remove('hidden');

    for (const item of volatileSharedLinks) {
      if (!item) {
        continue;
      }
      const li = document.createElement('li');
      const stateClass =
        item.state === 'success'
          ? 'share-success'
          : item.state === 'pending'
          ? 'share-pending'
          : 'share-error';
      li.className = `shared-link-item ${stateClass}`;

      const topRow = document.createElement('div');
      topRow.className = 'shared-link-top';

      const providerSpan = document.createElement('span');
      providerSpan.className = 'shared-link-provider';
      providerSpan.textContent = item.providerName || item.providerKey;

      const actionsDiv = document.createElement('div');
      actionsDiv.className = 'shared-link-actions';

      if (item.state === 'success' && item.shareUrl) {
        const copyBtn = document.createElement('button');
        copyBtn.type = 'button';
        copyBtn.className = 'ghost-btn';
        copyBtn.textContent = 'Copy';
        copyBtn.addEventListener('click', () => {
          const validUrl = SecurityUtils.validateShareUrl(item.providerKey, item.shareUrl);
          if (!validUrl) {
            return;
          }
          navigator.clipboard
            .writeText(validUrl)
            .then(() => {
              copyBtn.textContent = 'Copied!';
              setTimeout(() => {
                copyBtn.textContent = 'Copy';
              }, 1400);
            })
            .catch(() => {});
        });

        const openBtn = document.createElement('button');
        openBtn.type = 'button';
        openBtn.className = 'ghost-btn';
        openBtn.textContent = 'Open';
        openBtn.addEventListener('click', () => {
          const validUrl = SecurityUtils.validateShareUrl(item.providerKey, item.shareUrl);
          if (validUrl && chrome.tabs && chrome.tabs.create) {
            chrome.tabs.create({ url: validUrl });
          }
        });

        actionsDiv.appendChild(copyBtn);
        actionsDiv.appendChild(openBtn);
      } else if (item.state === 'error' && typeof item.tabId === 'number') {
        const openChatBtn = document.createElement('button');
        openChatBtn.type = 'button';
        openChatBtn.className = 'open-tab-link-btn';
        openChatBtn.textContent = 'Open chat';
        openChatBtn.title = 'Focus this chat tab to share manually';
        openChatBtn.addEventListener('click', () => {
          if (chrome.tabs && chrome.tabs.update) {
            chrome.tabs.update(item.tabId, { active: true }).catch(() => {});
          }
        });
        actionsDiv.appendChild(openChatBtn);
      }

      topRow.appendChild(providerSpan);
      topRow.appendChild(actionsDiv);
      li.appendChild(topRow);

      if (item.state === 'success' && item.shareUrl) {
        const urlDiv = document.createElement('div');
        urlDiv.className = 'shared-link-url';
        urlDiv.textContent = item.shareUrl;
        urlDiv.title = item.shareUrl;
        li.appendChild(urlDiv);
      } else {
        const statusDiv = document.createElement('div');
        statusDiv.className = 'shared-link-status';
        statusDiv.textContent =
          item.state === 'pending'
            ? '\u23F3 Waiting for response\u2026'
            : `\u26A0 ${item.message}`;
        li.appendChild(statusDiv);
      }

      sharedLinksListEl.appendChild(li);
    }
  }

  /**
   * Concurrently requests native public share links from all tabs that succeeded during broadcast.
   *
   * @param {Array<Object>} reports
   */
  async function requestShareLinksForReports(reports) {
    if (!Array.isArray(reports)) {
      return;
    }

    const successfulTargets = reports.filter((r) => {
      if (
        !r ||
        (r.ok !== true && r.status !== 'success') ||
        typeof r.tabId !== 'number'
      ) {
        return false;
      }
      const key = r.provider || r.providerKey;
      return Boolean(
        typeof key === 'string' &&
          AI_PROVIDERS[key] &&
          AI_PROVIDERS[key].share &&
          AI_PROVIDERS[key].share.supported
      );
    });

    if (successfulTargets.length === 0) {
      return;
    }

    clearVolatileSharedLinks();

    for (const target of successfulTargets) {
      const providerKey = target.provider || target.providerKey;
      const providerConfig = AI_PROVIDERS[providerKey];
      volatileSharedLinks.push({
        tabId: target.tabId,
        providerKey,
        providerName: target.providerName || (providerConfig ? providerConfig.name : providerKey),
        state: 'pending',
        shareUrl: null,
        code: null,
        message: 'Waiting for response\u2026'
      });
    }

    renderSharedLinksCard();

    const tasks = volatileSharedLinks.map(async (entry) => {
      try {
        // Verify the tab is still open and on the matching provider origin before sending
        const tabInfo = await chrome.tabs.get(entry.tabId);
        const matched =
          tabInfo && typeof tabInfo.url === 'string'
            ? ProviderRegistry.matchProviderByUrl(tabInfo.url)
            : null;

        if (!matched || matched.key !== entry.providerKey) {
          entry.state = 'error';
          entry.code = 'UNSUPPORTED';
          entry.message = 'Tab navigated away from provider.';
          renderSharedLinksCard();
          return;
        }

        shareRequestCounter += 1;
        const requestId = `share-${Date.now()}-${shareRequestCounter}`;

        const response = await chrome.tabs.sendMessage(entry.tabId, {
          action: 'GENERATE_SHARE_LINK',
          payload: { requestId }
        });

        if (response && response.ok && typeof response.shareUrl === 'string') {
          const validatedUrl = SecurityUtils.validateShareUrl(
            entry.providerKey,
            response.shareUrl
          );
          if (validatedUrl) {
            entry.state = 'success';
            entry.shareUrl = validatedUrl;
            entry.code = null;
            entry.message = 'Link ready';
            renderSharedLinksCard();
            return;
          }
        }

        entry.state = 'error';
        entry.code = (response && response.code) || 'LINK_NOT_FOUND';
        entry.message = formatShareErrorReason(
          response && response.code,
          response && response.message
        );
        renderSharedLinksCard();
      } catch (err) {
        entry.state = 'error';
        entry.code = 'LINK_NOT_FOUND';
        entry.message =
          err instanceof Error
            ? err.message
            : 'Tab closed or disconnected while waiting for share link.';
        renderSharedLinksCard();
      }
    });

    await Promise.allSettled(tasks);
  }

  /**
   * Hides and clears the inline public-link confirmation bar.
   */
  function hideShareConfirmRow() {
    if (!shareConfirmContainerEl) {
      return;
    }
    clearChildNodes(shareConfirmContainerEl);
    shareConfirmContainerEl.classList.add('hidden');
  }

  /**
   * Counts how many open tabs across selected providers will be targeted.
   * @returns {number}
   */
  function countTargetOpenTabs() {
    let total = 0;
    for (const key of selectedProviders) {
      const tabs = activeProviderTabs[key] || [];
      total += tabs.length;
    }
    return total > 0 ? total : selectedProviders.size;
  }

  /**
   * Validates inputs and either shows the one-time public-link confirmation row
   * (when auto-share is ON) or dispatches the broadcast immediately.
   */
  async function executeBroadcast() {
    if (isBroadcasting) {
      return;
    }

    const rawPrompt = promptInputEl.value || '';
    const promptValidation = SecurityUtils.validatePromptText(rawPrompt);
    if (!promptValidation.valid) {
      renderStatusReports([
        {
          providerName: 'Validation',
          status: 'error',
          message: promptValidation.reason || 'Invalid prompt.'
        }
      ]);
      return;
    }

    if (promptValidation.prompt.trim().length === 0 && volatileAttachments.length === 0) {
      renderStatusReports([
        {
          providerName: 'Validation',
          status: 'error',
          message: 'Enter a prompt or attach at least one image before broadcasting.'
        }
      ]);
      return;
    }

    if (selectedProviders.size === 0) {
      renderStatusReports([
        {
          providerName: 'Targets',
          status: 'error',
          message: 'Select at least one target AI platform.'
        }
      ]);
      return;
    }

    const shouldGenerateShareLinks = Boolean(autoShareToggle && autoShareToggle.checked);
    await performBroadcastDispatch(promptValidation.prompt, shouldGenerateShareLinks);
  }

  /**
   * Executes the simultaneous multi-provider broadcast workflow and optionally
   * triggers public share link generation across successful tabs.
   *
   * @param {string} validatedPrompt
   * @param {boolean} generateShareLinks
   */
  async function performBroadcastDispatch(validatedPrompt, generateShareLinks) {
    if (isBroadcasting) {
      return;
    }

    hideShareConfirmRow();
    isBroadcasting = true;
    sendBtn.disabled = true;
    sendBtnTextEl.textContent = 'Broadcasting...';

    /** @type {Object | null} */
    let volatilePayload = null;
    /** @type {Array<Object> | null} */
    let settledReports = null;

    try {
      // Encode attachments to volatile Base64 DataURLs only for the duration of the IPC call
      const serializedImages = [];
      for (const item of volatileAttachments) {
        const dataUrl = await readFileAsVolatileDataUrl(item.file);
        serializedImages.push({
          name: item.safeName,
          type: item.type,
          size: item.size,
          dataUrl
        });
      }

      const windowId = await getCurrentPanelWindowId();

      volatilePayload = {
        prompt: validatedPrompt,
        images: serializedImages,
        targetProviders: Array.from(selectedProviders),
        windowId
      };

      const response = await chrome.runtime.sendMessage({
        action: 'BROADCAST_TO_PROVIDERS',
        payload: volatilePayload
      });

      if (response && Array.isArray(response.reports)) {
        settledReports = response.reports;
        renderStatusReports(response.reports);
      } else if (response && response.error) {
        renderStatusReports([
          {
            providerName: 'Broadcast',
            status: 'error',
            message: response.error
          }
        ]);
      }

      // Immediately wipe prompt & volatile image attachments if configured (enabled by default)
      if (response && response.ok && clearAfterSendCheckbox.checked) {
        promptInputEl.value = '';
        updateCharCounter();
        clearAllVolatileAttachments();
      }
    } catch (err) {
      renderStatusReports([
        {
          providerName: 'Broadcast Error',
          status: 'error',
          message: err instanceof Error ? err.message : 'Unexpected broadcast failure.'
        }
      ]);
    } finally {
      // Zero-out volatile transfer buffers immediately
      SecurityUtils.scrubVolatilePayload(volatilePayload);
      volatilePayload = null;
      isBroadcasting = false;
      sendBtn.disabled = false;
      sendBtnTextEl.textContent = 'Broadcast Prompt';
      refreshActiveProviders();
    }

    if (generateShareLinks && Array.isArray(settledReports)) {
      requestShareLinksForReports(settledReports);
    }
  }

  /**
   * Updates character counter display safely.
   */
  function updateCharCounter() {
    const len = (promptInputEl.value || '').length;
    charCounterEl.textContent = `${len.toLocaleString()} chars`;
  }

  // Event Listeners
  refreshTabsBtn.addEventListener('click', () => {
    refreshActiveProviders();
  });

  openMissingBtn.addEventListener('click', () => {
    openMissingSelectedProviders();
  });

  dropzoneEl.addEventListener('click', () => {
    fileInputEl.click();
  });

  dropzoneEl.addEventListener('keydown', (event) => {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      fileInputEl.click();
    }
  });

  fileInputEl.addEventListener('change', () => {
    if (fileInputEl.files && fileInputEl.files.length > 0) {
      addFilesToVolatileStore(fileInputEl.files);
      fileInputEl.value = '';
    }
  });

  dropzoneEl.addEventListener('dragover', (event) => {
    event.preventDefault();
    dropzoneEl.classList.add('drag-active');
  });

  dropzoneEl.addEventListener('dragleave', () => {
    dropzoneEl.classList.remove('drag-active');
  });

  dropzoneEl.addEventListener('drop', (event) => {
    event.preventDefault();
    dropzoneEl.classList.remove('drag-active');
    if (event.dataTransfer && event.dataTransfer.files) {
      addFilesToVolatileStore(event.dataTransfer.files);
    }
  });

  // Global paste listener inside Side Panel for quick Ctrl+V screenshot attachment
  document.addEventListener('paste', (event) => {
    if (!event.clipboardData || !event.clipboardData.files) {
      return;
    }
    if (event.clipboardData.files.length > 0) {
      event.preventDefault();
      addFilesToVolatileStore(event.clipboardData.files);
    }
  });

  clearImagesBtn.addEventListener('click', () => {
    clearAllVolatileAttachments();
  });

  promptInputEl.addEventListener('input', () => {
    updateCharCounter();
  });

  promptInputEl.addEventListener('keydown', (event) => {
    if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') {
      event.preventDefault();
      executeBroadcast();
    }
  });

  sendBtn.addEventListener('click', () => {
    executeBroadcast();
  });

  dismissStatusBtn.addEventListener('click', () => {
    clearChildNodes(statusListEl);
    statusSectionEl.classList.add('hidden');
  });

  if (autoShareToggle) {
    // Enabled by default on Side Panel open
    autoShareToggle.checked = true;
    autoShareToggle.addEventListener('change', () => {
      if (!autoShareToggle.checked) {
        hideShareConfirmRow();
      }
    });
  }

  if (copyAllLinksBtn) {
    copyAllLinksBtn.addEventListener('click', () => {
      const validUrls = [];
      for (const item of volatileSharedLinks) {
        if (item && item.state === 'success' && item.shareUrl) {
          const validated = SecurityUtils.validateShareUrl(item.providerKey, item.shareUrl);
          if (validated) {
            validUrls.push(validated);
          }
        }
      }
      if (validUrls.length === 0) {
        return;
      }
      navigator.clipboard
        .writeText(validUrls.join('\n'))
        .then(() => {
          copyAllLinksBtn.textContent = 'Copied!';
          setTimeout(() => {
            copyAllLinksBtn.textContent = 'Copy all links';
          }, 1400);
        })
        .catch(() => {});
    });
  }

  if (copySeoLinksBtn) {
    copySeoLinksBtn.addEventListener('click', () => {
      const markdownLines = [];
      for (const item of volatileSharedLinks) {
        if (item && item.state === 'success' && item.shareUrl) {
          const validated = SecurityUtils.validateShareUrl(item.providerKey, item.shareUrl);
          if (validated) {
            markdownLines.push(`- [${item.providerName} Shared Response](${validated})`);
          }
        }
      }
      if (markdownLines.length === 0) {
        return;
      }
      navigator.clipboard
        .writeText(markdownLines.join('\n'))
        .then(() => {
          copySeoLinksBtn.textContent = 'Copied SEO!';
          setTimeout(() => {
            copySeoLinksBtn.textContent = 'Copy SEO/AEO';
          }, 1400);
        })
        .catch(() => {});
    });
  }

  if (clearSharedLinksBtn) {
    clearSharedLinksBtn.addEventListener('click', () => {
      clearVolatileSharedLinks();
    });
  }

  // Auto-refresh tab status when browser tabs change
  if (chrome.tabs) {
    let refreshTimer = null;
    const scheduleRefresh = () => {
      if (refreshTimer) {
        clearTimeout(refreshTimer);
      }
      refreshTimer = setTimeout(() => {
        refreshActiveProviders();
      }, 300);
    };
    chrome.tabs.onUpdated.addListener(scheduleRefresh);
    chrome.tabs.onRemoved.addListener(scheduleRefresh);
    chrome.tabs.onCreated.addListener(scheduleRefresh);
    if (chrome.tabs.onDetached) {
      chrome.tabs.onDetached.addListener(scheduleRefresh);
    }
    if (chrome.tabs.onAttached) {
      chrome.tabs.onAttached.addListener(scheduleRefresh);
    }
  }

  // Strict volatile memory hygiene on panel unload/hide
  const scrubAllPanelMemory = () => {
    clearAllVolatileAttachments();
    clearVolatileSharedLinks();
    hideShareConfirmRow();
    if (promptInputEl) {
      promptInputEl.value = '';
    }
  };
  window.addEventListener('pagehide', scrubAllPanelMemory);
  window.addEventListener('beforeunload', scrubAllPanelMemory);

  // Initial render
  renderProviderGrid();
  renderAttachmentList();
  updateCharCounter();
  refreshActiveProviders();
})(typeof globalThis !== 'undefined' ? globalThis : self);

