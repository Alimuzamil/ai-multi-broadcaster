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
  const { SecurityUtils, AI_PROVIDERS } = globalScope;

  /**
   * Volatile in-memory store for attached image files.
   * Each entry: { id: string, file: File, safeName: string, size: number, type: string, previewUrl: string }
   * @type {Array<{ id: string, file: File, safeName: string, size: number, type: string, previewUrl: string }>}
   */
  const volatileAttachments = [];

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
  const sendBtn = document.getElementById('send-btn');
  const sendBtnTextEl = document.getElementById('send-btn-text');
  const statusSectionEl = document.getElementById('status-section');
  const statusListEl = document.getElementById('status-list');
  const dismissStatusBtn = document.getElementById('dismiss-status-btn');

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
   * Executes the simultaneous multi-provider broadcast workflow.
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

    isBroadcasting = true;
    sendBtn.disabled = true;
    sendBtnTextEl.textContent = 'Broadcasting...';

    /** @type {Object | null} */
    let volatilePayload = null;

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
        prompt: promptValidation.prompt,
        images: serializedImages,
        targetProviders: Array.from(selectedProviders),
        windowId
      };

      const response = await chrome.runtime.sendMessage({
        action: 'BROADCAST_TO_PROVIDERS',
        payload: volatilePayload
      });

      if (response && Array.isArray(response.reports)) {
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

