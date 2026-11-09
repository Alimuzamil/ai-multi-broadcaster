/**
 * @file background.js
 * @description Manifest V3 Service Worker Orchestrator for AI Multi-Broadcaster.
 *
 * Responsibilities:
 *  - Configures Chrome Side Panel behavior (`openPanelOnActionClick: true`).
 *  - Discovers open tabs strictly matching the 4 whitelisted AI domains.
 *  - Dynamically ensures content scripts are injected on pre-existing tabs.
 *  - Broadcasts validated volatile payloads concurrently across target tabs.
 *  - Immediately scrubs volatile memory buffers after broadcast completion.
 */

'use strict';

importScripts('utils/security.js', 'providers.js');

const { SecurityUtils, ProviderRegistry, AI_PROVIDERS } = self;

/**
 * Enable opening the Side Panel directly when the user clicks the extension action icon.
 */
function configureSidePanelBehavior() {
  if (chrome.sidePanel && chrome.sidePanel.setPanelBehavior) {
    chrome.sidePanel
      .setPanelBehavior({ openPanelOnActionClick: true })
      .catch(() => {
        // Ignore on older Chromium builds
      });
  }
}

chrome.runtime.onInstalled.addListener(() => {
  configureSidePanelBehavior();
});

chrome.runtime.onStartup.addListener(() => {
  configureSidePanelBehavior();
});

configureSidePanelBehavior();

/**
 * Ensures the content script suite is loaded inside a whitelisted tab.
 * If the tab was opened before the extension was installed/reloaded, injects the scripts.
 *
 * @param {number} tabId
 * @returns {Promise<boolean>}
 */
async function ensureContentScriptReady(tabId) {
  try {
    const pingResponse = await chrome.tabs.sendMessage(tabId, {
      action: 'PING_PROVIDER'
    });
    if (pingResponse && pingResponse.ok && pingResponse.version === '1.3.0') {
      return true;
    }
  } catch {
    // Content script not yet injected in this tab; inject programmatically
  }

  try {
    await chrome.scripting.executeScript({
      target: { tabId },
      files: ['utils/security.js', 'providers.js', 'content/injector.js']
    });
    return true;
  } catch {
    return false;
  }
}

/**
 * Queries open tabs matching the 4 whitelisted AI provider URL patterns
 * strictly within the target Chrome window where the Side Panel is open,
 * and groups them by provider key.
 *
 * @param {number | null} [targetWindowId]
 * @returns {Promise<Record<string, Array<{ tabId: number, title: string, active: boolean }>>>}
 */
async function discoverProviderTabs(targetWindowId) {
  /** @type {Record<string, Array<{ tabId: number, title: string, active: boolean }>>} */
  const grouped = {};
  for (const key of Object.keys(AI_PROVIDERS)) {
    grouped[key] = [];
  }

  let resolvedWindowId =
    typeof targetWindowId === 'number' &&
    Number.isInteger(targetWindowId) &&
    targetWindowId >= 0
      ? targetWindowId
      : null;

  if (resolvedWindowId === null && chrome.windows && chrome.windows.getLastFocused) {
    try {
      const lastFocusedWin = await chrome.windows.getLastFocused({
        windowTypes: ['normal']
      });
      if (lastFocusedWin && typeof lastFocusedWin.id === 'number') {
        resolvedWindowId = lastFocusedWin.id;
      }
    } catch {
      // Ignore
    }
  }

  const patterns = ProviderRegistry.getAllUrlMatchPatterns();
  const queryInfo = { url: patterns };
  if (resolvedWindowId !== null) {
    queryInfo.windowId = resolvedWindowId;
  }

  const tabs = await chrome.tabs.query(queryInfo);

  for (const tab of tabs) {
    if (typeof tab.id !== 'number' || typeof tab.url !== 'string') {
      continue;
    }
    if (resolvedWindowId !== null && tab.windowId !== resolvedWindowId) {
      continue;
    }
    const matched = ProviderRegistry.matchProviderByUrl(tab.url);
    if (!matched) {
      continue;
    }
    grouped[matched.key].push({
      tabId: tab.id,
      title: typeof tab.title === 'string' ? tab.title : matched.config.name,
      active: Boolean(tab.active)
    });
  }

  return grouped;
}

/**
 * Broadcasts the prompt and volatile image attachments simultaneously across
 * all open tabs belonging to the selected AI providers.
 *
 * @param {Object} payload
 * @returns {Promise<Object>}
 */
async function handleBroadcastToProviders(payload) {
  try {
    const validation = SecurityUtils.validateDispatchPayload(payload);
    if (!validation.valid) {
      return {
        ok: false,
        error: validation.reason || 'Invalid broadcast payload.'
      };
    }

    const requestedProviders = Array.isArray(payload.targetProviders)
      ? payload.targetProviders.filter((key) => Object.prototype.hasOwnProperty.call(AI_PROVIDERS, key))
      : Object.keys(AI_PROVIDERS);

    if (requestedProviders.length === 0) {
      return {
        ok: false,
        error: 'Select at least one AI provider to broadcast to.'
      };
    }

    const targetWindowId =
      typeof payload.windowId === 'number' &&
      Number.isInteger(payload.windowId) &&
      payload.windowId >= 0
        ? payload.windowId
        : null;

    const groupedTabs = await discoverProviderTabs(targetWindowId);

    /** @type {Array<{ providerKey: string, providerName: string, tabId: number }>} */
    const dispatchTargets = [];
    /** @type {Array<{ providerKey: string, providerName: string, status: string, message: string }>} */
    const providerReports = [];

    for (const providerKey of requestedProviders) {
      const providerConfig = AI_PROVIDERS[providerKey];
      const tabsForProvider = groupedTabs[providerKey] || [];

      if (tabsForProvider.length === 0) {
        providerReports.push({
          providerKey,
          providerName: providerConfig.name,
          status: 'skipped',
          message: `No open ${providerConfig.name} tab found.`
        });
        continue;
      }

      // Prefer the active tab for that provider if multiple are open, or dispatch to all open tabs for that provider
      for (const tabInfo of tabsForProvider) {
        dispatchTargets.push({
          providerKey,
          providerName: providerConfig.name,
          tabId: tabInfo.tabId
        });
      }
    }

    if (dispatchTargets.length === 0) {
      return {
        ok: false,
        error: 'No open tabs found for the selected AI providers. Open at least one provider tab first.',
        reports: providerReports
      };
    }

    // Dispatch concurrently across all target tabs
    const dispatchPromises = dispatchTargets.map(async (target) => {
      const ready = await ensureContentScriptReady(target.tabId);
      if (!ready) {
        return {
          providerKey: target.providerKey,
          providerName: target.providerName,
          tabId: target.tabId,
          status: 'error',
          message: `Could not attach injector to ${target.providerName} (Tab #${target.tabId}).`
        };
      }

      try {
        const response = await chrome.tabs.sendMessage(target.tabId, {
          action: 'DISPATCH_PROMPT',
          payload: {
            prompt: payload.prompt,
            images: payload.images
          }
        });

        if (response && response.ok) {
          const methodDetail =
            response.uploadMethodUsed && response.uploadMethodUsed !== 'none'
              ? `${response.uploadMethodUsed}, ${response.sentVia || 'click'}`
              : response.sentVia || 'click';
          return {
            providerKey: target.providerKey,
            providerName: target.providerName,
            tabId: target.tabId,
            status: 'success',
            message: `Sent to ${target.providerName} (${methodDetail}).`
          };
        }

        return {
          providerKey: target.providerKey,
          providerName: target.providerName,
          tabId: target.tabId,
          status: 'error',
          message:
            (response && response.error) ||
            `Failed to send on ${target.providerName}.`
        };
      } catch (err) {
        return {
          providerKey: target.providerKey,
          providerName: target.providerName,
          tabId: target.tabId,
          status: 'error',
          message:
            err instanceof Error
              ? err.message
              : `Communication error with ${target.providerName}.`
        };
      }
    });

    const settledResults = await Promise.allSettled(dispatchPromises);
    for (const item of settledResults) {
      if (item.status === 'fulfilled') {
        providerReports.push(item.value);
      } else {
        providerReports.push({
          providerKey: 'unknown',
          providerName: 'Unknown Provider',
          status: 'error',
          message: 'Unhandled rejection during tab dispatch.'
        });
      }
    }

    const successCount = providerReports.filter((r) => r.status === 'success').length;

    return {
      ok: successCount > 0,
      successCount,
      totalTargets: dispatchTargets.length,
      reports: providerReports
    };
  } finally {
    // Zero-out volatile prompt and Base64 image strings immediately in Service Worker memory
    SecurityUtils.scrubVolatilePayload(payload);
  }
}

/**
 * Central message router with strict origin & action validation.
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const envelopeCheck = SecurityUtils.validateMessageEnvelope(message, sender);
  if (!envelopeCheck.valid) {
    sendResponse({ ok: false, error: envelopeCheck.reason });
    return false;
  }

  if (message.action === 'QUERY_ACTIVE_PROVIDERS') {
    const targetWindowId =
      message.payload &&
      typeof message.payload.windowId === 'number' &&
      Number.isInteger(message.payload.windowId) &&
      message.payload.windowId >= 0
        ? message.payload.windowId
        : null;

    discoverProviderTabs(targetWindowId)
      .then((groupedTabs) => {
        sendResponse({ ok: true, providers: groupedTabs });
      })
      .catch((err) => {
        sendResponse({
          ok: false,
          error: err instanceof Error ? err.message : 'Failed to query tabs.'
        });
      });
    return true;
  }

  if (message.action === 'OPEN_PROVIDER_TAB') {
    const providerKey =
      message.payload && typeof message.payload.providerKey === 'string'
        ? message.payload.providerKey
        : '';

    if (!Object.prototype.hasOwnProperty.call(AI_PROVIDERS, providerKey)) {
      sendResponse({ ok: false, error: 'Invalid AI provider identifier.' });
      return false;
    }

    const targetWindowId =
      message.payload &&
      typeof message.payload.windowId === 'number' &&
      Number.isInteger(message.payload.windowId) &&
      message.payload.windowId >= 0
        ? message.payload.windowId
        : null;

    const launchUrl = AI_PROVIDERS[providerKey].launchUrl;
    const createProperties = { url: launchUrl, active: false };
    if (targetWindowId !== null) {
      createProperties.windowId = targetWindowId;
    }

    chrome.tabs
      .create(createProperties)
      .then((tab) => {
        sendResponse({ ok: true, tabId: tab.id, providerKey });
      })
      .catch((err) => {
        sendResponse({
          ok: false,
          error: err instanceof Error ? err.message : 'Could not open tab.'
        });
      });
    return true;
  }

  if (message.action === 'BROADCAST_TO_PROVIDERS') {
    handleBroadcastToProviders(message.payload)
      .then((result) => {
        sendResponse(result);
      })
      .catch((err) => {
        sendResponse({
          ok: false,
          error: err instanceof Error ? err.message : 'Broadcast failed.'
        });
      });
    return true;
  }

  return false;
});

