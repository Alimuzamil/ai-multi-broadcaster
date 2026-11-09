/**
 * @file content/clipboard-hook.js
 * @description MAIN-world navigator.clipboard.writeText interceptor for AI Multi-Broadcaster.
 *
 * Captures native public share URLs when provider Share dialogs invoke
 * navigator.clipboard.writeText(), including when the provider tab is in the background
 * and native clipboard writes would otherwise fail due to document focus restrictions.
 */

'use strict';

(() => {
  try {
    const c = navigator.clipboard;
    if (!c || typeof c.writeText !== 'function' || c.__ambHooked) {
      return;
    }
    const orig = c.writeText.bind(c);
    c.writeText = (text) => {
      try {
        const s = String(text);
        if (s.length < 2048 && s.startsWith('https://')) {
          window.postMessage(
            { type: '__AMB_SHARE_CLIPBOARD__', text: s },
            location.origin
          );
        }
      } catch {
        // Ignore postMessage serialization errors
      }
      return orig(text).catch(() => {
        // Background-tab focus errors are expected and safely swallowed
      });
    };
    Object.defineProperty(c, '__ambHooked', {
      value: true,
      configurable: false,
      enumerable: false,
      writable: false
    });
  } catch {
    // Ignore if navigator.clipboard is non-configurable in this frame
  }
})();

