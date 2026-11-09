/**
 * @file utils/security.js
 * @description Zero-Trust Security & Memory Hygiene Utilities.
 *
 * Enforces:
 *  1. Strict sender, context (Side Panel vs Service Worker vs Content Script), and origin verification.
 *  2. Schema, MIME-type, and binary Magic-Byte signature validation for image attachments.
 *  3. Filename sanitization against path-traversal or control-character injection.
 *  4. Volatile memory scrubbing to zero-out references immediately after dispatch.
 */

'use strict';

(function initSecurityUtils(globalScope) {
  const ALLOWED_ACTIONS = Object.freeze(new Set([
    'PING_PROVIDER',
    'DISPATCH_PROMPT',
    'BROADCAST_TO_PROVIDERS',
    'QUERY_ACTIVE_PROVIDERS',
    'OPEN_PROVIDER_TAB',
    'GENERATE_SHARE_LINK'
  ]));

  const ALLOWED_IMAGE_MIME_TYPES = Object.freeze(new Set([
    'image/png',
    'image/jpeg',
    'image/webp',
    'image/gif'
  ]));

  const MAX_PROMPT_LENGTH = 200000;
  const MAX_IMAGE_COUNT = 10;
  const MAX_SINGLE_IMAGE_BYTES = 20 * 1024 * 1024; // 20 MB per image
  const MAX_TOTAL_IMAGE_BYTES = 50 * 1024 * 1024;  // 50 MB total per broadcast

  const DATA_URL_PREFIX_REGEX = /^data:(image\/(?:png|jpeg|webp|gif));base64,([A-Za-z0-9+/=]+)$/;

  /**
   * Validates that an incoming chrome.runtime message originates from this extension
   * and conforms to the expected top-level structure.
   *
   * @param {unknown} message
   * @param {chrome.runtime.MessageSender} sender
   * @returns {{ valid: boolean, reason?: string }}
   */
  function validateMessageEnvelope(message, sender) {
    if (!sender || typeof sender !== 'object') {
      return { valid: false, reason: 'Missing message sender metadata.' };
    }
    if (typeof chrome !== 'undefined' && chrome.runtime && sender.id !== chrome.runtime.id) {
      return { valid: false, reason: 'Untrusted extension sender ID.' };
    }
    // Reject messages originating from content script tabs when sent to privileged listeners,
    // or messages from tab contexts pretending to be the background service worker.
    if (sender.tab) {
      return { valid: false, reason: 'Messages from content script tab contexts are not permitted.' };
    }
    if (!message || typeof message !== 'object' || Array.isArray(message)) {
      return { valid: false, reason: 'Malformed message envelope.' };
    }
    if (typeof message.action !== 'string' || !ALLOWED_ACTIONS.has(message.action)) {
      return { valid: false, reason: 'Disallowed or unknown message action.' };
    }
    return { valid: true };
  }

  /**
   * Verifies that the binary file header (magic bytes) matches the declared image MIME type.
   * Prevents MIME-spoofing attacks (e.g., an HTML/SVG/executable renamed to .png).
   *
   * @param {Uint8Array} bytes
   * @param {string} mimeType
   * @returns {boolean}
   */
  function verifyImageMagicBytes(bytes, mimeType) {
    if (!(bytes instanceof Uint8Array) || bytes.length < 12) {
      return false;
    }
    if (mimeType === 'image/png') {
      // 89 50 4E 47 0D 0A 1A 0A
      return (
        bytes[0] === 0x89 &&
        bytes[1] === 0x50 &&
        bytes[2] === 0x4e &&
        bytes[3] === 0x47 &&
        bytes[4] === 0x0d &&
        bytes[5] === 0x0a &&
        bytes[6] === 0x1a &&
        bytes[7] === 0x0a
      );
    }
    if (mimeType === 'image/jpeg') {
      // FF D8 FF
      return bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff;
    }
    if (mimeType === 'image/gif') {
      // 'GIF87a' or 'GIF89a'
      return (
        bytes[0] === 0x47 &&
        bytes[1] === 0x49 &&
        bytes[2] === 0x46 &&
        bytes[3] === 0x38 &&
        (bytes[4] === 0x37 || bytes[4] === 0x39) &&
        bytes[5] === 0x61
      );
    }
    if (mimeType === 'image/webp') {
      // 'RIFF'....'WEBP'
      return (
        bytes[0] === 0x52 &&
        bytes[1] === 0x49 &&
        bytes[2] === 0x46 &&
        bytes[3] === 0x46 &&
        bytes[8] === 0x57 &&
        bytes[9] === 0x45 &&
        bytes[10] === 0x42 &&
        bytes[11] === 0x50
      );
    }
    return false;
  }

  /**
   * Sanitizes a filename to prevent control characters, HTML specials, or path traversal.
   * @param {unknown} rawName
   * @param {string} fallbackMime
   * @returns {string}
   */
  function sanitizeFileName(rawName, fallbackMime) {
    const extMap = {
      'image/png': '.png',
      'image/jpeg': '.jpg',
      'image/webp': '.webp',
      'image/gif': '.gif'
    };
    const defaultExt = extMap[fallbackMime] || '.png';

    if (typeof rawName !== 'string' || !rawName.trim()) {
      return 'attachment' + defaultExt;
    }

    const cleaned = rawName
      .replace(/[\u0000-\u001F\u007F<>:"/\\|?*]+/g, '_')
      .replace(/\.{2,}/g, '.')
      .replace(/^[.\s_]+|[.\s_]+$/g, '')
      .slice(0, 80);

    if (!cleaned) {
      return 'attachment' + defaultExt;
    }
    const hasValidExt = /\.(png|jpe?g|webp|gif)$/i.test(cleaned);
    return hasValidExt ? cleaned : cleaned + defaultExt;
  }

  /**
   * Sanitizes prompt text without altering legitimate user formatting/code blocks.
   * Removes only null bytes and validates length boundaries.
   * @param {unknown} rawPrompt
   * @returns {{ valid: boolean, prompt: string, reason?: string }}
   */
  function validatePromptText(rawPrompt) {
    if (typeof rawPrompt !== 'string') {
      return { valid: false, prompt: '', reason: 'Prompt must be a string.' };
    }
    const sanitized = rawPrompt.replace(/\u0000/g, '');
    if (sanitized.length > MAX_PROMPT_LENGTH) {
      return {
        valid: false,
        prompt: '',
        reason: `Prompt exceeds maximum length of ${MAX_PROMPT_LENGTH} characters.`
      };
    }
    return { valid: true, prompt: sanitized };
  }

  /**
   * Validates an array of serialized image attachments in volatile memory.
   * Each attachment must have: { name: string, type: string, size: number, dataUrl: string }
   *
   * @param {unknown} images
   * @returns {{ valid: boolean, reason?: string }}
   */
  function validateImageAttachments(images) {
    if (images === undefined || images === null) {
      return { valid: true };
    }
    if (!Array.isArray(images)) {
      return { valid: false, reason: 'Attachments payload must be an array.' };
    }
    if (images.length > MAX_IMAGE_COUNT) {
      return { valid: false, reason: `Maximum of ${MAX_IMAGE_COUNT} images allowed per broadcast.` };
    }

    let totalBytes = 0;
    for (let i = 0; i < images.length; i += 1) {
      const item = images[i];
      if (!item || typeof item !== 'object') {
        return { valid: false, reason: `Attachment at index ${i} is malformed.` };
      }
      if (!ALLOWED_IMAGE_MIME_TYPES.has(item.type)) {
        return { valid: false, reason: `Unsupported image MIME type: ${String(item.type)}` };
      }
      if (typeof item.size !== 'number' || !Number.isFinite(item.size) || item.size <= 0) {
        return { valid: false, reason: `Invalid file size for attachment ${i + 1}.` };
      }
      if (item.size > MAX_SINGLE_IMAGE_BYTES) {
        return { valid: false, reason: `Attachment ${i + 1} exceeds 20 MB limit.` };
      }
      totalBytes += item.size;
      if (totalBytes > MAX_TOTAL_IMAGE_BYTES) {
        return { valid: false, reason: 'Total image attachments exceed 50 MB limit.' };
      }
      if (typeof item.dataUrl !== 'string' || !DATA_URL_PREFIX_REGEX.test(item.dataUrl)) {
        return { valid: false, reason: `Attachment ${i + 1} failed Base64 DataURL integrity check.` };
      }
    }

    return { valid: true };
  }

  /**
   * Validates a full dispatch payload (prompt + optional images).
   * Requires at least non-empty prompt text OR at least one valid image.
   *
   * @param {unknown} payload
   * @returns {{ valid: boolean, reason?: string }}
   */
  function validateDispatchPayload(payload) {
    if (!payload || typeof payload !== 'object') {
      return { valid: false, reason: 'Missing dispatch payload.' };
    }
    const promptCheck = validatePromptText(payload.prompt ?? '');
    if (!promptCheck.valid) {
      return promptCheck;
    }
    const imageCheck = validateImageAttachments(payload.images ?? []);
    if (!imageCheck.valid) {
      return imageCheck;
    }
    const hasText = promptCheck.prompt.trim().length > 0;
    const hasImages = Array.isArray(payload.images) && payload.images.length > 0;
    if (!hasText && !hasImages) {
      return { valid: false, reason: 'Provide a prompt or attach at least one image.' };
    }
    return { valid: true };
  }

  /**
   * Reconstructs a native File object from a validated Base64 DataURL in volatile memory.
   * Verifies binary magic bytes and zeroes out the intermediate Uint8Array buffer copy
   * immediately once the Blob/File is constructed.
   *
   * @param {{ name: string, type: string, dataUrl: string }} serializedImage
   * @returns {File}
   */
  function dataUrlToVolatileFile(serializedImage) {
    const match = DATA_URL_PREFIX_REGEX.exec(serializedImage.dataUrl);
    if (!match) {
      throw new Error('Invalid image DataURL format.');
    }
    const mimeType = match[1];
    const base64Data = match[2];
    const binaryString = atob(base64Data);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);

    for (let i = 0; i < len; i += 1) {
      bytes[i] = binaryString.charCodeAt(i);
    }

    if (!verifyImageMagicBytes(bytes, mimeType)) {
      bytes.fill(0);
      throw new Error(`Binary file signature does not match declared MIME type (${mimeType}).`);
    }

    const safeName = sanitizeFileName(serializedImage.name, mimeType);
    const file = new File([bytes], safeName, {
      type: mimeType,
      lastModified: Date.now()
    });

    // Zero out the typed array after File construction for defense-in-depth memory hygiene
    bytes.fill(0);
    return file;
  }

  /**
   * Validates a candidate public share URL against strict HTTPS, credential-free,
   * and provider-specific shareUrlPattern rules.
   *
   * @param {string} providerKey
   * @param {unknown} rawUrl
   * @returns {string | null} Normalized URL string if valid, otherwise null.
   */
  function validateShareUrl(providerKey, rawUrl) {
    if (typeof providerKey !== 'string' || typeof rawUrl !== 'string') {
      return null;
    }
    const trimmed = rawUrl.trim();
    if (trimmed.length === 0 || trimmed.length > 2048) {
      return null;
    }
    let parsed;
    try {
      parsed = new URL(trimmed);
    } catch {
      return null;
    }
    if (parsed.protocol !== 'https:' || parsed.username !== '' || parsed.password !== '') {
      return null;
    }
    const providers = globalScope.AI_PROVIDERS;
    if (!providers || !Object.prototype.hasOwnProperty.call(providers, providerKey)) {
      return null;
    }
    const providerConfig = providers[providerKey];
    if (
      !providerConfig ||
      !providerConfig.share ||
      !(providerConfig.share.shareUrlPattern instanceof RegExp)
    ) {
      return null;
    }
    const normalized = parsed.href;
    if (!providerConfig.share.shareUrlPattern.test(normalized)) {
      return null;
    }
    return normalized;
  }

  /**
   * Explicitly scrubs a dispatch payload object in-place so sensitive prompt strings
   * and Base64 image buffers are dereferenced for immediate garbage collection.
   *
   * @param {Object | null | undefined} payload
   */
  function scrubVolatilePayload(payload) {
    if (!payload || typeof payload !== 'object') {
      return;
    }
    if (Array.isArray(payload.images)) {
      for (let i = 0; i < payload.images.length; i += 1) {
        const item = payload.images[i];
        if (item && typeof item === 'object') {
          item.dataUrl = '';
          item.name = '';
        }
        payload.images[i] = null;
      }
      payload.images.length = 0;
    }
    if ('prompt' in payload) {
      payload.prompt = '';
    }
  }

  globalScope.SecurityUtils = Object.freeze({
    ALLOWED_ACTIONS,
    ALLOWED_IMAGE_MIME_TYPES,
    MAX_PROMPT_LENGTH,
    MAX_IMAGE_COUNT,
    MAX_SINGLE_IMAGE_BYTES,
    MAX_TOTAL_IMAGE_BYTES,
    validateMessageEnvelope,
    verifyImageMagicBytes,
    sanitizeFileName,
    validatePromptText,
    validateImageAttachments,
    validateDispatchPayload,
    dataUrlToVolatileFile,
    validateShareUrl,
    scrubVolatilePayload
  });
})(typeof globalThis !== 'undefined' ? globalThis : self);
