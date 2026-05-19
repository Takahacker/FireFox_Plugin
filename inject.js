// Runs inside the page's JS context (injected via content.js).
// Hooks native browser APIs used for fingerprinting and reports detections
// back to content.js via window.postMessage.
(function () {
  'use strict';

  function report(type, api, method, extra) {
    window.postMessage(
      Object.assign({ source: 'PRIVACY_GUARD', type, api, method }, extra),
      '*'
    );
  }

  function reportFP(api, method) {
    report('FINGERPRINT', api, method);
  }

  function reportHijack(data) {
    report('HIJACK', null, null, { data });
  }

  // ── Canvas fingerprinting ──────────────────────────────────────────────
  // toDataURL and getImageData are the canonical canvas FP methods.
  // They convert rendered pixel data to a value that encodes GPU + font rendering.
  (function hookCanvas() {
    const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
    HTMLCanvasElement.prototype.toDataURL = function (...args) {
      reportFP('Canvas', 'toDataURL');
      return origToDataURL.apply(this, args);
    };

    const origToBlob = HTMLCanvasElement.prototype.toBlob;
    HTMLCanvasElement.prototype.toBlob = function (...args) {
      reportFP('Canvas', 'toBlob');
      return origToBlob.apply(this, args);
    };

    const origGetImageData = CanvasRenderingContext2D.prototype.getImageData;
    CanvasRenderingContext2D.prototype.getImageData = function (...args) {
      reportFP('Canvas', 'getImageData');
      return origGetImageData.apply(this, args);
    };
  })();

  // ── WebGL fingerprinting ───────────────────────────────────────────────
  // getParameter() exposes GPU vendor/renderer info.
  // WEBGL_debug_renderer_info extension gives unmasked hardware strings.
  function hookWebGLContext(Ctx) {
    if (!Ctx) return;

    const origGetParameter = Ctx.prototype.getParameter;
    Ctx.prototype.getParameter = function (param) {
      // UNMASKED_VENDOR_WEBGL = 37445, UNMASKED_RENDERER_WEBGL = 37446
      if (param === 37445 || param === 37446) {
        reportFP('WebGL', 'getParameter(WEBGL_debug_renderer_info)');
      } else if (param === 7937 || param === 7938 || param === 35724) {
        // RENDERER=7937, VERSION=7938, SHADING_LANGUAGE_VERSION=35724
        reportFP('WebGL', 'getParameter');
      } else {
        reportFP('WebGL', 'getParameter');
      }
      return origGetParameter.call(this, param);
    };

    const origGetExtension = Ctx.prototype.getExtension;
    Ctx.prototype.getExtension = function (name) {
      if (name === 'WEBGL_debug_renderer_info') {
        reportFP('WebGL', 'getExtension(WEBGL_debug_renderer_info)');
      }
      return origGetExtension.call(this, name);
    };

    const origGetSupportedExtensions = Ctx.prototype.getSupportedExtensions;
    Ctx.prototype.getSupportedExtensions = function (...args) {
      reportFP('WebGL', 'getSupportedExtensions');
      return origGetSupportedExtensions.apply(this, args);
    };
  }

  hookWebGLContext(window.WebGLRenderingContext);
  hookWebGLContext(window.WebGL2RenderingContext);

  // ── AudioContext fingerprinting ────────────────────────────────────────
  // createOscillator + createDynamicsCompressor are used to render a unique
  // audio signal that encodes CPU and audio hardware characteristics.
  function hookAudioContext(Ctx) {
    if (!Ctx) return;

    const origCreateOscillator = Ctx.prototype.createOscillator;
    Ctx.prototype.createOscillator = function (...args) {
      reportFP('AudioContext', 'createOscillator');
      return origCreateOscillator.apply(this, args);
    };

    const origCreateDynamicsCompressor = Ctx.prototype.createDynamicsCompressor;
    Ctx.prototype.createDynamicsCompressor = function (...args) {
      reportFP('AudioContext', 'createDynamicsCompressor');
      return origCreateDynamicsCompressor.apply(this, args);
    };

    const origCreateAnalyser = Ctx.prototype.createAnalyser;
    Ctx.prototype.createAnalyser = function (...args) {
      reportFP('AudioContext', 'createAnalyser');
      return origCreateAnalyser.apply(this, args);
    };

    const origCreateBuffer = Ctx.prototype.createBuffer;
    Ctx.prototype.createBuffer = function (...args) {
      reportFP('AudioContext', 'createBuffer');
      return origCreateBuffer.apply(this, args);
    };
  }

  hookAudioContext(window.AudioContext);
  hookAudioContext(window.OfflineAudioContext);

  // ── Browser hijacking / hooking detection ─────────────────────────────
  // Detect attempts to override core browser functions.
  const sensitiveOverrides = [
    ['history', 'pushState'],
    ['history', 'replaceState'],
    ['navigator', 'userAgent'],
    ['navigator', 'platform'],
    ['navigator', 'languages']
  ];

  for (const [obj, prop] of sensitiveOverrides) {
    const target = window[obj];
    if (!target) continue;
    const descriptor = Object.getOwnPropertyDescriptor(target, prop);
    if (!descriptor) continue;

    try {
      Object.defineProperty(target, prop, {
        get: descriptor.get || (() => descriptor.value),
        set(val) {
          reportHijack({
            type: 'property-override',
            target: `${obj}.${prop}`,
            reason: `Attempt to override ${obj}.${prop} detected`
          });
          if (descriptor.set) descriptor.set.call(this, val);
        },
        configurable: true
      });
    } catch { /* some properties are non-configurable */ }
  }
})();
