// Mark the page so the report UI can detect the extension.
document.documentElement.setAttribute('data-bb-ext', '1');

// Relay "open session" requests from the page to the background worker.
window.addEventListener('message', function (ev) {
  if (ev.source !== window) return;
  var msg = ev.data;
  if (!msg || msg.type !== 'BB_OPEN_SESSION') return;
  chrome.runtime.sendMessage({
    type: 'BB_OPEN_SESSION',
    domain: msg.domain,
    reportId: msg.reportId,
    serverUrl: window.location.origin
  }, function (resp) {
    window.postMessage({
      type: 'BB_OPEN_SESSION_RESULT',
      ok: !!(resp && resp.ok),
      error: resp && resp.error
    }, '*');
  });
});
