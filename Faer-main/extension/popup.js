document.addEventListener('DOMContentLoaded', async () => {
  // 1. Get Active Tab Info immediately for the Glimpse
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

  if (tab) {
    const titleEl = document.getElementById('siteTitle');
    const domainEl = document.getElementById('siteDomain');
    const iconEl = document.getElementById('favicon');
    const gmailHint = document.getElementById('gmailHint');

    // Set Title
    titleEl.textContent = tab.title || 'Unknown Page';

    // Set Domain
    if (tab.url) {
      try {
        const urlObj = new URL(tab.url);
        domainEl.textContent = urlObj.hostname;

        if (tab.url.startsWith('chrome://') || tab.url.startsWith('edge://')) {
          titleEl.textContent = "System Page";
          domainEl.textContent = "Browser Internal";
        }

        // Show Gmail hint if user is on Gmail
        if (urlObj.hostname === 'mail.google.com') {
          gmailHint.classList.add('visible');
        }
      } catch (e) {
        domainEl.textContent = 'Invalid URL';
      }
    }

    // Set Favicon
    if (tab.favIconUrl) {
      iconEl.src = tab.favIconUrl;
    } else {
      iconEl.style.display = 'none';
    }
  }
});

// ========== SCAN WEBSITE ==========
document.getElementById('scanWebBtn').addEventListener('click', async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

  if (!tab.url || tab.url.startsWith('chrome://') || tab.url.startsWith('edge://')) {
    alert('Cannot scan browser system pages.');
    return;
  }

  chrome.scripting.executeScript({
    target: { tabId: tab.id },
    function: getPageContent,
  }, (results) => {
    if (chrome.runtime.lastError) {
      console.error(chrome.runtime.lastError);
      alert('Error scanning page: ' + chrome.runtime.lastError.message);
      return;
    }
    if (results && results[0]) {
      const { url, text } = results[0].result;
      const safeText = text.substring(0, 3000);
      // type=website tells the webapp to open the Overview/Dashboard page
      const targetUrl = `http://localhost:5173/?type=website&url=${encodeURIComponent(url)}&text=${encodeURIComponent(safeText)}`;
      chrome.tabs.create({ url: targetUrl });
    }
  });
});

// ========== SCAN EMAIL ==========
document.getElementById('scanEmailBtn').addEventListener('click', async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

  if (!tab.url || tab.url.startsWith('chrome://') || tab.url.startsWith('edge://')) {
    alert('Cannot scan browser system pages.');
    return;
  }

  chrome.scripting.executeScript({
    target: { tabId: tab.id },
    function: getEmailContent,
  }, (results) => {
    if (chrome.runtime.lastError) {
      console.error(chrome.runtime.lastError);
      alert('Error extracting email: ' + chrome.runtime.lastError.message);
      return;
    }
    if (results && results[0]) {
      const { sender, subject, body } = results[0].result;
      const safeBody = body.substring(0, 4000);
      // type=email tells the webapp to open the Email Scanner page
      const targetUrl = `http://localhost:5173/?type=email&sender=${encodeURIComponent(sender)}&subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(safeBody)}`;
      chrome.tabs.create({ url: targetUrl });
    }
  });
});

// ========== SCAN CHAT ==========
document.getElementById('scanChatBtn').addEventListener('click', async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

  if (!tab.url || tab.url.startsWith('chrome://') || tab.url.startsWith('edge://')) {
    alert('Cannot scan browser system pages.');
    return;
  }

  chrome.scripting.executeScript({
    target: { tabId: tab.id },
    function: getChatContent,
  }, (results) => {
    if (chrome.runtime.lastError) {
      console.error(chrome.runtime.lastError);
      alert('Error extracting chat: ' + chrome.runtime.lastError.message);
      return;
    }
    if (results && results[0]) {
      const { sender, message } = results[0].result;
      
      if (!message) {
        alert('Please highlight the suspicious chat message text before scanning!');
        return;
      }
      
      const safeMessage = message.substring(0, 4000);
      // type=chat tells the webapp to open the Chat Scanner page
      const targetUrl = `http://localhost:5173/?type=chat&sender=${encodeURIComponent(sender || '')}&message=${encodeURIComponent(safeMessage)}`;
      chrome.tabs.create({ url: targetUrl });
    }
  });
});

// ========== CONTENT EXTRACTION FUNCTIONS ==========

function getPageContent() {
  return {
    url: window.location.href,
    text: document.body.innerText
  };
}

function getEmailContent() {
  let sender = '';
  let subject = '';
  let body = '';

  const getVisibleOrLast = (selector) => {
    const elements = Array.from(document.querySelectorAll(selector));
    const visible = elements.filter(el => el.offsetWidth > 0 || el.offsetHeight > 0);
    if (visible.length > 0) {
      return visible[visible.length - 1];
    }
    if (elements.length > 0) {
      return elements[elements.length - 1];
    }
    return null;
  };

  // ===== GMAIL EXTRACTION =====
  if (window.location.hostname === 'mail.google.com') {

    // --- Sender ---
    const senderSelectors = [
      'span.gD[email]',                 // Specific Gmail sender element
      'span.gD',                        // Sender name class
      '[data-hovercard-id]',            // Hovercard on sender name
      'table.cf.gJ span[email]',        // Sender in header table
      'span.go',                        // Sender in message header
      'span[email]',                    // Fallback generic email attribute
    ];

    for (const sel of senderSelectors) {
      const el = getVisibleOrLast(sel);
      if (el) {
        sender = el.getAttribute('email') || el.getAttribute('data-hovercard-id') || el.textContent.trim();
        if (sender) break;
      }
    }

    // --- Subject ---
    const subjectSelectors = [
      'h2[data-thread-perm-id]',
      'h2.hP',
      'div[data-thread-perm-id] h2',
      'h2[data-legacy-thread-id]',
    ];

    for (const sel of subjectSelectors) {
      const el = getVisibleOrLast(sel);
      if (el) {
        subject = el.textContent.trim();
        if (subject) break;
      }
    }

    if (!subject && document.title) {
      const titleParts = document.title.split(' - ');
      if (titleParts.length >= 2) {
        subject = titleParts[0].trim();
      }
    }

    // --- Body ---
    const bodySelectors = [
      'div.a3s.aiL',
      'div.a3s',
      'div[data-message-id] div.a3s',
      'div.ii.gt',
    ];

    for (const sel of bodySelectors) {
      const el = getVisibleOrLast(sel);
      if (el) {
        body = el.innerText.trim();
        if (body) break;
      }
    }

    if (!body) {
      const allBodies = Array.from(document.querySelectorAll('div.a3s')).filter(el => el.offsetWidth > 0 || el.offsetHeight > 0);
      if (allBodies.length > 0) {
        body = allBodies.map(el => el.innerText.trim()).join('\n---\n');
      }
    }
  }

  else if (window.location.hostname.includes('outlook.live.com') || window.location.hostname.includes('outlook.office.com')) {
    // Sender
    const senderEl = getVisibleOrLast('[data-testid="SenderPersona"] span') ||
      getVisibleOrLast('.lpc-hoverTarget span');
    if (senderEl) sender = senderEl.textContent.trim();

    // Subject
    const subjectEl = getVisibleOrLast('[role="heading"][aria-level="2"]') ||
      getVisibleOrLast('span[title].rps_49dc');
    if (subjectEl) subject = subjectEl.textContent.trim();

    // Body
    const bodyEl = getVisibleOrLast('[role="document"]') ||
      getVisibleOrLast('div[aria-label="Message body"]');
    if (bodyEl) body = bodyEl.innerText.trim();
  }

  // ===== GENERIC FALLBACK =====
  // If nothing was extracted, grab everything visible on the page
  if (!sender && !subject && !body) {
    // Try to extract from visible page content as a last resort
    body = document.body.innerText;

    // Try to infer subject from page title
    if (document.title) {
      subject = document.title;
    }
  }

  return { sender, subject, body };
}

function getChatContent() {
  let sender = '';
  let message = window.getSelection().toString().trim();

  try {
    // Try to auto-extract sender from known chat platforms
    const host = window.location.hostname;
    
    if (host.includes('web.whatsapp.com')) {
      const headerTitle = document.querySelector('#main header span[title]');
      if (headerTitle) {
        sender = headerTitle.getAttribute('title').trim();
      } else {
        const altHeader = document.querySelector('#main header [dir="auto"]');
        if (altHeader) sender = altHeader.textContent.trim();
      }
    } else if (host.includes('web.telegram.org')) {
      const headerTitle = document.querySelector('.chat-title, .ChatInfo .person-name, .info .title');
      if (headerTitle) {
        sender = headerTitle.textContent.trim();
      }
    } else if (host.includes('messages.google.com')) {
      const headerTitle = document.querySelector('.conversation-title, mws-conversation-list-item[selected] .name');
      if (headerTitle) {
        sender = headerTitle.textContent.trim();
      }
    }
  } catch(e) {
    console.error("Auto-extraction of sender failed", e);
  }

  return { sender, message };
}
