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

  // ===== GMAIL EXTRACTION =====
  if (window.location.hostname === 'mail.google.com') {

    // --- Sender ---
    // Gmail uses data-hovercard-id or email attribute on sender elements
    const senderSelectors = [
      'span[email]',                    // Most reliable - has email attribute
      '[data-hovercard-id]',            // Hovercard on sender name
      'span.gD',                        // Sender name in expanded view
      'span.go',                        // Sender in message header
      'table.cf.gJ span[email]',       // Sender in header table
    ];

    for (const sel of senderSelectors) {
      const el = document.querySelector(sel);
      if (el) {
        sender = el.getAttribute('email') || el.getAttribute('data-hovercard-id') || el.textContent.trim();
        if (sender) break;
      }
    }

    // --- Subject ---
    const subjectSelectors = [
      'h2[data-thread-perm-id]',       // Thread subject heading
      'h2.hP',                          // Subject line in conversation view
      'div[data-thread-perm-id] h2',   // Nested subject
      'h2[data-legacy-thread-id]',     // Legacy thread ID heading
    ];

    for (const sel of subjectSelectors) {
      const el = document.querySelector(sel);
      if (el) {
        subject = el.textContent.trim();
        if (subject) break;
      }
    }

    // If subject still not found, try the page title (Gmail sets it to subject)
    if (!subject && document.title) {
      // Gmail title format: "Subject - sender@email.com - Gmail"
      const titleParts = document.title.split(' - ');
      if (titleParts.length >= 2) {
        subject = titleParts[0].trim();
      }
    }

    // --- Body ---
    const bodySelectors = [
      'div.a3s.aiL',                   // Main email body container
      'div.a3s',                        // Email body without aiL class
      'div[data-message-id] div.a3s',  // Scoped to message
      'div.ii.gt',                      // Another body container
    ];

    for (const sel of bodySelectors) {
      const el = document.querySelector(sel);
      if (el) {
        body = el.innerText.trim();
        if (body) break;
      }
    }

    // If multiple email bodies (conversation), get all
    if (!body) {
      const allBodies = document.querySelectorAll('div.a3s');
      if (allBodies.length > 0) {
        body = Array.from(allBodies).map(el => el.innerText.trim()).join('\n---\n');
      }
    }
  }

  else if (window.location.hostname.includes('outlook.live.com') || window.location.hostname.includes('outlook.office.com')) {
    // Sender
    const senderEl = document.querySelector('[data-testid="SenderPersona"] span') ||
      document.querySelector('.lpc-hoverTarget span');
    if (senderEl) sender = senderEl.textContent.trim();

    // Subject
    const subjectEl = document.querySelector('[role="heading"][aria-level="2"]') ||
      document.querySelector('span[title].rps_49dc');
    if (subjectEl) subject = subjectEl.textContent.trim();

    // Body
    const bodyEl = document.querySelector('[role="document"]') ||
      document.querySelector('div[aria-label="Message body"]');
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
