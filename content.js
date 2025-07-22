/**
 * Content Script for Tech Support Scam Detector Extension (MVP)
 *
 * This script detects tech support scams and displays a generic warning banner.
 *
 * Branding: Uses red/yellow for severity, a warning icon, and generic scam advice.
 */

// MVP NOTE:
// This extension uses a small, curated list of trusted domains for demo purposes.
// In a full product, we would use scalable heuristics, user customization, or a remote API
// to reduce false positives on legitimate sites.

// --- Scam Detection MVP Configuration ---
const scamIndicators = {
  // High-risk keywords: Strong indicators of a scam
  highRiskKeywords: [
    'virus detected', 'security alert', 'illegal website', 'hack attempt',
    'call support', 'tech support', 'microsoft support', 'apple support',
    'your computer is infected', 'critical alert', 'security warning',
    'system error', 'windows error', 'mac error', 'license expired',
    'renew license', 'your account is locked', 'suspicious activity',
    'unauthorized access', 'your device is at risk', 'immediate action required',
    'security breach', 'data breach', 'your information is at risk',
    'call now', 'toll-free', '1-800', '1-888', '1-877', '1-866', '1-855', '1-844',
    'call immediately', 'do not ignore', 'your data will be deleted', 'government notice',
    'fbi warning', 'police report', 'bank account suspended',
    'unauthorized payment', 'illegal content detected', 'your files are encrypted',
    'malware infection', 'system compromised', 'dangerous website'
  ],
  // Medium-risk keywords: Weaker, but still suspicious
  mediumRiskKeywords: [
    'warning', 'alert', 'error', 'problem', 'issue', 'help', 'support',
    'contact', 'call', 'phone', 'number', 'assistance', 'service',
    'technical', 'computer', 'device', 'system', 'security', 'protection',
    'scan', 'detect', 'remove', 'fix', 'repair', 'renew', 'expired',
    'subscription', 'account', 'login', 'password', 'verify', 'confirm',
    'popup', 'popup alert', 'auto-renew', 'your system has been compromised',
    'free trial', 'limited time', 'act now', 'upgrade',
    'important update', 'attention', 'service required',
    'your session has expired', 'auto-debit', 'unusual login attempt'
  ],
  // Suspicious TLDs: Uncommon or high-risk domain extensions
  suspiciousTLDs: [
    'xyz', 'top', 'online', 'support', 'click', 'gq', 'tk', 'ml', 'cf', 'ga'
  ],
  // Trusted domains: Whitelisted, never flagged
  trustedDomains: [
    'microsoft.com', 'apple.com', 'google.com', 'youtube.com',
    'facebook.com', 'twitter.com', 'x.com', 'linkedin.com', 'reddit.com',
    'stackoverflow.com', 'github.com', 'wikipedia.org', 'wikimedia.org',
    'medium.com', 'quora.com', 'techcrunch.com', 'wired.com', 'theverge.com',
    'arstechnica.com', 'cnet.com', 'pcmag.com', 'howtogeek.com',
    'gmail.com', 'outlook.com', 'yahoo.com', 'protonmail.com',
    'dropbox.com', 'onedrive.live.com', 'drive.google.com',
    'chase.com', 'bankofamerica.com', 'wellsfargo.com',
    'irs.gov', 'ssa.gov', 'usps.com', 'fedex.com', 'ups.com'
  ],
  // Search engine domains: Never flagged
  searchEngineDomains: [
    'google.com', 'www.google.com', 'bing.com', 'www.bing.com',
    'yahoo.com', 'www.yahoo.com', 'search.yahoo.com', 'search.bing.com',
    'duckduckgo.com', 'www.duckduckgo.com', 'startpage.com', 'www.startpage.com',
    'search.brave.com', 'brave.com', 'www.brave.com', 'ecosia.org', 'www.ecosia.org',
    'google.ca', 'www.google.ca', 'ask.com', 'aol.com', 'yandex.com'
  ],
  // Educational/discussion phrases: Used to skip educational/discussion content
  educationalPhrases: [
    'how to spot', 'how to identify', 'warning signs of', 'common scams', 'scam alert',
    'fraud prevention', 'security tips', 'how to protect', 'scam awareness', 'educational',
    'tutorial', 'guide', 'article', 'blog post', 'discussion', 'forum', 'community',
    'help center', 'support center', 'knowledge base', 'documentation', 'question', 'answer',
    'asked', 'answered', 'quora', 'discussion thread', 'forum post', 'community post',
    'user comment', 'user response', 'expert answer', 'tweet', 'thread', 'retweet', 'reply',
    'quote tweet', 'social media post', 'status update', 'timeline', 'shared experience',
    'my story', 'i was scammed', 'report scam', 'how i recovered', 'reddit thread'
  ]
};

/**
 * Checks if a domain is in the trusted domains list
 * @param {string} domain
 * @returns {boolean}
 */
function isTrustedDomain(domain) {
  return scamIndicators.trustedDomains.some(trusted => 
    domain === trusted || domain.endsWith('.' + trusted)
  );
}

/**
 * Checks if a domain is a search engine
 * @param {string} domain
 * @returns {boolean}
 */
function isSearchEngine(domain) {
  return scamIndicators.searchEngineDomains.some(searchEngine => 
    domain === searchEngine || domain.endsWith('.' + searchEngine)
  );
}

/**
 * Checks if the page is educational or a discussion (to avoid false positives)
 * @param {string} text
 * @returns {boolean}
 */
function isEducationalContent(text) {
  const lowerText = text.toLowerCase();
  // Social media and major discussion platforms are always considered educational
  if (window.location.hostname.includes('twitter.com') ||
      window.location.hostname.includes('x.com') ||
      window.location.hostname.includes('facebook.com') ||
      window.location.hostname.includes('linkedin.com') ||
      window.location.hostname.includes('reddit.com') ||
      window.location.hostname.includes('quora.com') ||
      window.location.hostname.includes('stackoverflow.com')) {
    return true;
  }
  // Check for educational/discussion phrases
  const hasEducationalPhrase = scamIndicators.educationalPhrases.some(phrase => 
    lowerText.includes(phrase)
  );
  return hasEducationalPhrase;
}

/**
 * Extracts the TLD (top-level domain) from a hostname
 * @param {string} hostname
 * @returns {string}
 */
function getTLD(hostname) {
  const parts = hostname.split('.');
  return parts.length > 1 ? parts[parts.length - 1] : '';
}

/**
 * Checks if the domain has a suspicious TLD
 * @param {string} hostname
 * @returns {boolean}
 */
function hasSuspiciousTLD(hostname) {
  return scamIndicators.suspiciousTLDs.includes(getTLD(hostname));
}

/**
 * Gets all visible text from the page (ignores hidden elements)
 * @returns {string}
 */
function getVisibleText() {
  function isVisible(node) {
    return !!(node.offsetWidth || node.offsetHeight || node.getClientRects().length);
  }
  let walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, null, false);
  let text = '';
  let node;
  while ((node = walker.nextNode())) {
    if (isVisible(node.parentElement)) {
      text += node.textContent + ' ';
    }
  }
  return text.toLowerCase();
}

/**
 * Detects toll-free and generic phone numbers in the text
 * @param {string} text
 * @returns {Array}
 */
function detectPhoneNumbers(text) {
  const phonePattern = /\b(1[-.\s]?)?(800|888|877|866|855|844|833|822)[-.\s]?\d{3}[-.\s]?\d{4}\b/g;
  return text.match(phonePattern) || [];
}

/**
 * Checks for suspicious modals/popups (common in scam sites)
 * @returns {Object}
 */
function checkForFakeAntivirus() {
  const results = {
    hasPopups: false,
    score: 0
  };
  // Look for elements with scammy modal/popup classes or IDs
  const suspiciousModals = document.querySelectorAll(
    'div[class*="modal"], div[class*="popup"], div[class*="alert"], ' +
    'div[id*="modal"], div[id*="popup"], div[id*="alert"], ' +
    'div[class*="warning"], div[id*="warning"], ' +
    'div[class*="error"], div[id*="error"], ' +
    'div[class*="welcome"], div[id*="welcome"], ' +
    'div[class*="jBox"], div[class*="sweet-alert"]'
  );
  if (suspiciousModals.length > 0) {
    results.hasPopups = true;
    results.score += 5;
  }
  return results;
}

/**
 * Main scam detection logic: scores the page based on scam indicators
 * @returns {Object}
 */
function checkPageContent() {
  // Skip trusted/search/educational pages
  if (isSearchEngine(window.location.hostname) || isTrustedDomain(window.location.hostname)) return { score: 0 };
  const pageText = getVisibleText();
  if (isEducationalContent(pageText)) return { score: 0 };
  const results = {
    score: 0,
    keywords: { highRisk: [], mediumRisk: [] },
    hasPopups: false,
    suspiciousUrl: false,
    phoneNumbers: []
  };
  // Check for high-risk keywords
  scamIndicators.highRiskKeywords.forEach(keyword => {
    if (pageText.includes(keyword.toLowerCase())) {
      results.keywords.highRisk.push(keyword);
    }
  });
  // Check for medium-risk keywords
  scamIndicators.mediumRiskKeywords.forEach(keyword => {
    if (pageText.includes(keyword.toLowerCase())) {
      results.keywords.mediumRisk.push(keyword);
    }
  });
  // Check for suspicious phone numbers
  results.phoneNumbers = detectPhoneNumbers(pageText);
  // Check for suspicious TLD
  results.suspiciousUrl = hasSuspiciousTLD(window.location.hostname);
  // Check for popups/modals
  const popupResults = checkForFakeAntivirus();
  if (popupResults.hasPopups) {
    results.hasPopups = true;
    results.score += 5;
  }
  // Scoring system
  if (results.keywords.highRisk.length > 0) results.score += results.keywords.highRisk.length * 3;
  if (results.keywords.mediumRisk.length > 0) results.score += results.keywords.mediumRisk.length;
  if (results.phoneNumbers.length > 0) results.score += 2;
  if (results.suspiciousUrl) results.score += 2;
  return results;
}

/**
 * Adds a warning banner to the page if scam indicators are found
 * @param {Object} results
 */
function addWarningBanner(results) {
  if (!results || results.score < 6) return; // Only show for score >= 6
  // Remove any existing banner
  const existingBanner = document.getElementById('scam-warning-banner');
  if (existingBanner) existingBanner.remove();

  // Generic severity colors and icons
  const highSeverityColor = '#cc0000'; // Red
  const mediumSeverityColor = '#ff4444'; // Bright red
  const lowSeverityColor = '#ffaa00'; // Yellow
  const warningIcon = '⚠️';

  // Set severity color and message
  let bannerColor, severityMessage;
  if (results.score >= 10) {
    bannerColor = highSeverityColor;
    severityMessage = 'HIGH PROBABILITY OF SCAM';
  } else if (results.score >= 8) {
    bannerColor = mediumSeverityColor;
    severityMessage = 'MODERATE PROBABILITY OF SCAM';
  } else {
    bannerColor = lowSeverityColor;
    severityMessage = 'LOW PROBABILITY OF SCAM';
  }

  // Create banner element
  const banner = document.createElement('div');
  banner.id = 'scam-warning-banner';
  banner.className = 'scam-warning-banner';
  banner.style.cssText = `position: fixed; top: 0; left: 0; right: 0; background-color: ${bannerColor}; color: white; padding: 18px; text-align: center; z-index: 999999; font-family: Arial, Helvetica, sans-serif; box-shadow: 0 2px 8px rgba(0,0,0,0.18); border-bottom: 4px solid #fff3cd;`;

  const warningContent = document.createElement('div');
  warningContent.style.cssText = `max-width: 900px; margin: 0 auto; display: flex; justify-content: space-between; align-items: center;`;

  const warningText = document.createElement('div');
  warningText.style.cssText = `flex-grow: 1; text-align: left; margin-right: 24px; font-size: 1.1em;`;

  // Build warning message (generic)
  let warningMessage = `<strong style="font-size:1.2em;">${warningIcon} ${severityMessage}</strong><br>`;
  warningMessage += `<span style="color:#fff3cd;font-weight:bold;">Security Notice:</span> Potential tech support scam activity detected on this page.<br>`;
  if (results.keywords.highRisk.length > 0) warningMessage += `• Suspicious tech support keywords detected<br>`;
  if (results.hasPopups) warningMessage += `• Suspicious popup detected<br>`;
  if (results.suspiciousUrl) warningMessage += `• Suspicious website address<br>`;
  if (results.phoneNumbers.length > 0) warningMessage += `• Suspicious phone number(s) detected<br>`;
  if (results.score >= 10) {
    warningMessage += `<br><strong>⚠️ URGENT:</strong> This site (<strong>${window.location.hostname}</strong>) is very likely a tech support scam.<br>
    • <span style="color:#fff3cd;">DO NOT</span> call any phone numbers shown on this page<br>
    • <span style="color:#fff3cd;">DO NOT</span> download any software<br>
    • <span style="color:#fff3cd;">CLOSE THIS PAGE IMMEDIATELY</span><br>
    • If you already called a number, seek help from a trusted professional or your bank.`;
  } else if (results.score >= 8) {
    warningMessage += `<br>This site (<strong>${window.location.hostname}</strong>) shows several scam indicators. Proceed with caution.`;
  } else {
    warningMessage += `<br>This site (<strong>${window.location.hostname}</strong>) shows some suspicious elements. Be careful.`;
  }
  warningText.innerHTML = warningMessage;
  warningContent.appendChild(warningText);

  // Add close button (generic style)
  const buttonContainer = document.createElement('div');
  buttonContainer.style.cssText = `display: flex; gap: 10px;`;
  const closeButton = document.createElement('button');
  closeButton.textContent = 'Close Warning';
  closeButton.style.cssText = `background-color: #fff3cd; color: #cc0000; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; font-weight: bold; font-size: 1em; box-shadow: 0 1px 3px rgba(0,0,0,0.08);`;
  closeButton.onmouseover = () => closeButton.style.backgroundColor = '#ffe066';
  closeButton.onmouseout = () => closeButton.style.backgroundColor = '#fff3cd';
  closeButton.onclick = () => banner.remove();
  buttonContainer.appendChild(closeButton);
  warningContent.appendChild(buttonContainer);
  banner.appendChild(warningContent);
  document.body.appendChild(banner);
}

// --- Performance: Debounced, limited observer ---
let scanTimeout = null;
const observer = new MutationObserver(() => {
  if (scanTimeout) clearTimeout(scanTimeout);
  scanTimeout = setTimeout(() => {
    const results = checkPageContent();
    if (results.score > 0) addWarningBanner(results);
  }, 500);
});
observer.observe(document.body, { childList: true, subtree: true });
// Initial scan on page load
const initialResults = checkPageContent();
if (initialResults.score > 0) addWarningBanner(initialResults);