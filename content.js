/**
 * Content Script for Tech Support Scam Detector Extension (MVP)
 *
 * This script detects tech support scams and displays a generic warning banner.
 *
 * Branding: Uses red/yellow for severity, a warning icon, and generic scam advice.
 */

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
  ],
  // Domain reputation patterns
  domainReputation: {
    // Suspicious domain patterns that indicate potential scams
    suspiciousPatterns: [
      'support', 'help', 'assist', 'fix', 'repair', 'secure', 'security',
      'virus', 'malware', 'clean', 'scan', 'protect', 'defend', 'guard',
      'microsoft', 'windows', 'apple', 'mac', 'ios', 'android',
      'bank', 'credit', 'card', 'account', 'login', 'verify',
      'urgent', 'critical', 'warning', 'alert', 'danger', 'risk',
      'free', 'trial', 'limited', 'offer', 'discount', 'save',
      'click', 'visit', 'go', 'redirect', 'link', 'url'
    ],
    // Suspicious domain structures
    suspiciousStructures: [
      'support-', 'help-', 'assist-', 'fix-', 'repair-', 'secure-',
      'virus-', 'malware-', 'clean-', 'scan-', 'protect-', 'defend-',
      'microsoft-', 'windows-', 'apple-', 'mac-', 'ios-', 'android-',
      'bank-', 'credit-', 'card-', 'account-', 'login-', 'verify-',
      'urgent-', 'critical-', 'warning-', 'alert-', 'danger-', 'risk-',
      'free-', 'trial-', 'limited-', 'offer-', 'discount-', 'save-',
      '-support', '-help', '-assist', '-fix', '-repair', '-secure',
      '-virus', '-malware', '-clean', '-scan', '-protect', '-defend',
      '-microsoft', '-windows', '-apple', '-mac', '-ios', '-android',
      '-bank', '-credit', '-card', '-account', '-login', '-verify',
      '-urgent', '-critical', '-warning', '-alert', '-danger', '-risk',
      '-free', '-trial', '-limited', '-offer', '-discount', '-save'
    ],
    // Suspicious domain lengths (too short or too long)
    suspiciousLengths: {
      tooShort: 5, // Domains shorter than 5 chars are suspicious
      tooLong: 50  // Domains longer than 50 chars are suspicious
    },
    // Suspicious character patterns
    suspiciousChars: [
      '--', '---', '____', '0000', '1111', '2222', '3333', '4444',
      '5555', '6666', '7777', '8888', '9999', 'aaaa', 'bbbb', 'cccc',
      'dddd', 'eeee', 'ffff', 'gggg', 'hhhh', 'iiii', 'jjjj', 'kkkk',
      'llll', 'mmmm', 'nnnn', 'oooo', 'pppp', 'qqqq', 'rrrr', 'ssss',
      'tttt', 'uuuu', 'vvvv', 'wwww', 'xxxx', 'yyyy', 'zzzz'
    ]
  }
};

// Track user-trusted domains (using Set for O(1) lookup performance)
let userTrustedDomains = new Set();

// Load user-trusted domains from storage
chrome.storage.local.get(['userTrustedDomains'], (result) => {
  // Convert array from storage to Set for faster lookups
  userTrustedDomains = new Set(result.userTrustedDomains || []);
});

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
 * Checks if a domain is in the user-trusted domains list
 * @param {string} domain
 * @returns {boolean}
 */
function isUserTrustedDomain(domain) {
  // O(1) lookup using Set instead of O(n) array search
  return userTrustedDomains.has(domain);
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
  if (isSearchEngine(window.location.hostname) || 
      isTrustedDomain(window.location.hostname) || 
      isUserTrustedDomain(window.location.hostname)) {
    return { score: 0 };
  }
  const pageText = getVisibleText();
  if (isEducationalContent(pageText)) return { score: 0 };
  
  const results = {
    score: 0,
    keywords: { highRisk: [], mediumRisk: [] },
    hasPopups: false,
    suspiciousUrl: false,
    phoneNumbers: [],
    // New fields for improved scoring
    hasSuspiciousTLD: false,
    hasPhoneWithScamText: false,
    keywordScore: 0,
    contextScore: 0,
    // Second layer: Domain reputation analysis
    domainAnalysis: null,
    domainAge: null,
    urlAnalysis: null,
    domainReputationScore: 0,
    secondLayerScore: 0
  };

  // FIRST LAYER: Content-based detection
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
  results.hasSuspiciousTLD = results.suspiciousUrl;

  // Check for popups/modals
  const popupResults = checkForFakeAntivirus();
  if (popupResults.hasPopups) {
    results.hasPopups = true;
  }

  // SECOND LAYER: Domain reputation analysis
  results.domainAnalysis = analyzeDomainReputation(window.location.hostname);
  results.domainAge = checkDomainAge(window.location.hostname);
  results.urlAnalysis = analyzeURLStructure(window.location.href);
  
  // Calculate domain reputation score
  results.domainReputationScore = results.domainAnalysis.score + 
                                 results.domainAge.score + 
                                 results.urlAnalysis.score;
  
  results.secondLayerScore = results.domainReputationScore;

  // ENHANCED SCORING SYSTEM WITH TWO LAYERS

  // Layer 1: Content-based scoring
  const highRiskScore = Math.min(results.keywords.highRisk.length * 2, 4);
  const mediumRiskScore = Math.min(results.keywords.mediumRisk.length * 0.5, 1);
  results.keywordScore = highRiskScore + mediumRiskScore;
  results.score += results.keywordScore;

  // Context-aware popup scoring
  if (results.hasPopups) {
    if (results.keywords.highRisk.length > 0 || results.hasSuspiciousTLD) {
      results.score += 3;
    } else {
      results.score += 1;
    }
  }

  // Phone number context scoring
  if (results.phoneNumbers.length > 0 && results.keywords.highRisk.length > 0) {
    results.hasPhoneWithScamText = true;
    results.score += 2;
  } else if (results.phoneNumbers.length > 0) {
    results.score += 1;
  }

  // TLD scoring
  if (results.hasSuspiciousTLD) {
    if (results.keywords.highRisk.length > 0) {
      results.score += 2;
    } else {
      results.score += 1;
    }
  }

  // Layer 2: Domain reputation scoring (weighted more heavily)
  if (results.domainReputationScore > 0) {
    // Higher weight for domain reputation issues
    const domainMultiplier = results.domainAnalysis.overallRisk === 'very_high' ? 3 : 
                            results.domainAnalysis.overallRisk === 'high' ? 2 : 1;
    results.score += results.domainReputationScore * domainMultiplier;
  }

  // Cross-layer bonus: If both content AND domain are suspicious
  if (results.keywordScore > 0 && results.domainReputationScore > 0) {
    results.score += 3; // Significant bonus for multi-layer detection
  }

  // Final weighted combinations bonus
  const hasMultipleHighRiskIndicators = 
    results.keywords.highRisk.length >= 2 || 
    (results.keywords.highRisk.length >= 1 && results.hasSuspiciousTLD) ||
    (results.keywords.highRisk.length >= 1 && results.hasPhoneWithScamText) ||
    (results.domainReputationScore >= 5); // Include domain reputation

  if (hasMultipleHighRiskIndicators) {
    results.score += 2;
  }

  results.contextScore = results.score - results.keywordScore;

  return results;
}

/**
 * Analyzes domain reputation and suspicious patterns
 * @param {string} hostname
 * @returns {Object}
 */
function analyzeDomainReputation(hostname) {
  const analysis = {
    score: 0,
    indicators: [],
    suspiciousPatterns: [],
    suspiciousStructures: [],
    suspiciousChars: [],
    domainLength: hostname.length,
    hasSuspiciousLength: false,
    hasSuspiciousPattern: false,
    hasSuspiciousStructure: false,
    hasSuspiciousChars: false,
    overallRisk: 'low'
  };

  const domain = hostname.toLowerCase();
  
  // Check for suspicious patterns in domain name
  scamIndicators.domainReputation.suspiciousPatterns.forEach(pattern => {
    if (domain.includes(pattern)) {
      analysis.suspiciousPatterns.push(pattern);
      analysis.hasSuspiciousPattern = true;
      analysis.score += 2; // High weight for suspicious patterns
    }
  });

  // Check for suspicious domain structures (prefixes/suffixes)
  scamIndicators.domainReputation.suspiciousStructures.forEach(structure => {
    if (domain.includes(structure)) {
      analysis.suspiciousStructures.push(structure);
      analysis.hasSuspiciousStructure = true;
      analysis.score += 3; // Higher weight for structural patterns
    }
  });

  // Check for suspicious character patterns
  scamIndicators.domainReputation.suspiciousChars.forEach(chars => {
    if (domain.includes(chars)) {
      analysis.suspiciousChars.push(chars);
      analysis.hasSuspiciousChars = true;
      analysis.score += 4; // Very high weight for suspicious chars
    }
  });

  // Check domain length
  if (domain.length < scamIndicators.domainReputation.suspiciousLengths.tooShort) {
    analysis.hasSuspiciousLength = true;
    analysis.score += 1;
    analysis.indicators.push('Domain too short');
  } else if (domain.length > scamIndicators.domainReputation.suspiciousLengths.tooLong) {
    analysis.hasSuspiciousLength = true;
    analysis.score += 1;
    analysis.indicators.push('Domain too long');
  }

  // Check for excessive numbers (common in scam domains)
  const numberCount = (domain.match(/\d/g) || []).length;
  const letterCount = (domain.match(/[a-z]/g) || []).length;
  if (numberCount > letterCount && domain.length > 10) {
    analysis.score += 2;
    analysis.indicators.push('Excessive numbers in domain');
  }

  // Check for excessive special characters
  const specialCharCount = (domain.match(/[^a-z0-9.-]/g) || []).length;
  if (specialCharCount > 2) {
    analysis.score += 2;
    analysis.indicators.push('Excessive special characters');
  }

  // Check for typosquatting patterns (common scam technique)
  const commonBrands = ['microsoft', 'apple', 'google', 'facebook', 'amazon', 'paypal', 'ebay'];
  commonBrands.forEach(brand => {
    if (domain.includes(brand) && !isTrustedDomain(hostname)) {
      analysis.score += 3;
      analysis.indicators.push(`Possible typosquatting of ${brand}`);
    }
  });

  // Determine overall risk level
  if (analysis.score >= 8) {
    analysis.overallRisk = 'very_high';
  } else if (analysis.score >= 5) {
    analysis.overallRisk = 'high';
  } else if (analysis.score >= 3) {
    analysis.overallRisk = 'medium';
  } else if (analysis.score >= 1) {
    analysis.overallRisk = 'low';
  } else {
    analysis.overallRisk = 'safe';
  }

  return analysis;
}

/**
 * Checks if domain appears to be newly registered (common scam indicator)
 * @param {string} hostname
 * @returns {Object}
 */
function checkDomainAge(hostname) {
  const analysis = {
    appearsNew: false,
    score: 0,
    indicators: []
  };

  // Check for common new domain patterns
  const newDomainPatterns = [
    'temp', 'new', 'fresh', 'recent', 'latest', 'updated',
    '2024', '2023', '2022', '2021', '2020',
    'v1', 'v2', 'v3', 'beta', 'alpha', 'test'
  ];

  const domain = hostname.toLowerCase();
  newDomainPatterns.forEach(pattern => {
    if (domain.includes(pattern)) {
      analysis.appearsNew = true;
      analysis.score += 1;
      analysis.indicators.push(`New domain pattern: ${pattern}`);
    }
  });

  return analysis;
}

/**
 * Analyzes URL structure for suspicious patterns
 * @param {string} url
 * @returns {Object}
 */
function analyzeURLStructure(url) {
  const analysis = {
    score: 0,
    indicators: [],
    suspiciousParams: [],
    suspiciousPaths: []
  };

  try {
    const urlObj = new URL(url);
    
    // Check for suspicious URL parameters
    const suspiciousParams = ['support', 'help', 'fix', 'repair', 'virus', 'malware', 'clean'];
    urlObj.searchParams.forEach((value, key) => {
      suspiciousParams.forEach(param => {
        if (key.toLowerCase().includes(param) || value.toLowerCase().includes(param)) {
          analysis.suspiciousParams.push(`${key}=${value}`);
          analysis.score += 2;
        }
      });
    });

    // Check for suspicious URL paths
    const suspiciousPaths = ['support', 'help', 'assist', 'fix', 'repair', 'secure', 'virus', 'malware'];
    const pathSegments = urlObj.pathname.toLowerCase().split('/').filter(segment => segment.length > 0);
    
    pathSegments.forEach(segment => {
      suspiciousPaths.forEach(path => {
        if (segment.includes(path)) {
          analysis.suspiciousPaths.push(segment);
          analysis.score += 1;
        }
      });
    });

    // Check for excessive path depth (common in scam sites)
    if (pathSegments.length > 5) {
      analysis.score += 1;
      analysis.indicators.push('Excessive URL depth');
    }

    // Check for suspicious file extensions
    const suspiciousExtensions = ['.exe', '.zip', '.rar', '.scr', '.bat', '.cmd'];
    suspiciousExtensions.forEach(ext => {
      if (urlObj.pathname.toLowerCase().includes(ext)) {
        analysis.score += 3;
        analysis.indicators.push(`Suspicious file extension: ${ext}`);
      }
    });

  } catch (error) {
    // Invalid URL
    analysis.score += 1;
    analysis.indicators.push('Invalid URL structure');
  }

  return analysis;
}

/**
 * Adds a warning banner to the page if scam indicators are found
 * @param {Object} results
 */
function addWarningBanner(results) {
  // DYNAMIC THRESHOLDS
  let warningThreshold = 6; // Default threshold
  
  // Lower threshold for suspicious TLDs (more sensitive)
  if (results.hasSuspiciousTLD) {
    warningThreshold = 4;
  }
  
  // Higher threshold for trusted-looking domains (less sensitive)
  if (window.location.hostname.includes('.com') && !results.hasSuspiciousTLD) {
    warningThreshold = 8;
  }

  if (!results || results.score < warningThreshold) return;

  // Remove any existing banner
  const existingBanner = document.getElementById('scam-warning-banner');
  if (existingBanner) existingBanner.remove();

  // Modern severity colors and icons
  const severityConfig = {
    high: {
      color: '#dc2626',
      bgColor: '#fef2f2',
      borderColor: '#fecaca',
      icon: '🚨',
      title: 'HIGH RISK SCAM DETECTED'
    },
    medium: {
      color: '#ea580c',
      bgColor: '#fff7ed',
      borderColor: '#fed7aa',
      icon: '⚠️',
      title: 'MODERATE RISK DETECTED'
    },
    low: {
      color: '#d97706',
      bgColor: '#fffbeb',
      borderColor: '#fde68a',
      icon: '⚡',
      title: 'SUSPICIOUS ACTIVITY DETECTED'
    }
  };

  // Determine severity level
  let severity;
  if (results.score >= 10 || (results.hasSuspiciousTLD && results.score >= 6)) {
    severity = severityConfig.high;
  } else if (results.score >= 8 || (results.hasSuspiciousTLD && results.score >= 4)) {
    severity = severityConfig.medium;
  } else {
    severity = severityConfig.low;
  }

  // Create modern banner with CSS-in-JS
  const bannerStyles = `
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    background: ${severity.bgColor};
    border-bottom: 3px solid ${severity.borderColor};
    color: ${severity.color};
    padding: 0;
    z-index: 999999;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
    transform: translateY(-100%);
    transition: transform 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    backdrop-filter: blur(8px);
  `;

  const banner = document.createElement('div');
  banner.id = 'scam-warning-banner';
  banner.style.cssText = bannerStyles;

  // Main container
  const containerStyles = `
    max-width: 1200px;
    margin: 0 auto;
    padding: 20px 24px;
    display: flex;
    align-items: flex-start;
    gap: 20px;
  `;

  const container = document.createElement('div');
  container.style.cssText = containerStyles;

  // Icon section
  const iconStyles = `
    flex-shrink: 0;
    font-size: 32px;
    margin-top: 4px;
    animation: pulse 2s infinite;
  `;

  const icon = document.createElement('div');
  icon.style.cssText = iconStyles;
  icon.textContent = severity.icon;

  // Content section
  const contentStyles = `
    flex: 1;
    min-width: 0;
  `;

  const content = document.createElement('div');
  content.style.cssText = contentStyles;

  // Header
  const headerStyles = `
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 12px;
  `;

  const header = document.createElement('div');
  header.style.cssText = headerStyles;

  const titleStyles = `
    font-size: 18px;
    font-weight: 700;
    color: ${severity.color};
    margin: 0;
  `;

  const title = document.createElement('h2');
  title.style.cssText = titleStyles;
  title.textContent = severity.title;

  const scoreStyles = `
    background: ${severity.color};
    color: white;
    padding: 4px 8px;
    border-radius: 12px;
    font-size: 12px;
    font-weight: 600;
    min-width: 24px;
    text-align: center;
  `;

  const score = document.createElement('span');
  score.style.cssText = scoreStyles;
  score.textContent = results.score;

  header.appendChild(title);
  header.appendChild(score);

  // Description
  const descriptionStyles = `
    font-size: 14px;
    line-height: 1.5;
    color: #374151;
    margin-bottom: 16px;
  `;

  const description = document.createElement('div');
  description.style.cssText = descriptionStyles;

  let descriptionText = `Security analysis detected potential tech support scam indicators on <strong>${window.location.hostname}</strong>.`;

  // Add specific indicators from both layers
  const indicators = [];
  
  // Layer 1: Content indicators
  if (results.keywords.highRisk.length > 0) {
    indicators.push(`${results.keywords.highRisk.length} high-risk keywords`);
  }
  if (results.hasPopups) {
    indicators.push('suspicious popups');
  }
  if (results.hasSuspiciousTLD) {
    indicators.push(`suspicious domain (${getTLD(window.location.hostname)})`);
  }
  if (results.phoneNumbers.length > 0) {
    indicators.push('suspicious phone numbers');
  }
  
  // Layer 2: Domain reputation indicators
  if (results.domainAnalysis && results.domainAnalysis.score > 0) {
    if (results.domainAnalysis.suspiciousPatterns.length > 0) {
      indicators.push(`${results.domainAnalysis.suspiciousPatterns.length} suspicious domain patterns`);
    }
    if (results.domainAnalysis.suspiciousStructures.length > 0) {
      indicators.push(`${results.domainAnalysis.suspiciousStructures.length} suspicious domain structures`);
    }
    if (results.domainAnalysis.suspiciousChars.length > 0) {
      indicators.push(`${results.domainAnalysis.suspiciousChars.length} suspicious character patterns`);
    }
  }
  
  if (results.domainAge && results.domainAge.appearsNew) {
    indicators.push('newly registered domain');
  }
  
  if (results.urlAnalysis && results.urlAnalysis.score > 0) {
    if (results.urlAnalysis.suspiciousParams.length > 0) {
      indicators.push(`${results.urlAnalysis.suspiciousParams.length} suspicious URL parameters`);
    }
    if (results.urlAnalysis.suspiciousPaths.length > 0) {
      indicators.push(`${results.urlAnalysis.suspiciousPaths.length} suspicious URL paths`);
    }
  }

  if (indicators.length > 0) {
    descriptionText += ` Detected: ${indicators.join(', ')}.`;
  }
  
  // Add domain reputation summary
  if (results.domainAnalysis && results.domainAnalysis.overallRisk !== 'safe') {
    descriptionText += ` Domain reputation: ${results.domainAnalysis.overallRisk.replace('_', ' ')} risk.`;
  }

  description.innerHTML = descriptionText;

  // Action buttons
  const buttonContainerStyles = `
    display: flex;
    gap: 12px;
    flex-wrap: wrap;
  `;

  const buttonContainer = document.createElement('div');
  buttonContainer.style.cssText = buttonContainerStyles;

  // Close button
  const closeButtonStyles = `
    background: ${severity.color};
    color: white;
    border: none;
    padding: 10px 16px;
    border-radius: 8px;
    font-size: 14px;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.2s ease;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
  `;

  const closeButton = document.createElement('button');
  closeButton.style.cssText = closeButtonStyles;
  closeButton.textContent = 'Dismiss Warning';
  
  closeButton.addEventListener('mouseenter', () => {
    closeButton.style.transform = 'translateY(-1px)';
    closeButton.style.boxShadow = '0 4px 6px rgba(0, 0, 0, 0.15)';
  });
  
  closeButton.addEventListener('mouseleave', () => {
    closeButton.style.transform = 'translateY(0)';
    closeButton.style.boxShadow = '0 1px 3px rgba(0, 0, 0, 0.1)';
  });
  
  closeButton.addEventListener('click', () => {
    // Set cooldown to prevent immediate re-adding
    bannerCooldown = true;
    if (bannerCooldownTimeout) clearTimeout(bannerCooldownTimeout);
    bannerCooldownTimeout = setTimeout(() => {
      bannerCooldown = false;
    }, 5000); // 5 second cooldown
    
    banner.style.transform = 'translateY(-100%)';
    setTimeout(() => banner.remove(), 300);
  });

  // Trust button
  const trustButtonStyles = `
    background: #10b981;
    color: white;
    border: none;
    padding: 10px 16px;
    border-radius: 8px;
    font-size: 14px;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.2s ease;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
  `;

  const trustButton = document.createElement('button');
  trustButton.style.cssText = trustButtonStyles;
  trustButton.textContent = 'Trust This Site';
  
  trustButton.addEventListener('mouseenter', () => {
    trustButton.style.transform = 'translateY(-1px)';
    trustButton.style.boxShadow = '0 4px 6px rgba(0, 0, 0, 0.15)';
  });
  
  trustButton.addEventListener('mouseleave', () => {
    trustButton.style.transform = 'translateY(0)';
    trustButton.style.boxShadow = '0 1px 3px rgba(0, 0, 0, 0.1)';
  });
  
  trustButton.addEventListener('click', () => {
    const currentDomain = window.location.hostname;
    if (!userTrustedDomains.has(currentDomain)) {
      userTrustedDomains.add(currentDomain);
      chrome.storage.local.set({ userTrustedDomains: Array.from(userTrustedDomains) });
    }
    
    // Set cooldown to prevent immediate re-adding
    bannerCooldown = true;
    if (bannerCooldownTimeout) clearTimeout(bannerCooldownTimeout);
    bannerCooldownTimeout = setTimeout(() => {
      bannerCooldown = false;
    }, 5000); // 5 second cooldown
    
    banner.style.transform = 'translateY(-100%)';
    setTimeout(() => banner.remove(), 300);
    
    // Show modern confirmation toast
    showConfirmationToast('Website added to trusted list');
  });

  buttonContainer.appendChild(closeButton);
  buttonContainer.appendChild(trustButton);

  // Assemble the banner
  content.appendChild(header);
  content.appendChild(description);
  content.appendChild(buttonContainer);

  container.appendChild(icon);
  container.appendChild(content);
  banner.appendChild(container);

  // Add CSS animations
  const style = document.createElement('style');
  style.textContent = `
    @keyframes pulse {
      0%, 100% { transform: scale(1); }
      50% { transform: scale(1.1); }
    }
    
    @keyframes slideIn {
      from { transform: translateY(-100%); }
      to { transform: translateY(0); }
    }
    
    @keyframes fadeIn {
      from { opacity: 0; }
      to { opacity: 1; }
    }
  `;
  document.head.appendChild(style);

  // Add to page and animate in
  document.body.appendChild(banner);
  
  // Trigger animation
  requestAnimationFrame(() => {
    banner.style.transform = 'translateY(0)';
  });

  // Auto-hide for low-risk warnings after 30 seconds
  if (results.score < 8) {
    setTimeout(() => {
      if (banner.parentNode) {
        // Set cooldown to prevent immediate re-adding
        bannerCooldown = true;
        if (bannerCooldownTimeout) clearTimeout(bannerCooldownTimeout);
        bannerCooldownTimeout = setTimeout(() => {
          bannerCooldown = false;
        }, 5000); // 5 second cooldown
        
        banner.style.transform = 'translateY(-100%)';
        setTimeout(() => banner.remove(), 300);
      }
    }, 30000);
  }
}

/**
 * Shows a modern confirmation toast
 * @param {string} message
 */
function showConfirmationToast(message) {
  const toastStyles = `
    position: fixed;
    top: 20px;
    right: 20px;
    background: #10b981;
    color: white;
    padding: 12px 20px;
    border-radius: 8px;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    font-size: 14px;
    font-weight: 500;
    z-index: 1000000;
    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
    transform: translateX(100%);
    transition: transform 0.3s ease;
  `;

  const toast = document.createElement('div');
  toast.style.cssText = toastStyles;
  toast.textContent = message;
  
  document.body.appendChild(toast);
  
  // Animate in
  requestAnimationFrame(() => {
    toast.style.transform = 'translateX(0)';
  });
  
  // Remove after 3 seconds
  setTimeout(() => {
    toast.style.transform = 'translateX(100%)';
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}

// --- Performance: Debounced, limited observer ---
let scanTimeout = null;
let bannerCooldown = false;
let bannerCooldownTimeout = null;

const observer = new MutationObserver(() => {
  if (scanTimeout) clearTimeout(scanTimeout);
  scanTimeout = setTimeout(() => {
    // Don't add banner if we're in cooldown or if banner already exists
    if (bannerCooldown || document.querySelector('#scam-warning-banner')) {
      return;
    }
    
    const results = checkPageContent();
    if (results.score > 0) addWarningBanner(results);
  }, 500);
});
observer.observe(document.body, { childList: true, subtree: true });

// Initial scan on page load
const initialResults = checkPageContent();
if (initialResults.score > 0) addWarningBanner(initialResults);