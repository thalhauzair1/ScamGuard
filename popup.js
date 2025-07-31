// Function to update the popup UI with scan results
function updatePopup(results) {
  const statusElement = document.getElementById('scan-status');
  const detailsElement = document.getElementById('scan-details');
  
  if (!results) {
    statusElement.className = 'scan-status warning';
    statusElement.innerHTML = `
      <span>⚠️</span>
      <span>Unable to scan page</span>
    `;
    detailsElement.style.display = 'block';
    detailsElement.innerHTML = 'Please refresh the page and try again.';
    return;
  }

  // Determine status and styling
  let statusClass, statusIcon, statusText, scoreClass;
  
  if (results.score >= 10 || (results.hasSuspiciousTLD && results.score >= 6)) {
    statusClass = 'danger';
    statusIcon = '🚨';
    statusText = 'HIGH RISK DETECTED';
    scoreClass = 'danger';
  } else if (results.score >= 8 || (results.hasSuspiciousTLD && results.score >= 4)) {
    statusClass = 'warning';
    statusIcon = '⚠️';
    statusText = 'MODERATE RISK DETECTED';
    scoreClass = 'warning';
  } else if (results.score > 0) {
    statusClass = 'warning';
    statusIcon = '⚡';
    statusText = 'LOW RISK DETECTED';
    scoreClass = 'warning';
  } else {
    statusClass = 'safe';
    statusIcon = '✅';
    statusText = 'NO THREATS DETECTED';
    scoreClass = '';
  }

  // Update status display
  statusElement.className = `scan-status ${statusClass}`;
  statusElement.innerHTML = `
    <span>${statusIcon}</span>
    <span>${statusText}</span>
    <span class="score-badge ${scoreClass}">${results.score}</span>
  `;

  // Build detailed information
  let detailsHTML = '';
  
  // Add indicators list from both layers
  const indicators = [];
  
  // Layer 1: Content indicators
  if (results.keywords.highRisk.length > 0) {
    indicators.push({
      icon: '🚨',
      text: `${results.keywords.highRisk.length} high-risk keywords detected`,
      type: 'danger'
    });
  }
  
  if (results.keywords.mediumRisk.length > 0) {
    indicators.push({
      icon: '⚠️',
      text: `${results.keywords.mediumRisk.length} medium-risk keywords detected`,
      type: 'warning'
    });
  }
  
  if (results.hasPopups) {
    indicators.push({
      icon: '🪟',
      text: 'Suspicious popups detected',
      type: 'warning'
    });
  }
  
  if (results.suspiciousUrl) {
    indicators.push({
      icon: '🌐',
      text: 'Suspicious website address detected',
      type: 'warning'
    });
  }
  
  if (results.phoneNumbers && results.phoneNumbers.length > 0) {
    indicators.push({
      icon: '📞',
      text: `${results.phoneNumbers.length} suspicious phone number(s) detected`,
      type: 'danger'
    });
  }
  
  // Layer 2: Domain reputation indicators
  if (results.domainAnalysis && results.domainAnalysis.score > 0) {
    if (results.domainAnalysis.suspiciousPatterns.length > 0) {
      indicators.push({
        icon: '🔍',
        text: `${results.domainAnalysis.suspiciousPatterns.length} suspicious domain patterns`,
        type: 'danger'
      });
    }
    
    if (results.domainAnalysis.suspiciousStructures.length > 0) {
      indicators.push({
        icon: '🏗️',
        text: `${results.domainAnalysis.suspiciousStructures.length} suspicious domain structures`,
        type: 'warning'
      });
    }
    
    if (results.domainAnalysis.suspiciousChars.length > 0) {
      indicators.push({
        icon: '🔤',
        text: `${results.domainAnalysis.suspiciousChars.length} suspicious character patterns`,
        type: 'danger'
      });
    }
  }
  
  if (results.domainAge && results.domainAge.appearsNew) {
    indicators.push({
      icon: '🆕',
      text: 'Newly registered domain detected',
      type: 'warning'
    });
  }
  
  if (results.urlAnalysis && results.urlAnalysis.score > 0) {
    if (results.urlAnalysis.suspiciousParams.length > 0) {
      indicators.push({
        icon: '🔗',
        text: `${results.urlAnalysis.suspiciousParams.length} suspicious URL parameters`,
        type: 'warning'
      });
    }
    
    if (results.urlAnalysis.suspiciousPaths.length > 0) {
      indicators.push({
        icon: '📁',
        text: `${results.urlAnalysis.suspiciousPaths.length} suspicious URL paths`,
        type: 'warning'
      });
    }
  }
  
  if (results.isEducational) {
    indicators.push({
      icon: '📚',
      text: 'Educational content detected (false positive likely)',
      type: 'info'
    });
  }

  if (indicators.length > 0) {
    detailsHTML += '<div class="indicator-list">';
    indicators.forEach(indicator => {
      detailsHTML += `
        <div class="indicator-item">
          <div class="indicator-icon ${indicator.type}">${indicator.icon}</div>
          <span>${indicator.text}</span>
        </div>
      `;
    });
    detailsHTML += '</div>';
  } else {
    detailsHTML += '<p>No specific indicators found.</p>';
  }

  // Add risk level explanation
  detailsHTML += `
    <div style="margin-top: 16px; padding-top: 16px; border-top: 1px solid #e5e7eb;">
      <strong>Risk Level:</strong> ${getRiskLevelDescription(results.score)}
    </div>
  `;
  
  // Add domain reputation analysis if available
  if (results.domainAnalysis && results.domainAnalysis.score > 0) {
    detailsHTML += `
      <div style="margin-top: 12px; padding: 12px; background: #f0f9ff; border-radius: 6px; border-left: 4px solid #0ea5e9;">
        <strong style="color: #0ea5e9;">🔍 Domain Analysis:</strong><br>
        <strong>Reputation Score:</strong> ${results.domainReputationScore || 0}<br>
        <strong>Risk Level:</strong> ${results.domainAnalysis.overallRisk.replace('_', ' ')}<br>
        ${results.domainAnalysis.indicators.length > 0 ? 
          `<strong>Issues:</strong> ${results.domainAnalysis.indicators.join(', ')}` : 
          'No specific domain issues detected'
        }
      </div>
    `;
  }

  // Add recommendations
  if (results.score >= 8) {
    detailsHTML += `
      <div style="margin-top: 12px; padding: 12px; background: #fef2f2; border-radius: 6px; border-left: 4px solid #dc2626;">
        <strong style="color: #dc2626;">⚠️ RECOMMENDATION:</strong><br>
        • Do not call any phone numbers on this page<br>
        • Do not download any software<br>
        • Close this page immediately<br>
        • If you already called a number, contact your bank
      </div>
    `;
  } else if (results.score > 0) {
    detailsHTML += `
      <div style="margin-top: 12px; padding: 12px; background: #fffbeb; border-radius: 6px; border-left: 4px solid #d97706;">
        <strong style="color: #d97706;">⚠️ CAUTION:</strong><br>
        • Proceed with caution<br>
        • Be wary of unsolicited support offers<br>
        • Verify any phone numbers independently
      </div>
    `;
  }

  detailsElement.style.display = 'block';
  detailsElement.innerHTML = detailsHTML;
}

/**
 * Get human-readable risk level description
 * @param {number} score
 * @returns {string}
 */
function getRiskLevelDescription(score) {
  if (score >= 10) {
    return 'Very High - Strong indicators of a scam';
  } else if (score >= 8) {
    return 'High - Multiple suspicious elements detected';
  } else if (score >= 6) {
    return 'Moderate - Some concerning indicators';
  } else if (score >= 4) {
    return 'Low - Minor suspicious elements';
  } else if (score > 0) {
    return 'Very Low - Minimal concerns';
  } else {
    return 'Safe - No threats detected';
  }
}

// Listen for messages from content script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'SCAN_RESULTS') {
    updatePopup(message.results);
  }
});

// Request initial scan results when popup opens
document.addEventListener('DOMContentLoaded', () => {
  chrome.tabs.query({active: true, currentWindow: true}, (tabs) => {
    if (tabs[0]) {
      chrome.tabs.sendMessage(tabs[0].id, {type: 'GET_SCAN_RESULTS'}, (response) => {
        if (chrome.runtime.lastError) {
          console.error('Error getting scan results:', chrome.runtime.lastError);
          updatePopup(null);
          return;
        }
        updatePopup(response);
      });
    } else {
      updatePopup(null);
    }
  });
}); 