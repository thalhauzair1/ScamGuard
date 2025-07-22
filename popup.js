// Function to update the popup UI with scan results
function updatePopup(results) {
  const statusElement = document.getElementById('scan-status');
  const detailsElement = document.getElementById('scan-details');
  
  if (!results) {
    statusElement.textContent = 'No scan results available';
    detailsElement.textContent = 'Please refresh the page to scan again.';
    return;
  }

  // Update status
  if (results.score >= 8) {
    statusElement.textContent = '⚠️ Potential Scam Detected';
    statusElement.style.color = '#ff4444';
  } else {
    statusElement.textContent = '✅ No Scam Detected';
    statusElement.style.color = '#4CAF50';
  }

  // Update details
  let details = '';
  
  if (results.keywords.highRisk.length > 0) {
    details += `High-risk keywords found: ${results.keywords.highRisk.length}\n`;
  }
  
  if (results.keywords.mediumRisk.length > 0) {
    details += `Medium-risk keywords found: ${results.keywords.mediumRisk.length}\n`;
  }
  
  if (results.hasPopups) {
    details += 'Suspicious popups detected\n';
  }
  
  if (results.suspiciousUrl) {
    details += 'Suspicious website address detected\n';
  }
  
  if (results.isEducational) {
    details += 'Educational content detected\n';
  }
  
  details += `\nFinal Score: ${results.score}`;
  
  detailsElement.textContent = details;
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
    }
  });
}); 