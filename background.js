// Listen for installation
chrome.runtime.onInstalled.addListener(() => {
  console.log('Scam Website Warning extension installed');
});

// Listen for tab updates
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete') {
    // You could add automatic scanning here if desired
  }
});

// Listen for false positive reports
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'reportFalsePositive') {
    // Get the domain from the URL
    const url = new URL(request.url);
    const domain = url.hostname;
    
    // Get existing false positives from storage
    chrome.storage.local.get(['userFalsePositives'], (result) => {
      const userFalsePositives = result.userFalsePositives || [];
      
      // Add new domain if not already in the list
      if (!userFalsePositives.includes(domain)) {
        userFalsePositives.push(domain);
        
        // Save updated list
        chrome.storage.local.set({ userFalsePositives }, () => {
          console.log('Added false positive:', domain);
          sendResponse({ success: true });
        });
      } else {
        sendResponse({ success: true, alreadyExists: true });
      }
    });
    
    return true; // Keep the message channel open for async response
  }
}); 