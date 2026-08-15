// Background script for PhishGuard
// Handles installation events and potential background monitoring

chrome.runtime.onInstalled.addListener(() => {
    console.log("PhishGuard Extension Installed");
});

// Listen for tab updates to potentially auto-scan (optional feature)
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url) {
        // In a full version, we could auto-scan here and update the badge
        // chrome.action.setBadgeText({text: "..."});
    }
});
