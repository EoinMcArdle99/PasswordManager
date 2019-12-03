
chrome.runtime.onMessage.addListener(
  function(request, sender, sendResponse) {
      
    initNative(request);
  });

function initNative(website){
    var port = chrome.runtime.connectNative('com.my_company.my_application');
    
    //port.postMessage({"text" : "https://stackoverflow.com/users/login?ssrc=head&returnurl=https%3a%2f%2fstackoverflow.com%2f"});
    
    port.postMessage(website);
    
    port.onMessage.addListener(processNative);
    
    port.onDisconnect.addListener(function() {
      console.log("Disconnected");
    });
}

function processNative(msg){
    chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
        chrome.tabs.sendMessage(tabs[0].id, msg);
    });
}

