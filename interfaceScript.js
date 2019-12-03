var add = document.getElementById("add");
var remove = document.getElementById("remove");


var show = document.getElementById("show");

show.addEventListener("click", function(event){
    let msg = {
        operation: "displayCurrWebsites"
        
    }
    chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
      chrome.tabs.sendMessage(tabs[0].id, msg, function(response) {
      });
    });
});


add.addEventListener("click", function (event){
    var URL = getURL();
    let websiteData = {
        operation: "add",
        websiteURL : URL
    }
    
    chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
      chrome.tabs.sendMessage(tabs[0].id, websiteData, function(response) {
        //console.log(response.status);
      });
    });
});

remove.addEventListener("click", function(event){
    var URL = getURL();
    let websiteData = {
        operation: "remove",
        websiteURL : URL
    }
    chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
      chrome.tabs.sendMessage(tabs[0].id, websiteData, function(response) {
        //console.log(response.status);
      });
    });
});


function getURL(){
    return document.getElementById("websiteURL").value;
}