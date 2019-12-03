var supportedWebsites = [];
getWebsitesInLocalStorage(); // Stores array of websites in supported websites

var accountDetails = {};

chrome.runtime.onMessage.addListener(function (message, sender, response){
    
    if(message.operation === "add"){
        let object = {};
        object[message.websiteURL] = true;
        chrome.storage.local.set(object, function(){
            console.log("Website added to local storage");
        });
        supportedWebsites = getWebsitesInLocalStorage();
    }
    else if(message.operation === "remove"){
        chrome.storage.local.remove([message.websiteURL], function(){
            console.log("Website removed from local storage");
        });
        supportedWebsites = getWebsitesInLocalStorage();
    }
    else if(message.operation === "displayCurrWebsites"){
        var stringWeb = "Websites Stored:\n";
        for(var i = 0; i < supportedWebsites.length; i++){
            stringWeb += supportedWebsites[i] + "\n";
        }
        alert(stringWeb);
    }
});

window.addEventListener("load", checkWebsite);

function pollForElement(){
    if(document.getElementById(accountDetails.emailID) == null){
        setTimeout(pollForElement, 100);
    }
    else{
        enterDetails(accountDetails.emailID, accountDetails.passwordID, accountDetails.emailAddress, accountDetails.password);
    }
}

function checkWebsite(){
    if(supportedWebsites.indexOf(window.location.href) != -1){
        chrome.runtime.sendMessage({text : window.location.href});

        chrome.runtime.onMessage.addListener(function(msg, sender, response){   
            accountDetails = msg;
            pollForElement();
        });
    }
}

function enterDetails(emailID, passwordID, emailAddress, password){
    var emailInput = document.getElementById(emailID);
    var passwordInput = document.getElementById(passwordID);

    emailInput.focus();
    emailInput.select();
    emailInput.value = emailAddress;

    passwordInput.focus();
    passwordInput.select();
    passwordInput.value = password;
}


function getWebsitesInLocalStorage(){
    chrome.storage.local.get(null, function(websiteObjects){
        supportedWebsites = Object.keys(websiteObjects);
    })
}

