//to do later: connect the backend for api checks and sandboxing


//points will be display in a seperate waring box , ui is in progress

let threatPoints = 0;

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'addThreatPoints') {
    threatPoints += message.points;
    console.log(`Total Threat Points: ${threatPoints}`);
    grade=determineGrade(threatPoints,20);//on the grade will be show in ui;
    if (threatPoints >= 5) {
      // for testing purpose;
      chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icon.png',
        title: '⚠️ Unsafe Page Detected',
        message: 'This site may be unsafe. Proceed with caution!'
      });
    }
  }
  if(message.type=='alert'){
    chrome.notifications.create({
      type:'basic',
      iconUrl:'icon.png',
      title:'alert',
      message:message.details
    })
  }
});




