//to do later: connect the backend for api checks and sandboxing


//points will be display in a seperate waring box , ui is in progress

let threatPoints = 0;

function determineGrade(score){
  if(score<6) return 'B';
  else if(score<12) return 'A';
  else return 'S';
  
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'addThreatPoints') {
    threatPoints += message.points;
    console.log(`Total Threat Points: ${threatPoints}`);
    grade=determineGrade(threatPoints);//on the grade will be show in ui;
    console.log(grade);
  }
  if(message.type=='alert'){
    console.log(message.details);
  }
});




