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

function injectGradeBadge(grade) {
  let badge = document.getElementById("threat-grade-badge");
  if (!badge) {
    badge = document.createElement("div");
    badge.id = "threat-grade-badge";
    badge.style.position = "fixed";
    badge.style.bottom = "10px";
    badge.style.left = "10px";
    badge.style.width = "40px";
    badge.style.height = "40px";
    badge.style.borderRadius = "50%";
    badge.style.backgroundColor = getColorForGrade(grade);
    badge.style.zIndex = 99999;
    badge.style.display = "flex";
    badge.style.alignItems = "center";
    badge.style.justifyContent = "center";
    badge.style.color = "#fff";
    badge.style.fontWeight = "bold";
    badge.style.fontFamily = "Arial";
    badge.innerText = grade;
    document.body.appendChild(badge);
  } else {
    badge.style.backgroundColor = getColorForGrade(grade);
    badge.innerText = grade;
  }
}





