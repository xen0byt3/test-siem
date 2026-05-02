let systemRunning = true;
let tickets = [];
let ticketCounter = 1;
let escalationInterval = null;
let isCriticalMode = false;
let monitoringState = "OFF"; 
// OFF | ACTIVE | IDLE | ALERT

let lastCommandTime = Date.now();
let idleTimer = null;

let incidents = [];
let incidentCounter = 1;

let attackSequence = [
  "phishing",
  "initial",
  "c2",
  "exfil",
  "ransom"
];

let currentStage = 0;

let countryAnomaly = {};
let currentWave = [];
let heatLayers = [];
let map = L.map('map').setView([20, 0], 2); // world view
L.circle([14.55, 121.02], {
  radius: 500000,
  color: "red"
}).addTo(map);

setTimeout(() => {
  map.invalidateSize();
}, 500);

window.addEventListener("resize", () => {
  map.invalidateSize();
});

L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
  maxZoom: 5,
}).addTo(map);


let controls = {
  alertEvolution: false,
  mitre: false,
  liveThreats: false,
  packetStream: false,

  // 🆕 NEW SYSTEMS
  mode: "analyst",        // analyst | attacker
  speed: "real",          // slow | fast | real
  scenario: "all",        // ransomware | phishing | insider | all
  threatLevel: "medium",  // low | medium | high | critical

  severity: {
    critical: true,
    warning: true,
    info: true
  },

  techniques: {
    "T1566": true,
    "T1110": true,
    "T1071": true,
    "T1041": true,
    "T1486": true
  }
};

// Country tracking
let countryAttackCount = {
  "USA": 50,
  "China": 50,
  "Russia": 50,
  "India": 40,
  "North Korea": 45,

  "Germany": 25,
  "UK": 25,
  "Brazil": 25,
  "South Korea": 25,
  "Japan": 25,
  "France": 25,
  "Australia": 25,
  "Canada": 25
};

// AI baseline tracking
let baseline = {
  failedLogins: 0,
  outboundTraffic: 0
};

let totalCount = 0;
let level12Count = 0;
let failCount = 0;
let successCount = 0;

setInterval(()=>{
  if(systemRunning) pushPacket();
}, 800);

let currentStageIndex = 0;

function getRealTimestamp(){
  let now = new Date();

  let months = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];

  let month = months[now.getMonth()];
  let day = String(now.getDate()).padStart(2,'0');
  let time = now.toTimeString().split(" ")[0];

  return `${month} ${day} ${time}`;
}

const rulesPanel = document.getElementById("rulesPanel");
const logs = document.getElementById("logs");
const threats = document.getElementById("threats");
const fail = document.getElementById("fail");
const success = document.getElementById("success");
const lvl12 = document.getElementById("lvl12");
const packetStream = document.getElementById("packetStream");
const terminal = document.getElementById("terminal");
const terminalContent = document.getElementById("terminalContent");
const cmd = document.getElementById("cmd");

const logsData = [

/* PHISHING */
"mail postfix: Phishing email from support@paypaI-secure.com",
"mail postfix: Suspicious attachment invoice.zip",
"mail postfix: Spoofed sender detected admin@micros0ft.com",
"mail postfix: Suspicious attachment gcash.zip",
"mail postfix: Spoofed sender detected admin@gmali.com",

/* WEB / PROXY */
"proxy squid: Suspicious URL http://login-secure-paypal.com",
"proxy squid: Suspicious URL http://its-me-your-auntie.com",
"proxy squid: Blocked access to known malicious domain",
"proxy squid: User accessed phishing landing page",
"proxy squid: Suspicious URL http://claim-your-free-iphone-17-pro-max.com",

/* BRUTE FORCE */
"sshd: Failed password for root from 192.168.1.101",
"sshd: Failed password for admin from 192.168.1.102",
"sshd: Failed password for test from 10.0.0.5",
"sshd: Accepted password for root from 192.168.1.101",
"sshd: Failed password for root from 192.861.0.254",
"sshd: Failed password for root from 192.861.0.254",
"sshd: Failed password for root from 192.861.0.254",
"sshd: Failed password for root from 192.861.0.254",
"sshd: Failed password for root from 192.861.0.254",
"sshd: Failed password for root from 192.861.0.254",
"sshd: Failed password for root from 192.861.0.254",
"sshd: Accepted password for root from 192.861.0.254",
"sshd: Accepted password for root from 192.861.0.254",
"sshd: Accepted password for root from 192.861.0.254",
"sshd: Failed password for root from 35.25.37.124",
"sshd: Failed password for root from 35.25.37.124",
"sshd: Failed password for root from 35.25.37.124",
"sshd: Failed password for root from 35.25.37.124",


/* PRIVILEGE ESCALATION */
"sudo: user NOT in sudoers",
"sudo: root access granted to user1",
"auth: privilege escalation attempt detected",

/* MALWARE */
"kernel: Suspicious binary /tmp/.xcrypto executed",
"antivirus: Trojan detected in /home/user/file.exe",
"systemd: Unknown service persistence detected",
"antivirus: Updating your system please open C:/users",

/* C2 */
"snort: Possible C2 communication to 45.77.12.90",
"ids: Beaconing behavior detected to 185.199.110.153",
"firewall: Outbound connection to suspicious IP",

/* DATA EXFIL */
"firewall: Large outbound traffic 500MB",
"netflow: Data exfiltration to external server",
"auditd: Sensitive file copied to USB",
"auditd: Sensitive file copied to Local Disk C:",

/* SQL INJECTION */
"mod_security: SQL Injection attempt detected",
"apache: Suspicious query ' OR 1=1 --",
"waf: Blocked injection payload",

/* DDOS */
"firewall: DDoS threshold exceeded",
"ids: SYN flood detected",
"netflow: Abnormal traffic spike detected",

/* RANSOMWARE */
"ransomware: Files encrypted in /home/user/docs",
"fs: массовое изменение файлов detected",
"system: Shadow copies deleted",

/* BACKDOOR */
"systemd: Backdoor service started",
"cron: Suspicious scheduled task created",
"process: Reverse shell detected",

/* INTERNAL THREAT */
"auditd: File copied to USB device",
"user: Unauthorized access to HR records",
"db: Bulk data export initiated",

/* NETWORK */
"arp: ARP spoofing detected",
"dns: Suspicious domain resolution detected",
"dhcp: Rogue DHCP server detected",

/* GENERAL */
"system: Configuration file modified",
"kernel: Unauthorized module loaded",
"login: Multiple failed login attempts",

/* EXTRA RANDOM */
"ftp: Anonymous login enabled",
"smb: Suspicious file share access",
"rdp: Remote login attempt detected",
"vpn: Login from unusual location",
"cloud: IAM policy modified",
"api: Suspicious API token usage",
"docker: Container escape attempt detected",
"k8s: Unauthorized pod execution",
"email: Mass email sending detected",
"endpoint: Suspicious registry change",

/* CLOUD ATTACKS */
"aws: Root login from unusual location",
"azure: Suspicious role assignment detected",
"gcp: API key abuse detected",
"cloudtrail: Privilege escalation attempt",
"iam: User created with admin privileges",

/* LATERAL MOVEMENT */
"smb: Lateral movement via file share",
"rdp: Multiple lateral login attempts",
"winlogon: Pass-the-hash attempt detected",
"kerberos: Ticket reuse anomaly",
"netbios: Suspicious session established",

/* DATA LEAK */
"ftp: Large file upload to external server",
"scp: Data transfer to unknown host",
"s3: Public bucket exposure detected",
"dropbox: Bulk file sync detected",
"gdrive: Unusual file sharing activity",

/* ENDPOINT ATTACKS */
"endpoint: Keylogger detected",
"endpoint: Suspicious DLL injection",
"endpoint: Unauthorized script execution",
"powershell: Encoded command detected",
"powershell: Download cradle execution",

/* WEB ATTACKS */
"nginx: Directory traversal attempt",
"apache: XSS attack detected",
"waf: Malicious payload blocked",
"webapp: File upload exploit attempt",
"api: Unauthorized endpoint access",

/* NETWORK ANOMALY */
"netflow: Port scanning activity detected",
"firewall: Suspicious outbound connection",
"ids: Unusual DNS query pattern",
"snort: Exploit kit activity detected",
"switch: MAC flooding detected",

/* INSIDER */
"user: Access outside working hours",
"user: Mass file deletion detected",
"user: Suspicious USB usage",
"user: Unauthorized privilege usage",
"user: Sensitive folder accessed repeatedly",

/* MALWARE ADVANCED */
"malware: Polymorphic variant detected",
"trojan: Backdoor communication active",
"worm: Rapid propagation detected",
"virus: File infection spreading",
"rootkit: Hidden process detected",

/* EXTRA NOISE */
"system: Backup completed",
"system: Update installed",
"service: Restart successful",
"cron: Scheduled job executed",
"monitor: Health check OK"
];


let logElements = [];
let logBuffer = [];

const rules = [
  {name:"Brute Force Attack", keyword:"failed password", level:"warning", type:"brute"},
  {name:"Phishing Email", keyword:"phishing", level:"warning", type:"phishing"},
  {name:"Insider Threat", keyword:"usb", level:"critical", type:"insider"},

  {name:"Ransomware Activity", keyword:"ransomware", level:"critical", type:"malware"},
  {name:"C2 Communication", keyword:"c2", level:"critical", type:"c2"},
  {name:"Data Exfiltration", keyword:"outbound", level:"critical", type:"exfil"},

  {name:"Normal Login", keyword:"accepted password", level:"info", type:"normal"}
];

function renderRules(){
  rulesPanel.innerHTML = '';

  rules.forEach(r=>{
    let div = document.createElement('div');
    div.className = 'rule ' + r.level;
    div.innerHTML = `
      <div class="rule-left">
        <span class="rule-dot ${r.level}"></span>
        <strong>${r.name}</strong>
      </div>
      <span class="rule-keyword">${r.keyword}</span>
    `;
    rulesPanel.appendChild(div);
  });
}

renderRules();

function showAlert(message){
  const banner = document.getElementById("alertBanner");

  banner.textContent = "🚨 " + message;
  banner.classList.add("show");

  // auto hide after 3 seconds
  setTimeout(()=>{
    banner.classList.remove("show");
  },3000);
}

let attackIndex = 0;
let currentAttack = null;

function createAttack(){
  return {
    step: 0,
    flow: [
      "mail postfix: Phishing email detected",
      "sshd: Failed password for admin",
      "sshd: Accepted password for admin",
      "snort: Possible C2 communication",
      "firewall: Large outbound traffic",
      "ransomware: Files encrypted"
    ]
  };
}

let attackStory = [
  { stage:"Phishing", log:"mail postfix: Phishing email from support@paypal-secure.com" },
  { stage:"Phishing", log:"proxy squid: User clicked phishing link" },

  { stage:"Initial Access", log:"sshd: Failed password for admin from 192.168.1.100" },
  { stage:"Initial Access", log:"sshd: Accepted password for admin from 192.168.1.100" },

  { stage:"C2", log:"snort: Possible C2 communication to 45.77.12.90" },

  { stage:"Exfiltration", log:"firewall: Large outbound traffic 700MB" },

  { stage:"Ransomware", log:"ransomware: Files encrypted in /home/user/docs" }
];

function addLog(){
  if(!systemRunning) return;
  if(!controls.liveThreats) return;

  let chance;

  if(controls.threatLevel === "low") chance = 0.1;
  if(controls.threatLevel === "medium") chance = 0.3;
  if(controls.threatLevel === "high") chance = 0.6;
  if(controls.threatLevel === "critical") chance = 0.9;

  if(!currentAttack && Math.random() < chance){
    currentAttack = createAttack();
  }

  let l;

  if(currentAttack){
    l = currentAttack.flow[currentAttack.step];

    currentAttack.step++;

    if(currentAttack.step >= currentAttack.flow.length){
      currentAttack = null; // reset attack
    }
  }else{
    l = logsData[Math.floor(Math.random()*logsData.length)];
  }

  let useScenario = controls.scenario !== "all";

  if(useScenario){
    let filtered = attackStory.filter(s => 
      s.stage.toLowerCase().includes(controls.scenario)
    );

    if(filtered.length > 0){
      l = filtered[Math.floor(Math.random()*filtered.length)].log;
    } else {
      l = logsData[Math.floor(Math.random()*logsData.length)];
    }
  }
  else if(Math.random() < 0.3){
    // follow attack story
    l = attackStory[attackIndex].log;

    attackIndex++;

    // loop attack again after finishing
    if(attackIndex >= attackStory.length){
      attackIndex = 0;

      // reset chain visually
      document.querySelectorAll(".chain-step").forEach(el=>{
        el.classList.remove("active");
      });
    }

  }else{
    // random noise logs
    l = logsData[Math.floor(Math.random()*logsData.length)];
  }

  // replace sample IPs with random ones
  l = l.replace("192.168.1.101", randomIP());
  l = l.replace("192.168.1.102", randomIP());
  l = l.replace("10.0.0.5", randomIP());
  let div = document.createElement('div');

  let time = getRealTimestamp();

  div.dataset.raw = l;

  let lower = l.toLowerCase();
  //  TOTAL LOGS
  totalCount++;

  let anomalyScore = 0;

// detect brute force behavior
if(lower.includes("failed password")){
  baseline.failedLogins++;
  if(baseline.failedLogins > 5){
    anomalyScore += 20;
  }
}

// detect data exfiltration behavior
if(lower.includes("outbound")){
  baseline.outboundTraffic++;
  if(baseline.outboundTraffic > 3){
    anomalyScore += 25;
  }
}

// random anomaly spike (simulation)
if(Math.random() < 0.05){
  anomalyScore += 30;
}

// trigger alert
if(anomalyScore > 30){
  showAlert("AI DETECTED ANOMALY 🚨");
}

  //  AUTH FAILURE
  if(lower.includes("failed password")){
    failCount++;
  }

  //  AUTH SUCCESS
  if(lower.includes("accepted password")){
    successCount++;
  }

  //  LEVEL 12+ (HIGH SEVERITY SIMULATION)
  if(
    lower.includes("ransomware") ||
    lower.includes("ddos") ||
    lower.includes("c2") ||
    lower.includes("exfiltration")
  ){
    level12Count++;
  }

  threats.textContent = totalCount;
  fail.textContent = failCount;
  success.textContent = successCount;
  lvl12.textContent = level12Count;

  let delay = Math.random() * 2000;

  setTimeout(()=>{
    updateAttackChain(lower);
    updateTechniqueCounter(lower);
    updateAIScore(lower);
  }, delay);

  let matchedRule = null;

  // match rule
  for(let r of rules){
    if(lower.includes(r.keyword)){
      matchedRule = r;
      break;
    }
  }

  let severityLabel = "LOW";

  if(matchedRule){
    if(matchedRule.level === "critical") severityLabel = "CRITICAL";
    else if(matchedRule.level === "warning") severityLabel = "MEDIUM";
    else severityLabel = "LOW";
  }

  if(matchedRule){
    let ip = extractIP(l);

    if(matchedRule.type === "brute" && ip){
      simulateResponse("Blocked IP", ip);
    }

    if(matchedRule.type === "insider"){
      simulateResponse("User Disabled", "employee01");
    }

    if(matchedRule.type === "phishing"){
      simulateResponse("Email Quarantined", "mail-server");
    }
  }

  // apply style based on rule
  if(matchedRule){
    // count per time window (NOT total)
    // threat-aware weighting
    let weight = 1;

    if(controls.threatLevel === "low") weight = 0.5;
    if(controls.threatLevel === "medium") weight = 1;
    if(controls.threatLevel === "high") weight = 2;
    if(controls.threatLevel === "critical") weight = 3;

    let baseIncrease = 0.3; // slow growth
    let randomness = Math.random() * 0.5;

    windowStats[matchedRule.level] += (baseIncrease + randomness) * weight;

  // check if severity is disabled
  if(!controls.severity[matchedRule.level]){
    return; // OK for now (safe), just be aware
  }


  if(matchedRule.level === "critical"){
    div.classList.add("log-critical");

    // 🚨 trigger banner
    showAlert(matchedRule.name);

  }else if(matchedRule.level === "warning"){
    div.classList.add("log-warning");
  }else{
    div.classList.add("log-info");
  }
}

  div.innerHTML = `
    <span style="color:#94a3b8;">${time}</span> 
    <span>[${severityLabel}]</span>
    <span style="margin-left:6px;">${l}</span>
  `;

  div.onclick = () => {
  openModal(time, l, matchedRule);
};



let ip = extractIP(l);
if(ip){
  detectIncident(l.toLowerCase(), ip);
}

let country = getCountryFromIP(ip);
countryAnomaly[country] = (countryAnomaly[country] || 0) + 1;

// detect spike
if(countryAnomaly[country] > 8){
  showAlert(`⚠️ AI DETECTED SPIKE FROM ${country}`);
  countryAnomaly[country] = 0; // reset
}

// track country attacks
let boost = 1;

// dominant countries grow faster
if(
  country === "USA" ||
  country === "China" ||
  country === "Russia" ||
  country === "India" ||
  country === "North Korea"
){
  boost = 2.5;
}

countryAttackCount[country] = (countryAttackCount[country] || 0) + boost;

console.log("ATTACK IP:", ip);
plotAttack(ip);
updateCountryLeaderboard();

if(ip){
  let delay = controls.mode === "attacker" 
    ? Math.random() * 500   // faster attacks
    : Math.random() * 2000; // slower (analyst)

  setTimeout(()=>{
    plotAttack(ip);
  }, delay);
}

logElements.push({el: div, text: l.toLowerCase()});
logs.appendChild(div);

  if(logs.children.length>30){
    logs.removeChild(logs.firstChild);
  }

  updateMitreChart();
}

setInterval(()=>{
  if(!systemRunning) return;
  updateAlertChart();
}, 1000); // update every second

function runCmd(e){
  
  if(e.key === 'Enter'){
    let raw = cmd.value.trim();
    let query = raw.toLowerCase();

    appendToTerminal(`xen0byt3@siem:~$ ${raw}`, "command");
    lastCommandTime = Date.now();
    if(monitoringState === "ACTIVE"){
      startIdleTimer();
    }

    if(query === "clear"){
      terminalContent.innerHTML = "";
      cmd.value = "";
      return;
    }

    let parts = query.split("|").map(p => p.trim());

    // ==========================
    // MONITORING LOCK SYSTEM
    // ==========================
    if(
      (monitoringState === "OFF" || monitoringState === "IDLE") &&
      !query.includes("ado start monitoring")
    ){
      appendToTerminal("⚠ Monitoring is OFF/IDLE. Use 'ado start monitoring' first.", "error");
      cmd.value = "";
      return;
    }

    let result = logsData.slice(); // copy all logs
    let isAdoCommand = false;
    let commandHandled = false;
    let hasValidCommand = false;

    parts.forEach(part => {
      // =========================
      // ADO COMMANDS (ADMIN)
      // =========================

      // require ado keyword
      if(part.startsWith("ado")){

        isAdoCommand = true; 
        let cmd = part.replace("ado","").trim();

        // ==========================
        // MONITORING CONTROL
        // ==========================

        // START MONITORING
        if(cmd === "start monitoring"){
          setStatus("ACTIVE");
          setSIEM(true);

          systemRunning = true; // resume system

          appendToTerminal("✔ Monitoring STARTED", "success");
          commandHandled = true;
          return;
        }

        // STOP MONITORING
        else if(cmd === "stop monitoring"){
          setStatus("OFF");
          setSIEM(false);

          // HARD STOP EVERYTHING
          systemRunning = false;

          controls.liveThreats = false;
          controls.packetStream = false;
          controls.alertEvolution = false;
          controls.mitre = false;

          stopAutoEscalation(); // also stop escalation

          appendToTerminal("✖ Monitoring STOPPED (ALL SYSTEMS HALTED)", "error");
        }

        // ALERT EVOLUTION
        if(cmd === "start alerts evo"){
          controls.alertEvolution = true;
          appendToTerminal("✔ Alert Level Evolution STARTED", "success");
          commandHandled = true;
        }

        else if(cmd === "stop alerts evo"){
          controls.alertEvolution = false;
          appendToTerminal("✖ Alert Level Evolution STOPPED", "error");
          commandHandled = true;
        }

        // MITRE
       else if(cmd === "start mitre"){
          controls.mitre = true;
          appendToTerminal("✔ MITRE ATT&CK ENABLED", "success");
          commandHandled = true;
        }

        else if(cmd === "stop mitre"){
          controls.mitre = false;
          appendToTerminal("✖ MITRE ATT&CK DISABLED", "error");
          commandHandled = true;
        }

        // LIVE THREATS
        else if(cmd === "start live threats"){
          controls.liveThreats = true;
          appendToTerminal("✔ Live Threats ENABLED", "success");
          commandHandled = true;
        }

        else if(cmd === "stop live threats"){
          controls.liveThreats = false;

          // CLEAR MAP
          map.eachLayer(layer=>{
            if(layer instanceof L.Circle || 
              layer instanceof L.Polyline || 
              layer instanceof L.Marker){
              map.removeLayer(layer);
            }
          });

          appendToTerminal("✖ Live Threats DISABLED", "error");
          commandHandled = true;
        }

        // PACKET STREAM
        else if(cmd === "start packet stream"){
          controls.packetStream = true;
          appendToTerminal("✔ Packet Stream ENABLED", "success");
          commandHandled = true;
        }

        else if(cmd === "stop packet stream"){
          controls.packetStream = false;
          appendToTerminal("✖ Packet Stream DISABLED", "error");
          commandHandled = true;
        }

        // SEVERITY CONTROL
        else if(cmd.startsWith("enable")){
          let type = cmd.split(" ")[1];

          if(controls.severity[type] !== undefined){
            controls.severity[type] = true;
            appendToTerminal(`✔ ${type.toUpperCase()} ENABLED`);
            commandHandled = true;
          }

          if(controls.techniques[type.toUpperCase()]){
            controls.techniques[type.toUpperCase()] = true;
            appendToTerminal(`✔ ${type.toUpperCase()} ENABLED`);
            commandHandled = true;
          }
        }

        else if(cmd.startsWith("disable")){
          let type = cmd.split(" ")[1];

          if(controls.severity[type] !== undefined){
            controls.severity[type] = false;
            appendToTerminal(`✖ ${type.toUpperCase()} DISABLED`);
            commandHandled = true;
          }

          if(controls.techniques[type.toUpperCase()]){
            controls.techniques[type.toUpperCase()] = false;
            appendToTerminal(`✖ ${type.toUpperCase()} DISABLED`);
            commandHandled = true;
          }
        }
      
      else if(cmd === "status"){
        appendToTerminal("=== SYSTEM STATUS ===");

        appendToTerminal(`Alert Evolution: ${controls.alertEvolution ? "ON" : "OFF"}`);
        appendToTerminal(`MITRE ATT&CK: ${controls.mitre ? "ON" : "OFF"}`);
        appendToTerminal(`Live Threats: ${controls.liveThreats ? "ON" : "OFF"}`);
        appendToTerminal(`Packet Stream: ${controls.packetStream ? "ON" : "OFF"}`);

        appendToTerminal("--- Severity ---");
        appendToTerminal(`Critical: ${controls.severity.critical ? "ON" : "OFF"}`);
        appendToTerminal(`Warning: ${controls.severity.warning ? "ON" : "OFF"}`);
        appendToTerminal(`Info: ${controls.severity.info ? "ON" : "OFF"}`);

        appendToTerminal("--- Techniques ---");
        for(let t in controls.techniques){
          appendToTerminal(`${t}: ${controls.techniques[t] ? "ON" : "OFF"}`);
        }

        commandHandled = true;

      }

      else if(cmd === "reset"){
        location.reload();
        commandHandled = true;
      }

      else if(cmd === "simulate attack"){

        appendToTerminal("Simulating Full Attack Chain...");

        createTicket("HIGH", "Brute Force Attack");

        attackStory.forEach((step, index) => {
          setTimeout(()=>{
            let fakeLog = step.log.toLowerCase();

            updateAttackChain(fakeLog);
            updateTechniqueCounter(fakeLog);
            updateAIScore(fakeLog);

            appendToTerminal(`[SIM] ${step.log}`);
          }, index * 800);
        });

        commandHandled = true;
      }

      // MODE
      else if(cmd.startsWith("mode")){
        let m = cmd.split(" ")[1];
        controls.mode = m;
        appendToTerminal(`✔ Mode set to ${m.toUpperCase()}`, "success");
        commandHandled = true;

        // CHECK RECOVERY HERE TOO
        if(controls.mode === "analyst" && controls.threatLevel === "low"){
          setStatus("ACTIVE");
          appendToTerminal("✔ System stabilized. Monitoring Active.", "success");
        }
      }

      // SPEED
      else if(cmd.startsWith("speed")){
        let s = cmd.split(" ")[1];
        controls.speed = s;
        appendToTerminal(`✔ Speed set to ${s.toUpperCase()}`, "success");
        commandHandled = true;
      }

      // SCENARIO
      else if(cmd.startsWith("scenario")){
        let sc = cmd.split(" ")[1];
        controls.scenario = sc;
        appendToTerminal(`✔ Scenario set to ${sc.toUpperCase()}`, "success");
        commandHandled = true;
      }

      // THREAT LEVEL
      else if(cmd.startsWith("threat")){
        let t = cmd.split(" ")[1];
        controls.threatLevel = t;
        appendToTerminal(`✔ Threat Level set to ${t.toUpperCase()}`, "success");
        commandHandled = true;

        // ==========================
        // TRIGGER APT
        // ==========================
        if(controls.mode === "attacker" && controls.threatLevel === "critical"){
          setStatus("ALERT");
          createTicket("CRITICAL", "APT Detection");
          updateReport();
          isCriticalMode = true;
          startAutoEscalation();
          appendToTerminal("Advanced Persistent Threat Detected!", "error");
        }

        // ==========================
        // RECOVER TO ACTIVE
        // ==========================
        else if(controls.mode === "analyst" && controls.threatLevel === "low"){
          setStatus("ACTIVE");
          isCriticalMode = false;
          stopAutoEscalation();
          appendToTerminal("✔ System stabilized. Monitoring Active.", "success");
        }
      }
  
      // EXPORT LOGS
      else if(cmd === "export logs"){
        exportLogs();
        appendToTerminal("✔ Logs exported", "success");
        commandHandled = true;
      }

      else if(cmd === "show tickets"){
        appendToTerminal("=== TICKETS ===");

        if(tickets.length === 0){
          appendToTerminal("No tickets found.");
        } else {
          tickets.forEach(t=>{
            appendToTerminal(`${t.id} | ${t.severity} | ${t.status} | ${t.time}`);
          });
        }

        commandHandled = true;
      }

      else if(cmd === "export tickets"){
        exportTickets();
        appendToTerminal("✔ Tickets exported", "success");
        commandHandled = true;
      }

        if(!commandHandled){
          appendToTerminal("❌ Unknown ado command", "error");
        }
        return; // stop further processing
      }


      

      // SEARCH
      if(part.startsWith("search")){
        let queryStr = part.replace("search","").trim();

        result = logsData.filter(log=>{
          let l = log.toLowerCase();

          // AND
          if(queryStr.includes(" and ")){
            let [a,b] = queryStr.split(" and ");
            return l.includes(a) && l.includes(b);
          }

          // OR
          if(queryStr.includes(" or ")){
            let [a,b] = queryStr.split(" or ");
            return l.includes(a) || l.includes(b);
          }

          // NOT
          if(queryStr.startsWith("not ")){
            let word = queryStr.replace("not ","");
            return !l.includes(word);
          }

          return l.includes(queryStr);
        });

        commandHandled = true;
        hasValidCommand = true;
      }

      // COUNT
      else if(part === "stats count"){
        result = [`Count: ${result.length}`];
        commandHandled = true;
        hasValidCommand = true; 
      }

      // TOP IP
      else if(part === "top ip"){
        result = topIP(result);
        commandHandled = true;
        hasValidCommand = true;
      }

      // TIME (SIMPLIFIED: LAST N LOGS)
      else if(part.startsWith("time")){
        let num = parseInt(part.split(" ")[1]);

        if(!isNaN(num)){
          result = result.slice(-num);
          commandHandled = true;
          hasValidCommand = true;   // ✅ ADD THIS
        }
      }

      // search by IP
      else if(part.startsWith("search ip")){
        let ip = part.split(" ")[2];
        result = logsData.filter(l => l.includes(ip));
        hasValidCommand = true;
      }

    });

    // ==========================
    // FINAL OUTPUT CONTROL
    // ==========================

    // ADO commands already handled
    if(isAdoCommand){
      cmd.value = "";
      return;
    }

    // VALID COMMAND → show result
    if(hasValidCommand){
      if(result.length === 0){
        appendToTerminal("⚠ No results found", "error");
      } else {
        appendLines(result);
      }
    }

    // INVALID COMMAND → show error
    else{
      appendToTerminal("❌ Unknown command", "error");
    }

    // ==========================
    // RESET IDLE TIMER
    // ==========================
    if(monitoringState === "ACTIVE"){
      startIdleTimer();
    }

    cmd.value = "";
  }
}

function printOutput(lines){
  let html = "<pre>";

  lines.forEach(line=>{
    html += line + "\n";
  });

  html += "</pre>";

  output.innerHTML = html;
}

function filterBar(index){
  let original = [12,19,30,25,22]; // your original data

  let filtered = original.map((v,i)=> i===index ? v : 0);

  bar.data.datasets[0].data = filtered;
  bar.update();
}

function filterLogs(){
  logs.innerHTML = '';

  logsData.forEach(l=>{
    if(Math.random() > 0.5){
      let div = document.createElement('div');
      div.textContent = new Date().toLocaleTimeString()+" "+l;
      logs.appendChild(div);
    }
  });
}

function rand(arr){return arr.map(v=>Math.max(5,v+Math.floor(Math.random()*10-5)))}

let alertHistory = {
  labels: [],
  critical: [],
  warning: [],
  info: []
};

let windowStats = {
  critical: 0,
  warning: 0,
  info: 0
};


// Charts (responsive + animated)
const agentLabels = ['macOS','CentOS','Windows','Win-Server','Debian'];

const agentColors = [
  '#3b82f6', // macOS (blue)
  '#ef4444', // CentOS (red)
  '#f97316', // Windows (orange)
  '#facc15', // Win-Server (yellow)
  '#14b8a6'  // Debian (teal)
];

let area = new Chart(areaChart, {
  type: 'line',
  data: {
    labels: [],
    datasets: [
      { label: "Critical", data: [], borderColor:"#ef4444", fill:true },
      { label: "Warning", data: [], borderColor:"#f59e0b", fill:true },
      { label: "Info", data: [], borderColor:"#22c55e", fill:true }
    ]
  },
  options:{
    responsive:true,
    maintainAspectRatio:false,
    plugins:{
      legend:{
        labels:{
          usePointStyle:true,
          pointStyle:'rect' // 🔥 SQUARE
        }
      }
    }
  }
});

let mitre = new Chart(mitreChart,{
  type:'doughnut',
  data:{
    labels: [],
    datasets:[{
      data: [],
      cutout:'80%'
    }]
  },
  options:{
    responsive:true,
    maintainAspectRatio:false,
    plugins:{
      legend:{
        position:'left',
        labels:{
          usePointStyle: true,
          pointStyle: 'rect' // 🔥 makes it square
        }
      }
    }
  }
});

let pie=new Chart(pieChart,{
  type:'doughnut',
  data:{
    labels: agentLabels,
    datasets:[{
      data:[10,20,30,25,15],
      backgroundColor: agentColors,
      cutout:'80%'
    }]
  },
  options:{
    responsive:true,
    maintainAspectRatio:false,
    plugins:{legend:{position:'right'}},
    animation:{animateRotate:true}
  }
});

pie.options.onClick = (e, elements) => {
  if(elements.length > 0){
    let index = elements[0].index;

    selectedAgent = agentLabels[index];

    filterBar(index);

    //  highlight logs based on agent keyword
    highlightLogs(agentLabels[index].toLowerCase());
  }
};

let bar=new Chart(barChart,{
  type:'bar',
  data:{
    labels: agentLabels,
    datasets:[{
      label: 'Events',
      data:[12,19,30,25,22],
      backgroundColor: agentColors   // 🔥 SAME COLORS
    }]
  },
  options:{
    responsive:true,
    maintainAspectRatio:false,
    animation:{duration:1000}
  }
});


let timeline=new Chart(timelineChart,{type:'line',data:{labels:[1],datasets:[{label:"Events",data:[1],tension:0.4}]},options:{responsive:true,maintainAspectRatio:false,animation:{duration:1000}}});

setInterval(()=>{
  if(!systemRunning) return;
  pie.data.datasets[0].data=rand(pie.data.datasets[0].data);
  bar.data.datasets[0].data=rand(bar.data.datasets[0].data);
  area.update();mitre.update();pie.update();bar.update();

  let t=timeline.data.labels.length;
  timeline.data.labels.push(t);
  timeline.data.datasets[0].data.push(Math.floor(Math.random()*3)+1);
  if(timeline.data.labels.length>10){timeline.data.labels.shift();timeline.data.datasets[0].data.shift();}
  timeline.update();

  highlightTopAgent();
},2000);

function highlightTopAgent(){
  let data = bar.data.datasets[0].data;

  let max = Math.max(...data);
  let index = data.indexOf(max);

  // reset colors
  bar.data.datasets[0].backgroundColor = [...agentColors];

  // highlight highest
  bar.data.datasets[0].backgroundColor[index] = '#22c55e';

  bar.update();
}

function toggleTheme(){
  document.body.classList.toggle("dark");
}

function openModal(time, log, rule){
  document.getElementById("investigationModal").style.display = "flex";

  modalTime.textContent = time;
  modalLog.textContent = log;

  if(rule){
    modalRule.textContent = rule.name;
    modalSeverity.textContent = rule.level.toUpperCase();
  }else{
    modalRule.textContent = "None";
    modalSeverity.textContent = "Info";
  }

  // 🔥 MITRE DETECTION
  let lower = log.toLowerCase();
  let mitreText = "None";

  for(let key in mitreMapping){
    if(lower.includes(key)){
      let m = mitreMapping[key];
      mitreText = `${m.tactic} | ${m.technique} | ${m.name}`;
      break;
    }
  }

  document.getElementById("modalMitre").textContent = mitreText;
}

function closeModal(){
  document.getElementById("investigationModal").style.display = "none";
}

function highlightLogs(keyword){
  logElements.forEach(log=>{
    log.el.classList.remove("log-highlight","log-dim");

    if(log.text.includes(keyword)){
      log.el.classList.add("log-highlight");
    }else{
      log.el.classList.add("log-dim");
    }
  });
}

const attackStages = [
  {name:"Phishing", keyword:"phishing"},
  {name:"Initial Access", keyword:"failed password"},
  {name:"C2", keyword:"c2"},
  {name:"Exfiltration", keyword:"outbound"},
  {name:"Ransomware", keyword:"ransomware"}
];

const mitreMapping = {
  "phishing": {
    tactic: "Initial Access",
    technique: "T1566",
    name: "Phishing"
  },
  "failed password": {
    tactic: "Credential Access",
    technique: "T1110",
    name: "Brute Force"
  },
  "c2": {
    tactic: "Command and Control",
    technique: "T1071",
    name: "Application Layer Protocol"
  },
  "outbound": {
    tactic: "Exfiltration",
    technique: "T1041",
    name: "Exfiltration Over C2 Channel"
  },
  "ransomware": {
    tactic: "Impact",
    technique: "T1486",
    name: "Data Encrypted for Impact"
  }
};

function renderAttackChain(){
  attackChain.innerHTML = '';

  attackStages.forEach(stage=>{
    let mitre = mitreMapping[stage.keyword];

    let div = document.createElement('div');
    let tacticClass = "";

    if (mitre) {
      if (mitre.tactic === "Initial Access") tacticClass = "initial-access";
      if (mitre.tactic === "Credential Access") tacticClass = "credential-access";
      if (mitre.tactic === "Command and Control") tacticClass = "command-control";
      if (mitre.tactic === "Exfiltration") tacticClass = "exfiltration";
      if (mitre.tactic === "Impact") tacticClass = "impact";
    }

div.className = `chain-step ${tacticClass}`;

    let tooltipText = mitre
      ? `${mitre.tactic} | ${mitre.technique} | ${mitre.name}`
      : "No MITRE mapping";

    div.title = tooltipText;

    div.innerHTML = `
      <strong>${stage.name}</strong><br>
      <small>${mitre ? mitre.technique : ""}</small>
    `;

    div.id = "stage-" + stage.keyword;

    attackChain.appendChild(div);
  });
}

renderAttackChain();

function updateAttackChain(logText){
  let stage = attackStages[currentStageIndex];
  if(!stage) return;

  if(logText.includes(stage.keyword)){
    let el = document.getElementById("stage-" + stage.keyword);

    if(el){
      el.classList.add("active");
    }

    currentStageIndex++;

    if(currentStageIndex >= attackStages.length){
      setTimeout(()=>{
        document.querySelectorAll(".chain-step").forEach(el=>{
          el.classList.remove("active");
        });
        currentStageIndex = 0;
      }, 1500);
    }
  }
}

function highlightSearch(keyword){
  logElements.forEach(log=>{
    log.el.classList.remove("log-highlight","log-dim");

    if(log.text.includes(keyword)){
      log.el.classList.add("log-highlight");
    }else{
      log.el.classList.add("log-dim");
    }
  });
}

function randomIP(){
  return `${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}`;
}


let techniqueCounter = {};

function updateTechniqueCounter(logText){
  let lower = logText.toLowerCase();

  for (let key in mitreMapping){
    if(lower.includes(key)){
      let tech = mitreMapping[key].technique;

      // 🚫 skip if disabled
      if(!controls.techniques[tech]) continue;

      techniqueCounter[tech] = (techniqueCounter[tech] || 0) + 1;
    }
  }

  renderTechniqueCounter();
}

function renderTechniqueCounter(){
  techCounter.innerHTML = "";

  Object.keys(techniqueCounter).forEach(k=>{
    let div = document.createElement("div");
    div.className = "rule info";
    div.innerHTML = `<strong>${k}</strong><span>${techniqueCounter[k]}</span>`;
    techCounter.appendChild(div);
  });
}

function calculateThreatScore(logText){
  let score = 0;
  let lower = logText.toLowerCase();

  // 🔴 HIGH RISK
  if(lower.includes("ransomware")) score += 40;
  if(lower.includes("c2") || lower.includes("beacon")) score += 35;
  if(lower.includes("data exfil") || lower.includes("large outbound")) score += 30;
  if(lower.includes("ddos")) score += 30;

  // 🟠 MEDIUM RISK
  if(lower.includes("failed password")) score += 15;
  if(lower.includes("brute") || lower.includes("ssh")) score += 15;
  if(lower.includes("sql")) score += 20;
  if(lower.includes("suspicious")) score += 10;

  // 🟡 LOW RISK
  if(lower.includes("login")) score += 5;
  if(lower.includes("proxy")) score += 5;

  // BONUS escalation logic (multi-signal detection)
  if(lower.includes("failed password") && lower.includes("root")) score += 10;
  if(lower.includes("suspicious") && lower.includes("outbound")) score += 10;

  // clamp 0–100
  return Math.min(100, score);
}

function detectIncident(logText, ip){
  let score = calculateThreatScore(logText);

  // only create incident if meaningful
  if(score < 30) return;

  let existing = incidents.find(i => i.ip === ip && !i.closed);

  if(existing){
    existing.logs.push(logText);
    existing.score += score;
    existing.severity = getSeverity(existing.score);

    // auto escalate status
    if(existing.status === "OPEN"){
      existing.status = "INVESTIGATING";
    }

    if(existing.score > 80){
      existing.tier = "Tier 3";
    }else if(existing.score > 50){
      existing.tier = "Tier 2";
    }

    existing.severity = getSeverity(existing.score);
    existing.lastSeen = new Date();
  }else{
    let incident = {
      id: "INC-" + String(incidentCounter++).padStart(4,'0'),
      ip: ip,
      logs: [logText],
      score: score,
      severity: getSeverity(score),

      tier: "Tier 1",

      status: "OPEN",          
      analyst: "Unassigned",   

      created: new Date(),
      lastSeen: new Date(),
      resolvedTime: null,      

      closed: false
    };

    if(score > 80) incident.tier = "Tier 3";
    else if(score > 50) incident.tier = "Tier 2";

    incidents.push(incident);
  }

  renderIncidents();
  updateReport();
}

function getSeverity(score){
  if(score >= 80) return "CRITICAL";
  if(score >= 60) return "HIGH";
  if(score >= 40) return "MEDIUM";
  return "LOW";
}

let recentLogs = [];

function updateAIScore(logText){
  recentLogs.push(logText);
  if(recentLogs.length > 10) recentLogs.shift();

  let total = 0;

  recentLogs.forEach(l=>{
    total += calculateThreatScore(l);
  });

  let baseScore = total / recentLogs.length;

  // FORCE RANGE BASED ON THREAT LEVEL
  let min = 0, max = 100;

  if(controls.threatLevel === "low"){ min = 0; max = 25; }
  if(controls.threatLevel === "medium"){ min = 26; max = 50; }
  if(controls.threatLevel === "high"){ min = 51; max = 75; }
  if(controls.threatLevel === "critical"){ min = 76; max = 100; }

  // normalize baseScore (0–100) into selected range
  let normalized = baseScore / 100; // convert to 0–1

  let score = min + (max - min) * normalized;

  // small randomness so it "moves"
  score += (Math.random() * 4 - 2); // ±2 variation

  // clamp final
  score = Math.max(min, Math.min(max, score));

  score = Math.round(score);
  document.getElementById("aiScore").textContent = score;

  let bar = document.getElementById("aiBar");
  bar.style.width = score + "%";

  // color logic
  if(score >= 70){
    bar.style.background = "#ef4444"; // red
  } else if(score >= 40){
    bar.style.background = "#f59e0b"; // orange
  } else {
    bar.style.background = "#22c55e"; // green
  }
}


function updateAlertChart(){

  // decay (prevents spike stacking)
  windowStats.critical *= 0.75;
  windowStats.warning *= 0.80;
  windowStats.info *= 0.85;

  // stop if disabled
  if(!controls.alertEvolution) return;

  let time = new Date().toLocaleTimeString();

  alertHistory.labels.push(time);

  // smoothing function
  function smooth(prev, next){
    return prev * 0.7 + next * 0.3;
  }

  let lastIndex = alertHistory.critical.length - 1;

  let prevCritical = alertHistory.critical[lastIndex] || 0;
  let prevWarning = alertHistory.warning[lastIndex] || 0;
  let prevInfo = alertHistory.info[lastIndex] || 0;

  // smooth values
  alertHistory.critical.push(smooth(prevCritical, windowStats.critical));
  alertHistory.warning.push(smooth(prevWarning, windowStats.warning));
  alertHistory.info.push(smooth(prevInfo, windowStats.info));

  // natural movement
  windowStats.critical = windowStats.critical * 0.85 + Math.random()*0.3;
  windowStats.warning = windowStats.warning * 0.85 + Math.random()*0.2;
  windowStats.info = windowStats.info * 0.85 + Math.random()*0.1;

  // limit size
  if(alertHistory.labels.length > 200){
    alertHistory.labels.shift();
    alertHistory.critical.shift();
    alertHistory.warning.shift();
    alertHistory.info.shift();
  }

  // update chart
  area.data.labels = alertHistory.labels;
  area.data.datasets[0].data = alertHistory.critical;
  area.data.datasets[1].data = alertHistory.warning;
  area.data.datasets[2].data = alertHistory.info;

  area.update();
}


function updateMitreChart(){
  if(!controls.mitre) return;
  let labels = [];
  let data = [];
  let colors = [];

  const mitreColors = {
    "T1566": "#f59e0b", // Phishing (Initial Access)
    "T1110": "#3b82f6", // Brute Force (Credential Access)
    "T1071": "#8b5cf6", // C2
    "T1041": "#ef4444", // Exfiltration
    "T1486": "#dc2626"  // Impact (Ransomware)
  };

  for(let key in techniqueCounter){
    labels.push(key);
    data.push(techniqueCounter[key]);

    colors.push(mitreColors[key] || "#64748b"); // default gray
  }

  mitre.data.labels = labels;
  mitre.data.datasets[0].data = data;
  mitre.data.datasets[0].backgroundColor = colors;

  mitre.update();
}

const packetTypes = [
  { type:"HTTP", risk:"normal" },
  { type:"DNS", risk:"normal" },
  { type:"SSH", risk:"normal" },
  { type:"ICMP", risk:"normal" },

  { type:"SSH", risk:"suspicious" },
  { type:"HTTP", risk:"suspicious" },
  { type:"DNS-TUNNEL", risk:"suspicious" },

  { type:"SSH", risk:"attack" },
  { type:"HTTP POST", risk:"attack" },
  { type:"C2 BEACON", risk:"attack" },
  { type:"DATA EXFIL", risk:"attack" }
];

function generatePacket(){
  let p = packetTypes[Math.floor(Math.random()*packetTypes.length)];

  let src = randomIP();
  let dst = randomIP();

  let size = Math.floor(Math.random()*1500) + 40;

  let time = getRealTimestamp();

  return {
    raw: `${p.type} ${src} -> ${dst} SIZE:${size}`,
    type: p.type,
    risk: p.risk,
    time
  };
}

function pushPacket(){
  if(!systemRunning || !controls.packetStream) return;
  if(!controls.packetStream) return;
  let pkt = generatePacket();

  let div = document.createElement("div");

  let className = "packet-normal";
  if(pkt.risk === "suspicious") className = "packet-suspicious";
  if(pkt.risk === "attack") className = "packet-attack";

  div.className = className;

  div.innerHTML = `
    <span class="packet-tag">${pkt.type}</span>
    <span style="color:#94a3b8;">${pkt.time}</span>
    <span> ${pkt.raw}</span>
  `;

  packetStream.appendChild(div);

  // limit memory
  if(packetStream.children.length > 15){
    packetStream.removeChild(packetStream.firstChild);
  }

  // 🔥 connect to your AI engine
  updateAIScore(pkt.raw);
  // OPTIONAL: disable packet influence
  // updateAttackChain(pkt.raw.toLowerCase());
  updateTechniqueCounter(pkt.raw.toLowerCase());
  updateMitreChart();
}

function appendToTerminal(text, type="output"){
  let div = document.createElement("div");

  // COLOR SYSTEM
  if(type === "command"){
    div.style.color = "#22c55e"; // green
  }
  else if(type === "error"){
    div.style.color = "#ef4444"; // red
    div.style.fontWeight = "bold";
  }
  else if(type === "success"){
    div.style.color = "#38bdf8"; // cyan
  }
  else{
    div.style.color = "#e5e7eb"; // default (white/gray)
  }

  div.textContent = text;
  terminalContent.appendChild(div);

  // auto scroll
  terminal.scrollTop = terminal.scrollHeight;
}

function appendLines(lines){
  lines.forEach(line=>{
    appendToTerminal(line);
  });
}

function topIP(data){
  let ipCount = {};

  data.forEach(log=>{
    let match = log.match(/\b\d+\.\d+\.\d+\.\d+\b/);
    if(match){
      let ip = match[0];
      ipCount[ip] = (ipCount[ip] || 0) + 1;
    }
  });

  let sorted = Object.entries(ipCount)
    .sort((a,b)=>b[1]-a[1])
    

  return sorted.map(([ip,count]) => `${ip} → ${count}`);
}

function animateMetric(id){
  let el = document.getElementById(id);
  el.style.transform = "scale(1.2)";
  setTimeout(()=>el.style.transform="scale(1)",200);
}

animateMetric("fail");
animateMetric("success");
animateMetric("lvl12");

appendToTerminal("⚠ Monitoring is OFF. Use 'ado start monitoring' first.", "error");
appendToTerminal("⚠ Alert Evolution is OFF (use: ado start alerts evo)");
appendToTerminal("⚠ MITRE ATT&CK is OFF (use: ado start mitre)");
appendToTerminal("⚠ Live Threats are OFF (use: ado start live threats)");
appendToTerminal("⚠ Packet Stream is OFF (use: ado start packet stream)");


function getSpeedInterval(){
  if(controls.mode === "attacker") return 300;   // VERY FAST
  if(controls.mode === "analyst") return 1200;   // SLOWER

  if(controls.speed === "slow") return 2000;
  if(controls.speed === "fast") return 300;
  return 500;
}

function startLogEngine(){
  setInterval(()=>{
    let multiplier = 1;

    // MODE BASE
    if(controls.mode === "attacker") multiplier = 6;
    if(controls.mode === "analyst") multiplier = 1;

    // THREAT LEVEL BOOST
    if(controls.threatLevel === "low") multiplier += 0;
    if(controls.threatLevel === "medium") multiplier += 1;
    if(controls.threatLevel === "high") multiplier += 3;
    if(controls.threatLevel === "critical") multiplier += 6;

    // threat level affects volume
    if(controls.threatLevel === "high") multiplier += 2;
    if(controls.threatLevel === "critical") multiplier += 4;

    for(let i=0;i<multiplier;i++){
      addLog();
    }

  }, getSpeedInterval());
}

startLogEngine();
setInterval(()=>{
  logBuffer.forEach(d=>logs.appendChild(d));
  logBuffer = [];
}, 500);

function exportLogs(){
  let content = "";

  logElements.forEach(l=>{
    content += l.text + "\n";
  });

  let blob = new Blob([content], {type:"text/plain"});
  let url = URL.createObjectURL(blob);

  let a = document.createElement("a");
  a.href = url;
  a.download = "cyberlab_logs.txt";
  a.click();

  URL.revokeObjectURL(url);
}

async function getGeoIP(ip){
  try{
    let res = await fetch(`https://ip-api.com/json/${ip}`);
    let data = await res.json();

    return {
      lat: data.lat,
      lon: data.lon,
      country: data.country
    };
  }catch{
    return null;
  }
}

function extractIP(log){
  let match = log.match(/\b\d+\.\d+\.\d+\.\d+\b/);
  return match ? match[0] : null;
}

async function plotAttack(ip){
  if(!controls.liveThreats) return;

  // 1. Get Geo (optional)
  let geo = await getGeoIP(ip);

  // 2. Get country (your simulation logic)
  let country = getCountryFromIP(ip);

  // 3. Static coordinates (PRIMARY source)
  let coords = {
    "USA":[37,-95],
    "China":[35,103],
    "Russia":[60,90],
    "Germany":[51,10],
    "UK":[55,-3],
    "India":[20,78],
    "Brazil":[-10,-55],
    "North Korea":[40,127],
    "South Korea":[36,128],
    "Japan":[36,138],
    "France":[46,2],
    "Australia":[-25,133],
    "Canada":[56,-106]
  };

  // 4. Choose attacker position
  let attacker;

  if(coords[country]){
    attacker = coords[country]; // use simulated country
  } else if(geo){
    attacker = [geo.lat, geo.lon]; // fallback to GeoIP
  } else {
    attacker = [20, 0]; // final fallback
  }

  // DEBUG (safe now)
  console.log("PLOTTING:", ip, attacker);

  // 5. Attack intensity
  let count = countryAttackCount[country] || 1;

  let target = [14.55, 121.02];

  let normalized = Math.min(count, 10);
  let radiusSize = (4 + normalized * 1.5) * 30000;

  let heatColor = normalized < 4 ? "yellow" :
                  normalized < 7 ? "orange" :
                  "red";

  // 6. Draw heat
  let heat = L.circle(attacker,{
    radius: radiusSize,
    color: heatColor,
    fillColor: heatColor,
    fillOpacity: 0.3
  }).addTo(map);

  // 7. Label
  let label = L.marker(attacker,{
    icon: L.divIcon({
      className: "country-label",
      html: `<small>${country}</small>`
    })
  }).addTo(map);

  // 8. Attacker marker
  let marker = L.circle(attacker,{
    radius:200000,
    color:"red",
    opacity:0.5
  }).addTo(map);

  // 9. Attack line
  let line = L.polyline([attacker, target],{
    color:"orange",
    weight:2
  }).addTo(map);

  // 10. Cleanup
  setTimeout(()=>{
    map.removeLayer(marker);
    map.removeLayer(line);
    map.removeLayer(heat);
    map.removeLayer(label);
  }, 15000);
}

setInterval(()=>{
  plotAttack("8.8.8.8");
}, 2000);

function getCountryFromIP(ip){

  let weighted = [
    "USA","USA","USA","USA",
    "China","China","China",
    "Russia","Russia","Russia",
    "India","India",
    "North Korea","North Korea",

    // others (less frequent)
    "Germany","UK","Brazil","South Korea",
    "Japan","France","Australia","Canada"
  ];

  return weighted[Math.floor(Math.random()*weighted.length)];
}

function updateCountryLeaderboard(){
  let board = document.getElementById("countryBoard");
  if(!board) return;

  let sorted = Object.entries(countryAttackCount)
    .sort((a,b)=>Math.round(b[1]) - Math.round(a[1]))
    .slice(0,5);

  board.innerHTML = `
    <table class="country-table">
      <thead>
        <tr>
          <th>Country</th>
          <th>Count</th>
          <th>Threat</th>
        </tr>
      </thead>
      <tbody></tbody>
    </table>
  `;

  let tbody = board.querySelector("tbody");

  sorted.forEach(([country,count])=>{

    let threat =
      country === "Russia" ? "Brute Force" :
      country === "China" ? "C2 Traffic" :
      country === "USA" ? "Phishing" :
      "Mixed Activity";

    let row = document.createElement("tr");

    row.innerHTML = `
      <td>${country}</td>
      <td>${Math.round(count)}</td>
      <td class="threat-${threat.replace(/\s/g,'-').toLowerCase()}">${threat}</td>
    `;

    tbody.appendChild(row);
  });
}

setInterval(generateAttackWave, 10000);
generateAttackWave();

function generateAttackWave(){
  let countries = [
    "USA","China","Russia","Germany","UK",
    "India","Brazil","South Korea","Japan",
    "France","Australia","Canada"
  ];

  currentWave = [];

  for(let i=0;i<3;i++){
    let c = countries[Math.floor(Math.random()*countries.length)];
    if(!currentWave.includes(c)){
      currentWave.push(c);
    }
  }
}

function renderIncidents(){
  let container = document.getElementById("incidentList");
  if(!container) return;

  container.innerHTML = "";

  let active = incidents.filter(i => !i.closed).slice(-5);

  active.forEach(inc=>{
    let div = document.createElement("div");

    let color =
      inc.tier === "Tier 3" ? "#ef4444" :
      inc.tier === "Tier 2" ? "#f59e0b" :
      "#3b82f6"; // Tier 1

    div.style.borderLeft = `4px solid ${color}`;
    div.style.padding = "6px";
    div.style.marginBottom = "6px";
    div.style.background = "rgba(0,0,0,0.2)";
    div.style.fontSize = "12px";

    div.innerHTML = `
      <strong>${inc.id}</strong> 
      <span style="color:#94a3b8">(${inc.severity})</span>
      <span style="margin-left:6px; font-weight:bold;">
        [${inc.tier || "Tier 1"}]
      </span><br>

      IP: ${inc.ip}<br>
      Status: <span class="status-${inc.status.toLowerCase()}">${inc.status}</span><br>
      Analyst: ${inc.analyst}<br>
      Logs: ${inc.logs.length}

      <br>

      <button class="investigate-btn" onclick="investigateIncident('${inc.id}')">
        🕵️ Investigate Case
      </button>

      <button class="assign-btn" onclick="assignAnalyst('${inc.id}')">
        👤 Assign
      </button>
    `;

    container.appendChild(div);
  });
}

function resolveIncident(id){
  let inc = incidents.find(i=>i.id === id);
  if(inc){
    inc.status = "RESOLVED";
    inc.closed = true;
    inc.resolvedTime = new Date();
    renderIncidents();
    updateReport();
  }
}

function assignAnalyst(id){
  let inc = incidents.find(i => i.id === id);
  if(!inc) return;

  let name = prompt("Enter Analyst Name:");

  if(name){
    inc.analyst = name;
    inc.status = "INVESTIGATING";
    renderIncidents();

    showAlert(`${inc.id} assigned to ${name}`);
  }
}

let activeIncident = null;

function investigateIncident(id){
  let inc = incidents.find(i => i.id === id);
  if(!inc) return;

  activeIncident = inc;

  document.getElementById("incidentModal").style.display = "flex";

  document.getElementById("incTitle").textContent = inc.id;
  document.getElementById("incIP").textContent = "IP: " + inc.ip;
  document.getElementById("incSeverity").textContent = "Severity: " + inc.severity;
  document.getElementById("incStatus").textContent = "Status: " + inc.status;
  document.getElementById("incAnalyst").textContent = "Analyst: " + inc.analyst;

  // ⏱ time open
  let openTime = Math.floor((new Date() - inc.created)/1000);
  document.getElementById("incTime").textContent = "Open for: " + openTime + " sec";

  let logBox = document.getElementById("incLogs");
  logBox.innerHTML = "";

  inc.logs.slice(-10).forEach(l=>{
    let div = document.createElement("div");
    div.textContent = l;
    logBox.appendChild(div);
  });
}

function closeIncident(){
  document.getElementById("incidentModal").style.display = "none";
}

function resolveIncident(){
  if(!activeIncident) return;

  activeIncident.closed = true;
  activeIncident.status = "RESOLVED";
  activeIncident.resolvedTime = new Date();

  let duration = Math.floor((activeIncident.resolvedTime - activeIncident.created)/1000);

  showAlert(`✅ ${activeIncident.id} resolved in ${duration}s`);

  showAlert(`Incident ${activeIncident.id} resolved`);

  closeIncident();
  renderIncidents();
  
}

setInterval(()=>{
  plotAttack("8.8.8.8");
}, 2000);

function simulateResponse(action, target){
  appendToTerminal(`⚡ RESPONSE: ${action} → ${target}`, "success");
}



function updateReport(){
  let total = incidents.length;
  let open = incidents.filter(i => !i.closed).length;
  let closed = incidents.filter(i => i.closed).length;

  let percent = total === 0 ? 0 : Math.round((closed / total) * 100);

  animateValue("repTotal", total);
  document.getElementById("repOpen").textContent = open;
  document.getElementById("repResolved").textContent = closed;
  document.getElementById("repPercent").textContent = percent + "%";

  document.getElementById("repBar").style.width = percent + "%";

  let escalated = tickets.filter(t=>t.status === "ESCALATED").length;
  document.getElementById("repEscalated").textContent = escalated;  

  let escalatedTickets = tickets.filter(
    t => t.status === "ESCALATED" || t.status === "RESOLVED"
  );

    document.getElementById("repEscalated").textContent = escalatedTickets.length;

    const list = document.getElementById("escalationList");

    if(escalatedTickets.length === 0){
      list.innerHTML = "<small>No escalated incidents</small>";
    } else {
      list.innerHTML = escalatedTickets.map(t => `
        <div class="escalation-item ${t.status.toLowerCase()}" onclick="openTicket('${t.id}')">
          ${t.id} | ${t.severity} | ${t.status}
        </div>
      `).join("");
    }
}

function animateValue(id, value){
  let el = document.getElementById(id);
  let start = 0;
  let step = Math.ceil(value / 20);

  let interval = setInterval(()=>{
    start += step;
    if(start >= value){
      start = value;
      clearInterval(interval);
    }
    el.textContent = start;
  },20);
}

function updateClock(){
  const now = new Date();
  const time = now.toLocaleTimeString();
  document.getElementById("clock").textContent = time;
}

setInterval(updateClock, 1000);
updateClock();

function setStatus(state){
  const status = document.getElementById("statusIndicator");
  const text = document.getElementById("statusText");

  monitoringState = state;

  status.classList.remove("active","idle","alert","off");

  if(state === "OFF"){
    text.textContent = "Monitoring OFF";
    status.classList.add("off");
  }

  if(state === "ACTIVE"){
    text.textContent = "Monitoring Active";
    status.classList.add("active");

    simulateInitialization();
    startIdleTimer();
  }

  if(state === "IDLE"){
    text.textContent = "Idle";
    status.classList.add("idle");
  }

  if(state === "ALERT"){
    text.textContent = "Advanced Persistent Threat";
    status.classList.add("alert");
  }
}

function startIdleTimer(){
  clearTimeout(idleTimer);

  idleTimer = setTimeout(()=>{
    setStatus("IDLE");
    appendToTerminal("⚠ System is now IDLE due to inactivity");
  }, 5 * 60 * 1000);
}

function simulateInitialization(){
  const messages = [
    "Initializing SIEM modules...",
    "Loading threat intelligence feeds...",
    "Establishing secure channels...",
    "Deploying monitoring agents...",
    "System ready."
  ];

  let i = 0;

  const interval = setInterval(()=>{
    if(i < messages.length){
      printToTerminal(messages[i]);
      i++;
    } else {
      clearInterval(interval);
    }
  }, 1000);
}

function exportCSV(){
  let csv = "ID,Time,Severity,Status,Source\n";

  tickets.forEach(t=>{
    csv += `${t.id},${t.time},${t.severity},${t.status},${t.source}\n`;
  });

  const blob = new Blob([csv], { type: 'text/csv' });
  const url = window.URL.createObjectURL(blob);

  const a = document.createElement("a");
  a.href = url;
  a.download = "siem_report.csv";
  a.click();
}

function setSIEM(status){
  const el = document.getElementById("siemStatus");

  if(status){
    el.textContent = "SIEM Connected";
    el.classList.remove("disconnected");
    el.classList.add("connected");
  } else {
    el.textContent = "SIEM Disconnected";
    el.classList.remove("connected");
    el.classList.add("disconnected");
  }
}

// ==========================
// INITIAL SYSTEM STATE
// ==========================
window.addEventListener("load", () => {
  setStatus("OFF");
  setSIEM(false);
});

function createTicket(severity, source){

  const now = new Date();

  const ticket = {
    id: "INC-" + String(ticketCounter).padStart(4, "0"),
    time: now.toISOString(), // 🔥 improved for CSV
    severity: severity,
    status: "OPEN",
    source: source,
    notes: "Initial investigation pending"
  };

  tickets.push(ticket);
  ticketCounter++;

  appendToTerminal(`🎟 Ticket Created: ${ticket.id} [${severity}]`, "error");

  // ==========================
  // 🔥 AUTO ESCALATE (CRITICAL)
  // ==========================
  if(severity === "CRITICAL"){
    escalateTicket(ticket);
  }

  // ==========================
  // MULTI-INCIDENT DETECTION
  // ==========================
  let recent = tickets.slice(-3);

  if(recent.length === 3 && recent.every(t => t.severity === "HIGH")){
    escalateTicket(ticket);
  }

  // ==========================
  // AUTO RESOLVE (NON-CRITICAL ONLY)
  // ==========================
  if(severity !== "CRITICAL"){
    setTimeout(()=>{
      ticket.status = "RESOLVED";
      appendToTerminal(`✔ Ticket ${ticket.id} RESOLVED`, "success");
      updateReport();
    }, 10000);
  }

  // ==========================
  // ALWAYS UPDATE DASHBOARD
  // ==========================
  updateReport();
}

function escalateTicket(ticket){

  if(ticket.status === "ESCALATED") return; // prevent duplicate

  ticket.status = "ESCALATED";

  appendToTerminal(`🚨 Ticket ${ticket.id} ESCALATED`, "error");
}

function exportTickets(){

  if(tickets.length === 0){
    appendToTerminal("⚠ No tickets to export", "error");
    return;
  }

  let csv = [
    "Ticket ID",
    "Date",
    "Time",
    "Severity",
    "Status",
    "Source",
    "Notes"
  ].join(",") + "\n";

  tickets.forEach(t => {

    // Split date + time
    let dateObj = new Date(t.time);
    let date = dateObj.toLocaleDateString();
    let time = dateObj.toLocaleTimeString();

    csv += [
      t.id,
      date,
      time,
      t.severity,
      t.status,
      t.source || "N/A",
      t.notes || ""
    ].join(",") + "\n";

  });

  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);

  const link = document.createElement("a");
  link.href = url;

  // 🔥 filename with timestamp
  const now = new Date();
  const fileName = `SIEM_Tickets_${now.toISOString().slice(0,19)}.csv`;

  link.setAttribute("download", fileName);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);

  appendToTerminal("✔ Tickets exported successfully", "success");
}

function openTicket(id){
  const ticket = tickets.find(t => t.id === id);
  ticket.notes = "Investigating lateral movement";

  document.getElementById("ticketTitle").textContent = ticket.id;
  document.getElementById("ticketDetails").innerHTML = `
    Severity: ${ticket.severity}<br>
    Status: ${ticket.status}<br>
    Time: ${ticket.time}<br>
    Source: ${ticket.source}
  `;

  document.getElementById("ticketPanel").classList.remove("hidden");
}

function closeTicket(){
  document.getElementById("ticketPanel").classList.add("hidden");
}

function startAutoEscalation(){
  // prevent duplicate intervals
  if(escalationInterval) return;

  escalationInterval = setInterval(() => {

    if(!isCriticalMode) return;

    // create escalation ticket automatically
    createTicket("CRITICAL", "Auto Escalation - Threat Spike");

    console.log("AUTO ESCALATION TRIGGERED");

  }, 30000); // 30 seconds
}

function stopAutoEscalation(){
  if(escalationInterval){
    clearInterval(escalationInterval);
    escalationInterval = null;
  }
}