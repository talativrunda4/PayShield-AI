/**
 * PayShield AI - Core Application Controller
 * Behavioral Anomaly Scoring, NLP Phishing Scanner, Live Network Simulator, SVG Chart Generator
 */

// ==========================================
// 1. GLOBAL STATE & CONFIGURATION
// ==========================================
const STATE = {
    scansCount: 0,
    fraudCount: 0,
    safeCount: 0,
    scansVolume: 284300,
    // Pre-populate history with realistic mock audits
    auditHistory: [
        {
            timestamp: "2026-05-20 11:15:24",
            upiId: "rahul.mehta@okaxis",
            amount: 1200,
            riskScore: 8,
            threatLevel: "SAFE",
            reasons: ["Optimal behavioral matches"]
        },
        {
            timestamp: "2026-05-20 11:22:05",
            upiId: "paytm_cashback_78@paytm",
            amount: 15000,
            riskScore: 68,
            threatLevel: "SUSPICIOUS",
            reasons: ["Fresh unverified account", "Social engineering remark keywords"]
        },
        {
            timestamp: "2026-05-20 11:34:50",
            upiId: "urgent-help-bhim@sbi",
            amount: 45000,
            riskScore: 92,
            threatLevel: "FRAUD",
            reasons: ["Midnight anomaly", "Rooted device signature", "phishing remark syntax"]
        }
    ],
    // Risk bands for SVG Bar Chart: [10-1K, 1K-5K, 5K-15K, 15K-50K, 50K+]
    riskBands: [15, 32, 55, 78, 94]
};

// NLP Social Engineering Phishing Keywords dictionary
const PHISHING_KEYWORDS = [
    "lottery", "prize", "won", "reward", "urgent", "urgently", "refund", "cashback", 
    "bonus", "free", "claim", "help", "otp", "code", "pin", "verify", "draw", "gift", 
    "lucky", "update", "cancel", "bank", "paytm", "support", "kyc", "alert"
];

// Suspicious UPI Substrings
const SUSPICIOUS_UPI_SUBSTRINGS = [
    "scam", "refund", "win", "reward", "helpline", "support", "lucky", "cashback", "alert"
];

// ==========================================
// 2. INITIALIZATION ON DOM LOAD
// ==========================================
document.addEventListener("DOMContentLoaded", () => {
    initUIEventListeners();
    startLiveTransactionSimulator();
    recalculateDashboardStats();
    renderCustomCharts();
    runRealTimeThreatPreview(); // Initial preview check
});

// ==========================================
// 3. UI EVENT LISTENERS
// ==========================================
function initUIEventListeners() {
    const scanForm = document.getElementById("upi-scan-form");
    const frequencySlider = document.getElementById("input-frequency");
    const frequencyValueText = document.getElementById("frequency-val");
    const amountTags = document.querySelectorAll(".btn-tag");
    const exportCsvBtn = document.getElementById("btn-export-csv");

    // Form Submission
    scanForm.addEventListener("submit", handleScanSubmission);

    // Slider Counter Update
    frequencySlider.addEventListener("input", (e) => {
        const val = e.target.value;
        frequencyValueText.textContent = `${val} transaction${val > 1 ? 's' : ''}`;
        runRealTimeThreatPreview();
    });

    // Quick tag amount selectors
    amountTags.forEach(tag => {
        tag.addEventListener("click", () => {
            const val = tag.getAttribute("data-val");
            document.getElementById("input-amount").value = val;
            runRealTimeThreatPreview();
        });
    });

    // Real-Time Estimation Input Listeners
    const realTimeInputs = [
        "input-upi-id", "input-amount", "input-time-window", 
        "input-frequency", "input-location", "input-account-age", 
        "input-device-rooted", "input-remarks"
    ];
    realTimeInputs.forEach(id => {
        const el = document.getElementById(id);
        if (el) {
            el.addEventListener("input", runRealTimeThreatPreview);
            el.addEventListener("change", runRealTimeThreatPreview);
        }
    });

    // Export CSV Button click
    exportCsvBtn.addEventListener("click", exportAuditTrailCSV);
}

// ==========================================
// 4. BEHAVIORAL SCORING ENGINE (SIMULATED ML)
// ==========================================
function evaluateBehavioralRisk() {
    // Collect Inputs
    const upiId = document.getElementById("input-upi-id").value.trim().toLowerCase();
    const amount = parseFloat(document.getElementById("input-amount").value) || 0;
    const timeWindow = document.getElementById("input-time-window").value;
    const frequency = parseInt(document.getElementById("input-frequency").value) || 1;
    const location = document.getElementById("input-location").value;
    const accountAge = document.getElementById("input-account-age").value;
    const isRooted = document.getElementById("input-device-rooted").checked;
    const remarks = document.getElementById("input-remarks").value.trim().toLowerCase();

    // Attribution vectors
    let amountRisk = 0;
    let timeLocRisk = 0;
    let deviceRisk = 0;
    let nlpRisk = 0;

    const reasons = [];

    // --- 1. AMOUNT ANOMALY SCORING ---
    if (amount > 50000) {
        amountRisk = 95;
        reasons.push({ type: "danger", msg: "Extremely high value UPI transaction limit breached (₹50K+)." });
    } else if (amount > 20000) {
        amountRisk = 70;
        reasons.push({ type: "warning", msg: "Unusual volume bracket detected for typical consumer patterns." });
    } else if (amount > 5000) {
        amountRisk = 30;
    } else {
        amountRisk = 10;
    }

    // --- 2. TEMPORAL & GEOGRAPHIC SCORING ---
    // Time Window
    if (timeWindow === "midnight") {
        timeLocRisk += 45;
        reasons.push({ type: "warning", msg: "Initiated in Peak Fraud Window (12 AM - 5 AM) - midnight anomaly." });
    } else if (timeWindow === "early") {
        timeLocRisk += 15;
    }

    // Location & Anonymous networks
    if (location === "vpn") {
        timeLocRisk += 50;
        reasons.push({ type: "danger", msg: "VPN / Anonymous network tunnel detected (location cloaked)." });
    } else if (location === "state") {
        timeLocRisk += 25;
        reasons.push({ type: "warning", msg: "Geographical mismatch: payment source state deviates from typical cluster." });
    }

    // --- 3. VELOCITY & HARDWARE INTEGRITY ---
    // Frequency
    if (frequency >= 7) {
        deviceRisk += 50;
        reasons.push({ type: "danger", msg: `High-frequency velocity alert: ${frequency} transactions scanned in 10 mins.` });
    } else if (frequency >= 4) {
        deviceRisk += 25;
        reasons.push({ type: "warning", msg: `Elevated transaction frequency (${frequency} in last 10 mins).` });
    }

    // Device Rooted Flag
    if (isRooted) {
        deviceRisk += 50;
        reasons.push({ type: "danger", msg: "Device hardware subverted: rooted/jailbroken Android or iOS environment." });
    }

    // --- 4. NLP SCAN & VPA REPUTATION ---
    // NLP Keyword search in remarks
    let matchedKeywords = [];
    PHISHING_KEYWORDS.forEach(kw => {
        if (remarks.includes(kw)) {
            matchedKeywords.push(kw);
        }
    });
    if (matchedKeywords.length > 0) {
        nlpRisk += Math.min(30 * matchedKeywords.length, 90);
        reasons.push({ type: "danger", msg: `NLP Scan flagged intent: Phishing terms identified [${matchedKeywords.join(', ')}].` });
    }

    // Account Age
    if (accountAge === "new") {
        nlpRisk += 30;
        reasons.push({ type: "danger", msg: "Receiver UPI account age under 7 days (freshly minted node)." });
    }

    // Suspicious UPI ID search
    let matchedUPIKeywords = [];
    SUSPICIOUS_UPI_SUBSTRINGS.forEach(kw => {
        if (upiId.includes(kw)) {
            matchedUPIKeywords.push(kw);
        }
    });
    if (matchedUPIKeywords.length > 0) {
        nlpRisk += 20;
        reasons.push({ type: "warning", msg: `UPI virtual address reputation scan: Contains high-risk patterns.` });
    }

    // Caps individual attributions to 100%
    amountRisk = Math.min(amountRisk, 100);
    timeLocRisk = Math.min(timeLocRisk, 100);
    deviceRisk = Math.min(deviceRisk, 100);
    nlpRisk = Math.min(nlpRisk, 100);

    // Compute Overall Weighted Risk score
    // Weights: Amount (20%), Time/Location (30%), Behavioral/Device (25%), NLP/Trust (25%)
    let rawScore = (amountRisk * 0.20) + (timeLocRisk * 0.30) + (deviceRisk * 0.25) + (nlpRisk * 0.25);
    let finalScore = Math.round(rawScore);

    // Dynamic scale adjustment: if rooted + VPN + new account = guaranteed high risk
    if (isRooted && location === "vpn" && accountAge === "new") {
        finalScore = Math.max(finalScore, 98);
    }

    // Default reason if perfectly safe
    if (reasons.length === 0) {
        reasons.push({ type: "success", msg: "Optimal behavioral patterns. Clean hardware telemetry and verified beneficiary." });
    }

    return {
        score: finalScore,
        attributions: {
            amount: Math.round(amountRisk),
            time: Math.round(timeLocRisk),
            device: Math.round(deviceRisk),
            nlp: Math.round(nlpRisk)
        },
        reasons: reasons
    };
}

// ==========================================
// 5. REAL-TIME THREAT INDICATOR PREVIEW
// ==========================================
function runRealTimeThreatPreview() {
    const analysis = evaluateBehavioralRisk();
    const indicatorEl = document.getElementById("live-threat-estimate");

    let statusText = "Safe Range";
    let colorClass = "text-green";

    if (analysis.score > 75) {
        statusText = "Critical Threat Range";
        colorClass = "text-red";
    } else if (analysis.score > 30) {
        statusText = "Suspicious / Moderate Threat";
        colorClass = "text-warning";
    }

    indicatorEl.innerHTML = `<span class="${colorClass}">● ${statusText} (~${analysis.score}%)</span>`;
}

// ==========================================
// 6. FORM SCANNED INTEL GENERATOR
// ==========================================
function handleScanSubmission(e) {
    e.preventDefault();

    const btn = document.getElementById("btn-submit-scan");
    const spinner = document.getElementById("scan-btn-spinner");
    const emptyStateEl = document.getElementById("intel-state-empty");
    const loadedStateEl = document.getElementById("intel-state-loaded");

    // UI Feedback: Loading
    btn.disabled = true;
    spinner.classList.remove("hidden");
    emptyStateEl.classList.add("hidden");
    loadedStateEl.classList.add("hidden");

    // Simulate ML network latency
    setTimeout(() => {
        btn.disabled = false;
        spinner.classList.add("hidden");
        loadedStateEl.classList.remove("hidden");

        renderScanResults();
    }, 1200);
}

function renderScanResults() {
    const upiId = document.getElementById("input-upi-id").value.trim();
    const amount = parseFloat(document.getElementById("input-amount").value) || 0;
    
    // Evaluate Data
    const result = evaluateBehavioralRisk();

    // 1. UPDATE RISK GAUGE UI
    const scoreValText = document.getElementById("risk-score-value");
    const gaugeFill = document.getElementById("risk-gauge-fill");
    const gaugeNeedle = document.getElementById("risk-gauge-needle");
    const verdictBadge = document.getElementById("risk-verdict-badge");
    const timestampEl = document.getElementById("risk-timestamp");

    scoreValText.textContent = `${result.score}%`;

    // Semicircle gauge logic: dasharray = 157. Fill calculation:
    // stroke-dashoffset = 157 - (157 * percent)
    const strokeOffset = Math.round(157 - (157 * (result.score / 100)));
    gaugeFill.setAttribute("stroke-dashoffset", strokeOffset);

    // Needle Rotation logic: 0% is -90deg, 100% is 90deg.
    // Degrees = -90 + (180 * (score / 100))
    const needleDegs = -90 + (180 * (result.score / 100));
    gaugeNeedle.style.transform = `rotate(${needleDegs}deg)`;

    // Classify threat levels & styling color sets
    verdictBadge.className = "verdict-badge"; // reset classes
    let threatLevelStr = "SAFE";
    
    if (result.score > 75) {
        threatLevelStr = "FRAUD";
        verdictBadge.classList.add("verdict-fraud");
        verdictBadge.textContent = "FRAUD DETECTED";
        gaugeFill.setAttribute("stroke", "var(--color-fraud)");
        gaugeNeedle.setAttribute("stroke", "var(--color-fraud)");
    } else if (result.score > 30) {
        threatLevelStr = "SUSPICIOUS";
        verdictBadge.classList.add("verdict-suspicious");
        verdictBadge.textContent = "SUSPICIOUS";
        gaugeFill.setAttribute("stroke", "var(--color-warning)");
        gaugeNeedle.setAttribute("stroke", "var(--color-warning)");
    } else {
        threatLevelStr = "SAFE";
        verdictBadge.classList.add("verdict-safe");
        verdictBadge.textContent = "SAFE VERIFIED";
        gaugeFill.setAttribute("stroke", "var(--color-safe)");
        gaugeNeedle.setAttribute("stroke", "var(--color-safe)");
    }

    const curTime = new Date().toLocaleTimeString();
    timestampEl.textContent = `Analyzed today at ${curTime}`;

    // 2. XAI PROGRESS BARS
    document.getElementById("attribution-amount-percent").textContent = `${result.attributions.amount}%`;
    document.getElementById("attribution-amount-fill").style.width = `${result.attributions.amount}%`;

    document.getElementById("attribution-time-percent").textContent = `${result.attributions.time}%`;
    document.getElementById("attribution-time-fill").style.width = `${result.attributions.time}%`;

    document.getElementById("attribution-device-percent").textContent = `${result.attributions.device}%`;
    document.getElementById("attribution-device-fill").style.width = `${result.attributions.device}%`;

    document.getElementById("attribution-nlp-percent").textContent = `${result.attributions.nlp}%`;
    document.getElementById("attribution-nlp-fill").style.width = `${result.attributions.nlp}%`;

    // 3. FRAUD REASONS LIST
    const reasonsContainer = document.getElementById("reasons-list-container");
    reasonsContainer.innerHTML = ""; // clean

    result.reasons.forEach(item => {
        const li = document.createElement("li");
        
        let borderClass = "success-border";
        let iconColorClass = "success";
        let iconPath = `<circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/>`; // checkmark

        if (item.type === "danger") {
            borderClass = "danger-border";
            iconColorClass = "danger";
            iconPath = `<polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>`;
        } else if (item.type === "warning") {
            borderClass = "warning-border";
            iconColorClass = "warning";
            iconPath = `<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>`;
        }

        li.className = `reason-item ${borderClass}`;
        li.innerHTML = `
            <svg class="reason-icon ${iconColorClass}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                ${iconPath}
            </svg>
            <span>${item.msg}</span>
        `;
        reasonsContainer.appendChild(li);
    });

    // 4. DYNAMIC SAFETY ADVISORY TEXT
    const safetyAdvisoryBox = document.getElementById("safety-advisory-box");
    const safetyAdvisoryText = document.getElementById("safety-advisory-text");

    if (result.score > 75) {
        safetyAdvisoryBox.className = "safety-advisory-block scam-warning";
        safetyAdvisoryText.innerHTML = `<strong>CRITICAL FRAUD THREAT:</strong> This transaction matches known phishing scripts. DO NOT authorize this payment in your UPI app. The sender's claim is highly suspect.`;
    } else if (result.score > 30) {
        safetyAdvisoryBox.className = "safety-advisory-block scam-warning";
        safetyAdvisoryText.innerHTML = `<strong>ELEVATED SUSPICION:</strong> Multi-signal indicators suggest location or VPA identity inconsistency. Verify target via alternative secure channels before proceeding.`;
    } else {
        safetyAdvisoryBox.className = "safety-advisory-block";
        safetyAdvisoryText.innerHTML = `<strong>PAYMENT SECURE:</strong> Telemetry registers within safe operational benchmarks. Standard safety procedures apply.`;
    }

    // 5. UPDATE STATE AND STATISTICS
    STATE.scansCount += 1;
    STATE.scansVolume += amount;
    if (threatLevelStr === "FRAUD") {
        STATE.fraudCount += 1;
    } else if (threatLevelStr === "SAFE") {
        STATE.safeCount += 1;
    }

    // Append to Audit history array
    const dateFormatted = new Date().toISOString().replace('T', ' ').substring(0, 19);
    const shortReasons = result.reasons.map(r => r.msg.substring(0, 40) + "...");
    
    STATE.auditHistory.unshift({
        timestamp: dateFormatted,
        upiId: upiId,
        amount: amount,
        riskScore: result.score,
        threatLevel: threatLevelStr,
        reasons: shortReasons.slice(0, 2)
    });

    // Recalculate and update charts
    recalculateDashboardStats();
    updateAuditHistoryTable();
    updateDynamicChartBands(amount, result.score);
    renderCustomCharts();
}

// ==========================================
// 7. STATISTICS AND AUDIT LEDGER UPDATERS
// ==========================================
function recalculateDashboardStats() {
    // Audit counting from state array
    const total = STATE.auditHistory.length;
    const fraud = STATE.auditHistory.filter(item => item.threatLevel === "FRAUD").length;
    const safe = STATE.auditHistory.filter(item => item.threatLevel === "SAFE").length;

    // Volume formatting
    const formattedVolume = "₹" + STATE.scansVolume.toLocaleString("en-IN");
    
    // Percent
    const safeRatePercent = total > 0 ? Math.round((safe / total) * 100) : 100;

    // Inject
    document.getElementById("stat-total-scans").textContent = total;
    document.getElementById("stat-total-fraud").textContent = fraud;
    document.getElementById("stat-safe-rate").textContent = `${safeRatePercent}%`;
    document.getElementById("stat-volume").textContent = formattedVolume;

    updateAuditHistoryTable();
}

function updateAuditHistoryTable() {
    const tableBody = document.getElementById("audit-table-body");
    tableBody.innerHTML = ""; // clean

    STATE.auditHistory.forEach(item => {
        const tr = document.createElement("tr");

        let badgeClass = "badge-success";
        if (item.threatLevel === "FRAUD") badgeClass = "badge-danger";
        else if (item.threatLevel === "SUSPICIOUS") badgeClass = "badge-warning";

        tr.innerHTML = `
            <td>${item.timestamp}</td>
            <td><monospace>${item.upiId}</monospace></td>
            <td>₹${item.amount.toLocaleString("en-IN")}</td>
            <td><span class="audit-score-badge text-${badgeClass === 'badge-danger' ? 'red' : badgeClass === 'badge-warning' ? 'warning' : 'green'}">${item.riskScore}%</span></td>
            <td><span class="badge ${badgeClass}">${item.threatLevel}</span></td>
            <td>${item.reasons.join(" | ")}</td>
        `;
        tableBody.appendChild(tr);
    });
}

function updateDynamicChartBands(amount, score) {
    // Dynamic chart shifts for visual impact
    if (amount <= 1000) STATE.riskBands[0] = Math.round((STATE.riskBands[0] + score) / 2);
    else if (amount <= 5000) STATE.riskBands[1] = Math.round((STATE.riskBands[1] + score) / 2);
    else if (amount <= 15000) STATE.riskBands[2] = Math.round((STATE.riskBands[2] + score) / 2);
    else if (amount <= 50000) STATE.riskBands[3] = Math.round((STATE.riskBands[3] + score) / 2);
    else STATE.riskBands[4] = Math.round((STATE.riskBands[4] + score) / 2);
}

// ==========================================
// 8. CUSTOM RESPONSIVE SVG CHARTS GENERATOR
// ==========================================
function renderCustomCharts() {
    // --- CHART 1: LINE CHART DRAWING ---
    const lineStroke = document.getElementById("svg-line-path-stroke");
    const lineArea = document.getElementById("svg-line-path-area");
    const dotsGroup = document.getElementById("line-chart-dots");

    // Coordinates points list: x ranges 40 to 380, y ranges 10 (top) to 150 (bottom axes)
    // Map mock data points: 6 data nodes
    // Threat heights mapping: High (y=45), Med (y=80), Low (y=115)
    let yPoints = [120, 115, 75, 125, 45, 95];
    
    // Add real scanned history values to line charts dynamic display
    if (STATE.auditHistory.length > 0) {
        // Map the last 6 risk scores into y-scale values
        const lastSix = [...STATE.auditHistory].reverse().slice(-6);
        for(let i=0; i < lastSix.length; i++) {
            // formula: y = 150 - (140 * score/100)
            yPoints[5 - i] = Math.round(150 - (120 * (lastSix[i].riskScore / 100)));
        }
    }

    const xCoords = [60, 120, 180, 240, 300, 360];
    
    let pathD = `M ${xCoords[0]} ${yPoints[0]}`;
    for (let i = 1; i < xCoords.length; i++) {
        // Draw smooth cubic curves instead of rigid straight lines
        const cpX1 = xCoords[i - 1] + 30;
        const cpY1 = yPoints[i - 1];
        const cpX2 = xCoords[i] - 30;
        const cpY2 = yPoints[i];
        pathD += ` C ${cpX1} ${cpY1}, ${cpX2} ${cpY2}, ${xCoords[i]} ${yPoints[i]}`;
    }

    lineStroke.setAttribute("d", pathD);

    // Draw filled area gradient path under line
    let areaD = pathD + ` L ${xCoords[5]} 150 L ${xCoords[0]} 150 Z`;
    lineArea.setAttribute("d", areaD);

    // Draw active dots on SVG points
    dotsGroup.innerHTML = ""; // clean
    for (let i = 0; i < xCoords.length; i++) {
        const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
        circle.setAttribute("cx", xCoords[i]);
        circle.setAttribute("cy", yPoints[i]);
        circle.setAttribute("r", 4);
        circle.setAttribute("class", "chart-dot");
        
        // Dynamic color for dot based on height
        let dotColor = "var(--accent-primary)";
        if (yPoints[i] < 60) dotColor = "var(--color-fraud)";
        else if (yPoints[i] < 100) dotColor = "var(--color-warning)";
        circle.style.stroke = dotColor;

        dotsGroup.appendChild(circle);
    }

    // --- CHART 2: BAR CHART DRAWING ---
    const barsGroup = document.getElementById("bar-chart-bars-group");
    barsGroup.innerHTML = ""; // clean

    const barWidth = 32;
    const barXCoords = [64, 134, 204, 274, 339]; // corresponding to x labels

    for (let i = 0; i < barXCoords.length; i++) {
        const score = STATE.riskBands[i];
        // Height formula: maximum 130px at y=150
        const barHeight = Math.round(130 * (score / 100));
        const barY = 150 - barHeight;

        // Choose bar color gradient
        let barColor = "var(--color-safe)";
        if (score > 75) barColor = "var(--color-fraud)";
        else if (score > 35) barColor = "var(--color-warning)";

        // Construct SVG rect
        const rect = document.createElementNS("http://www.w3.org/2000/svg", "rect");
        rect.setAttribute("x", barXCoords[i]);
        rect.setAttribute("y", barY);
        rect.setAttribute("width", barWidth);
        rect.setAttribute("height", barHeight);
        rect.setAttribute("rx", 3);
        rect.setAttribute("class", "chart-bar");
        rect.style.fill = barColor;
        rect.style.opacity = 0.85;

        // Dynamic value hover text
        const text = document.createElementNS("http://www.w3.org/2000/svg", "text");
        text.setAttribute("x", barXCoords[i] + barWidth/2);
        text.setAttribute("y", barY - 6);
        text.setAttribute("font-size", "7.5");
        text.setAttribute("font-weight", "600");
        text.setAttribute("fill", "var(--text-secondary)");
        text.setAttribute("text-anchor", "middle");
        text.textContent = `${score}%`;

        barsGroup.appendChild(rect);
        barsGroup.appendChild(text);
    }
}

// ==========================================
// 9. REAL-TIME STREAM SIMULATOR (LEFT SIDEBAR)
// ==========================================
function startLiveTransactionSimulator() {
    const streamContainer = document.getElementById("live-stream-container");
    streamContainer.innerHTML = ""; // Clean placeholder

    const firstNames = ["vikram", "amit", "sneha", "rahul", "pooja", "rohit", "ananya", "kabir", "neha", "karan", "vishwa", "vrunda", "raj", "riya"];
    const upiHandles = ["okaxis", "ybl", "okhdfc", "oksbi", "paytm", "bhbhbhBHIM"];
    const scamPhrases = ["prize", "draw", "helpdesk", "refunds", "scam_checker", "jackpot", "airtel_bonus"];

    // Generate first 4 cards instantly
    for (let i = 0; i < 4; i++) {
        injectStreamCard(generateSimulatedCardData());
    }

    // Schedule subsequent cards
    setInterval(() => {
        injectStreamCard(generateSimulatedCardData());
    }, 4500);

    function generateSimulatedCardData() {
        const isSuspicious = Math.random() < 0.25; // 25% chance
        const isFraud = Math.random() < 0.08;      // 8% chance

        let upiId = "";
        let remarks = "";
        let amount = Math.floor(Math.random() * 8000) + 100;
        let threat = "SAFE";

        if (isFraud) {
            // Force red flags
            upiId = scamPhrases[Math.floor(Math.random() * scamPhrases.length)] + "@paytm";
            amount = Math.floor(Math.random() * 60000) + 20000;
            threat = "FRAUD";
        } else if (isSuspicious) {
            upiId = firstNames[Math.floor(Math.random() * firstNames.length)] + "_refund@okaxis";
            amount = Math.floor(Math.random() * 15000) + 5000;
            threat = "SUSPICIOUS";
        } else {
            upiId = firstNames[Math.floor(Math.random() * firstNames.length)] + Math.floor(Math.random() * 99) + "@" + upiHandles[Math.floor(Math.random() * upiHandles.length)];
            threat = "SAFE";
        }

        const now = new Date();
        const timeStr = now.toTimeString().split(' ')[0];

        return { upiId, amount, threat, timeStr };
    }

    function injectStreamCard(data) {
        const card = document.createElement("div");
        
        let cardStateClass = "card-safe";
        let badgeStateClass = "badge-success-outline";
        
        if (data.threat === "FRAUD") {
            cardStateClass = "card-fraud";
            badgeStateClass = "badge-danger";
        } else if (data.threat === "SUSPICIOUS") {
            cardStateClass = "card-suspicious";
            badgeStateClass = "badge-warning";
        }

        card.className = `stream-card ${cardStateClass}`;
        card.innerHTML = `
            <div class="stream-card-row">
                <span class="stream-upi" title="${data.upiId}">${data.upiId}</span>
                <span class="badge ${badgeStateClass}">${data.threat}</span>
            </div>
            <div class="stream-card-row">
                <span class="stream-amount">₹${data.amount.toLocaleString("en-IN")}</span>
                <span class="stream-time">${data.timeStr}</span>
            </div>
        `;

        // Prepend and trim lists length to max 7 elements
        streamContainer.insertBefore(card, streamContainer.firstChild);
        if (streamContainer.children.length > 7) {
            streamContainer.removeChild(streamContainer.lastChild);
        }
    }
}

// ==========================================
// 10. COMPLIANCE CSV LOG EXPORTER
// ==========================================
function exportAuditTrailCSV() {
    if (STATE.auditHistory.length === 0) {
        alert("The audit history registry ledger is empty. Scan transactions first!");
        return;
    }

    let csvContent = "data:text/csv;charset=utf-8,";
    // Header Columns
    csvContent += "Timestamp,Beneficiary UPI VPA,Amount (INR),Risk Probability Score,Threat Classification,Flags Summary\n";

    // Row loop
    STATE.auditHistory.forEach(item => {
        // Escape VPA comma separators
        const upiStr = `"${item.upiId}"`;
        const reasonStr = `"${item.reasons.join(" | ").replace(/"/g, '""')}"`;
        const row = [item.timestamp, upiStr, item.amount, `${item.riskScore}%`, item.threatLevel, reasonStr];
        csvContent += row.join(",") + "\n";
    });

    // Trigger local download link browser prompt
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `payshield_compliance_audit_ledger_${new Date().toISOString().slice(0,10)}.csv`);
    document.body.appendChild(link);
    
    // click trigger
    link.click();
    document.body.removeChild(link);
}
// ================= SIGNUP =================

function signup() {

    let name = document.getElementById("signupName")?.value;
    let email = document.getElementById("signupEmail")?.value;
    let password = document.getElementById("signupPassword")?.value;

    if(!name || !email || !password){
        alert("Please fill all fields");
        return;
    }

    let user = {
        name,
        email,
        password
    };

    localStorage.setItem(email, JSON.stringify(user));

    alert("Signup Successful!");

    window.location.href = "login.html";
}



// ================= LOGIN =================

function login() {

    let email = document.getElementById("loginEmail")?.value;
    let password = document.getElementById("loginPassword")?.value;

    let storedUser = JSON.parse(localStorage.getItem(email));

    if(storedUser == null){
        alert("User not found");
        return;
    }

    if(storedUser.password === password){

        localStorage.setItem(
            "currentUser",
            JSON.stringify(storedUser)
        );

        alert("Login Successful");

        window.location.href = "index.html";

    } else {

        alert("Wrong Password");
    }
}



// ================= LOGOUT =================

function logout(){

    localStorage.removeItem("currentUser");

    window.location.href = "login.html";
}
