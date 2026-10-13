"use strict";

/* =====================================================
   ScamShield – rule-based message checker (no AI, no backend)
   All analysis happens in the browser. Nothing is stored or sent.
   ===================================================== */

/* ---------- 1. Settings ---------- */
const MEDIUM_THRESHOLD = 30; // score >= 30 -> Medium
const HIGH_THRESHOLD = 60;   // score >= 60 -> High
const COMBO_BONUS = 10;      // extra points when risky signs appear together

/* ---------- 2. Rules ----------
   Each rule has:
   - id, label, explain: text shown to the user
   - group: rules in the same group do NOT add up (only the highest counts)
   - weight: points added to the score
   - pattern: regular expression to search for
   - exclude (optional): if the matched text also matches this, ignore it
   - tip: safety recommendation shown when the rule matches */
const RULES = [
  {
    id: "urgency", group: "urgency", weight: 15,
    label: "Urgent or pressuring language",
    explain: "Scammers create panic so you act before thinking.",
    pattern: /\b(urgent(ly)?|immediately|right now|act now|last chance|final warning|expires? (today|soon)|within \d+ (hours?|minutes?))\b/i,
    tip: "Pause. Genuine organisations rarely demand action within minutes."
  },
  {
    id: "secrecy", group: "urgency", weight: 10,
    label: "Request to keep it secret",
    explain: "Asking you not to tell anyone is a common manipulation tactic.",
    pattern: /\b(do not|don't|dont) (tell|share this with|inform) (anyone|anybody|others)\b|\bkeep (this|it) (secret|confidential)\b/i,
    tip: "Talk to a family member or friend before acting."
  },
  {
    id: "threat", group: "threat", weight: 20,
    label: "Threat of account suspension or blocking",
    explain: "The message threatens to block, suspend or close an account or service.",
    pattern: /\b(account|card|sim|service|wallet)\b[^.]{0,40}(suspend|block|clos|deactivat|terminat|lock|expire)/i,
    tip: "Do not click anything. Contact the company using its official app or number."
  },
  {
    id: "prize", group: "prize", weight: 20,
    label: "Unexpected prize, reward or lottery",
    explain: "Unexpected winnings are a classic bait used to collect your details or money.",
    pattern: /\b(congratulations|you (have )?won|you('ve| have) been selected|lottery|jackpot|lucky (winner|draw)|free gift|cashback offer|claim (your )?(prize|reward|gift))\b/i,
    tip: "You cannot win a contest you never entered. Ignore and delete."
  },
  {
    id: "sensitive", group: "sensitive", weight: 30,
    label: "Request for OTP, password, PIN or bank details",
    explain: "Banks and genuine services never ask you to share these secrets by message.",
    pattern: /\b(share|send|enter|provide|confirm|verify|update|submit|tell|give|reply with)\b[^.]{0,40}\b(otp|one[- ]time password|password|pin|cvv|card number|account number|bank details|net ?banking|aadhaar)\b/i,
    exclude: /\b(do not|don't|dont|never)\b/i, // "Never share your OTP" is a warning, not a request
    tip: "Never share OTPs, PINs, passwords or card details with anyone."
  },
  {
    id: "shortlink", group: "link", weight: 15,
    label: "Shortened link",
    explain: "Short links hide the real destination website.",
    pattern: /\b(bit\.ly|tinyurl\.com|t\.co|goo\.gl|cutt\.ly|is\.gd|rb\.gy|shorturl\.at|ow\.ly)\/\S*/i,
    tip: "Do not open shortened links from unknown senders."
  },
  {
    id: "oddlink", group: "link", weight: 15,
    label: "Unusual web address",
    explain: "The link uses a raw IP address or a domain ending often seen in scams.",
    pattern: /https?:\/\/\d{1,3}(\.\d{1,3}){3}\S*|https?:\/\/\S+\.(xyz|top|icu|click|vip|tk|cc)\b\S*/i,
    tip: "Type the official website address yourself instead of using the link."
  },
  {
    id: "clicklink", group: "link", weight: 10,
    label: "Asks you to click a link",
    explain: "Links in unexpected messages are a common way to reach fake websites.",
    pattern: /\b(click|tap|open|visit)\b[^.]{0,20}\b(link|here|below|url)\b/i,
    tip: "Avoid clicking links in unexpected messages."
  },
  {
    id: "fee", group: "fee", weight: 20,
    label: "Request to pay a fee to receive something",
    explain: "Real prizes or refunds do not need an upfront fee.",
    pattern: /\b(pay|deposit|transfer|send)\b[^.]{0,40}\b(fee|charges?|tax|registration|processing)\b|\b(processing|registration|claim|release|delivery|handling) (fee|charges?)\b/i,
    tip: "Never pay money to receive a prize, refund or parcel."
  },
  {
    id: "impersonation", group: "impersonation", weight: 10,
    label: "Possible impersonation of a trusted organisation",
    explain: "The message mentions a bank, delivery company, government body or support team. Scammers often pretend to be these.",
    pattern: /\b(sbi|hdfc|icici|axis bank|paytm|phonepe|bank|customer (care|support)|support team|india post|fedex|dhl|courier|parcel|amazon|flipkart|income tax|rbi|government|kyc)\b/i,
    tip: "Verify using the organisation's official website or app, not the message."
  },
  {
    id: "install", group: "install", weight: 20,
    label: "Asks you to install an app",
    explain: "Unknown apps (especially APK files or remote-access tools) can steal data.",
    pattern: /\b(install|download)\b[^.]{0,30}\b(app|apk|application|software|anydesk|teamviewer)\b|\.apk\b/i,
    tip: "Only install apps from the official Play Store / App Store."
  },
  {
    id: "transfer", group: "transfer", weight: 20,
    label: "Unusual request to transfer money",
    explain: "The message asks you to send money, gift cards or crypto.",
    pattern: /\b(transfer|send|wire|pay)\b[^.]{0,30}(₹|rs\.?\s?\d|inr|\$|usd|\d+\s?(rupees|dollars)|gift cards?|upi|bitcoin|crypto)/i,
    tip: "Do not send money to people or numbers you cannot verify."
  }
];

/* ---------- 3. Sample messages ---------- */
const SAMPLES = {
  suspicious: "Congratulations! You have won a prize. Pay a processing fee immediately and enter your bank details to claim your reward.",
  normal: "Hi, our class meeting is scheduled for tomorrow at 10 AM in the seminar hall. Please arrive on time.",
  bank: "Your account will be suspended immediately. Click this link and share your OTP to restore access."
};

/* Extra test cases (run runTests() in the browser console) */
const TEST_CASES = [
  { text: SAMPLES.suspicious, expected: "High" },
  { text: SAMPLES.bank, expected: "High" },
  { text: SAMPLES.normal, expected: "Low" },
  { text: "Your parcel is held. Pay Rs 49 fee at bit.ly/x9Kd to release delivery.", expected: "High" },
  { text: "Please install this APK to get your refund from SBI.", expected: "Medium" },
  { text: "Dear customer, update your KYC today or your account will be blocked.", expected: "Medium" },
  { text: "Lunch at 1 PM? I'll send you the notes on WhatsApp.", expected: "Low" },
  { text: "Never share your OTP with anyone. – Your Bank", expected: "Low" }
];

/* ---------- 4. Analysis logic ---------- */

/* Checks the text against every rule and returns the result object. */
function analyzeMessage(text) {
  const matched = [];

  for (const rule of RULES) {
    const found = rule.pattern.exec(text);
    if (!found) continue;
    // Look at a few words BEFORE the match too (e.g. "Never" in "Never share your OTP")
    const context = text.slice(Math.max(0, found.index - 25), found.index + found[0].length);
    if (rule.exclude && rule.exclude.test(context)) continue;
    matched.push({ rule: rule, snippet: found[0].trim().slice(0, 60), counted: false });
  }

  // Only the strongest rule in each group is counted, so repeated ideas don't inflate the score.
  const best = {};
  for (const item of matched) {
    const g = item.rule.group;
    if (!best[g] || item.rule.weight > best[g].rule.weight) best[g] = item;
  }
  let score = 0;
  for (const g in best) {
    best[g].counted = true;
    score += best[g].rule.weight;
  }

  // Bonus when a secret-request appears together with another strong sign.
  const groups = Object.keys(best);
  const hasCombo = groups.includes("sensitive") &&
    (groups.includes("link") || groups.includes("threat") || groups.includes("prize"));
  if (hasCombo) score += COMBO_BONUS;

  score = Math.min(score, 100);

  let level = "Low";
  if (score >= HIGH_THRESHOLD) level = "High";
  else if (score >= MEDIUM_THRESHOLD) level = "Medium";

  // Collect unique safety tips
  const tips = [];
  for (const item of matched) {
    if (!tips.includes(item.rule.tip)) tips.push(item.rule.tip);
  }

  return { score: score, level: level, signs: matched, tips: tips, combo: hasCombo };
}

/* Short explanation of the overall result */
function buildSummary(result) {
  const count = result.signs.length;
  if (count === 0) {
    return "No known warning patterns were found. This does NOT mean the message is safe. Scams can use wording these rules do not know about.";
  }
  const names = result.signs.filter(s => s.counted).map(s => s.rule.label.toLowerCase());
  const start = result.level === "High" ? "Several strong warning signs were found" :
                result.level === "Medium" ? "Some warning signs were found" :
                "Only minor warning signs were found";
  return start + ": " + names.join("; ") + ". Treat this as an estimate, not a verdict.";
}

/* ---------- 5. Page elements ---------- */
const input = document.getElementById("messageInput");
const charCount = document.getElementById("charCount");
const errorMsg = document.getElementById("errorMsg");
const analyzeBtn = document.getElementById("analyzeBtn");
const clearBtn = document.getElementById("clearBtn");
const scanner = document.getElementById("scanner");
const resultsBox = document.getElementById("results");
const scoreNumber = document.getElementById("scoreNumber");
const scoreCircle = document.getElementById("scoreCircle");
const riskBadge = document.getElementById("riskBadge");
const meterFill = document.getElementById("meterFill");
const riskSummary = document.getElementById("riskSummary");
const signsList = document.getElementById("signsList");
const recList = document.getElementById("recList");
const copyBtn = document.getElementById("copyBtn");
const downloadBtn = document.getElementById("downloadBtn");
const againBtn = document.getElementById("againBtn");
const statusMsg = document.getElementById("statusMsg");

let lastResult = null;   // newest analysis (kept only in memory)
let lastMessage = "";
let scanTimer = null;
let animationId = null;

/* ---------- 6. Display functions ---------- */

function updateCounter() {
  charCount.textContent = input.value.length + " / " + input.maxLength;
}

function showError(text) { errorMsg.textContent = text; }

/* Counts the score up from 0 for a smooth animation */
function animateScore(target) {
  cancelAnimationFrame(animationId);
  const start = performance.now();
  const duration = 1000;
  function step(now) {
    const progress = Math.min((now - start) / duration, 1);
    scoreNumber.textContent = Math.round(target * progress);
    if (progress < 1) animationId = requestAnimationFrame(step);
  }
  animationId = requestAnimationFrame(step);
}

/* Builds the results dashboard from the analysis object */
function showResults(result) {
  const levelClass = "level-" + result.level.toLowerCase();
  resultsBox.className = "card results " + levelClass;
  riskBadge.textContent = result.level + " Risk";
  riskSummary.textContent = buildSummary(result);
  meterFill.style.width = "0%";
  requestAnimationFrame(() => { meterFill.style.width = result.score + "%"; });
  animateScore(result.score);

  // Warning signs
  signsList.innerHTML = "";
  if (result.signs.length === 0) {
    const li = document.createElement("li");
    li.innerHTML = "<strong>No warning signs detected</strong><p>Remember: this is not proof the message is safe.</p>";
    signsList.appendChild(li);
  }
  for (const item of result.signs) {
    const li = document.createElement("li");
    const title = document.createElement("strong");
    const name = document.createElement("span");
    const pts = document.createElement("span");
    name.textContent = item.rule.label;
    pts.className = "pts";
    pts.textContent = item.counted ? "+" + item.rule.weight + " pts" : "related (not added again)";
    title.append(name, pts);
    const why = document.createElement("p");
    why.textContent = item.rule.explain + " Matched text: ";
    const code = document.createElement("code");
    code.textContent = item.snippet; // textContent keeps user text safe from HTML injection
    why.appendChild(code);
    li.append(title, why);
    signsList.appendChild(li);
  }
  if (result.combo) {
    const li = document.createElement("li");
    li.innerHTML = "<strong>Combination bonus <span class='pts'>+" + COMBO_BONUS + " pts</span></strong><p>A request for secret details together with another warning sign is especially risky.</p>";
    signsList.appendChild(li);
  }

  // Recommendations
  recList.innerHTML = "";
  const tips = result.tips.slice();
  tips.push("When in doubt, contact the organisation through its official website, app or number.");
  if (result.level === "High") tips.push("Report it: in India, use cybercrime.gov.in or call 1930.");
  for (const t of tips) {
    const li = document.createElement("li");
    li.textContent = t;
    recList.appendChild(li);
  }

  resultsBox.hidden = false;
  statusMsg.textContent = "";
  resultsBox.scrollIntoView({ behavior: "smooth", block: "start" });
}

/* ---------- 7. Button handlers ---------- */

function handleAnalyze() {
  const text = input.value.trim();
  if (text === "") {
    showError("Please paste a message first.");
    input.focus();
    return;
  }
  showError("");
  resultsBox.hidden = true;
  scanner.hidden = false;
  analyzeBtn.disabled = true;

  // Short delay to show the scanning animation
  scanTimer = setTimeout(() => {
    try {
      lastResult = analyzeMessage(text);
      lastMessage = text;
      showResults(lastResult);
    } catch (err) {
      showError("Something went wrong while analyzing. Please try again.");
      console.error(err);
    } finally {
      scanner.hidden = true;
      analyzeBtn.disabled = false;
    }
  }, 1100);
}

function handleClear() {
  clearTimeout(scanTimer);
  cancelAnimationFrame(animationId);
  input.value = "";
  lastResult = null;
  lastMessage = "";
  resultsBox.hidden = true;
  scanner.hidden = true;
  analyzeBtn.disabled = false;
  showError("");
  statusMsg.textContent = "";
  updateCounter();
  input.focus();
}

/* Plain-text report used by Copy and Download */
function buildReportText() {
  const r = lastResult;
  const lines = [];
  lines.push("SCAMSHIELD ANALYSIS REPORT");
  lines.push("(Rule-based demo – heuristic estimate, not a guaranteed scam detector)");
  lines.push("Date: " + new Date().toLocaleString());
  lines.push("");
  lines.push("Risk category: " + r.level);
  lines.push("Risk score: " + r.score + "/100 (heuristic estimate)");
  lines.push("");
  lines.push("Summary: " + buildSummary(r));
  lines.push("");
  lines.push("Warning signs detected:");
  if (r.signs.length === 0) lines.push("- None detected (this does not mean the message is safe)");
  r.signs.forEach(s => lines.push("- " + s.rule.label + ": " + s.rule.explain + ' [matched: "' + s.snippet + '"]'));
  lines.push("");
  lines.push("Recommendations:");
  r.tips.forEach(t => lines.push("- " + t));
  lines.push("- When in doubt, contact the organisation through its official website, app or number.");
  lines.push("");
  lines.push("Analyzed message:");
  lines.push(lastMessage);
  return lines.join("\n");
}

/* Copy using the Clipboard API, with a fallback for older browsers */
async function handleCopy() {
  if (!lastResult) return;
  const text = buildReportText();
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
    } else {
      throw new Error("Clipboard API unavailable");
    }
    statusMsg.textContent = "✅ Results copied to clipboard.";
  } catch (e) {
    // Fallback: temporary textarea + execCommand
    const temp = document.createElement("textarea");
    temp.value = text;
    temp.style.position = "fixed";
    temp.style.opacity = "0";
    document.body.appendChild(temp);
    temp.select();
    let ok = false;
    try { ok = document.execCommand("copy"); } catch (err) { ok = false; }
    document.body.removeChild(temp);
    statusMsg.textContent = ok ? "✅ Results copied to clipboard."
                               : "⚠️ Copy is not available in this browser. Please use Download Report instead.";
  }
}

/* Download the report as a .txt file */
function handleDownload() {
  if (!lastResult) return;
  try {
    const blob = new Blob([buildReportText()], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "scamshield-report.txt";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    statusMsg.textContent = "✅ Report downloaded.";
  } catch (e) {
    statusMsg.textContent = "⚠️ Could not create the report file.";
  }
}

function handleSample(event) {
  const key = event.currentTarget.dataset.sample;
  if (!SAMPLES[key]) return;
  input.value = SAMPLES[key];
  showError("");
  updateCounter();
  input.focus();
}

/* ---------- 8. Event listeners ---------- */
input.addEventListener("input", () => { updateCounter(); if (input.value.trim()) showError(""); });
analyzeBtn.addEventListener("click", handleAnalyze);
clearBtn.addEventListener("click", handleClear);
copyBtn.addEventListener("click", handleCopy);
downloadBtn.addEventListener("click", handleDownload);
againBtn.addEventListener("click", () => { handleClear(); window.scrollTo({ top: 0, behavior: "smooth" }); });
document.querySelectorAll("[data-sample]").forEach(btn => btn.addEventListener("click", handleSample));
input.addEventListener("keydown", (e) => { if (e.ctrlKey && e.key === "Enter") handleAnalyze(); });

updateCounter();

/* ---------- 9. Self-test (type runTests() in the browser console) ---------- */
function runTests() {
  const rows = TEST_CASES.map(t => {
    const r = analyzeMessage(t.text);
    return { message: t.text.slice(0, 45) + "...", score: r.score, got: r.level, expected: t.expected,
             result: r.level === t.expected ? "PASS" : "FAIL" };
  });
  console.table(rows);
}
window.runTests = runTests;
