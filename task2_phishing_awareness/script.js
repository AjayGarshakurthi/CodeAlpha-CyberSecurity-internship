/**
 * PhishGuard Training — Interactive Script
 * CodeAlpha Cybersecurity Internship — Task 2
 */

"use strict";

// ═══════════════════════════════════════════════════════════════
//  QUIZ DATA
// ═══════════════════════════════════════════════════════════════

const QUIZ_QUESTIONS = [
  {
    q: "You receive an email from 'support@paypa1.com' asking you to verify your account. What should you do?",
    options: [
      "Click the link and log in to verify",
      "Reply with your username and password",
      "Check the sender domain carefully — 'paypa1' uses a number '1' instead of 'l'. Delete the email.",
      "Forward it to all your colleagues as a warning"
    ],
    correct: 2,
    explanation: "Lookalike domains (paypa1 vs paypal) are a classic phishing tactic. Always inspect the sender domain character by character before clicking anything."
  },
  {
    q: "Which of the following is the BEST indicator that a website login page is legitimate?",
    options: [
      "The page has a padlock icon (HTTPS)",
      "The page looks identical to the real site",
      "The full domain name in the address bar matches the official site exactly",
      "The page loaded quickly"
    ],
    correct: 2,
    explanation: "HTTPS only means the connection is encrypted — phishing sites use HTTPS too. The only reliable check is verifying the exact domain name in the address bar."
  },
  {
    q: "A spear phishing attack differs from regular phishing because it:",
    options: [
      "Uses phone calls instead of emails",
      "Is personalised using information about the specific target",
      "Only targets large corporations",
      "Always contains malware attachments"
    ],
    correct: 1,
    explanation: "Spear phishing uses personal details (your name, employer, colleagues) gathered from social media or data breaches to make the attack highly convincing."
  },
  {
    q: "Your CEO emails you urgently asking for a $50,000 wire transfer to a new vendor. What is the safest response?",
    options: [
      "Process it immediately — the CEO is always right",
      "Reply to the email asking for more details",
      "Call the CEO directly using a known phone number to verify the request",
      "Forward the email to your finance team to handle"
    ],
    correct: 2,
    explanation: "This is a classic Business Email Compromise (BEC) / whaling attack. Always verify financial requests via a separate, trusted communication channel — never by replying to the suspicious email."
  },
  {
    q: "What is 'vishing'?",
    options: [
      "Phishing via fake websites",
      "Phishing via SMS text messages",
      "Phishing via voice/phone calls",
      "Phishing via video calls"
    ],
    correct: 2,
    explanation: "Vishing = Voice + Phishing. Attackers call victims impersonating tech support, banks, or government agencies to extract sensitive information verbally."
  },
  {
    q: "You receive a text: 'USPS: Your package is on hold. Confirm your address: bit.ly/pkg-confirm'. What should you do?",
    options: [
      "Click the link — it's probably a real delivery notification",
      "Ignore it — this is a smishing (SMS phishing) attempt",
      "Reply STOP to unsubscribe",
      "Forward it to USPS customer service"
    ],
    correct: 1,
    explanation: "This is smishing (SMS phishing). Legitimate delivery companies don't ask you to click shortened links to confirm addresses. Go directly to the carrier's official website instead."
  },
  {
    q: "Which social engineering tactic involves creating a false sense of time pressure?",
    options: [
      "Reciprocity",
      "Social proof",
      "Urgency / Scarcity",
      "Familiarity"
    ],
    correct: 2,
    explanation: "Urgency tactics ('Act in 24 hours or your account will be closed!') are designed to prevent you from thinking critically or verifying the request."
  },
  {
    q: "A password manager helps protect against phishing because it:",
    options: [
      "Generates very long passwords that are hard to guess",
      "Only auto-fills credentials on the correct domain, not on lookalike sites",
      "Encrypts your hard drive",
      "Blocks phishing emails from reaching your inbox"
    ],
    correct: 1,
    explanation: "Password managers auto-fill only on the exact domain they saved credentials for. If you land on a fake site (paypa1.com), the manager won't fill in your PayPal credentials — a built-in phishing detector."
  },
  {
    q: "In the 2023 MGM Resorts breach, how did attackers gain initial access?",
    options: [
      "By exploiting an unpatched software vulnerability",
      "By brute-forcing the admin password",
      "By using a 10-minute LinkedIn research + vishing call to impersonate an employee to the IT help desk",
      "By intercepting network traffic"
    ],
    correct: 2,
    explanation: "The ALPHV/BlackCat group used social engineering — researching an employee on LinkedIn then calling the IT help desk to impersonate them. This highlights that human factors are often the weakest link."
  },
  {
    q: "Which of the following is the MOST secure way to handle a suspicious email attachment?",
    options: [
      "Open it in a preview pane to check if it looks safe",
      "Open it only if the sender's name looks familiar",
      "Do not open it; report it to your IT/security team and delete it",
      "Scan it with your antivirus, then open it if no threats are found"
    ],
    correct: 2,
    explanation: "Antivirus scanners can miss zero-day exploits. The safest action is to not open unexpected attachments at all — report them to your security team who can analyse them safely."
  }
];

// ═══════════════════════════════════════════════════════════════
//  STATE
// ═══════════════════════════════════════════════════════════════

let answers = new Array(QUIZ_QUESTIONS.length).fill(null);
let answered = new Array(QUIZ_QUESTIONS.length).fill(false);

// ═══════════════════════════════════════════════════════════════
//  QUIZ RENDERING
// ═══════════════════════════════════════════════════════════════

function renderQuiz() {
  const container = document.getElementById("quizContainer");
  container.innerHTML = "";

  QUIZ_QUESTIONS.forEach((q, qi) => {
    const block = document.createElement("div");
    block.className = "quiz-question-block";
    block.id = `q-${qi}`;

    const letters = ["A", "B", "C", "D"];
    const optionsHTML = q.options.map((opt, oi) => `
      <div class="quiz-option" id="opt-${qi}-${oi}" onclick="selectOption(${qi}, ${oi})">
        <span class="option-letter">${letters[oi]}</span>
        <span>${opt}</span>
      </div>
    `).join("");

    block.innerHTML = `
      <div class="quiz-q-num">Question ${qi + 1} of ${QUIZ_QUESTIONS.length}</div>
      <div class="quiz-q-text">${q.q}</div>
      <div class="quiz-options" id="opts-${qi}">${optionsHTML}</div>
      <div class="quiz-feedback" id="fb-${qi}"></div>
    `;
    container.appendChild(block);
  });

  const submitBtn = document.createElement("button");
  submitBtn.className = "quiz-submit-btn";
  submitBtn.id = "submitBtn";
  submitBtn.textContent = "Submit Answers";
  submitBtn.onclick = submitQuiz;
  container.appendChild(submitBtn);
}

function selectOption(qi, oi) {
  if (answered[qi]) return;

  // Clear previous selection highlight (before answering)
  document.querySelectorAll(`#opts-${qi} .quiz-option`).forEach(el => {
    el.style.borderColor = "";
    el.style.background  = "";
  });

  answers[qi] = oi;

  // Highlight selected
  const selected = document.getElementById(`opt-${qi}-${oi}`);
  selected.style.borderColor = "var(--accent)";
  selected.style.background  = "rgba(88,166,255,.1)";
}

function submitQuiz() {
  // Check all answered
  const unanswered = answers.map((a, i) => a === null ? i + 1 : null).filter(Boolean);
  if (unanswered.length > 0) {
    alert(`Please answer question(s): ${unanswered.join(", ")}`);
    return;
  }

  let score = 0;

  QUIZ_QUESTIONS.forEach((q, qi) => {
    answered[qi] = true;
    const chosen  = answers[qi];
    const correct = q.correct;
    const isRight = chosen === correct;
    if (isRight) score++;

    // Style all options
    document.querySelectorAll(`#opts-${qi} .quiz-option`).forEach((el, oi) => {
      el.classList.add("disabled");
      el.style.borderColor = "";
      el.style.background  = "";
      if (oi === correct) el.classList.add("correct");
      if (oi === chosen && !isRight) el.classList.add("wrong");
    });

    // Show feedback
    const fb = document.getElementById(`fb-${qi}`);
    fb.classList.add("show");
    if (isRight) {
      fb.classList.add("correct-fb");
      fb.innerHTML = `✅ Correct! ${q.explanation}`;
    } else {
      fb.classList.add("wrong-fb");
      fb.innerHTML = `❌ Incorrect. ${q.explanation}`;
    }
  });

  // Hide submit button
  document.getElementById("submitBtn").style.display = "none";

  // Show result after short delay
  setTimeout(() => showResult(score), 600);
  updateProgress();
}

function showResult(score) {
  const total = QUIZ_QUESTIONS.length;
  const pct   = Math.round((score / total) * 100);

  const resultEl = document.getElementById("quizResult");
  resultEl.style.display = "block";
  resultEl.scrollIntoView({ behavior: "smooth", block: "center" });

  document.getElementById("scoreDisplay").textContent = `${score} / ${total}`;

  let icon, title, msg;
  if (pct >= 90) {
    icon  = "🏆";
    title = "Excellent! You're a Phishing Expert!";
    msg   = "Outstanding score! You have a strong understanding of phishing threats and how to defend against them.";
  } else if (pct >= 70) {
    icon  = "🎯";
    title = "Good Job! Solid Awareness.";
    msg   = "You have a good grasp of phishing concepts. Review the questions you missed to strengthen your knowledge.";
  } else if (pct >= 50) {
    icon  = "📚";
    title = "Keep Learning!";
    msg   = "You're on the right track, but there are gaps in your phishing awareness. Re-read the training material and try again.";
  } else {
    icon  = "⚠️";
    title = "Needs Improvement";
    msg   = "You may be at risk. Please review all sections of this training carefully before retaking the quiz.";
  }

  document.getElementById("resultIcon").textContent  = icon;
  document.getElementById("resultTitle").textContent = title;
  document.getElementById("resultMsg").textContent   = msg;
}

function restartQuiz() {
  answers  = new Array(QUIZ_QUESTIONS.length).fill(null);
  answered = new Array(QUIZ_QUESTIONS.length).fill(false);
  document.getElementById("quizResult").style.display = "none";
  renderQuiz();
  document.getElementById("quizContainer").scrollIntoView({ behavior: "smooth" });
}

// ═══════════════════════════════════════════════════════════════
//  PROGRESS TRACKER
// ═══════════════════════════════════════════════════════════════

const SECTIONS = ["what-is", "types", "recognize", "social-eng", "examples", "best-practices", "quiz"];

function updateProgress() {
  const scrollY = window.scrollY + window.innerHeight * 0.6;
  let visited = 0;

  SECTIONS.forEach(id => {
    const el = document.getElementById(id);
    if (el && el.offsetTop <= scrollY) visited++;
  });

  const pct = Math.round((visited / SECTIONS.length) * 100);
  document.getElementById("progressFill").style.width = pct + "%";
  document.getElementById("progressPct").textContent  = pct + "%";
}

window.addEventListener("scroll", updateProgress, { passive: true });

// ═══════════════════════════════════════════════════════════════
//  TYPE CARD ACCORDION
// ═══════════════════════════════════════════════════════════════

function toggleType(card) {
  card.classList.toggle("open");
}

// ═══════════════════════════════════════════════════════════════
//  TOOLTIP SYSTEM
// ═══════════════════════════════════════════════════════════════

const tooltipPopup = document.getElementById("tooltipPopup");
const tooltipBox   = document.getElementById("tooltipBox");

document.querySelectorAll(".red-flag[data-tip]").forEach(el => {
  el.addEventListener("mouseenter", (e) => {
    tooltipPopup.textContent = el.dataset.tip;
    tooltipPopup.classList.add("visible");
    tooltipBox.textContent = "💡 " + el.dataset.tip;
    positionTooltip(e);
  });
  el.addEventListener("mousemove", positionTooltip);
  el.addEventListener("mouseleave", () => {
    tooltipPopup.classList.remove("visible");
    tooltipBox.textContent = "👆 Hover over the ⚠️ flags above to learn why each element is suspicious.";
  });
});

function positionTooltip(e) {
  const x = e.clientX + 14;
  const y = e.clientY - 10;
  const w = tooltipPopup.offsetWidth;
  const h = tooltipPopup.offsetHeight;
  tooltipPopup.style.left = (x + w > window.innerWidth  ? x - w - 28 : x) + "px";
  tooltipPopup.style.top  = (y + h > window.innerHeight ? y - h      : y) + "px";
}

// ═══════════════════════════════════════════════════════════════
//  INIT
// ═══════════════════════════════════════════════════════════════

document.addEventListener("DOMContentLoaded", () => {
  renderQuiz();
  updateProgress();
});
