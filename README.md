# 🛡️ ScamShield – Suspicious Message Checker

> **Think Before You Click.** A browser-based, rule-based demo that checks messages for common scam warning signs.


## 📖 Introduction
ScamShield lets you paste an SMS, WhatsApp message, email or other text and receive an **estimated** risk level (Low, Medium or High), a 0–100 heuristic score, the warning signs found, and practical safety advice. Everything runs in your browser.

## 🔎 Project Overview
**Problem:** Scam messages use urgency, fake prizes and requests for OTPs or fees to trick people into acting quickly.

**Solution:** ScamShield scans the text for known warning patterns using transparent, configurable rules and explains each finding in plain language, so users learn to recognise scams themselves.

## ✨ Key Features
- 🔍 **Message scanning** with a short scanning animation
- 🚦 **Risk classification:** Low, Medium or High, shown with colour coding
- 🔢 **Animated risk score** (0–100), labelled as a heuristic estimate
- ⚠️ **Detected warning signs** with an explanation and the matched text
- ✅ **Safety recommendations** based on what was detected
- 📋 **Copy Results** (Clipboard API with a fallback)
- ⬇️ **Download Report** as a plain-text `.txt` file
- 🧪 One-click sample messages, a character counter, input validation and a Clear / Try Another Message option
- 📱 Responsive layout for phones, tablets and desktops

## 🧰 Technology Stack
| Technology | Purpose |
|---|---|
| HTML5 | Page structure |
| CSS3 | Styling, layout, animations, responsiveness |
| Vanilla JavaScript | Rule-based analysis and interactivity |

No frameworks, backend, database, API keys or external services are used.

## ⚙️ How It Works
1. The message is checked against a list of rules in `script.js`. Each rule has a regular expression, a weight, an explanation and a safety tip.
2. Rules that belong to the same group (for example, the three link rules) are **not added together**. Only the highest-weight rule in each group counts, so repeated ideas don't inflate the score.
3. A **+10 combination bonus** applies when a request for OTP, password or bank details appears together with a link, threat or prize.
4. The score is capped at 100 and mapped to a category:

| Score | Category |
|---|---|
| 0–29 | Low |
| 30–59 | Medium |
| 60–100 | High |

**Warning signs checked:** urgent or pressuring language, requests for secrecy, account-suspension threats, unexpected prizes, requests for OTP/password/PIN/bank details, shortened or unusual links, fee demands, impersonation of trusted organisations, requests to install apps, and unusual money-transfer requests.

A result of Low or "no warning signs" does **not** mean a message is safe.

## 📁 Project Structure
```
scamshield/
├── index.html   # Page structure
├── style.css    # Styling and responsive design
├── script.js    # Rules, scoring and interactivity
└── README.md    # Project documentation
```

## 🌐 Live Demo
🔗 **[Add your GitHub Pages URL here](https://YOUR-USERNAME.github.io/YOUR-REPOSITORY-NAME/)**

## 💻 Installation and Setup
**Download:** click **Code → Download ZIP** on the repository page and extract it.

**Or clone:**
```bash
git clone https://github.com/YOUR-USERNAME/YOUR-REPOSITORY-NAME.git
cd YOUR-REPOSITORY-NAME
```

**Run:** double-click `index.html`, or open the folder in VS Code and use the **Live Server** extension (right-click `index.html` → *Open with Live Server*).

No installation, build step or internet connection is required.

## 🕹️ Usage Instructions
1. Paste a message into the text box (or click an example button).
2. Click **Analyze Message** (or press `Ctrl + Enter`).
3. Read the results:
   - **Risk category and score:** a heuristic estimate, not a verdict
   - **Warning signs:** what was found, why it matters and the matched text
   - **Recommended actions:** practical safety steps
4. Use **Copy Results** or **Download Report** to save the analysis.
5. Click **Clear** or **Try Another Message** to start again.

## 🧪 Sample Test Messages
| Type | Message | Expected result |
|---|---|---|
| Suspicious | "Congratulations! You have won a prize. Pay a processing fee immediately and enter your bank details to claim your reward." | High |
| Urgent bank alert | "Your account will be suspended immediately. Click this link and share your OTP to restore access." | High |
| Normal | "Hi, our class meeting is scheduled for tomorrow at 10 AM in the seminar hall. Please arrive on time." | Low |
| Delivery fee | "Your parcel is held. Pay Rs 49 fee at bit.ly/x9Kd to release delivery." | High |
| Fake app | "Please install this APK to get your refund from SBI." | Medium |
| Safety notice | "Never share your OTP with anyone. – Your Bank" | Low |

You can also run the built-in checks by opening the browser console (F12) and typing `runTests()`.

## 🚀 Deployment on GitHub Pages
1. Push the four files to a GitHub repository.
2. Open **Settings → Pages**.
3. Under **Source**, choose **Deploy from a branch**, select `main` and `/ (root)`, then click **Save**.
4. After a minute, your site is available at `https://YOUR-USERNAME.github.io/YOUR-REPOSITORY-NAME/`.
5. Paste that URL in the [Live Demo](#-live-demo) section.

## ⚠️ Limitations and Disclaimer
- ScamShield uses **rule-based detection** on visible text patterns. It is **not** AI or machine learning.
- It is **not a guaranteed scam detector** and does not replace professional security tools.
- Scams written in other languages, slang or with deliberate misspellings may be missed.
- Genuine messages that mention banks, KYC or OTPs may receive a higher score.
- It does not check whether a link is actually malicious.
- Always verify suspicious messages through the organisation's official website, app or phone number.
- Messages are processed locally in your browser and are never sent to a server. The report is only saved if you choose to download it.

*This is an educational demo project.*

## 🔮 Future Enhancements
- Integrating a trained AI/ML model for smarter detection
- Multilingual support (for example, Hindi and other regional languages)
- Improved threat detection with more rules and link analysis
- Editable rule settings in the interface
- Saved history stored only on the user's device

## 👤 Author 
**Author:** Radhika Singh

