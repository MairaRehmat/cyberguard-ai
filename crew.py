import json
import os
import re
from datetime import datetime, timezone
from typing import List

from crewai import Agent, Crew, LLM, Process, Task

try:
    from screenshot_tool import ScreenshotAnalysisTool
except Exception:
    ScreenshotAnalysisTool = None

# ============================================================
# ENVIRONMENT
# ============================================================

OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY") or os.getenv(
    "OPENAI_API_KEY"
)

OPENROUTER_BASE_URL = os.getenv(
    "OPENAI_BASE_URL",
    "https://openrouter.ai/api/v1"
)

MODEL_NAME = os.getenv(
    "CYBERGUARD_MODEL",
    "openrouter/google/gemini-2.5-flash"
)


# ============================================================
# LLM
# ============================================================

cyberguard_llm = None

if OPENROUTER_API_KEY:

    try:
        cyberguard_llm = LLM(
            model=MODEL_NAME,
            api_key=OPENROUTER_API_KEY,
            base_url=OPENROUTER_BASE_URL,
            max_tokens=1000,
            temperature=0.2,
        )

    except Exception as e:
        print(f"LLM initialization warning: {e}")
        cyberguard_llm = None


# ============================================================
# SCREENSHOT TOOL
# ============================================================

screenshot_tool = None

if ScreenshotAnalysisTool is not None:

    try:
        screenshot_tool = ScreenshotAnalysisTool()

    except Exception as e:
        print(f"Screenshot tool initialization warning: {e}")
        screenshot_tool = None


# ============================================================
# AGENTS
# ============================================================

if cyberguard_llm:

    security_analyst = Agent(
        role="Cybersecurity Assistant",
        goal=(
            "Answer cybersecurity questions accurately, safely, "
            "clearly and in simple language."
        ),
        backstory=(
            "You are a cybersecurity assistant that helps users "
            "understand phishing, scams, suspicious messages, "
            "password safety, malware and online security."
        ),
        llm=cyberguard_llm,
        verbose=False,
        allow_delegation=False,
    )

    report_writer = Agent(
        role="Cybersecurity Report Writer",
        goal=(
            "Provide concise and useful cybersecurity guidance."
        ),
        backstory=(
            "You explain cybersecurity concepts in a simple "
            "and user-friendly way."
        ),
        llm=cyberguard_llm,
        verbose=False,
        allow_delegation=False,
    )

else:
    security_analyst = None
    report_writer = None


# ============================================================
# NORMALIZATION
# ============================================================

def normalize_text(text: str) -> str:

    if not text:
        return ""

    text = str(text)

    replacements = {
        "\u2018": "'",
        "\u2019": "'",
        "\u201c": '"',
        "\u201d": '"',
        "\u00a0": " ",
        "\u2013": "-",
        "\u2014": "-",
    }

    for old, new in replacements.items():
        text = text.replace(old, new)

    text = text.lower()

    text = re.sub(r"\s+", " ", text)

    return text.strip()


# ============================================================
# RISK CALCULATION
# ============================================================

def calculate_risk(message: str):

    text = normalize_text(message)

    score = 0

    threats: List[str] = []
    reasons: List[str] = []
    warnings: List[str] = []
    safe_actions: List[str] = []

    # --------------------------------------------------------
    # Empty / normal message
    # --------------------------------------------------------

    if not text:

        return {
            "risk_score": 0,
            "verdict": "SAFE",
            "threats": [],
            "reasons": [
                "No suspicious message content was detected."
            ],
            "warnings": [],
            "safe_actions": [
                "Continue following normal cybersecurity practices."
            ],
            "recommendation": (
                "No immediate cybersecurity action is required."
            ),
            "education": (
                "Always be careful with unexpected links and requests "
                "for sensitive information."
            ),
        }

    # --------------------------------------------------------
    # HIGH-RISK PATTERNS
    # --------------------------------------------------------

    dangerous_patterns = [

        # Credentials
        (
            r"\b(password|passcode)\b",
            30,
            "Credential request detected."
        ),

        # OTP / verification code
        (
            r"\b(otp|one[- ]time password|verification code|security code)\b",
            30,
            "A request involving an OTP or verification code was detected."
        ),

        # Financial information
        (
            r"\b(card number|credit card|debit card|cvv|bank account|"
            r"account number|bank details)\b",
            35,
            "Sensitive financial information is being requested."
        ),

        # Prize / reward
        (
            r"\b(congratulations|you(?:'| are)?ve been selected|"
            r"selected for|winner|won|prize|reward|cash prize|"
            r"free money)\b",
            35,
            "An unexpected prize or reward claim was detected."
        ),

        # Urgency
        (
            r"\b(urgent|immediately|right now|act now|"
            r"within \d+ minutes?|within \d+ hours?|"
            r"expires today|last chance)\b",
            20,
            "Urgent or pressure-based language was detected."
        ),

        # Account threats
        (
            r"\b(account will be suspended|account suspended|"
            r"account will be closed|account blocked|"
            r"account locked|access will be revoked)\b",
            25,
            "A threatening account-related claim was detected."
        ),

        # Verification
        (
            r"\b(verify your account|verify account|"
            r"confirm your account|verification required|"
            r"verify your identity)\b",
            25,
            "A request to verify an account or identity was detected."
        ),

        # Click actions
        (
            r"\b(click here|click the link|clicking the link|"
            r"clicking this link|click below|click the button|"
            r"tap here|tap the link|open the link)\b",
            25,
            "The message asks the user to interact with a link or button."
        ),

        # Claim actions
        (
            r"\b(claim now|claim your prize|redeem now|"
            r"redeem your reward|collect your reward)\b",
            30,
            "The message asks the user to claim or redeem something."
        ),

        # Malware
        (
            r"\b(download this file|download the attachment|"
            r"install this app|install the software|"
            r"malware|virus|trojan|ransomware)\b",
            40,
            "Potentially malicious software or attachment activity was detected."
        ),
    ]

    for pattern, points, reason in dangerous_patterns:

        if re.search(pattern, text):

            score += points

            if reason not in reasons:
                reasons.append(reason)

    # --------------------------------------------------------
    # URL DETECTION
    # --------------------------------------------------------

    url_matches = re.findall(
        r"(https?://[^\s]+|www\.[^\s]+)",
        text
    )

    if url_matches:

        score += 25

        threats.append(
            "Suspicious or externally supplied link detected."
        )

        reasons.append(
            "The message contains a clickable web link."
        )

        warnings.append(
            "Do not open unexpected links."
        )

    # --------------------------------------------------------
    # SUSPICIOUS DOMAIN INDICATORS
    # --------------------------------------------------------

    suspicious_domain_patterns = [

        r"\.tk\b",
        r"\.ml\b",
        r"\.ga\b",
        r"\.cf\b",
        r"\.gq\b",
        r"bit\.ly",
        r"tinyurl",
        r"t\.co",
        r"login-",
        r"verify-",
        r"secure-",
        r"account-",
        r"reward-",
        r"claim-",
    ]

    for pattern in suspicious_domain_patterns:

        if re.search(pattern, text):

            score += 25

            threats.append(
                "Potentially suspicious URL or domain pattern detected."
            )

            reasons.append(
                "The link contains characteristics commonly seen "
                "in suspicious URLs."
            )

            break

    # --------------------------------------------------------
    # IMPERSONATION
    # --------------------------------------------------------

    impersonation_patterns = [

        r"\b(bank|paypal|google|microsoft|apple|instagram|"
        r"facebook|netflix|amazon|whatsapp)\b",

        r"\b(support team|security team|customer support|"
        r"admin|administrator|official team)\b",
    ]

    for pattern in impersonation_patterns:

        if re.search(pattern, text):

            score += 10

            threats.append(
                "Possible impersonation or trusted-brand reference detected."
            )

            reasons.append(
                "The message references a trusted organization or authority."
            )

            break

    # --------------------------------------------------------
    # ACCOUNT / LOGIN ALERT
    # --------------------------------------------------------

    login_patterns = [
        r"\bunusual activity\b",
        r"\bsuspicious activity\b",
        r"\bnew login\b",
        r"\bnew sign[- ]in\b",
        r"\blogin attempt\b",
        r"\bsign[- ]in attempt\b",
        r"\brecent login activity\b",
        r"\baccount activity\b",
    ]

    login_detected = False

    for pattern in login_patterns:

        if re.search(pattern, text):

            login_detected = True
            break

    if login_detected:

        score += 20

        reasons.append(
            "The message refers to unusual or recent account activity."
        )

        warnings.append(
            "Verify account alerts through the official application or website."
        )

    # --------------------------------------------------------
    # HARD DANGEROUS COMBINATIONS
    # --------------------------------------------------------

    credential_request = bool(
        re.search(
            r"\b(password|passcode|otp|verification code|security code|"
            r"cvv|card number|bank details)\b",
            text
        )
    )

    link_present = bool(
        re.search(
            r"(https?://|www\.)",
            text
        )
    )

    urgent = bool(
        re.search(
            r"\b(urgent|immediately|act now|right now|"
            r"expires|within \d+ minutes?|last chance)\b",
            text
        )
    )

    prize = bool(
        re.search(
            r"\b(prize|reward|winner|congratulations|"
            r"selected|cash prize|free money)\b",
            text
        )
    )

    click_action = bool(
        re.search(
            r"\b(click|clicking|tap|open)\b",
            text
        )
    )

    verification = bool(
        re.search(
            r"\b(verify|verification|confirm your account|"
            r"verification code)\b",
            text
        )
    )

    if link_present and credential_request:

        score = max(score, 85)

        threats.append(
            "Credential harvesting attempt."
        )

        reasons.append(
            "The message combines a link with a request for sensitive credentials."
        )

    if prize and link_present and (
        click_action or credential_request or verification
    ):

        score = max(score, 100)

        threats.append(
            "Likely prize/reward phishing scam."
        )

        reasons.append(
            "The message combines an unexpected reward with a link "
            "and an action/request for verification."
        )

    if urgent and link_present and verification:

        score = max(score, 90)

        threats.append(
            "Urgent account verification phishing pattern."
        )

        reasons.append(
            "Urgency, a link and account verification are combined."
        )

    if urgent and credential_request:

        score = max(score, 90)

        threats.append(
            "Urgent request for sensitive information."
        )

        reasons.append(
            "The message pressures the user to provide sensitive information."
        )

    # --------------------------------------------------------
    # SPECIFIC SUSPICIOUS LOGIN SCENARIO
    # --------------------------------------------------------

    if login_detected and not credential_request:

        if not link_present:

            score = max(score, 35)

            threats.append(
                "Potential suspicious account activity alert."
            )

            reasons.append(
                "The message reports account activity that should "
                "be independently verified."
            )

    # --------------------------------------------------------
    # NORMALIZATION OF SCORE
    # --------------------------------------------------------

    score = max(0, min(100, score))

    # --------------------------------------------------------
    # VERDICT
    # --------------------------------------------------------

    if score >= 70:

        verdict = "DANGEROUS"

    elif score >= 25:

        verdict = "SUSPICIOUS"

    else:

        verdict = "SAFE"

    # --------------------------------------------------------
    # SAFE MESSAGE
    # --------------------------------------------------------

    if verdict == "SAFE":

        threats = []

        warnings = []

        reasons = [
            "No significant cybersecurity threat indicators were detected."
        ]

        safe_actions = [
            "Continue using normal cybersecurity precautions."
        ]

        recommendation = (
            "The message appears safe based on the available evidence."
        )

        education = (
            "Even when a message appears safe, avoid sharing passwords "
            "or sensitive information."
        )

    # --------------------------------------------------------
    # SUSPICIOUS MESSAGE
    # --------------------------------------------------------

    elif verdict == "SUSPICIOUS":

        if not warnings:

            warnings.append(
                "Verify the information through an official source."
            )

        safe_actions = [
            "Do not share passwords or verification codes.",
            "Verify the message through the official app or website.",
            "Avoid clicking unexpected links."
        ]

        recommendation = (
            "Treat this message with caution and verify it independently."
        )

        education = (
            "Suspicious messages may use realistic account alerts "
            "to encourage users to take unsafe actions."
        )

    # --------------------------------------------------------
    # DANGEROUS MESSAGE
    # --------------------------------------------------------

    else:

        safe_actions = [
            "Do not click the link.",
            "Do not provide passwords, OTPs or verification codes.",
            "Do not send financial information.",
            "Report or delete the message.",
            "If you already interacted with it, secure the affected account."
        ]

        recommendation = (
            "Do not interact with this message. It contains strong "
            "indicators of a phishing or scam attempt."
        )

        education = (
            "Phishing attacks often combine urgency, rewards, links "
            "and requests for sensitive information."
        )

    # Remove duplicate items while preserving order

    threats = list(dict.fromkeys(threats))
    reasons = list(dict.fromkeys(reasons))
    warnings = list(dict.fromkeys(warnings))
    safe_actions = list(dict.fromkeys(safe_actions))

    return {
        "risk_score": score,
        "verdict": verdict,
        "threats": threats,
        "threat_assessment": threats,
        "reasons": reasons,
        "warnings": warnings,
        "warning_signs": warnings,
        "safe_actions": safe_actions,
        "recommendation": recommendation,
        "education": education,
    }


# ============================================================
# SCREENSHOT TEXT EXTRACTION
# ============================================================

def extract_screenshot_text(image_path: str):

    if screenshot_tool is None:

        return {
            "success": False,
            "text": "",
            "error": "Screenshot analysis tool is unavailable."
        }

    try:

        result = screenshot_tool.run(
            image_path=image_path
        )

        if isinstance(result, dict):

            return result

        return {
            "success": True,
            "text": str(result),
            "error": ""
        }

    except Exception as e:

        return {
            "success": False,
            "text": "",
            "error": str(e)
        }


# ============================================================
# CHECK MESSAGE
# ============================================================

def check_message(message="", image_path=None):

    extracted_text = ""

    # --------------------------------------------------------
    # SCREENSHOT
    # --------------------------------------------------------

    if image_path:

        extraction = extract_screenshot_text(
            image_path
        )

        if not extraction.get("success", False):

            result = calculate_risk("")

            result["risk_score"] = 0
            result["verdict"] = "SUSPICIOUS"

            result["reasons"] = [
                "The screenshot could not be analyzed."
            ]

            result["recommendation"] = (
                "Please try uploading the screenshot again."
            )

            result["extracted_text"] = ""

            return result

        extracted_text = extraction.get(
            "text",
            ""
        )

        # IMPORTANT:
        # Screenshot text goes through the EXACT SAME
        # deterministic classifier as typed messages.

        result = calculate_risk(
            extracted_text
        )

        result["extracted_text"] = extracted_text

        save_security_activity(
            result
        )

        return result

    # --------------------------------------------------------
    # NORMAL TEXT
    # --------------------------------------------------------

    result = calculate_risk(
        message
    )

    result["extracted_text"] = ""

    save_security_activity(
        result
    )

    return result


# ============================================================
# SECURITY ACTIVITY LOG
# ============================================================

def save_security_activity(result):

    try:

        base_dir = os.path.dirname(
            os.path.dirname(
                os.path.dirname(
                    os.path.abspath(__file__)
                )
            )
        )

        logs_dir = os.path.join(
            base_dir,
            "logs"
        )

        os.makedirs(
            logs_dir,
            exist_ok=True
        )

        log_file = os.path.join(
            logs_dir,
            "security_activity.json"
        )

        data = []

        if os.path.exists(log_file):

            try:

                with open(
                    log_file,
                    "r",
                    encoding="utf-8"
                ) as f:

                    data = json.load(f)

                if not isinstance(data, list):
                    data = []

            except Exception:

                data = []

        entry = {
            "timestamp": datetime.now(
                timezone.utc
            ).isoformat(),

            "result": result
        }

        data.append(entry)

        with open(
            log_file,
            "w",
            encoding="utf-8"
        ) as f:

            json.dump(
                data,
                f,
                indent=2,
                ensure_ascii=False
            )

    except Exception as e:

        print(
            f"Security activity logging error: {e}"
        )


# ============================================================
# ASK CYBERGUARD
# ============================================================

def ask_cyberguard(question):

    if not question or not question.strip():

        return "Please enter a cybersecurity question."

    if not cyberguard_llm:

        return (
            "CyberGuard could not connect to the AI engine. "
            "Please check your OpenRouter API key and model settings."
        )

    try:

        task = Task(
            description=(
                "Answer the following cybersecurity question clearly "
                "and accurately.\n\n"
                f"Question: {question}\n\n"
                "Keep the answer concise and practical. "
                "Do not invent facts."
            ),

            expected_output=(
                "A clear cybersecurity answer in simple language."
            ),

            agent=security_analyst,
        )

        crew = Crew(
            agents=[security_analyst],
            tasks=[task],
            process=Process.sequential,
            verbose=False,
        )

        result = crew.kickoff()

        return str(result)

    except Exception as e:

        return (
            f"CyberGuard could not process the question: {e}"
        )
