import json
import os
import sys
from datetime import datetime, timedelta, timezone

import plotly.graph_objects as go
import requests
import streamlit as st
from dotenv import load_dotenv

load_dotenv()

# ============================================================
# PATH
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

SRC_DIR = os.path.join(
    BASE_DIR,
    "src"
)

if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)


# ============================================================
# PAGE
# ============================================================

st.set_page_config(
    page_title="CyberGuard AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ============================================================
# BACKEND
# ============================================================

CREW_AVAILABLE = False
CREW_ERROR = ""

check_message = None
ask_cyberguard = None

try:

    from crew import (
        check_message,
        ask_cyberguard,
    )

    CREW_AVAILABLE = True

except Exception as exc:

    CREW_ERROR = (
        f"{type(exc).__name__}: {exc}"
    )


# ============================================================
# N8N WEBHOOK
# ============================================================

N8N_WEBHOOK_URL = os.getenv(
    "N8N_WEBHOOK_URL",
    ""
).strip()


def send_to_n8n(message, result):

    if not N8N_WEBHOOK_URL:
        return False

    try:

        response = requests.post(
            N8N_WEBHOOK_URL,
            json={
                "message": message,
                "analysis": result,
            },
            timeout=15,
        )

        response.raise_for_status()

        return True

    except Exception as exc:

        print(
            f"n8n webhook error: "
            f"{type(exc).__name__}: {exc}"
        )

        return False


# ============================================================
# LOG
# ============================================================

LOG_FILE = os.path.join(
    SRC_DIR,
    "phish_guard_ai",
    "check_logs.jsonl"
)


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    st.title("🛡️ CyberGuard AI")

    st.caption(
        "Friendly AI Cybersecurity Assistant"
    )

    st.divider()

    if CREW_AVAILABLE:

        st.success(
            "🟢 AI Engine Online"
        )

    else:

        st.error(
            "🔴 AI Engine Error"
        )

        with st.expander("Backend error"):

            st.code(
                CREW_ERROR
            )

    st.divider()

    st.subheader(
        "🧭 Features"
    )

    st.write(
        "🔍 Message Analysis"
    )

    st.write(
        "🖼️ Screenshot Analysis"
    )

    st.write(
        "💬 Cybersecurity Chat"
    )

    st.write(
        "🎓 Cybersecurity Learning"
    )

    st.write(
        "📊 Security Activity"
    )

    st.divider()

    st.subheader(
        "📊 Risk Levels"
    )

    st.success(
        "🟢 0–33  Safe"
    )

    st.warning(
        "🟡 34–69  Suspicious"
    )

    st.error(
        "🔴 70–100  Dangerous"
    )


# ============================================================
# HEADER
# ============================================================

st.title(
    "🛡️ CyberGuard AI"
)

st.subheader(
    "Your friendly AI cybersecurity assistant"
)

st.write(
    "Analyze suspicious messages, screenshots and "
    "security alerts using AI-powered cybersecurity analysis."
)


# ============================================================
# NAVIGATION
# ============================================================

st.divider()

page = st.radio(
    "Choose what you want to do",
    [
        "🔍 Check a Message",
        "🖼️ Check a Screenshot",
        "💬 Ask CyberGuard",
        "🎓 Learn Cybersecurity",
        "📊 Security Activity",
    ],
    horizontal=True,
)


# ============================================================
# MESSAGE
# ============================================================

if page == "🔍 Check a Message":

    st.header(
        "🔍 Check a Suspicious Message"
    )

    st.write(
        "Paste an email, SMS, WhatsApp message, "
        "social-media message, security alert or suspicious URL."
    )

    message = st.text_area(
        "Message",
        height=220,
        placeholder=(
            "Paste the suspicious message here..."
        ),
    )

    if st.button(
        "🔍 Analyze Message",
        type="primary"
    ):

        if not message.strip():

            st.warning(
                "Please paste a message first."
            )

        elif not CREW_AVAILABLE:

            st.error(
                "CyberGuard AI backend is unavailable."
            )

            st.code(
                CREW_ERROR
            )

        else:

            with st.spinner(
                "🤖 CyberGuard is investigating..."
            ):

                try:

                    # ------------------------------------------------
                    # CREWAI ANALYSIS
                    # ------------------------------------------------

                    result = check_message(
                        message=message
                    )

                    st.session_state[
                        "last_result"
                    ] = result


                    # ------------------------------------------------
                    # SEND RESULT TO N8N
                    # ------------------------------------------------

                    n8n_sent = send_to_n8n(
                        message,
                        result
                    )

                    if n8n_sent:

                        st.success(
                            "Investigation completed and "
                            "sent to n8n."
                        )

                    else:

                        st.success(
                            "Investigation completed."
                        )

                except Exception as exc:

                    st.error(
                        "Investigation failed."
                    )

                    st.code(
                        f"{type(exc).__name__}: {exc}"
                    )


# ============================================================
# SCREENSHOT
# ============================================================

elif page == "🖼️ Check a Screenshot":

    st.header(
        "🖼️ Check a Screenshot"
    )

    st.write(
        "Upload a screenshot of a suspicious message, "
        "email, website, login page or security alert."
    )

    uploaded_file = st.file_uploader(
        "Upload screenshot",
        type=[
            "png",
            "jpg",
            "jpeg",
            "webp",
        ],
    )

    if uploaded_file:

        st.image(
            uploaded_file,
            caption="Uploaded Evidence",
            use_container_width=True,
        )

    if st.button(
        "🖼️ Analyze Screenshot",
        type="primary"
    ):

        if uploaded_file is None:

            st.warning(
                "Please upload a screenshot first."
            )

        elif not CREW_AVAILABLE:

            st.error(
                "CyberGuard AI backend is unavailable."
            )

            st.code(
                CREW_ERROR
            )

        else:

            temp_dir = os.path.join(
                BASE_DIR,
                "temp_evidence"
            )

            os.makedirs(
                temp_dir,
                exist_ok=True
            )

            image_path = os.path.join(
                temp_dir,
                uploaded_file.name
            )

            try:

                with open(
                    image_path,
                    "wb"
                ) as file:

                    file.write(
                        uploaded_file.getbuffer()
                    )

                with st.spinner(
                    "🖼️ Reading screenshot with AI..."
                ):

                    result = check_message(
                        message="",
                        image_path=image_path
                    )

                    st.session_state[
                        "last_result"
                    ] = result

                    st.success(
                        "Screenshot investigation completed."
                    )

            except Exception as exc:

                st.error(
                    "Screenshot investigation failed."
                )

                st.code(
                    f"{type(exc).__name__}: {exc}"
                )


# ============================================================
# RESULT
# ============================================================

if (
    "last_result" in st.session_state
    and page in [
        "🔍 Check a Message",
        "🖼️ Check a Screenshot"
    ]
):

    result = st.session_state[
        "last_result"
    ]

    verdict = str(
        result.get(
            "verdict",
            "SUSPICIOUS"
        )
    ).upper()

    try:

        risk = int(
            result.get(
                "risk_score",
                50
            )
        )

    except Exception:

        risk = 50

    risk = max(
        0,
        min(
            100,
            risk
        )
    )

    threat_assessment = result.get(
        "threat_assessment",
        []
    )

    reasons = result.get(
        "reasons",
        []
    )

    warning_signs = result.get(
        "warning_signs",
        []
    )

    safe_actions = result.get(
        "safe_actions",
        []
    )

    recommendation = result.get(
        "recommendation",
        ""
    )

    education = result.get(
        "education",
        ""
    )

    st.divider()

    st.header(
        "📊 Investigation Result"
    )

    result_col, score_col = st.columns(
        [2, 1]
    )

    # ========================================================
    # VERDICT
    # ========================================================

    with result_col:

        if verdict == "SAFE":

            st.success(
                "🟢 SAFE"
            )

            st.write(
                "No significant cybersecurity threat "
                "indicators were detected."
            )

        elif verdict == "DANGEROUS":

            st.error(
                "🔴 DANGEROUS"
            )

            st.write(
                "Strong indicators of phishing, scam activity "
                "or a serious cybersecurity incident were detected."
            )

        else:

            st.warning(
                "🟡 SUSPICIOUS"
            )

            st.write(
                "Some cybersecurity warning signs were detected. "
                "Further verification is recommended."
            )

        st.subheader(
            "🧩 Threat Assessment"
        )

        if threat_assessment:

            for item in threat_assessment:

                st.write(
                    "🚩 " + str(item)
                )

        else:

            st.write(
                "No specific high-risk attack pattern identified."
            )

        st.subheader(
            "⚠️ Why?"
        )

        if reasons:

            for reason in reasons:

                st.write(
                    "• " + str(reason)
                )

        if warning_signs:

            st.subheader(
                "🚩 Warning Signs"
            )

            for sign in warning_signs:

                st.write(
                    "• " + str(sign)
                )

    # ========================================================
    # RISK
    # ========================================================

    with score_col:

        st.subheader(
            "🎯 Risk Score"
        )

        if risk <= 33:

            risk_label = "🟢 Low Risk"

        elif risk <= 69:

            risk_label = "🟡 Medium Risk"

        else:

            risk_label = "🔴 High Risk"

        st.metric(
            "Threat Risk",
            f"{risk}/100"
        )

        st.write(
            risk_label
        )

        fig = go.Figure(
            go.Indicator(
                mode="gauge+number",
                value=risk,
                title={
                    "text": "Threat Level"
                },
                gauge={
                    "axis": {
                        "range": [
                            0,
                            100
                        ]
                    },
                    "steps": [
                        {
                            "range": [
                                0,
                                34
                            ],
                            "color": "#bbf7d0"
                        },
                        {
                            "range": [
                                34,
                                70
                            ],
                            "color": "#fde68a"
                        },
                        {
                            "range": [
                                70,
                                100
                            ],
                            "color": "#fecaca"
                        },
                    ],
                },
            )
        )

        fig.update_layout(
            height=280,
            margin=dict(
                l=10,
                r=10,
                t=40,
                b=10,
            ),
        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )

    # ========================================================
    # ACTIONS
    # ========================================================

    st.divider()

    st.header(
        "🛡️ What Can You Safely Do Now?"
    )

    for action in safe_actions:

        st.write(
            "✅ " + str(action)
        )

    if recommendation:

        st.info(
            recommendation
        )

    # ========================================================
    # EDUCATION
    # ========================================================

    st.divider()

    st.subheader(
        "🎓 What You Should Know"
    )

    st.write(
        education
    )


# ============================================================
# CHAT
# ============================================================

elif page == "💬 Ask CyberGuard":

    st.header(
        "💬 Ask CyberGuard"
    )

    question = st.text_input(
        "Your cybersecurity question"
    )

    if st.button(
        "💬 Ask AI",
        type="primary"
    ):

        if not question.strip():

            st.warning(
                "Please enter a question."
            )

        elif not CREW_AVAILABLE:

            st.error(
                "CyberGuard AI backend is unavailable."
            )

            st.code(
                CREW_ERROR
            )

        else:

            with st.spinner(
                "🤖 CyberGuard is thinking..."
            ):

                answer = ask_cyberguard(
                    question
                )

                st.markdown(
                    "### 🤖 CyberGuard"
                )

                st.write(
                    answer
                )


# ============================================================
# LEARNING
# ============================================================

elif page == "🎓 Learn Cybersecurity":

    st.header(
        "🎓 Cybersecurity Learning Center"
    )

    st.subheader(
        "🎣 Phishing"
    )

    st.write(
        "Phishing is when an attacker pretends to be "
        "a trusted person or organization to steal information."
    )

    st.subheader(
        "🔐 Password Safety"
    )

    st.write(
        "Use unique passwords and enable MFA whenever possible."
    )

    st.subheader(
        "🔢 OTP Safety"
    )

    st.write(
        "Never share an OTP with someone who unexpectedly "
        "contacts you."
    )

    st.subheader(
        "🔗 Link Safety"
    )

    st.write(
        "Check the domain carefully before opening a link."
    )

    st.subheader(
        "🛡️ Golden Rule"
    )

    st.success(
        "STOP → THINK → VERIFY → THEN ACT"
    )


# ============================================================
# ACTIVITY
# ============================================================

elif page == "📊 Security Activity":

    st.header(
        "📊 Security Activity"
    )

    counts = {
        "SAFE": 0,
        "SUSPICIOUS": 0,
        "DANGEROUS": 0
    }

    total = 0

    if os.path.exists(LOG_FILE):

        cutoff = (
            datetime.now(timezone.utc)
            - timedelta(days=7)
        )

        try:

            with open(
                LOG_FILE,
                "r",
                encoding="utf-8"
            ) as file:

                for line in file:

                    try:

                        entry = json.loads(
                            line
                        )

                        timestamp = datetime.fromisoformat(
                            entry["timestamp"]
                        )

                        if timestamp.tzinfo is None:

                            timestamp = timestamp.replace(
                                tzinfo=timezone.utc
                            )

                        if timestamp < cutoff:
                            continue

                        verdict_data = entry.get(
                            "verdict",
                            {}
                        )

                        if isinstance(
                            verdict_data,
                            dict
                        ):

                            current = str(
                                verdict_data.get(
                                    "verdict",
                                    "SUSPICIOUS"
                                )
                            ).upper()

                        else:

                            current = str(
                                verdict_data
                            ).upper()

                        if current not in counts:

                            current = "SUSPICIOUS"

                        counts[current] += 1

                        total += 1

                    except Exception:

                        continue

        except Exception:

            pass

    if total == 0:

        st.info(
            "No investigations recorded during the last 7 days."
        )

    else:

        c1, c2, c3, c4 = st.columns(4)

        c1.metric(
            "Total",
            total
        )

        c2.metric(
            "🟢 Safe",
            counts["SAFE"]
        )

        c3.metric(
            "🟡 Suspicious",
            counts["SUSPICIOUS"]
        )

        c4.metric(
            "🔴 Dangerous",
            counts["DANGEROUS"]
        )

        fig = go.Figure(
            go.Bar(
                x=[
                    "Safe",
                    "Suspicious",
                    "Dangerous"
                ],
                y=[
                    counts["SAFE"],
                    counts["SUSPICIOUS"],
                    counts["DANGEROUS"]
                ],
            )
        )

        fig.update_layout(
            title="Last 7 Days",
            height=350,
        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    "🛡️ CyberGuard AI • CrewAI • Streamlit • n8n"
)
