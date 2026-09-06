import json
import os
import sys
from datetime import datetime, timedelta, timezone
from io import BytesIO

import plotly.graph_objects as go
import streamlit as st
from dotenv import load_dotenv

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

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
# SECURITY ACTIVITY LOG
# ============================================================

LOG_FILE = os.path.join(
    BASE_DIR,
    "logs",
    "security_activity.json"
)


# ============================================================
# PDF SECURITY REPORT
# ============================================================

def generate_security_report(result, original_message):

    buffer = BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40,
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        fontSize=20,
        spaceAfter=10,
    )

    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Heading2"],
        alignment=TA_CENTER,
        fontSize=13,
        spaceAfter=20,
    )

    heading_style = ParagraphStyle(
        "ReportHeading",
        parent=styles["Heading2"],
        fontSize=13,
        spaceBefore=14,
        spaceAfter=7,
    )

    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["BodyText"],
        fontSize=10,
        leading=14,
        spaceAfter=5,
    )

    small_style = ParagraphStyle(
        "ReportSmall",
        parent=styles["BodyText"],
        fontSize=8,
        leading=11,
    )

    story = []

    # --------------------------------------------------------
    # RESULT DATA
    # --------------------------------------------------------

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

    # Make sure list fields are actually lists
    if not isinstance(threat_assessment, list):
        threat_assessment = [threat_assessment]

    if not isinstance(reasons, list):
        reasons = [reasons]

    if not isinstance(warning_signs, list):
        warning_signs = [warning_signs]

    if not isinstance(safe_actions, list):
        safe_actions = [safe_actions]

    # --------------------------------------------------------
    # TITLE
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "CyberGuard AI",
            title_style
        )
    )

    story.append(
        Paragraph(
            "Cybersecurity Investigation Report",
            subtitle_style
        )
    )

    # --------------------------------------------------------
    # INVESTIGATION INFORMATION
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "Investigation Information",
            heading_style
        )
    )

    report_data = [
        [
            "Investigation Date",
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        ],
        [
            "Verdict",
            verdict
        ],
        [
            "Risk Score",
            f"{risk}/100"
        ],
    ]

    table = Table(
        report_data,
        colWidths=[160, 330]
    )

    table.setStyle(
        TableStyle([
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.grey
            ),
            (
                "BACKGROUND",
                (0, 0),
                (0, -1),
                colors.lightgrey
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "TOP"
            ),
            (
                "PADDING",
                (0, 0),
                (-1, -1),
                7
            ),
        ])
    )

    story.append(table)

    # --------------------------------------------------------
    # ORIGINAL MESSAGE
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "Original Evidence",
            heading_style
        )
    )

    safe_message = (
        str(original_message)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\n", "<br/>")
    )

    story.append(
        Paragraph(
            safe_message,
            body_style
        )
    )

    # --------------------------------------------------------
    # THREAT ASSESSMENT
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "Threat Assessment",
            heading_style
        )
    )

    if threat_assessment:

        for item in threat_assessment:

            story.append(
                Paragraph(
                    "• " + str(item),
                    body_style
                )
            )

    else:

        story.append(
            Paragraph(
                "No specific high-risk attack pattern identified.",
                body_style
            )
        )

    # --------------------------------------------------------
    # WHY
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "Why This Verdict?",
            heading_style
        )
    )

    if reasons:

        for reason in reasons:

            story.append(
                Paragraph(
                    "• " + str(reason),
                    body_style
                )
            )

    else:

        story.append(
            Paragraph(
                "No additional reasons were provided.",
                body_style
            )
        )

    # --------------------------------------------------------
    # WARNING SIGNS
    # --------------------------------------------------------

    if warning_signs:

        story.append(
            Paragraph(
                "Warning Signs",
                heading_style
            )
        )

        for sign in warning_signs:

            story.append(
                Paragraph(
                    "• " + str(sign),
                    body_style
                )
            )

    # --------------------------------------------------------
    # SAFE ACTIONS
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "Recommended Safe Actions",
            heading_style
        )
    )

    if safe_actions:

        for action in safe_actions:

            story.append(
                Paragraph(
                    "• " + str(action),
                    body_style
                )
            )

    else:

        story.append(
            Paragraph(
                "No specific safe actions were provided.",
                body_style
            )
        )

    # --------------------------------------------------------
    # RECOMMENDATION
    # --------------------------------------------------------

    if recommendation:

        story.append(
            Paragraph(
                "Recommendation",
                heading_style
            )
        )

        story.append(
            Paragraph(
                str(recommendation),
                body_style
            )
        )

    # --------------------------------------------------------
    # SECURITY EDUCATION
    # --------------------------------------------------------

    if education:

        story.append(
            Paragraph(
                "Security Education",
                heading_style
            )
        )

        story.append(
            Paragraph(
                str(education),
                body_style
            )
        )

    # --------------------------------------------------------
    # FOOTER
    # --------------------------------------------------------

    story.append(
        Spacer(1, 20)
    )

    story.append(
        Paragraph(
            "Generated by CyberGuard AI • CrewAI • Streamlit",
            small_style
        )
    )

    doc.build(story)

    buffer.seek(0)

    return buffer.getvalue()


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

    st.write(
        "📄 Security Report"
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
# MESSAGE ANALYSIS
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

                    result = check_message(
                        message=message
                    )

                    st.session_state[
                        "last_result"
                    ] = result

                    st.session_state[
                        "last_message"
                    ] = message

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
# SCREENSHOT ANALYSIS
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

                    st.session_state[
                        "last_message"
                    ] = "Screenshot evidence was analyzed."

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


    # ========================================================
    # SECURITY REPORT
    # ========================================================

    st.divider()

    st.header(
        "📄 Security Report"
    )

    st.write(
        "Generate a downloadable PDF containing "
        "the complete cybersecurity investigation."
    )

    original_message = st.session_state.get(
        "last_message",
        "Evidence was analyzed by CyberGuard AI."
    )

    if st.button(
        "📄 Generate Security Report",
        type="primary"
    ):

        try:

            pdf_file = generate_security_report(
                result,
                original_message
            )

            st.download_button(
                label="⬇️ Download Security Report",
                data=pdf_file,
                file_name="CyberGuard_Security_Report.pdf",
                mime="application/pdf",
            )

            st.success(
                "Security report generated successfully."
            )

        except Exception as exc:

            st.error(
                "Could not generate security report."
            )

            st.code(
                f"{type(exc).__name__}: {exc}"
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

                try:

                    answer = ask_cyberguard(
                        question
                    )

                    st.markdown(
                        "### 🤖 CyberGuard"
                    )

                    st.write(
                        answer
                    )

                except Exception as exc:

                    st.error(
                        "CyberGuard could not answer."
                    )

                    st.code(
                        f"{type(exc).__name__}: {exc}"
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
# SECURITY ACTIVITY
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

    recent_entries = []

    cutoff = (
        datetime.now(timezone.utc)
        - timedelta(days=7)
    )

    if not os.path.exists(LOG_FILE):

        st.info(
            "No investigations recorded during the last 7 days."
        )

        st.caption(
            f"Activity file: {LOG_FILE}"
        )

    else:

        try:

            with open(
                LOG_FILE,
                "r",
                encoding="utf-8"
            ) as file:

                data = json.load(file)

            if not isinstance(data, list):

                data = []

            for entry in data:

                try:

                    timestamp_value = entry.get(
                        "timestamp"
                    )

                    if not timestamp_value:

                        continue

                    timestamp = datetime.fromisoformat(
                        timestamp_value
                    )

                    if timestamp.tzinfo is None:

                        timestamp = timestamp.replace(
                            tzinfo=timezone.utc
                        )

                    if timestamp < cutoff:

                        continue

                    result_data = entry.get(
                        "result",
                        {}
                    )

                    if isinstance(
                        result_data,
                        dict
                    ):

                        current = str(
                            result_data.get(
                                "verdict",
                                ""
                            )
                        ).upper()

                    else:

                        current = ""

                    if not current:

                        old_verdict = entry.get(
                            "verdict",
                            ""
                        )

                        if isinstance(
                            old_verdict,
                            dict
                        ):

                            current = str(
                                old_verdict.get(
                                    "verdict",
                                    "SUSPICIOUS"
                                )
                            ).upper()

                        else:

                            current = str(
                                old_verdict
                            ).upper()

                    if current not in counts:

                        current = "SUSPICIOUS"

                    counts[current] += 1

                    total += 1

                    risk_score = 0

                    if isinstance(
                        result_data,
                        dict
                    ):

                        try:

                            risk_score = int(
                                result_data.get(
                                    "risk_score",
                                    0
                                )
                            )

                        except Exception:

                            risk_score = 0

                    recent_entries.append(
                        {
                            "Time": timestamp,
                            "Verdict": current,
                            "Risk Score": risk_score,
                        }
                    )

                except Exception as entry_error:

                    print(
                        f"Activity entry error: {entry_error}"
                    )

                    continue

        except json.JSONDecodeError as exc:

            st.error(
                "Security activity file contains invalid JSON."
            )

            st.code(
                str(exc)
            )

        except Exception as exc:

            st.error(
                "Could not read security activity."
            )

            st.code(
                f"{type(exc).__name__}: {exc}"
            )

    if total == 0:

        st.info(
            "No investigations recorded during the last 7 days."
        )

        st.caption(
            f"Looking for activity file: {LOG_FILE}"
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

        st.divider()

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
                marker_color=[
                    "#22c55e",
                    "#f59e0b",
                    "#ef4444"
                ],
            )
        )

        fig.update_layout(
            title="Security Investigations - Last 7 Days",
            height=350,
            xaxis_title="Verdict",
            yaxis_title="Number of Investigations",
        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )

        if recent_entries:

            st.divider()

            st.subheader(
                "🕒 Recent Investigations"
            )

            recent_entries.sort(
                key=lambda x: x["Time"],
                reverse=True
            )

            display_entries = []

            for item in recent_entries:

                display_entries.append(
                    {
                        "Time": item["Time"].astimezone().strftime(
                            "%Y-%m-%d %H:%M:%S"
                        ),
                        "Verdict": item["Verdict"],
                        "Risk Score": item["Risk Score"],
                    }
                )

            st.dataframe(
                display_entries,
                use_container_width=True,
                hide_index=True,
            )


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    "🛡️ CyberGuard AI • CrewAI • Streamlit • n8n"
)
