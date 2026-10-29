import csv
import hashlib
import io
import json
import os
import re
import secrets
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

import click
from flask import (
    Flask,
    abort,
    flash,
    g,
    make_response,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from flask_wtf.csrf import CSRFError, CSRFProtect
from flask_wtf.csrf import generate_csrf
from markupsafe import Markup, escape
from werkzeug.security import check_password_hash, generate_password_hash


ROOT = Path(__file__).resolve().parent
INSTANCE_DIR = ROOT / "instance"
EVIDENCE_DIR = INSTANCE_DIR / "evidence"
DATABASE = INSTANCE_DIR / "forensix.sqlite3"
MAX_UPLOAD_BYTES = 5 * 1024 * 1024
MAX_RECORDS = 10000
ALLOWED_EXTENSIONS = {".csv", ".json"}
CASE_STATUSES = {"Open", "Investigating", "Contained", "Resolved", "Closed"}
MAX_ANALYSIS_EVENTS = 5000
MAX_CORRELATION_PAIRS = 200
MAX_CORRELATION_COMPARISONS = 100000
CORRELATION_WINDOW_SECONDS = 5 * 60
LOGIN_SEQUENCE_WINDOW_SECONDS = 30 * 60
TIMELINE_GAP_THRESHOLD_SECONDS = 60 * 60
DEMO_ACCOUNTS = (
    ("student@forensix.local", "student@forensix.local", "StudentDemo!2026", "student"),
    ("user@forensix.local", "user@forensix.local", "UserDemo!2026", "user"),
    (
        "investigator@forensix.local",
        "investigator@forensix.local",
        "InvestigatorDemo!2026",
        "investigator",
    ),
)
PUBLIC_ENDPOINTS = {"static", "login", "register"}
SHARED_ENDPOINTS = {"dashboard", "logout"}
ROLE_ENDPOINTS = {
    "student_lab": "student",
    "student_case": "student",
    "student_courses": "student",
    "student_course": "student",
    "student_lesson": "student",
    "student_assistant": "student",
    "personal_safety": "user",
    "safety_assistant": "user",
}
COURSE_SEEDS = [
    ("cybersecurity-fundamentals", "Cybersecurity Fundamentals", "Beginner", "Security foundations", "Understand core security goals, common threats, and practical ways to reduce risk.", "confidentiality, integrity, and availability", ("Security goals and assets", "Threats and vulnerabilities", "Everyday risk reduction")),
    ("introduction-digital-forensics", "Introduction to Digital Forensics", "Beginner", "Digital forensics", "Learn how digital evidence is identified, preserved, examined, and reported with care.", "the stages of a defensible digital examination", ("Forensic process overview", "Evidence preservation", "Clear reporting and limitations")),
    ("computer-filesystem-basics", "Computer and File-System Basics", "Beginner", "Computer fundamentals", "Explore how operating systems organize files, folders, storage, and metadata.", "files, file systems, and metadata", ("Files and storage", "Directories and file systems", "Metadata and timestamps")),
    ("networking-fundamentals", "Networking Fundamentals", "Beginner", "Networking", "Learn basic network components, addressing, protocols, and how to read a simple connection record.", "how devices exchange network traffic", ("Network models and devices", "Addresses and ports", "Common protocols")),
    ("linux-for-cybersecurity", "Linux for Cybersecurity", "Beginner", "Operating systems", "Practice safe command-line navigation and understand common Linux security logs.", "basic Linux navigation and log locations", ("Shell and filesystem navigation", "Users and permissions", "System logs")),
    ("windows-security-fundamentals", "Windows Security Fundamentals", "Beginner", "Operating systems", "Learn Windows account, authentication, and event-log concepts used in defensive review.", "Windows security settings and event records", ("Accounts and access", "Security event logs", "Safe system review")),
    ("introduction-logs-event-analysis", "Introduction to Logs and Event Analysis", "Beginner", "Log analysis", "Understand event fields, timestamps, outcomes, and the limits of incomplete records.", "read structured event records carefully", ("Anatomy of a log record", "Timestamps and timezones", "Evidence-based summaries")),
    ("password-security-mfa", "Password Security and Multi-Factor Authentication", "Beginner", "Account safety", "Learn safe password practices, MFA methods, and account-recovery precautions.", "protect accounts without sharing authentication secrets", ("Password managers and unique passwords", "MFA methods", "Recovery and session review")),
    ("phishing-social-engineering", "Phishing and Social Engineering Awareness", "Beginner", "Account safety", "Recognize common manipulation techniques and choose safe verification steps.", "identify warning signs in suspicious messages", ("Common manipulation tactics", "Inspecting messages safely", "Reporting and recovery")),
    ("network-traffic-pcap", "Network Traffic and PCAP Analysis", "Intermediate", "Networking", "Learn a cautious workflow for examining packet captures and documenting observed traffic.", "describe traffic visible in an authorized capture", ("Capture scope and safety", "Packets, flows, and protocols", "Filters and observations")),
    ("windows-event-log-analysis", "Windows Event Log Analysis", "Intermediate", "Log analysis", "Review event records using timestamps, event sources, and contextual cross-checks.", "organize Windows events into a sourced timeline", ("Event channels and fields", "Authentication records", "Timeline and corroboration")),
    ("linux-log-investigation", "Linux Log Investigation", "Intermediate", "Log analysis", "Examine common Linux authentication and system logs without over-interpreting them.", "filter and summarize Linux log records", ("Log locations and formats", "Authentication review", "Time-aware event sequences")),
    ("evidence-acquisition-integrity", "Digital Evidence Acquisition and Integrity", "Intermediate", "Digital forensics", "Study preservation principles, acquisition notes, and cryptographic hash comparison.", "document an integrity check and its limitations", ("Preservation principles", "Hashing and verification", "Acquisition notes")),
    ("file-metadata-timestamps", "File Metadata and Timestamp Analysis", "Intermediate", "Digital forensics", "Understand common metadata fields, timestamp interpretation, and timezone pitfalls.", "compare metadata while recording uncertainty", ("Metadata fields", "Timestamp semantics", "Corroborating file activity")),
    ("email-header-analysis", "Email Header Analysis", "Intermediate", "Communications", "Read common email-header fields and identify what routing records can and cannot show.", "describe header fields without asserting sender identity", ("Header structure", "Routing and authentication fields", "Caveats and verification")),
    ("malware-analysis-fundamentals", "Malware Analysis Fundamentals in a Safe Lab", "Intermediate", "Malware safety", "Learn safe, isolated, non-executing malware triage concepts and reporting language.", "use a static-first, safety-conscious triage workflow", ("Lab isolation and handling", "Static indicators", "Cautious reporting")),
    ("incident-response-investigation", "Incident Response and Investigation", "Intermediate", "Incident response", "Connect preparation, triage, containment, evidence handling, and lessons learned.", "describe an incident response sequence", ("Preparation and triage", "Containment and preservation", "Recovery and review")),
    ("memory-forensics-fundamentals", "Memory Forensics Fundamentals", "Intermediate", "Digital forensics", "Learn what memory images may contain and how to scope safe, authorized analysis.", "explain memory evidence sources and limitations", ("Memory evidence overview", "Volatile data concepts", "Documentation and interpretation")),
    ("steganography-detection", "Steganography Detection and Analysis", "Intermediate", "File analysis", "Understand basic indicators and limitations when reviewing suspected hidden content.", "describe safe indicators without promising detection", ("Steganography concepts", "File properties and anomalies", "Validation and caveats")),
    ("timeline-reconstruction", "Digital Forensic Timeline Reconstruction", "Intermediate", "Digital forensics", "Normalize supported timestamps, preserve originals, and build a sourced event timeline.", "create a chronology that records timezone uncertainty", ("Timestamp normalization", "Event sorting and provenance", "Gaps and alternate explanations")),
    ("threat-intelligence-fundamentals", "Threat Intelligence Fundamentals", "Intermediate", "Threat intelligence", "Learn to evaluate indicators, source reliability, context, and confidence.", "record indicators with sources and confidence limits", ("Indicators and context", "Source evaluation", "Responsible use")),
    ("advanced-forensic-investigation", "Advanced Digital Forensic Investigation", "Advanced", "Digital forensics", "Plan a scoped multi-source digital examination and keep observations distinct from hypotheses.", "structure a complex examination plan", ("Scope and examination strategy", "Multi-source review", "Findings and limitations")),
    ("memory-process-analysis", "Memory Forensics and Process Analysis", "Advanced", "Digital forensics", "Explore process and memory artifacts conceptually with emphasis on provenance and corroboration.", "evaluate process evidence in context", ("Process relationships", "Memory artifact context", "Corroboration")),
    ("network-intrusion-investigation", "Network Intrusion Investigation", "Advanced", "Incident response", "Build an authorized investigation plan from network records while avoiding attribution claims.", "correlate network observations with other sources", ("Investigation scope", "Traffic and infrastructure records", "Validation and reporting")),
    ("filesystem-artifact-analysis", "File-System and Artifact Analysis", "Advanced", "Digital forensics", "Review file-system artifacts, metadata, and application records as a sourced body of evidence.", "relate artifacts without assuming user intent", ("Artifact sources", "Metadata and consistency", "Contextual review")),
    ("incident-response-case-management", "Incident Response Case Management", "Advanced", "Incident response", "Organize response tasks, evidence references, decisions, and unresolved questions.", "maintain a traceable investigation record", ("Case scoping and roles", "Evidence and task tracking", "Review and closure")),
    ("cross-source-evidence-correlation", "Evidence Correlation Across Multiple Sources", "Advanced", "Digital forensics", "Compare independently sourced records and document matching fields and uncertainty.", "explain a correlation and its limits", ("Source quality and normalization", "Exact-match correlation", "Alternative explanations")),
    ("forensic-reporting-preservation", "Forensic Reporting and Evidence Preservation", "Advanced", "Digital forensics", "Write a neutral report with methods, sources, integrity checks, and explicit limitations.", "produce a clear, reviewable report", ("Preservation record", "Findings and references", "Limitations and review")),
    ("secure-evidence-chain-custody", "Secure Evidence Handling and Chain of Custody", "Advanced", "Evidence handling", "Understand access documentation, controlled storage, integrity checks, and transfer records.", "describe safeguards for evidence continuity", ("Handling and access control", "Transfers and audit records", "Integrity review")),
]


def build_course_catalog():
    courses = []
    for course_id, title, difficulty, category, description, focus, lesson_titles in COURSE_SEEDS:
        lessons = [
            {
                "title": lesson_title,
                "content": (
                    f"This lesson introduces {lesson_title.lower()} as part of {title}. "
                    f"Focus on {focus}. Record the source of each observation, preserve "
                    "the original context, and distinguish what the available material "
                    "shows from what remains uncertain."
                ),
                "exercise": (
                    f"Write two observations about {lesson_title.lower()} and one question "
                    "that would require additional, authorized evidence to answer."
                ),
            }
            for lesson_title in lesson_titles
        ]
        courses.append(
            {
                "id": course_id,
                "title": title,
                "difficulty": difficulty,
                "category": category,
                "description": description,
                "prerequisites": (
                    "No prior course required."
                    if difficulty == "Beginner"
                    else f"Recommended: foundational knowledge of {category.lower()} or equivalent study."
                ),
                "objectives": [
                    f"Explain the key concepts in {title}.",
                    f"Apply a careful workflow for {focus}.",
                    "State evidence limitations and identify appropriate next checks.",
                ],
                "lessons": lessons,
            }
        )
    return courses


STUDENT_COURSES = build_course_catalog()
STUDENT_COURSES_BY_ID = {course["id"]: course for course in STUDENT_COURSES}
SAFETY_ASSISTANT_GUIDANCE = {
    "en": {
        "name": "English",
        "generic": "Open the service's official app or website directly. Do not follow unexpected links or share passwords, OTPs, recovery codes, or payment PINs. If money or account access is at risk, contact the provider or bank using a verified channel.",
        "account": "1. Open the provider's official app/site directly. 2. Review recent sign-ins and active sessions; sign out devices you do not recognize. 3. Change a reused or exposed password through the official service and enable multi-factor authentication. 4. Check recovery details. Never share an OTP or recovery code.",
        "payment": "1. Do not approve a request you did not initiate, scan an unexpected QR code, or share your UPI PIN/OTP. 2. Check transactions in the official payment app. 3. If a transaction is unauthorized, contact your bank/payment provider immediately using its official number or app. 4. Preserve transaction references and use the official cybercrime reporting channel in your country.",
        "message": "Do not click the link, download an attachment, reply, or call a number in the message. Open the organization’s official app/site yourself to verify the claim. Report or delete the message using the provider's official tools. Hide personal details before sharing a screenshot.",
        "fallback": "I can offer general safety steps, but this local helper cannot inspect your account, device, messages, or payment records. Tell me whether this is about an account, a suspicious message, or a payment to see a focused checklist.",
    },
    "hi": {
        "name": "Hindi",
        "generic": "सेवा का आधिकारिक ऐप या वेबसाइट सीधे खोलें। अनजान लिंक न खोलें और पासवर्ड, OTP, रिकवरी कोड या भुगतान PIN साझा न करें। खाते या पैसे का जोखिम हो तो सत्यापित आधिकारिक माध्यम से सेवा प्रदाता या बैंक से संपर्क करें।",
        "account": "1. सेवा का आधिकारिक ऐप/वेबसाइट सीधे खोलें। 2. हाल के साइन-इन और सक्रिय डिवाइस देखें; अनजान डिवाइस से साइन आउट करें। 3. आधिकारिक सेवा पर पासवर्ड बदलें और बहु-स्तरीय सुरक्षा चालू करें। 4. रिकवरी जानकारी जाँचें। OTP या रिकवरी कोड कभी साझा न करें।",
        "payment": "1. अपनी ओर से शुरू न किए गए भुगतान अनुरोध को मंज़ूर न करें; अनजान QR कोड स्कैन न करें और UPI PIN/OTP साझा न करें। 2. आधिकारिक ऐप में लेन-देन देखें। 3. अनधिकृत लेन-देन हो तो बैंक/भुगतान सेवा से उनके आधिकारिक माध्यम से तुरंत संपर्क करें। 4. संदर्भ सुरक्षित रखें और अपने देश के आधिकारिक साइबर अपराध माध्यम से रिपोर्ट करें।",
        "message": "लिंक न खोलें, फ़ाइल डाउनलोड न करें और संदेश में दिए नंबर पर कॉल न करें। दावे की पुष्टि के लिए संस्था का आधिकारिक ऐप/वेबसाइट स्वयं खोलें। प्रदाता के आधिकारिक टूल से रिपोर्ट करें या संदेश हटाएँ। स्क्रीनशॉट साझा करने से पहले निजी जानकारी छिपाएँ।",
        "fallback": "यह स्थानीय सहायक आपके खाते, डिवाइस, संदेश या भुगतान रिकॉर्ड नहीं देख सकता। खाता, संदिग्ध संदेश या भुगतान में से विषय बताएँ; मैं संबंधित सामान्य सुरक्षा सूची दिखाऊँगा।",
    },
    "te": {
        "name": "Telugu",
        "generic": "సేవ యొక్క అధికారిక యాప్ లేదా వెబ్‌సైట్‌ను మీరే తెరవండి. అనుకోని లింక్‌లను నొక్కవద్దు; పాస్‌వర్డ్‌లు, OTPలు, రికవరీ కోడ్‌లు లేదా చెల్లింపు PINలను పంచుకోవద్దు. ఖాతా లేదా డబ్బుకు ప్రమాదం ఉంటే, ధృవీకరించిన అధికారిక మార్గంలో సేవా సంస్థ లేదా బ్యాంకును సంప్రదించండి.",
        "account": "1. సేవ యొక్క అధికారిక యాప్/సైట్‌ను నేరుగా తెరవండి. 2. ఇటీవలి సైన్-ఇన్‌లు, యాక్టివ్ సెషన్‌లను చూసి తెలియని పరికరాల నుంచి సైన్ అవుట్ చేయండి. 3. అధికారిక సేవలో పాస్‌వర్డ్ మార్చి, బహుళ-దశల భద్రతను ప్రారంభించండి. 4. రికవరీ వివరాలను తనిఖీ చేయండి. OTP లేదా రికవరీ కోడ్‌ను ఎప్పుడూ పంచుకోవద్దు.",
        "payment": "1. మీరు ప్రారంభించని చెల్లింపును ఆమోదించవద్దు; తెలియని QR కోడ్‌ను స్కాన్ చేయవద్దు; UPI PIN/OTP పంచుకోవద్దు. 2. అధికారిక యాప్‌లో లావాదేవీలను చూడండి. 3. అనధికార లావాదేవీ ఉంటే బ్యాంక్/చెల్లింపు సంస్థను వారి అధికారిక మార్గంలో వెంటనే సంప్రదించండి. 4. లావాదేవీ వివరాలను భద్రపరచి, మీ దేశంలోని అధికారిక సైబర్ క్రైమ్ మార్గంలో నివేదించండి.",
        "message": "లింక్‌ను నొక్కవద్దు, ఫైల్‌ను డౌన్‌లోడ్ చేయవద్దు, సందేశంలోని నంబర్‌కు కాల్ చేయవద్దు. సంస్థ యొక్క అధికారిక యాప్/వెబ్‌సైట్‌ను మీరే తెరిచి విషయాన్ని నిర్ధారించండి. అధికారిక మార్గంలో సందేశాన్ని నివేదించండి లేదా తొలగించండి. స్క్రీన్‌షాట్ పంచుకునే ముందు వ్యక్తిగత వివరాలను దాచండి.",
        "fallback": "ఈ స్థానిక సహాయకుడు మీ ఖాతా, పరికరం, సందేశాలు లేదా చెల్లింపు రికార్డులను చూడలేడు. ఖాతా, అనుమానాస్పద సందేశం లేదా చెల్లింపు—ఏ విషయం గురించి సహాయం కావాలో చెప్పండి.",
    },
}
STUDENT_SAMPLE_CASES = {
    "email-security-incident": {
        "title": "Email Security Incident",
        "summary": (
            "A fictional training exercise contains a small set of sign-in and mailbox "
            "events for a sample account. The records are incomplete and do not establish "
            "that an account was compromised."
        ),
        "evidence": [
            {
                "reference": "SYN-EMAIL-01",
                "name": "Sample sign-in export",
                "description": "Three fictional sign-in rows with UTC timestamps and outcomes.",
            },
            {
                "reference": "SYN-EMAIL-02",
                "name": "Mailbox-rule review note",
                "description": "A fictional analyst note that says no mailbox-rule export was provided.",
            },
        ],
        "timeline": [
            {
                "timestamp": "2026-04-14 08:02 UTC",
                "event": "Sample account sign-in succeeded",
                "source": "SYN-EMAIL-01",
            },
            {
                "timestamp": "2026-04-14 08:05 UTC",
                "event": "Sample account sign-in failed",
                "source": "SYN-EMAIL-01",
            },
            {
                "timestamp": "2026-04-14 08:18 UTC",
                "event": "Sample account sign-in succeeded",
                "source": "SYN-EMAIL-01",
            },
        ],
        "questions": [
            "Which events and outcomes are directly recorded?",
            "What account-activity records would help check whether the mailbox changed?",
            "What can’t be concluded from these sign-in rows alone?",
        ],
        "steps": [
            "Record the source and timezone of each timestamp.",
            "Compare the supplied outcomes without assuming who made the requests.",
            "List missing evidence, such as a mailbox-rule or active-session export.",
            "Write a neutral summary and include alternative explanations.",
        ],
    },
    "suspicious-login-activity": {
        "title": "Suspicious Login Activity",
        "summary": (
            "A fictional practice dataset shows several failed sign-ins followed by a "
            "successful event for one sample account. This is a classroom scenario, not "
            "a live alert or a finding about a real account."
        ),
        "evidence": [
            {
                "reference": "SYN-LOGIN-01",
                "name": "Authentication event table",
                "description": "Four fictional rows with a sample account, source address, and outcome.",
            },
            {
                "reference": "SYN-LOGIN-02",
                "name": "Device inventory extract",
                "description": "A fictional two-device list; it does not identify a real person or location.",
            },
        ],
        "timeline": [
            {
                "timestamp": "2026-05-03 22:41 UTC",
                "event": "Sample account sign-in failed",
                "source": "SYN-LOGIN-01",
            },
            {
                "timestamp": "2026-05-03 22:43 UTC",
                "event": "Sample account sign-in failed",
                "source": "SYN-LOGIN-01",
            },
            {
                "timestamp": "2026-05-03 22:47 UTC",
                "event": "Sample account sign-in failed",
                "source": "SYN-LOGIN-01",
            },
            {
                "timestamp": "2026-05-03 22:51 UTC",
                "event": "Sample account sign-in succeeded",
                "source": "SYN-LOGIN-01",
            },
        ],
        "questions": [
            "How many failed and successful rows are in the supplied export?",
            "Do the rows include a matching account, source address, and timezone?",
            "Which additional records would help assess whether a device is unfamiliar?",
        ],
        "steps": [
            "Count events from the provided rows and cite their reference.",
            "Check whether timestamps have explicit timezone information.",
            "Compare device details only against the supplied fictional inventory.",
            "Describe the sequence without inferring identity, intent, or compromise.",
        ],
    },
    "phishing-email-investigation": {
        "title": "Phishing Email Investigation",
        "summary": (
            "A fictional training email is presented for header-review practice. Its "
            "sample sender and domains are reserved example values; this scenario does "
            "not describe a real message or a confirmed phishing attempt."
        ),
        "evidence": [
            {
                "reference": "SYN-PHISH-01",
                "name": "Fictional message header",
                "description": "A training-only header using example.invalid addresses and documentation IP ranges.",
            },
            {
                "reference": "SYN-PHISH-02",
                "name": "Fictional mail-gateway result",
                "description": "A simulated SPF pass and DKIM result marked unavailable; not a real provider check.",
            },
        ],
        "timeline": [
            {
                "timestamp": "2026-06-11 13:15 UTC",
                "event": "Training message received by the sample mailbox",
                "source": "SYN-PHISH-01",
            },
            {
                "timestamp": "2026-06-11 13:16 UTC",
                "event": "Fictional gateway result recorded for the exercise",
                "source": "SYN-PHISH-02",
            },
            {
                "timestamp": "Not supplied",
                "event": "No click or attachment-execution record is included",
                "source": "Scenario limitation",
            },
        ],
        "questions": [
            "Which sender and routing fields are present in the sample header?",
            "What does an SPF pass establish, and what does it not establish?",
            "Is there any supplied evidence that a link was opened or a file executed?",
        ],
        "steps": [
            "Preserve and inspect the original message headers in the exercise data.",
            "Separate authentication results from the sender’s visible display name.",
            "Treat unavailable DKIM and missing click telemetry as unknown.",
            "Do not open links or attachments; use safe, authorized analysis material only.",
        ],
    },
    "suspicious-network-activity": {
        "title": "Suspicious Network Activity",
        "summary": (
            "A fictional classroom timeline contains two sample connection events, "
            "including a documentation-only IP address. No live traffic was collected "
            "and no real malicious activity is alleged."
        ),
        "evidence": [
            {
                "reference": "SYN-NET-01",
                "name": "Synthetic connection log",
                "description": "Two fictional connection rows using reserved documentation IP ranges.",
            },
            {
                "reference": "SYN-NET-02",
                "name": "Sample asset context",
                "description": "A fictional lab host label; no real organization or device is represented.",
            },
        ],
        "timeline": [
            {
                "timestamp": "2026-07-22 10:00 UTC",
                "event": "Sample lab host records an outbound connection",
                "source": "SYN-NET-01",
            },
            {
                "timestamp": "2026-07-22 10:04 UTC",
                "event": "Sample lab host records another outbound connection",
                "source": "SYN-NET-01",
            },
            {
                "timestamp": "2026-07-22 10:05 UTC",
                "event": "Fictional host label associated for the exercise",
                "source": "SYN-NET-02",
            },
        ],
        "questions": [
            "Which source and destination values are actually present in the sample?",
            "Does an IP address by itself identify a person or prove harmful activity?",
            "What DNS, firewall, or endpoint records would add context?",
        ],
        "steps": [
            "Identify the source evidence and the exact fields it contains.",
            "Check that the example IP ranges are documentation-only.",
            "Ask what time synchronization and network context are unavailable.",
            "Record possible benign explanations and request authorized corroborating logs.",
        ],
    },
}

app = Flask(__name__, instance_path=str(INSTANCE_DIR))
app.config.update(
    SECRET_KEY=os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32),
    MAX_CONTENT_LENGTH=MAX_UPLOAD_BYTES,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("FLASK_SESSION_COOKIE_SECURE", "").lower()
    in {"1", "true", "yes"},
    PERMANENT_SESSION_LIFETIME=60 * 60 * 8,
)
CSRFProtect(app)
INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)


@app.context_processor
def csrf_hidden_field():
    def hidden_field():
        return Markup(
            '<input type="hidden" name="csrf_token" value="{}">'.format(
                escape(generate_csrf())
            )
        )

    return {
        "csrf_token": hidden_field,
        "current_user": getattr(g, "user", None),
    }


@app.before_request
def enforce_authentication_and_roles():
    endpoint = request.endpoint
    if endpoint is None or endpoint in PUBLIC_ENDPOINTS:
        return
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("login"))
    user = get_db().execute(
        "SELECT id, username, email, role FROM users WHERE id = ? AND active = 1",
        (user_id,),
    ).fetchone()
    if user is None:
        session.clear()
        return redirect(url_for("login"))
    g.user = user
    if endpoint in SHARED_ENDPOINTS:
        return
    required_role = ROLE_ENDPOINTS.get(endpoint, "investigator")
    if user["role"] != required_role:
        abort(403)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        identity = request.form.get("identity", "").strip().lower()[:254]
        password = request.form.get("password", "")
        user = get_db().execute(
            "SELECT id, password_hash FROM users WHERE active = 1 "
            "AND (username = ? COLLATE NOCASE OR email = ? COLLATE NOCASE)",
            (identity, identity),
        ).fetchone()
        if (
            not user
            or len(password) > 128
            or not check_password_hash(user["password_hash"], password)
        ):
            flash("The username/email or password was not recognized.", "error")
        else:
            session.clear()
            session["user_id"] = user["id"]
            session.permanent = True
            return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        role = request.form.get("role", "")
        valid_email = (
            len(email) <= 254
            and email.count("@") == 1
            and not any(character.isspace() for character in email)
        )
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", username):
            flash("Choose a username with 3–32 letters, numbers, dots, dashes, or underscores.", "error")
        elif not valid_email:
            flash("Enter a valid email address.", "error")
        elif len(password) < 12 or len(password) > 128:
            flash("Your password must be between 12 and 128 characters.", "error")
        elif role not in {"student", "user"}:
            flash("Public accounts can only be Students or Personal Users.", "error")
        else:
            try:
                create_user(username, email, password, role)
            except sqlite3.IntegrityError:
                flash("That username or email is already registered.", "error")
            else:
                flash("Account created. You can now sign in.", "success")
                return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been signed out.", "success")
    return redirect(url_for("login"))


def create_user(username, email, password, role):
    if role not in {"student", "user", "investigator"}:
        raise ValueError("Unsupported account role.")
    if not 12 <= len(password) <= 128:
        raise ValueError("Passwords must be between 12 and 128 characters.")
    db = get_db()
    user_id = str(uuid.uuid4())
    with db:
        db.execute(
            "INSERT INTO users (id, username, email, password_hash, role, created_at, active) "
            "VALUES (?, ?, ?, ?, ?, ?, 1)",
            (user_id, username, email, generate_password_hash(password), role, utc_now()),
        )
        if role == "investigator":
            db.execute(
                "INSERT OR IGNORE INTO case_access (case_id, user_id, granted_at) "
                "SELECT id, ?, ? FROM cases WHERE NOT EXISTS "
                "(SELECT 1 FROM case_access WHERE case_id = cases.id)",
                (user_id, utc_now()),
            )
    return user_id


@app.cli.command("create-investigator")
def create_investigator_command():
    """Create an investigator account from a trusted local administration session."""
    username = click.prompt("Username")
    email = click.prompt("Email").strip().lower()
    password = click.prompt("Password", hide_input=True, confirmation_prompt=True)
    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", username):
        raise click.ClickException("Username must be 3–32 letters, numbers, dots, dashes, or underscores.")
    try:
        create_user(username, email, password, "investigator")
    except (ValueError, sqlite3.IntegrityError) as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"Investigator account created for {username}.")


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS cases (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'Open',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT NOT NULL COLLATE NOCASE UNIQUE,
            email TEXT NOT NULL COLLATE NOCASE UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK (role IN ('student', 'user', 'investigator')),
            created_at TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS case_access (
            case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            granted_at TEXT NOT NULL,
            PRIMARY KEY (case_id, user_id)
        );
        CREATE TABLE IF NOT EXISTS evidence (
            id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
            original_filename TEXT NOT NULL,
            stored_filename TEXT NOT NULL UNIQUE,
            file_size INTEGER NOT NULL,
            sha256 TEXT NOT NULL,
            uploaded_at TEXT NOT NULL,
            record_count INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS timeline_events (
            id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
            evidence_id TEXT NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
            timestamp_original TEXT NOT NULL,
            timestamp_sort REAL,
            event_type TEXT NOT NULL,
            account TEXT NOT NULL DEFAULT '',
            host TEXT NOT NULL DEFAULT '',
            source_ip TEXT NOT NULL DEFAULT '',
            outcome TEXT NOT NULL DEFAULT '',
            details TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS investigation_notes (
            id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
            body TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS student_lesson_progress (
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            course_id TEXT NOT NULL,
            lesson_index INTEGER NOT NULL,
            completed_at TEXT NOT NULL,
            PRIMARY KEY (user_id, course_id, lesson_index)
        );
        CREATE TABLE IF NOT EXISTS audit_records (
            id TEXT PRIMARY KEY,
            action TEXT NOT NULL,
            occurred_at TEXT NOT NULL,
            case_id TEXT REFERENCES cases(id) ON DELETE SET NULL,
            evidence_id TEXT REFERENCES evidence(id) ON DELETE SET NULL,
            actor TEXT NOT NULL DEFAULT 'local investigator',
            details TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_events_case_time
            ON timeline_events(case_id, timestamp_sort, timestamp_original);
        CREATE INDEX IF NOT EXISTS idx_evidence_case ON evidence(case_id);
        CREATE INDEX IF NOT EXISTS idx_audit_case ON audit_records(case_id, occurred_at);
        CREATE INDEX IF NOT EXISTS idx_case_access_user ON case_access(user_id, case_id);
        """
    )
    event_columns = {
        row[1] for row in db.execute("PRAGMA table_info(timeline_events)").fetchall()
    }
    if "source_ip" not in event_columns:
        db.execute("ALTER TABLE timeline_events ADD COLUMN source_ip TEXT NOT NULL DEFAULT ''")
    if "outcome" not in event_columns:
        db.execute("ALTER TABLE timeline_events ADD COLUMN outcome TEXT NOT NULL DEFAULT ''")
    if os.environ.get("FORENSIX_DEMO_MODE", "").lower() in {"1", "true", "yes"}:
        for username, email, password, role in DEMO_ACCOUNTS:
            exists = db.execute(
                "SELECT id FROM users WHERE username = ? COLLATE NOCASE", (username,)
            ).fetchone()
            if not exists:
                db.execute(
                    "INSERT INTO users (id, username, email, password_hash, role, created_at, active) "
                    "VALUES (?, ?, ?, ?, ?, ?, 1)",
                    (
                        str(uuid.uuid4()),
                        username,
                        email,
                        generate_password_hash(password),
                        role,
                        utc_now(),
                    ),
                )
        investigator = db.execute(
            "SELECT id FROM users WHERE username = ? COLLATE NOCASE",
            ("investigator@forensix.local",),
        ).fetchone()
        if investigator:
            db.execute(
                "INSERT OR IGNORE INTO case_access (case_id, user_id, granted_at) "
                "SELECT cases.id, ?, ? FROM cases WHERE NOT EXISTS "
                "(SELECT 1 FROM case_access WHERE case_id = cases.id)",
                (investigator["id"], utc_now()),
            )
    db.commit()
    db.close()


def audit(action, case_id=None, evidence_id=None, details=""):
    user = getattr(g, "user", None)
    get_db().execute(
        "INSERT INTO audit_records (id, action, occurred_at, case_id, evidence_id, actor, details) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            str(uuid.uuid4()),
            action,
            utc_now(),
            case_id,
            evidence_id,
            user["username"] if user else "local system",
            details,
        ),
    )


def parse_timestamp(value):
    value = str(value or "").strip()
    if not value:
        return "", None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return value, None
    if parsed.tzinfo is None:
        return value, None
    return value, parsed.astimezone(timezone.utc).timestamp()


def normalize_record(record):
    if not isinstance(record, dict):
        raise ValueError("Each event must be a JSON object or CSV row.")
    timestamp = record.get("timestamp", record.get("time", ""))
    event_type = record.get("event_type", record.get("type", ""))
    if not str(timestamp).strip() or not str(event_type).strip():
        raise ValueError("Every event must include timestamp and event_type (or type).")
    timestamp_original, timestamp_sort = parse_timestamp(timestamp)
    outcome = str(record.get("outcome", record.get("result", record.get("status", "")))).strip()[:40]
    if not outcome:
        event_name = str(event_type).lower()
        if "fail" in event_name or "denied" in event_name:
            outcome = "failure"
        elif "success" in event_name:
            outcome = "success"
    return {
        "timestamp_original": timestamp_original,
        "timestamp_sort": timestamp_sort,
        "event_type": str(event_type).strip()[:100],
        "account": str(record.get("account", record.get("user", "")))[:200],
        "host": str(record.get("host", record.get("device", "")))[:200],
        "source_ip": str(
            record.get("source_ip", record.get("src_ip", record.get("client_ip", record.get("ip", ""))))
        ).strip()[:45],
        "outcome": outcome,
        "details": str(record.get("details", record.get("description", "")))[:2000],
    }


def parse_upload(filename, content):
    suffix = Path(filename).suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS:
        raise ValueError("Only .csv and .json structured event files are supported.")
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("File must be valid UTF-8 text.") from exc
    if suffix == ".json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Malformed JSON: {exc.msg}.") from exc
        if isinstance(data, dict):
            records = data.get("events", [data])
        else:
            records = data
        if not isinstance(records, list):
            raise ValueError("JSON must contain an array of event objects.")
    else:
        try:
            records = list(csv.DictReader(io.StringIO(text, newline="")))
        except csv.Error as exc:
            raise ValueError(f"Malformed CSV: {exc}.") from exc
        if not records:
            raise ValueError("CSV must contain a header and at least one event.")
    if not records:
        raise ValueError("The file contains no event records.")
    if len(records) > MAX_RECORDS:
        raise ValueError(f"At most {MAX_RECORDS} records may be imported at once.")
    return [normalize_record(record) for record in records]


def import_evidence(case_id, original_filename, content):
    db = get_db()
    case_or_404(case_id)
    records = parse_upload(original_filename, content)
    evidence_id = "EV-" + uuid.uuid4().hex[:12].upper()
    stored_filename = uuid.uuid4().hex + Path(original_filename).suffix.lower()
    target = EVIDENCE_DIR / stored_filename
    digest = hashlib.sha256(content).hexdigest()
    with target.open("xb") as evidence_file:
        evidence_file.write(content)
    try:
        with db:
            db.execute(
                "INSERT INTO evidence (id, case_id, original_filename, stored_filename, "
                "file_size, sha256, uploaded_at, record_count) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    evidence_id,
                    case_id,
                    Path(original_filename.replace("\\", "/")).name[:255]
                    or "uploaded_evidence",
                    stored_filename,
                    len(content),
                    digest,
                    utc_now(),
                    len(records),
                ),
            )
            for record in records:
                db.execute(
                    "INSERT INTO timeline_events (id, case_id, evidence_id, timestamp_original, "
                    "timestamp_sort, event_type, account, host, source_ip, outcome, details, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        str(uuid.uuid4()),
                        case_id,
                        evidence_id,
                        record["timestamp_original"],
                        record["timestamp_sort"],
                        record["event_type"],
                        record["account"],
                        record["host"],
                        record["source_ip"],
                        record["outcome"],
                        record["details"],
                        utc_now(),
                    ),
                )
            audit("evidence_imported", case_id, evidence_id, f"{len(records)} structured records")
    except Exception:
        target.unlink(missing_ok=True)
        raise
    return evidence_id, len(records)


def case_or_404(case_id):
    case = get_db().execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
    if case is None:
        abort(404)
    user = getattr(g, "user", None)
    if user is None:
        abort(403)
    allowed = get_db().execute(
        "SELECT 1 FROM case_access WHERE case_id = ? AND user_id = ?",
        (case_id, user["id"]),
    ).fetchone()
    if allowed is None:
        abort(404)
    return case


def analyze_student_records(records):
    events = sorted(
        enumerate(records, start=1),
        key=lambda item: (
            item[1]["timestamp_sort"] is None,
            item[1]["timestamp_sort"] or 0,
            item[0],
        ),
    )
    findings = []
    failures = [
        (number, event)
        for number, event in events
        if event["outcome"].lower() in {"failure", "failed", "denied", "blocked"}
        or "fail" in event["event_type"].lower()
    ]
    failed_groups = {}
    for number, event in failures:
        identity = (event["account"], event["host"], event["source_ip"])
        if not any(identity):
            identity = ("", "", f"unidentified-row-{number}")
        failed_groups.setdefault(identity, []).append(number)
    for (account, host, source_ip), record_numbers in failed_groups.items():
        if len(record_numbers) >= 3:
            findings.append(
                {
                    "label": "Observed Fact",
                    "text": (
                        f"{len(record_numbers)} failed-login record(s) share the same "
                        f"account/device/source-IP fields: {', '.join(map(str, record_numbers))}."
                    ),
                    "interpretation": "This may warrant review; the exported records do not identify who initiated them.",
                    "records": record_numbers,
                }
            )
    for number, event in events:
        if event["timestamp_sort"] is None or not (
            event["event_type"].lower().find("login") >= 0
            or event["outcome"].lower() in {"success", "failure", "failed", "denied"}
        ):
            continue
        hour_utc = datetime.fromisoformat(
            event["timestamp_original"].replace("Z", "+00:00")
        ).astimezone(timezone.utc).hour
        if hour_utc < 5 or hour_utc >= 23:
            findings.append(
                {
                    "label": "Possible Interpretation",
                    "text": f"Login record {number} is timestamped at an unusual UTC hour ({hour_utc:02d}:00).",
                    "interpretation": "The user's local timezone and normal schedule are not available, so this is not proof of suspicious activity.",
                    "records": [number],
                }
            )
    explicit = [
        (number, event)
        for number, event in events
        if event["timestamp_sort"] is not None
    ]
    for (first_number, first), (second_number, second) in zip(explicit, explicit[1:]):
        difference = second["timestamp_sort"] - first["timestamp_sort"]
        if difference >= 3600:
            findings.append(
                {
                    "label": "Observed Fact",
                    "text": (
                        f"There is a {int(difference // 60)}-minute interval between "
                        f"available records {first_number} and {second_number}."
                    ),
                    "interpretation": "This describes the supplied dataset only; it does not prove that records are missing.",
                    "records": [first_number, second_number],
                }
            )
    return [event for _, event in events], findings


@app.template_filter("pretty_time")
def pretty_time(value):
    if not value:
        return "—"
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).strftime("%b %d, %Y %H:%M:%S")
    except ValueError:
        return value


def student_course_progress(user_id):
    rows = get_db().execute(
        "SELECT course_id, lesson_index FROM student_lesson_progress WHERE user_id = ?",
        (user_id,),
    ).fetchall()
    completed = {}
    for row in rows:
        completed.setdefault(row["course_id"], set()).add(row["lesson_index"])
    courses = []
    for course in STUDENT_COURSES:
        done = completed.get(course["id"], set())
        total = len(course["lessons"])
        courses.append(
            {
                **course,
                "completed_lessons": len(done),
                "lesson_count": total,
                "progress_percent": int(len(done) * 100 / total),
                "completed_indices": done,
            }
        )
    return courses


@app.route("/")
def dashboard():
    if g.user["role"] == "student":
        courses = student_course_progress(g.user["id"])
        return render_template(
            "student_dashboard.html",
            sample_cases=[
                {"slug": slug, "title": scenario["title"]}
                for slug, scenario in STUDENT_SAMPLE_CASES.items()
            ],
            courses=courses,
            course_categories=sorted({course["category"] for course in courses}),
        )
    if g.user["role"] == "user":
        return render_template("personal_dashboard.html")
    db = get_db()
    user_id = g.user["id"]
    stats = {
        "cases": db.execute(
            "SELECT COUNT(*) FROM case_access WHERE user_id = ?", (user_id,)
        ).fetchone()[0],
        "evidence": db.execute(
            "SELECT COUNT(*) FROM evidence WHERE case_id IN "
            "(SELECT case_id FROM case_access WHERE user_id = ?)",
            (user_id,),
        ).fetchone()[0],
        "events": db.execute(
            "SELECT COUNT(*) FROM timeline_events WHERE case_id IN "
            "(SELECT case_id FROM case_access WHERE user_id = ?)",
            (user_id,),
        ).fetchone()[0],
        "reviews": db.execute(
            "SELECT COUNT(*) FROM cases c JOIN case_access a ON a.case_id = c.id "
            "WHERE a.user_id = ? AND c.status IN ('Open', 'Investigating')",
            (user_id,),
        ).fetchone()[0],
    }
    recent = db.execute(
        "SELECT a.*, c.title AS case_title FROM audit_records a "
        "LEFT JOIN cases c ON c.id = a.case_id WHERE a.case_id IS NULL OR "
        "a.case_id IN (SELECT case_id FROM case_access WHERE user_id = ?) "
        "ORDER BY a.occurred_at DESC LIMIT 8",
        (user_id,),
    ).fetchall()
    distribution = [
        dict(row)
        for row in db.execute(
            "SELECT event_type, COUNT(*) AS count FROM timeline_events WHERE case_id IN "
            "(SELECT case_id FROM case_access WHERE user_id = ?) "
            "GROUP BY event_type ORDER BY count DESC LIMIT 8",
            (user_id,),
        ).fetchall()
    ]
    cases = db.execute(
        "SELECT c.* FROM cases c JOIN case_access a ON a.case_id = c.id "
        "WHERE a.user_id = ? ORDER BY c.updated_at DESC LIMIT 6",
        (user_id,),
    ).fetchall()
    return render_template(
        "index.html", stats=stats, recent=recent, distribution=distribution, cases=cases
    )


@app.route("/student/cases/<slug>", endpoint="student_case")
def student_case(slug):
    scenario = STUDENT_SAMPLE_CASES.get(slug)
    if scenario is None:
        abort(404)
    return render_template(
        "student_case.html",
        case=scenario,
        case_slug=slug,
    )


@app.route("/student/courses")
def student_courses():
    courses = student_course_progress(g.user["id"])
    query = request.args.get("q", "").strip()[:100]
    difficulty = request.args.get("difficulty", "").strip()
    category = request.args.get("category", "").strip()
    difficulties = sorted({course["difficulty"] for course in courses})
    categories = sorted({course["category"] for course in courses})
    filtered = [
        course for course in courses
        if (not query or query.casefold() in
            f"{course['title']} {course['description']} {course['category']}".casefold())
        and (not difficulty or course["difficulty"] == difficulty)
        and (not category or course["category"] == category)
    ]
    return render_template(
        "student_courses.html",
        courses=filtered,
        query=query,
        selected_difficulty=difficulty,
        selected_category=category,
        difficulties=difficulties,
        categories=categories,
    )


@app.route("/student/courses/<course_id>")
def student_course(course_id):
    course = STUDENT_COURSES_BY_ID.get(course_id)
    if course is None:
        abort(404)
    rows = get_db().execute(
        "SELECT lesson_index FROM student_lesson_progress "
        "WHERE user_id = ? AND course_id = ?",
        (g.user["id"], course_id),
    ).fetchall()
    completed = {row["lesson_index"] for row in rows}
    lesson_count = len(course["lessons"])
    return render_template(
        "student_course.html",
        course=course,
        completed=completed,
        progress_percent=int(len(completed) * 100 / lesson_count),
    )


@app.route(
    "/student/courses/<course_id>/lessons/<int:lesson_index>",
    methods=["GET", "POST"],
)
def student_lesson(course_id, lesson_index):
    course = STUDENT_COURSES_BY_ID.get(course_id)
    if course is None or not 0 <= lesson_index < len(course["lessons"]):
        abort(404)
    if request.method == "POST":
        get_db().execute(
            "INSERT OR IGNORE INTO student_lesson_progress "
            "(user_id, course_id, lesson_index, completed_at) VALUES (?, ?, ?, ?)",
            (g.user["id"], course_id, lesson_index, utc_now()),
        )
        get_db().commit()
        if lesson_index + 1 < len(course["lessons"]):
            return redirect(
                url_for(
                    "student_lesson",
                    course_id=course_id,
                    lesson_index=lesson_index + 1,
                )
            )
        return redirect(url_for("student_course", course_id=course_id))
    rows = get_db().execute(
        "SELECT lesson_index FROM student_lesson_progress "
        "WHERE user_id = ? AND course_id = ?",
        (g.user["id"], course_id),
    ).fetchall()
    completed = {row["lesson_index"] for row in rows}
    return render_template(
        "student_lesson.html",
        course=course,
        lesson=course["lessons"][lesson_index],
        lesson_index=lesson_index,
        lesson_count=len(course["lessons"]),
        completed=lesson_index in completed,
    )


def learning_assistant_answer(question):
    normalized = question.casefold()
    stop_words = {"what", "about", "course", "lessons", "learn", "explain", "please"}
    words = {
        word for word in re.findall(r"[a-z0-9-]+", normalized)
        if len(word) > 3 and word not in stop_words
    }
    matches = []
    for course in STUDENT_COURSES:
        title_words = {
            word for word in re.findall(r"[a-z0-9-]+", course["title"].casefold())
            if len(word) > 3 and word not in stop_words
        }
        overlap = words & title_words
        if course["title"].casefold() in normalized or overlap:
            matches.append((len(overlap), course))
    if matches:
        course = max(matches, key=lambda match: match[0])[1]
        lesson_titles = ", ".join(lesson["title"] for lesson in course["lessons"])
        return (
            f"Course reference: {course['title']}. {course['description']} "
            f"Lessons: {lesson_titles}. Learning objectives: "
            + " ".join(course["objectives"])
        ), course
    if any(term in normalized for term in ("lab", "log", "csv", "json", "hash", "timeline")):
        return (
            "The Student Log Analysis Lab accepts authorized CSV or JSON event exports "
            "in memory. It can sort supported timestamps, filter event type/host/account, "
            "calculate SHA-256, and flag a few simple patterns. Results refer to the "
            "provided records only; they are not proof of identity, compromise, or intent."
        ), None
    if any(term in normalized for term in ("case", "scenario", "phishing", "login")):
        return (
            "The Student Dashboard has fictional practice cases with their own evidence "
            "references, timelines, investigation questions, and guided steps. Each case "
            "is a training scenario, not a live alert or a conclusion about a real account."
        ), None
    return (
        "I am a local rule-based learning helper, not a connected AI model. I can point "
        "to course material, explain the Student Lab's supported checks, and describe "
        "the fictional practice cases. I cannot inspect uploaded files from this page or "
        "invent results. Ask about a course by name, the log lab, or a practice case."
    ), None


@app.route("/student/assistant", methods=["GET", "POST"])
def student_assistant():
    answer = None
    matched_course = None
    question = ""
    if request.method == "POST":
        question = request.form.get("question", "").strip()[:1200]
        if not question:
            flash("Enter a learning question to get local guidance.", "error")
        else:
            answer, matched_course = learning_assistant_answer(question)
    return render_template(
        "student_assistant.html",
        question=question,
        answer=answer,
        matched_course=matched_course,
    )


def safety_assistant_answer(question, language):
    guidance = SAFETY_ASSISTANT_GUIDANCE[language]
    normalized = question.casefold()
    payment_terms = (
        "payment", "upi", "bank", "money", "phonepe", "भुगतान", "पैसा",
        "यूपीआई", "बैंक", "చెల్లింపు", "డబ్బు", "యూపీఐ", "బ్యాంక్",
    )
    message_terms = (
        "message", "link", "phishing", "email", "sms", "संदेश", "लिंक",
        "ईमेल", "మెసేజ్", "లింక్", "సందేశం", "ఈమెయిల్",
    )
    account_terms = (
        "account", "login", "sign in", "password", "खाता", "अकाउंट",
        "लॉगिन", "पासवर्ड", "ఖాతా", "లాగిన్", "పాస్‌వర్డ్",
    )
    if any(term in normalized for term in payment_terms):
        response = guidance["payment"]
    elif any(term in normalized for term in message_terms):
        response = guidance["message"]
    elif any(term in normalized for term in account_terms):
        response = guidance["account"]
    else:
        response = guidance["generic"] + " " + guidance["fallback"]
    return response


@app.route("/safety/assistant", methods=["GET", "POST"])
def safety_assistant():
    answer = None
    question = ""
    language = session.get("preferred_safety_language", "en")
    if language not in SAFETY_ASSISTANT_GUIDANCE:
        language = "en"
    if request.method == "POST":
        requested_language = request.form.get("language", language)
        if requested_language not in SAFETY_ASSISTANT_GUIDANCE:
            flash("Choose one of the available assistant languages.", "error")
        else:
            language = requested_language
            session["preferred_safety_language"] = language
            question = request.form.get("question", "").strip()[:1200]
            if not question:
                flash("Enter a question to get a safety checklist.", "error")
            else:
                answer = safety_assistant_answer(question, language)
    return render_template(
        "safety_assistant.html",
        answer=answer,
        question=question,
        language=language,
        languages=SAFETY_ASSISTANT_GUIDANCE,
    )


@app.route("/student/lab", methods=["GET", "POST"])
def student_lab():
    events = []
    findings = []
    digest = None
    expected_hash = ""
    integrity = None
    event_type_filter = request.form.get("event_type_filter", "").strip()[:100]
    host_filter = request.form.get("host_filter", "").strip()[:200]
    account_filter = request.form.get("account_filter", "").strip()[:200]
    if request.method == "POST":
        upload = request.files.get("file")
        expected_hash = request.form.get("expected_hash", "").strip().lower()
        if not upload or not upload.filename:
            flash("Choose an authorized CSV or JSON event export.", "error")
        else:
            content = upload.stream.read(MAX_UPLOAD_BYTES + 1)
            if len(content) > MAX_UPLOAD_BYTES:
                flash("File exceeds the 5 MB limit.", "error")
            else:
                try:
                    records = parse_upload(upload.filename, content)
                except ValueError as exc:
                    flash(str(exc), "error")
                else:
                    all_events, findings = analyze_student_records(records)
                    events = [
                        event
                        for event in all_events
                        if event_type_filter.lower() in event["event_type"].lower()
                        and host_filter.lower() in event["host"].lower()
                        and account_filter.lower() in event["account"].lower()
                    ]
                    digest = hashlib.sha256(content).hexdigest()
                    if expected_hash:
                        if not re.fullmatch(r"[a-f0-9]{64}", expected_hash):
                            integrity = "Enter a valid 64-character SHA-256 hash to compare."
                        else:
                            integrity = (
                                "The uploaded file matches the supplied SHA-256 hash. "
                                "A match supports integrity verification but does not prove authenticity."
                                if secrets.compare_digest(digest, expected_hash)
                                else "The uploaded file does not match the supplied SHA-256 hash."
                            )
    return render_template(
        "student_lab.html",
        events=events,
        findings=findings,
        digest=digest,
        expected_hash=expected_hash,
        integrity=integrity,
        event_type_filter=event_type_filter,
        host_filter=host_filter,
        account_filter=account_filter,
    )


@app.route("/safety", methods=["GET", "POST"])
def personal_safety():
    checklist = {
        "email": ["Review recent sign-ins and active sessions.", "Remove devices you do not recognize.", "Check recovery email/phone and enable MFA."],
        "social": ["Review active sessions and connected apps.", "Check recovery settings and login alerts.", "Enable MFA and remove unfamiliar devices."],
        "payments": ["Review transactions only in the official app.", "Contact your bank/provider using its official support channel.", "Never share an OTP, payment PIN, or recovery code."],
    }
    activity_result = None
    category = request.form.get("category", "email")
    if request.method == "POST":
        if category not in checklist:
            flash("Choose an account category from the list.", "error")
            category = "email"
        else:
            raw_failures = request.form.get("failed_attempts", "").strip()
            device_unknown = request.form.get("unrecognized_device") == "yes"
            try:
                failed_attempts = int(raw_failures) if raw_failures else 0
            except ValueError:
                failed_attempts = -1
            if not 0 <= failed_attempts <= 10000:
                flash("Enter a non-negative failed-attempt count shown by the provider's activity page.", "error")
            else:
                warnings = []
                if failed_attempts >= 2:
                    warnings.append(
                        f"The details you entered report {failed_attempts} failed attempts. "
                        "Review them in the provider's official activity page."
                    )
                if device_unknown:
                    warnings.append(
                        "You marked a device as unfamiliar. Verify it in the official account page and sign it out if appropriate."
                    )
                activity_result = warnings or [
                    "No warning was identified from the details you entered. This does not prove the account is safe."
                ]
    return render_template(
        "personal_dashboard.html",
        checklist=checklist,
        selected_category=category,
        activity_result=activity_result,
    )


@app.route("/cases", methods=["GET", "POST"])
def cases():
    db = get_db()
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        if not title or len(title) > 160 or len(description) > 4000:
            flash("Enter a case title (up to 160 characters) and description (up to 4,000).", "error")
        else:
            case_id = "FX-" + uuid.uuid4().hex[:8].upper()
            with db:
                db.execute(
                    "INSERT INTO cases (id, title, description, status, created_at, updated_at) "
                    "VALUES (?, ?, ?, 'Open', ?, ?)",
                    (case_id, title, description, utc_now(), utc_now()),
                )
                db.execute(
                    "INSERT INTO case_access (case_id, user_id, granted_at) VALUES (?, ?, ?)",
                    (case_id, g.user["id"], utc_now()),
                )
                audit("case_created", case_id, details="Case created")
            flash(f"Case {case_id} created.", "success")
            return redirect(url_for("case_detail", case_id=case_id))
    query = request.args.get("q", "").strip()[:160]
    status = request.args.get("status", "")
    sql = (
        "SELECT c.* FROM cases c WHERE (c.title LIKE ? OR c.id LIKE ?) "
        "AND EXISTS (SELECT 1 FROM case_access a WHERE a.case_id = c.id AND a.user_id = ?)"
    )
    params = [f"%{query}%", f"%{query}%", g.user["id"]]
    if status in CASE_STATUSES:
        sql += " AND c.status = ?"
        params.append(status)
    results = db.execute(sql + " ORDER BY c.updated_at DESC", params).fetchall()
    return render_template("cases.html", cases=results, query=query, status=status, statuses=sorted(CASE_STATUSES))


@app.route("/cases/<case_id>")
def case_detail(case_id):
    case = case_or_404(case_id)
    db = get_db()
    evidence = db.execute(
        "SELECT * FROM evidence WHERE case_id = ? ORDER BY uploaded_at DESC", (case_id,)
    ).fetchall()
    events = db.execute(
        "SELECT t.*, e.original_filename FROM timeline_events t "
        "JOIN evidence e ON e.id = t.evidence_id WHERE t.case_id = ? "
        "ORDER BY t.timestamp_sort IS NULL, t.timestamp_sort, t.timestamp_original LIMIT 12",
        (case_id,),
    ).fetchall()
    notes = db.execute(
        "SELECT * FROM investigation_notes WHERE case_id = ? ORDER BY created_at DESC",
        (case_id,),
    ).fetchall()
    return render_template("case_detail.html", case=case, evidence=evidence, events=events, notes=notes, statuses=sorted(CASE_STATUSES))


@app.route("/cases/<case_id>/update", methods=["POST"])
def update_case(case_id):
    case_or_404(case_id)
    title = request.form.get("title", "").strip()
    description = request.form.get("description", "").strip()
    status = request.form.get("status", "")
    if not title or len(title) > 160 or len(description) > 4000 or status not in CASE_STATUSES:
        flash("Check the case title, description, and status.", "error")
    else:
        db = get_db()
        with db:
            db.execute(
                "UPDATE cases SET title = ?, description = ?, status = ?, updated_at = ? WHERE id = ?",
                (title, description, status, utc_now(), case_id),
            )
            audit("case_updated", case_id, details=f"Status set to {status}")
        flash("Case details updated.", "success")
    return redirect(url_for("case_detail", case_id=case_id))


@app.route("/evidence", methods=["GET", "POST"])
def evidence_page():
    db = get_db()
    if request.method == "POST":
        case_id = request.form.get("case_id", "")
        upload = request.files.get("file")
        if not upload or not upload.filename:
            flash("Choose a CSV or JSON event file.", "error")
        else:
            content = upload.stream.read(MAX_UPLOAD_BYTES + 1)
            if len(content) > MAX_UPLOAD_BYTES:
                flash("File exceeds the 5 MB limit.", "error")
            else:
                try:
                    evidence_id, count = import_evidence(case_id, upload.filename, content)
                except ValueError as exc:
                    flash(str(exc), "error")
                else:
                    flash(f"Imported {count} records as evidence {evidence_id}.", "success")
                    return redirect(url_for("case_detail", case_id=case_id))
    selected_case = request.args.get("case_id", "")
    all_cases = db.execute(
        "SELECT c.id, c.title FROM cases c JOIN case_access a ON a.case_id = c.id "
        "WHERE a.user_id = ? ORDER BY c.created_at DESC",
        (g.user["id"],),
    ).fetchall()
    items = db.execute(
        "SELECT e.*, c.title AS case_title FROM evidence e "
        "JOIN cases c ON c.id = e.case_id JOIN case_access a ON a.case_id = c.id "
        "WHERE a.user_id = ? ORDER BY e.uploaded_at DESC",
        (g.user["id"],),
    ).fetchall()
    return render_template("evidence.html", cases=all_cases, evidence=items, selected_case=selected_case)


@app.route("/evidence/<evidence_id>/verify", methods=["POST"])
def verify_evidence(evidence_id):
    db = get_db()
    item = db.execute("SELECT * FROM evidence WHERE id = ?", (evidence_id,)).fetchone()
    if item is None:
        abort(404)
    case_or_404(item["case_id"])
    file_path = EVIDENCE_DIR / item["stored_filename"]
    exists = file_path.is_file()
    actual = hashlib.sha256(file_path.read_bytes()).hexdigest() if exists else ""
    verified = exists and secrets.compare_digest(actual, item["sha256"])
    with db:
        audit(
            "integrity_check",
            item["case_id"],
            item["id"],
            "SHA-256 matched" if verified else "File missing or SHA-256 mismatch",
        )
    flash(
        "Integrity verified: SHA-256 matches the recorded value."
        if verified
        else "Integrity check failed: file is missing or its SHA-256 has changed.",
        "success" if verified else "error",
    )
    return redirect(url_for("case_detail", case_id=item["case_id"]))


@app.route("/timeline")
def timeline():
    db = get_db()
    clauses = [
        "EXISTS (SELECT 1 FROM case_access a WHERE a.case_id = t.case_id AND a.user_id = ?)"
    ]
    params = [g.user["id"]]
    for field in ("case_id", "event_type", "host", "account"):
        value = request.args.get(field, "").strip()[:200]
        if value:
            clauses.append(f"t.{field} LIKE ?")
            params.append(f"%{value}%")
    start = request.args.get("start", "").strip()
    end = request.args.get("end", "").strip()
    if start:
        clauses.append("substr(t.timestamp_original, 1, 10) >= ?")
        params.append(start)
    if end:
        clauses.append("substr(t.timestamp_original, 1, 10) <= ?")
        params.append(end)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    events = db.execute(
        "SELECT t.*, e.original_filename, c.title AS case_title "
        "FROM timeline_events t JOIN evidence e ON e.id = t.evidence_id "
        "JOIN cases c ON c.id = t.case_id "
        + where
        + " ORDER BY t.timestamp_sort IS NULL, t.timestamp_sort, t.timestamp_original LIMIT 500",
        params,
    ).fetchall()
    cases_list = db.execute(
        "SELECT c.id, c.title FROM cases c JOIN case_access a ON a.case_id = c.id "
        "WHERE a.user_id = ? ORDER BY c.created_at DESC",
        (g.user["id"],),
    ).fetchall()
    return render_template("timeline.html", events=events, cases=cases_list)


def assistant_response(case_id):
    db = get_db()
    case = case_or_404(case_id)
    events = db.execute(
        "SELECT * FROM timeline_events WHERE case_id = ? ORDER BY timestamp_sort IS NULL, timestamp_sort",
        (case_id,),
    ).fetchall()
    types = {row["event_type"].lower() for row in events}
    lines = [
        f"Case {case['id']} — {case['title']}. This is a deterministic prototype assistant, not a language model.",
        f"OBSERVATION: {len(events)} structured event(s) are available in this case.",
    ]
    for kind, terms in (
        ("authentication", ("login", "auth")),
        ("process activity", ("process",)),
        ("file activity", ("file",)),
        ("network activity", ("network",)),
    ):
        found = [row for row in events if any(term in row["event_type"].lower() for term in terms)]
        if not found:
            lines.append(f"UNKNOWN: No {kind} record is currently imported. This is not evidence that the activity did not occur.")
        else:
            ids = ", ".join(f"{row['id']} (evidence {row['evidence_id']})" for row in found[:5])
            lines.append(f"OBSERVATION: {len(found)} {kind} record(s): {ids}.")
    failed = [row for row in events if "fail" in row["event_type"].lower()]
    successful = [row for row in events if "success" in row["event_type"].lower()]
    if failed and successful:
        lines.append(
            "HYPOTHESIS TO REVIEW: Failed and successful activity both appear in this dataset; "
            "check account, host, and timestamp context before inferring a relationship. Supporting records: "
            + ", ".join(f"{row['id']} / {row['evidence_id']}" for row in (failed[:3] + successful[:3]))
            + "."
        )
    naive = [row for row in events if row["timestamp_sort"] is None]
    if naive:
        lines.append(
            "DATA QUALITY: Some timestamps have no explicit timezone or could not be parsed "
            f"({len(naive)} record(s)); do not assume a common timezone."
        )
    lines.append(
        "NEXT CHECKS: Review source records and collection context, compare independent logs, "
        "look for contradictory explanations, and document uncertainty. Missing categories remain unknown."
    )
    lines.append(
        "LIMITATION: Suggestions are unverified and do not determine identity, intent, causation, or guilt."
    )
    return "\n\n".join(lines)


@app.route("/assistant", methods=["GET", "POST"])
def assistant():
    db = get_db()
    cases_list = db.execute(
        "SELECT c.id, c.title FROM cases c JOIN case_access a ON a.case_id = c.id "
        "WHERE a.user_id = ? ORDER BY c.created_at DESC",
        (g.user["id"],),
    ).fetchall()
    selected = request.values.get("case_id", "")
    answer = None
    if request.method == "POST":
        if selected:
            answer = assistant_response(selected)
        else:
            flash("Select a case to review.", "error")
    return render_template("assistant.html", cases=cases_list, selected=selected, answer=answer)


def correlate_events(events):
    pairs = {}
    comparisons = 0
    truncated = False

    def add_match(first, second, reason):
        first, second = sorted(
            (first, second),
            key=lambda event: (
                event["timestamp_sort"] is None,
                event["timestamp_sort"] or 0,
                event["id"],
            ),
        )
        key = (first["id"], second["id"])
        if key not in pairs:
            if len(pairs) >= MAX_CORRELATION_PAIRS:
                return False
            pairs[key] = {
                "first": first,
                "second": second,
                "matched": [],
                "relation": "",
            }
        if reason not in pairs[key]["matched"]:
            pairs[key]["matched"].append(reason)
        return True

    groups = {}
    for event in events:
        for field in ("account", "host", "source_ip"):
            value = str(event[field] or "").strip().casefold()
            if value:
                groups.setdefault((field, value), {}).setdefault(
                    event["evidence_id"], []
                ).append(event)

    for (field, _value), sources in groups.items():
        source_events = list(sources.values())
        for source_index, first_source in enumerate(source_events):
            for second_source in source_events[source_index + 1 :]:
                for first in first_source:
                    for second in second_source:
                        comparisons += 1
                        if comparisons > MAX_CORRELATION_COMPARISONS:
                            truncated = True
                            break
                        if not add_match(first, second, f"same {field} across evidence records"):
                            truncated = True
                            break
                    if truncated:
                        break
                if truncated:
                    break
            if truncated:
                break
        if truncated:
            break

    explicit = sorted(
        (event for event in events if event["timestamp_sort"] is not None),
        key=lambda event: (event["timestamp_sort"], event["id"]),
    )
    for index, first in enumerate(explicit):
        if truncated:
            break
        for second in explicit[index + 1 :]:
            delta = second["timestamp_sort"] - first["timestamp_sort"]
            if delta > LOGIN_SEQUENCE_WINDOW_SECONDS:
                break
            if first["evidence_id"] == second["evidence_id"]:
                continue
            comparisons += 1
            if comparisons > MAX_CORRELATION_COMPARISONS:
                truncated = True
                break
            first_type = first["event_type"].casefold()
            second_type = second["event_type"].casefold()
            first_outcome = first["outcome"].casefold()
            second_outcome = second["outcome"].casefold()
            first_failed = "fail" in first_type or first_outcome in {
                "failure", "failed", "denied", "blocked"
            }
            second_succeeded = "success" in second_type or second_outcome == "success"
            identifiers = ("account", "source_ip")
            shared_identifiers = [
                field
                for field in identifiers
                if first[field]
                and second[field]
                and first[field].strip().casefold() == second[field].strip().casefold()
            ]
            if first_failed and second_succeeded and delta <= LOGIN_SEQUENCE_WINDOW_SECONDS:
                if shared_identifiers:
                    if not add_match(
                        first,
                        second,
                        "failed login followed by success within 30 minutes "
                        f"with matching {', '.join(shared_identifiers)}",
                    ):
                        truncated = True
                        break
            if delta <= CORRELATION_WINDOW_SECONDS:
                if not add_match(
                    first,
                    second,
                    "timestamps within five minutes (UTC-normalized)",
                ):
                    truncated = True
                    break

    output = list(pairs.values())
    for match in output:
        match["relation"] = (
            "One or more exact identifiers match across separate evidence records. "
            "This does not prove a shared actor, event, or cause."
            if any(reason.startswith("same ") for reason in match["matched"])
            else "Timestamp proximity is a review lead only; clock differences and other "
            "explanations are possible, and it does not establish causation."
        )
        if any(reason.startswith("failed login followed") for reason in match["matched"]):
            match["relation"] += (
                " The sequence is based only on the supplied outcome, account, IP, and "
                "timestamps; it does not identify who initiated either event."
            )
    return output, truncated


def find_timeline_gaps(events, threshold_seconds=TIMELINE_GAP_THRESHOLD_SECONDS):
    explicit = sorted(
        (event for event in events if event["timestamp_sort"] is not None),
        key=lambda event: (event["timestamp_sort"], event["id"]),
    )
    gaps = []
    for first, second in zip(explicit, explicit[1:]):
        difference = second["timestamp_sort"] - first["timestamp_sort"]
        if difference >= threshold_seconds:
            gaps.append(
                {
                    "first": first,
                    "second": second,
                    "seconds": int(difference),
                    "minutes": int(difference // 60),
                    "hours": difference / 3600,
                }
            )
            if len(gaps) > 100:
                break
    return gaps[:100], len(gaps) > 100


def case_event_analysis(case_id):
    rows = get_db().execute(
        "SELECT t.*, e.original_filename FROM timeline_events t "
        "JOIN evidence e ON e.id = t.evidence_id WHERE t.case_id = ? "
        "ORDER BY t.timestamp_sort IS NULL, t.timestamp_sort, t.timestamp_original, t.id "
        "LIMIT ?",
        (case_id, MAX_ANALYSIS_EVENTS + 1),
    ).fetchall()
    events_truncated = len(rows) > MAX_ANALYSIS_EVENTS
    events = rows[:MAX_ANALYSIS_EVENTS]
    matches, matches_truncated = correlate_events(events)
    gaps, gaps_truncated = find_timeline_gaps(events)
    return {
        "events": events,
        "matches": matches,
        "gaps": gaps,
        "events_truncated": events_truncated,
        "matches_truncated": matches_truncated,
        "gaps_truncated": gaps_truncated,
        "timed_events": sum(event["timestamp_sort"] is not None for event in events),
    }


@app.route("/cases/<case_id>/correlation")
def correlation(case_id):
    case = case_or_404(case_id)
    analysis = case_event_analysis(case_id)
    return render_template("correlation.html", case=case, **analysis)


@app.route("/cases/<case_id>/notes", methods=["POST"])
def add_note(case_id):
    case_or_404(case_id)
    body = request.form.get("body", "").strip()
    if not body or len(body) > 5000:
        flash("A note is required and must be 5,000 characters or fewer.", "error")
    else:
        db = get_db()
        with db:
            db.execute(
                "INSERT INTO investigation_notes (id, case_id, body, created_at) VALUES (?, ?, ?, ?)",
                (str(uuid.uuid4()), case_id, body, utc_now()),
            )
            audit("investigator_note_added", case_id, details="Investigator note added")
        flash("Investigator note saved.", "success")
    return redirect(url_for("case_detail", case_id=case_id) + "#notes")


@app.route("/cases/<case_id>/report")
def report(case_id):
    case = case_or_404(case_id)
    db = get_db()
    items = db.execute("SELECT * FROM evidence WHERE case_id = ? ORDER BY uploaded_at", (case_id,)).fetchall()
    events = db.execute(
        "SELECT * FROM timeline_events WHERE case_id = ? "
        "ORDER BY timestamp_sort IS NULL, timestamp_sort, timestamp_original LIMIT 500",
        (case_id,),
    ).fetchall()
    notes = db.execute(
        "SELECT * FROM investigation_notes WHERE case_id = ? ORDER BY created_at", (case_id,)
    ).fetchall()
    audit_rows = db.execute(
        "SELECT * FROM audit_records WHERE case_id = ? ORDER BY occurred_at DESC LIMIT 100",
        (case_id,),
    ).fetchall()
    analysis = case_event_analysis(case_id)
    return render_template(
        "report.html",
        case=case,
        evidence=items,
        events=events,
        notes=notes,
        audit_rows=audit_rows,
        suggestions=assistant_response(case_id),
        matches=analysis["matches"],
        gaps=analysis["gaps"],
        analysis=analysis,
        generated_at=utc_now(),
    )


@app.route("/cases/<case_id>/report.pdf")
def report_pdf(case_id):
    case = case_or_404(case_id)
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer
    except ImportError:
        flash("PDF export requires reportlab. Install project requirements and try again.", "error")
        return redirect(url_for("report", case_id=case_id))
    db = get_db()
    evidence = db.execute("SELECT * FROM evidence WHERE case_id = ?", (case_id,)).fetchall()
    events = db.execute(
        "SELECT * FROM timeline_events WHERE case_id = ? ORDER BY timestamp_sort IS NULL, timestamp_sort LIMIT 100",
        (case_id,),
    ).fetchall()
    notes = db.execute("SELECT * FROM investigation_notes WHERE case_id = ?", (case_id,)).fetchall()
    audit_rows = db.execute(
        "SELECT * FROM audit_records WHERE case_id = ? ORDER BY occurred_at DESC LIMIT 100",
        (case_id,),
    ).fetchall()
    analysis = case_event_analysis(case_id)
    buffer = io.BytesIO()
    document = SimpleDocTemplate(buffer, pagesize=letter, title=f"FORENSIX report {case_id}")
    styles = getSampleStyleSheet()
    story = [
        Paragraph("FORENSIX — Investigation Report", styles["Title"]),
        Paragraph(f"Generated: {utc_now()} (UTC)", styles["Normal"]),
        Paragraph(
            f"Case: {case['id']} — {escape(case['title'])}", styles["Heading2"]
        ),
        Paragraph(f"Status: {case['status']}", styles["Normal"]),
        Paragraph(
            "Description: "
            + escape(case["description"] or "None provided"),
            styles["Normal"],
        ),
        Paragraph("Evidence inventory and recorded SHA-256 hashes", styles["Heading2"]),
    ]
    for item in evidence:
        story.append(
            Paragraph(
                escape(
                    f"{item['id']} — {item['original_filename']} — SHA-256: {item['sha256']}"
                ),
                styles["BodyText"],
            )
        )
    story.append(Paragraph("Timeline summary (up to 100 events)", styles["Heading2"]))
    for event in events:
        line = f"{event['timestamp_original']} | {event['event_type']} | {event['account']} | {event['host']} | {event['details']} | event {event['id']} / evidence {event['evidence_id']}"
        story.append(Paragraph(line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"), styles["BodyText"]))
    story.append(Paragraph("Timeline intervals of 60 minutes or more", styles["Heading2"]))
    if analysis["gaps"]:
        for gap in analysis["gaps"]:
            line = (
                f"{gap['minutes']} minutes between event {gap['first']['id']} "
                f"(evidence {gap['first']['evidence_id']}) and event "
                f"{gap['second']['id']} (evidence {gap['second']['evidence_id']}). "
                "An interval in the supplied records is not proof of missing events."
            )
            story.append(Paragraph(escape(line), styles["BodyText"]))
        if analysis["gaps_truncated"]:
            story.append(
                Paragraph(
                    "Only the first 100 qualifying intervals are shown.",
                    styles["BodyText"],
                )
            )
    else:
        story.append(
            Paragraph(
                "No interval of 60 minutes or more was identified between explicit-timezone records.",
                styles["BodyText"],
            )
        )
    story.extend(
        [
            Paragraph("Rule-based assistant suggestions — unverified; human review required", styles["Heading2"]),
            Paragraph(
                escape(assistant_response(case_id)).replace("\n\n", "<br/><br/>"),
                styles["BodyText"],
            ),
            Paragraph("Investigator notes", styles["Heading2"]),
        ]
    )
    story.append(Paragraph("Correlated records — suggestions only", styles["Heading2"]))
    for match in analysis["matches"]:
        pair = (
            f"{match['first']['id']} / evidence {match['first']['evidence_id']} "
            f"<-> {match['second']['id']} / evidence {match['second']['evidence_id']}"
        )
        story.append(
            Paragraph(
                escape(pair + " — " + ", ".join(match["matched"]) + ". " + match["relation"]),
                styles["BodyText"],
            )
        )
    if analysis["events_truncated"]:
        story.append(
            Paragraph(
                "Analysis used only the first 5,000 chronologically ordered case records.",
                styles["BodyText"],
            )
        )
    if analysis["matches_truncated"]:
        story.append(
            Paragraph(
                "Correlation output was limited by the pair-display or comparison cap; "
                "additional candidate pairs may not be shown.",
                styles["BodyText"],
            )
        )
    story.append(Paragraph("Chain-of-custody activity (ordinary mutable audit log)", styles["Heading2"]))
    for record in audit_rows:
        line = f"{record['occurred_at']} | {record['action']} | {record['evidence_id'] or '—'} | {record['details']}"
        story.append(Paragraph(escape(line), styles["BodyText"]))
    for note in notes:
        story.append(Paragraph(note["body"].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"), styles["BodyText"]))
    story.append(Spacer(1, 12))
    story.append(
        Paragraph(
            "Limitations: educational local prototype; not tamper-proof and not validated "
            "for actual evidence handling. Suggestions are unverified. Missing records are "
            "unknown, not proof of absence. Matching records do not establish causation.",
            styles["BodyText"],
        )
    )
    story.append(Paragraph("Human-reviewed conclusion", styles["Heading2"]))
    story.append(
        Paragraph(
            "No automated conclusion is made. An investigator must independently review "
            "source evidence, validate findings, consider alternatives, and record a reasoned conclusion.",
            styles["BodyText"],
        )
    )
    document.build(story)
    buffer.seek(0)
    response = make_response(send_file(buffer, mimetype="application/pdf", as_attachment=True, download_name=f"FORENSIX-{case_id}-report.pdf"))
    with db:
        audit("report_generated", case_id, details="PDF report generated")
    return response


@app.route("/cases/demo", methods=["POST"])
def load_demo():
    db = get_db()
    case = db.execute(
        "SELECT c.id FROM cases c JOIN case_access a ON a.case_id = c.id "
        "WHERE c.title = ? AND a.user_id = ?",
        ("Synthetic incident demonstration", g.user["id"]),
    ).fetchone()
    if case:
        flash("Synthetic demonstration case is already loaded.", "success")
        return redirect(url_for("case_detail", case_id=case["id"]))
    case_id = "FX-" + uuid.uuid4().hex[:8].upper()
    now = utc_now()
    records = [
        {"timestamp": "2026-10-25T09:10:00+00:00", "event_type": "login_failed", "account": "demo.user", "host": "TEST-DEVICE-01", "details": "Synthetic failed sign-in attempt"},
        {"timestamp": "2026-10-25T09:12:00+00:00", "event_type": "login_failed", "account": "demo.user", "host": "TEST-DEVICE-01", "details": "Synthetic failed sign-in attempt"},
        {"timestamp": "2026-10-25T09:18:00+00:00", "event_type": "login_success", "account": "demo.user", "host": "TEST-DEVICE-01", "details": "Synthetic successful sign-in; fictional account"},
        {"timestamp": "2026-10-25T09:22:30+00:00", "event_type": "process_start", "account": "demo.user", "host": "TEST-DEVICE-01", "details": "Synthetic process demo-app.exe started"},
        {"timestamp": "2026-10-25T09:31:00+00:00", "event_type": "file_activity", "account": "demo.user", "host": "TEST-DEVICE-01", "details": "Synthetic read of sample.txt"},
        {"timestamp": "2026-10-25T09:35:00+00:00", "event_type": "network_connection", "account": "demo.user", "host": "TEST-DEVICE-01", "details": "Simulated connection to 192.0.2.25 (reserved example address)"},
    ]
    content = json.dumps({"events": records}, indent=2).encode("utf-8")
    with db:
        db.execute(
            "INSERT INTO cases (id, title, description, status, created_at, updated_at) "
            "VALUES (?, ?, ?, 'Investigating', ?, ?)",
            (case_id, "Synthetic incident demonstration", "Synthetic educational data only; fictional user and test device. No real personal information.", now, now),
        )
        db.execute(
            "INSERT INTO case_access (case_id, user_id, granted_at) VALUES (?, ?, ?)",
            (case_id, g.user["id"], now),
        )
        audit("case_created", case_id, details="Synthetic demonstration case created")
    import_evidence(case_id, "synthetic_demo_events.json", content)
    return redirect(url_for("case_detail", case_id=case_id))


@app.errorhandler(CSRFError)
def handle_csrf_error(_error):
    flash("The form security token expired or was invalid. Please try again.", "error")
    return redirect(request.referrer or url_for("dashboard"))


@app.errorhandler(413)
def upload_too_large(_error):
    flash("Upload exceeds the 5 MB limit.", "error")
    return redirect(request.referrer or url_for("evidence_page"))


init_db()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
