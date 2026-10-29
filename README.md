# FORENSIX — Evidence. Intelligence. Investigation.

FORENSIX is an educational digital-forensics and personal cybersecurity prototype. It has separate Student, Personal User, and authorized Investigator workspaces. Use synthetic data or data you are permitted to analyze; this is not a certified forensic platform or an operational police evidence system.

## Features

- Salted password hashing, CSRF-protected sign-in/registration/logout, and server-side role checks.
- Public registration is limited to Student and Personal User accounts. Investigator accounts require trusted local administration.
- Per-investigator case access; case, evidence, timeline, report, and assistant routes are not available to the other roles.
- A searchable Student course catalog with 29 lesson-based courses across beginner, intermediate, and advanced topics; course cards open course-specific material, lesson navigation works, and lesson progress is saved per student.
- A Student Learning Assistant and multilingual Personal Cyber Safety Assistant with explicitly labelled local rule-based fallback guidance in English, Hindi, and Telugu; neither claims live AI or account access.
- Four clickable Student practice cases (email security, suspicious login, phishing, and network activity) with dedicated synthetic evidence, timelines, questions, and guided steps; plus an in-memory CSV/JSON log analyzer, event filters, SHA-256 comparison, and cautious pattern explanations.
- Personal account-safety checklists, manual breach-awareness workflow, reported-login helper, and payment safety guidance. No private account/payment access.
- Investigator dashboard with case search/status management, CSV/JSON evidence import, private generated filenames, file-size limits, and SHA-256 integrity verification.
- Original uploaded files are retained separately from extracted timeline rows.
- Timeline filters for case, event type, host, account, and date; explicit timezone offsets are normalized for ordering, while original timestamps are preserved.
- Deterministic investigation assistant with evidence references, unknown-category notices, cautious hypotheses, and human-review warnings.
- Cross-evidence correlation for exact account, host, or source-IP matches; failed-login-to-success sequences with matching account/IP within 30 minutes; and timezone-explicit timestamps within five minutes.
- Timeline-gap review that flags adjacent explicit-timezone events separated by at least 60 minutes and links each interval to its source events/evidence. Gaps describe the available records only and do not imply missing activity.
- Investigator notes, an ordinary SQLite audit history, HTML report, and PDF report.
- Clearly labelled synthetic demonstration data and responsive dark dashboard.
- CSRF protection on state-changing forms, HTTP-only/SameSite session cookies, and non-debug local startup.

## Requirements and installation (Windows PowerShell)

Python 3.10 or later is recommended. From the project folder:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If PowerShell prevents environment activation, either use `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` for the current terminal or invoke the environment directly:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

## Local demo accounts

Demo accounts are created only when demo mode is explicitly enabled. Set the flag before initializing/running the app:

```powershell
$env:FORENSIX_DEMO_MODE = "1"
```

The demo passwords are intentionally public and must only be used for a local demonstration:

| Role | Username/email | Password |
|---|---|---|
| Student | `student@forensix.local` | `StudentDemo!2026` |
| Personal User | `user@forensix.local` | `UserDemo!2026` |
| Investigator | `investigator@forensix.local` | `InvestigatorDemo!2026` |

Passwords are stored as salted hashes. These seeded accounts are not production credentials. Existing cases without an access assignment are granted to the seeded demo Investigator when demo mode is enabled. Demo users are created only once; enabling the flag again does not reset their passwords.

To create a non-demo investigator account from a trusted local administration terminal:

```powershell
.\.venv\Scripts\flask.exe --app app create-investigator
```

This command prompts for a username, email, and password and grants that account access only to legacy cases that do not yet have an investigator assignment. Public registration cannot select the Investigator role.

## Run locally

```powershell
$env:FORENSIX_DEMO_MODE = "1"
$env:FLASK_SECRET_KEY = .\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_hex(32))"
.\.venv\Scripts\python.exe app.py
```

Open [http://127.0.0.1:5000](http://127.0.0.1:5000). Existing SQLite data is retained; new user/access tables and event fields are added with non-destructive schema migrations. The database and private evidence files stay under `instance\`.

If you do not want demo accounts, omit `FORENSIX_DEMO_MODE`. Public users can register as Student or Personal User. To keep sessions valid across restarts, set a persistent random session secret:

```powershell
$env:FLASK_SECRET_KEY = .\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_hex(32))"
.\.venv\Scripts\python.exe app.py
```

Without `FLASK_SECRET_KEY`, the app uses a random key for local development and existing sessions expire after restart. For HTTPS deployments, set `FLASK_SESSION_COOKIE_SECURE=1`.

## Synthetic sample data

Use **Load synthetic demo** on the dashboard. The demo creates fictional login-failure, login-success, process, file, and simulated network events using a test device, a fictional account, and the reserved example address `192.0.2.25`. The equivalent JSON is in `sample_data\synthetic_events.json`.

Student log analysis accepts authorized CSV/JSON event exports and processes them in memory. It does not retain the uploaded file. The Investigator workspace stores original evidence privately under `instance\evidence\`; never use real sensitive evidence with this prototype.

## Folder structure

```text
FORENSIX/
├── app.py
├── requirements.txt
├── README.md
├── .gitignore
├── .env.example
├── sample_data/
│   └── synthetic_events.json
├── static/
│   ├── css/style.css
│   └── js/main.js
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── login.html
│   ├── register.html
│   ├── student_dashboard.html
│   ├── student_courses.html
│   ├── student_course.html
│   ├── student_lesson.html
│   ├── student_assistant.html
│   ├── safety_assistant.html
│   ├── student_case.html
│   ├── student_lab.html
│   ├── personal_dashboard.html
│   ├── cases.html
│   ├── case_detail.html
│   ├── evidence.html
│   ├── timeline.html
│   ├── assistant.html
│   ├── correlation.html
│   └── report.html
├── tests/test_app.py
└── instance/                 # generated locally; ignored by Git
    ├── forensix.sqlite3
    └── evidence/
```

## Test

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Tests cover sign-in-related registration rules, salted password storage, role restrictions, all four Student practice-case routes, course navigation/search/filtering and private lesson progress, multilingual local assistant fallbacks, case/evidence workflows, synthetic demo loading, file validation, SHA-256 verification, timeline ordering, cross-evidence correlation, timezone-aware gap analysis, personal safety guidance, student log analysis, PDF export, CSRF, and assistant guardrails.

## Security limitations

- Authentication uses Werkzeug's salted password hashes and Flask's signed session cookie. Session cookies are HTTP-only and SameSite=Lax; set `FLASK_SESSION_COOKIE_SECURE=1` when running behind HTTPS.
- Investigator records are separated by explicit case-access assignments. Student and Personal User accounts cannot use investigator case/evidence routes. This is prototype-level authorization and requires independent review before deployment.
- Do not upload sensitive, personal, or real investigative evidence. Use synthetic data only.
- Student lab uploads and personal-user activity answers are processed for the request and are not saved. Investigator evidence uploads are retained privately under `instance\evidence\`.
- Demo account passwords are public and predictable by design. Never enable `FORENSIX_DEMO_MODE` on a public or production service; change/remove demo users before any shared use.
- If `FLASK_SECRET_KEY` is unset, a new random local-development key is generated on each run. Configure a secret outside Git for any persistent deployment.
- Uploads are limited to 5 MB and 10,000 records, accept UTF-8 CSV/JSON only, are stored outside public static paths, and use generated filenames.
- The database audit history is an ordinary mutable SQLite table, not a tamper-proof chain of custody. Local file access can alter the database and evidence.
- Correlation is a deterministic record-matching aid, limited to 5,000 events, 200 displayed pairs, and 100,000 pair comparisons. Timeline-gap review uses a fixed 60-minute threshold, displays up to 100 intervals, and ignores timestamps without explicit timezone offsets. Results can be incomplete because of record limits or gaps in collection.
- This prototype does not acquire or analyze forensic images, devices, or arbitrary file formats; it does not validate provenance, signatures, or legal admissibility. The student log analyzer uses simple heuristics and UTC-hour assumptions, not statistical baselines.
- No evidence is sent to an external AI provider. Investigator, student, and personal safety assistants use deterministic rule-based responses, not a language model or live account integrations; their suggestions are unverified.
- Independent security, privacy, and forensic validation is required before any operational use. The project makes no claim of suitability for real police evidence handling.

## GitHub setup

The `.gitignore` excludes local databases, evidence, virtual environments, secrets, caches, and logs. To initialize and push the source:

```powershell
git init
git add app.py requirements.txt README.md .gitignore .env.example sample_data static templates tests
git commit -m "Build FORENSIX educational forensics dashboard"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/YOUR-REPOSITORY.git
git push -u origin main
```

Create an empty repository on GitHub first and replace the remote URL. Review `git status` before pushing; never add `instance\`, uploaded evidence, `.env`, or secrets.

## Deployment preparation (not deployed)

**Do not deploy this student prototype for real investigations or sensitive personal data.** Authentication is a learning feature, not a substitute for a production security assessment. Before any network deployment, a qualified reviewer must validate authorization, HTTPS, secret management, private persistent storage, backups, logging, upload handling, and privacy protections:

1. Push the reviewed source to a private GitHub repository.
2. Create a private/internal Python web service and connect that repository. Do not enable public access or demo mode.
3. Use build command `pip install -r requirements.txt`.
4. Configure the service start command as `waitress-serve --host=0.0.0.0 --port=$PORT app:app`.
5. Set `FLASK_SECRET_KEY` to a generated secret in the host's secret manager; never put it in Git.
6. Configure a persistent, access-controlled disk for `instance/` and verify SQLite/evidence permissions and backups before any use.
7. Verify HTTPS, secure session cookies, access controls, upload limits, CSRF, private file storage, and logs in the actual deployment environment.

The service command above binds to the service network and must only be used after safeguards and an independent review. No deployment has been performed.

## Screenshots and future enhancements

Add screenshots here after launching the application. Possible future work includes MFA, investigator approval/assignment administration, append-only signed audit exports, richer reviewable relationship graphs, optional privacy-reviewed integrations, and production security validation.
