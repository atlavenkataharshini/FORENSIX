# FORENSIX — Evidence. Intelligence. Investigation.

FORENSIX is an educational digital-forensics and personal cybersecurity prototype. It has separate Student, Personal User, and authorized Investigator workspaces. Use synthetic data or data you are permitted to analyze; this is not a certified forensic platform or an operational police evidence system.

## Features

- Salted password hashing, CSRF-protected sign-in/registration/logout, and server-side role checks.
- Public workspace landing page with separate Student, Personal User, and controlled Professional sign-in paths; registration requires a full name and matching password confirmation.
- Editable role-specific profiles, explicit unverified professional status, and a per-account/IP sign-in throttle.
- One-time, 30-minute password-reset links with hashed tokens and optional SMTP delivery configured only through server environment variables.
- Public registration is available for Student, Personal User, and Professional applicants. Professional accounts remain pending with no case/evidence access until trusted local administration verifies identity and affiliation.
- Per-investigator case access with owner, collaborator, and read-only permissions. Case owners can grant access only to professionals marked verified by trusted local administration; profile pages otherwise show the unverified status.
- A searchable Student course catalog with 29 lesson-based courses across beginner, intermediate, and advanced topics; course cards open course-specific material, lesson navigation works, and lesson progress is saved per student.
- A Student Learning Assistant and multilingual Personal Cyber Safety Assistant with explicitly labelled local rule-based fallback guidance in English, Hindi, and Telugu; neither claims live AI or account access.
- Optional server-side OpenAI assistance for all three assistants. Requests are opt-in, investigator requests include at most 40 parsed event rows, and missing configuration/API failures return clearly labelled local guidance.
- Per-account assistant conversation history (last 20 messages per workspace) with clear-history controls; investigator history is restricted to cases the user can still access.
- Four clickable Student practice cases (email security, suspicious login, phishing, and network activity) with dedicated synthetic evidence, timelines, questions, and guided steps; plus an in-memory CSV/JSON log analyzer, event filters, SHA-256 comparison, and cautious pattern explanations.
- Personal account-safety checklists, manual breach-awareness workflow, reported-login helper, and payment safety guidance. No private account/payment access.
- Investigator dashboard with case search/status management, CSV/JSON evidence import, private generated filenames, file-size limits, and SHA-256 integrity verification.
- Authorized case members can download original evidence through a private, permission-checked route; download events are written to the ordinary local audit log.
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

## Optional OpenAI assistance

The assistants remain local and rule-based unless a user explicitly opts to send a question to OpenAI. To enable the optional integration, set `OPENAI_API_KEY` in the server environment (never in browser code or a committed file). `OPENAI_MODEL` defaults to `gpt-4o-mini`. The API key is sent only to OpenAI's server-side API client. Student/personal prompts are sent only after the user checks the consent box; investigator opt-in sends the case title and up to 40 parsed event rows, not original evidence files. Do not send sensitive or unauthorized records. OpenAI usage may incur charges and answers require human review. Without a configured key or if the service fails, the UI clearly identifies the local rule-based response instead of claiming AI analysis.

## Optional password-reset email

Self-service recovery needs an SMTP service. Configure `SMTP_HOST`, `SMTP_PORT`, `SMTP_FROM`, and optionally `SMTP_USERNAME`/`SMTP_PASSWORD` in the server environment. Port 465 uses SMTP-over-SSL; other ports require STARTTLS. Set `FORENSIX_PUBLIC_URL` to the canonical app origin used in email links. Without SMTP configuration, the recovery page clearly directs users to a trusted local administrator; it does not display reset tokens in the browser or logs. Never commit SMTP credentials.

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

This command prompts for a username, email, and password to create an administrator-managed Investigator account. Public Professional applications remain pending until an administrator completes a separate, offline identity/affiliation review:

```powershell
.\.venv\Scripts\flask.exe --app app verify-investigator
```

The command requires an explicit confirmation; FORENSIX itself does not verify identities or affiliations.

## Run locally

```powershell
$env:FORENSIX_DEMO_MODE = "1"
$env:FLASK_SECRET_KEY = .\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_hex(32))"
.\.venv\Scripts\python.exe app.py
```

Open [http://127.0.0.1:5000](http://127.0.0.1:5000) for the public FORENSIX landing page. The landing page links to separate Student, Personal User, and Professional sign-in pages. Use [http://127.0.0.1:5000/signup](http://127.0.0.1:5000/signup) to create a Student or Personal User account or submit a Professional application; Professional accounts stay pending until trusted local administration verifies them. Existing SQLite data is retained; schema changes are applied with non-destructive migrations. The database and private evidence files stay under `instance\`.

If you do not want demo accounts, omit `FORENSIX_DEMO_MODE`. Public users can register as Student or Personal User or apply as a Professional. To keep sessions valid across restarts, set a persistent random session secret:

```powershell
$env:FLASK_SECRET_KEY = .\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_hex(32))"
.\.venv\Scripts\python.exe app.py
```

Without `FLASK_SECRET_KEY`, the app uses a random key for local development and existing sessions expire after restart. For HTTPS deployments, set `FLASK_SESSION_COOKIE_SECURE=1`.

The current application is configured for a local SQLite database and private local evidence directory under `instance\`. This is suitable only for local development/demonstration. Do not deploy this storage configuration to Vercel or another ephemeral/read-only filesystem. Production deployment is not ready until a persistent database and private object-storage adapter are selected and integrated; no production storage provider has been configured.

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
│   ├── landing.html
│   ├── base.html
│   ├── index.html
│   ├── login.html
│   ├── forgot_password.html
│   ├── reset_password.html
│   ├── register.html
│   ├── professional_pending.html
│   ├── profile.html
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
│   ├── report.html
│   └── profile.html
├── tests/test_app.py
└── instance/                 # generated locally; ignored by Git
    ├── forensix.sqlite3
    └── evidence/
```

## Test

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Tests cover role-specific sign-in and registration, salted password storage, login throttling, one-time password reset tokens, profile updates, role restrictions, opt-in AI request behavior and local fallbacks, private/clearable conversation history, verified case collaboration and read-only access, evidence download auditing, all four Student practice-case routes, course navigation/search/filtering and private lesson progress, multilingual assistant fallbacks, case/evidence workflows, synthetic demo loading, file validation, SHA-256 verification, timeline ordering, cross-evidence correlation, timezone-aware gap analysis, personal safety guidance, student log analysis, PDF export, CSRF, and assistant guardrails.

## Security limitations

- Authentication uses Werkzeug's salted password hashes and Flask's signed session cookie. Session cookies are HTTP-only and SameSite=Lax; set `FLASK_SESSION_COOKIE_SECURE=1` when running behind HTTPS.
- Investigator records are separated by explicit case-access assignments. Student and Personal User accounts cannot use investigator case/evidence routes. This is prototype-level authorization and requires independent review before deployment.
- Do not upload sensitive, personal, or real investigative evidence. Use synthetic data only.
- Student lab uploads and personal-user activity-check form values are processed for the request and are not saved. Assistant conversation history is saved per account in SQLite until that user clears it. Investigator evidence uploads are retained privately under `instance\evidence\`.
- Demo account passwords are public and predictable by design. Never enable `FORENSIX_DEMO_MODE` on a public or production service; change/remove demo users before any shared use.
- If `FLASK_SECRET_KEY` is unset, a new random local-development key is generated on each run. Configure a secret outside Git for any persistent deployment.
- Uploads are limited to 5 MB and 10,000 records, accept UTF-8 CSV/JSON only, are stored outside public static paths, and use generated filenames.
- The database audit history is an ordinary mutable SQLite table, not a tamper-proof chain of custody. Local file access can alter the database and evidence.
- Correlation is a deterministic record-matching aid, limited to 5,000 events, 200 displayed pairs, and 100,000 pair comparisons. Timeline-gap review uses a fixed 60-minute threshold, displays up to 100 intervals, and ignores timestamps without explicit timezone offsets. Results can be incomplete because of record limits or gaps in collection.
- This prototype does not acquire or analyze forensic images, devices, or arbitrary file formats; it does not validate provenance, signatures, or legal admissibility. The student log analyzer uses simple heuristics and UTC-hour assumptions, not statistical baselines.
- OpenAI receives a user question or parsed case records only when a user explicitly opts in and `OPENAI_API_KEY` is configured; original evidence files are never sent. Otherwise assistants use deterministic local rule-based guidance. AI responses and local suggestions are unverified; no assistant has live account integrations.
- Independent security, privacy, and forensic validation is required before any operational use. The project makes no claim of suitability for real police evidence handling.
- This iteration does not include timed student exams/results/certificates, an administrator course/question editor with scheduled versioning, or student-professional mentoring.
- Evidence-at-rest encryption, permanent production object storage, owner-controlled evidence deletion, and tamper-proof custody records are not implemented. Evidence files are local plaintext files; original evidence is retained unless an administrator removes it outside the application.
- The only evidence access audit currently recorded is an authorized original-file download. Metadata views and every other page read are not individually audited.

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
