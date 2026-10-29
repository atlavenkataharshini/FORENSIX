import hashlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import app as forensix
from werkzeug.security import check_password_hash


class ForensixTestCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db_path = self.root / "test.sqlite3"
        self.evidence_dir = self.root / "evidence"
        self.evidence_dir.mkdir()
        self.database_patch = patch.object(forensix, "DATABASE", self.db_path)
        self.evidence_patch = patch.object(forensix, "EVIDENCE_DIR", self.evidence_dir)
        self.database_patch.start()
        self.evidence_patch.start()
        forensix.init_db()
        forensix.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
        self.client = forensix.app.test_client()
        with forensix.app.app_context():
            self.investigator_id = forensix.create_user(
                "test-investigator",
                "investigator@example.test",
                "InvestigatorTest!2026",
                "investigator",
            )
        with self.client.session_transaction() as session:
            session["user_id"] = self.investigator_id

    def tearDown(self):
        self.evidence_patch.stop()
        self.database_patch.stop()
        self.temp.cleanup()

    def create_case(self):
        response = self.client.post(
            "/cases",
            data={"title": "Test investigation", "description": "Synthetic test"},
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        with forensix.app.app_context():
            return forensix.get_db().execute("SELECT id FROM cases").fetchone()["id"]

    def test_create_case_and_load_synthetic_demo(self):
        case_id = self.create_case()
        self.assertIn(case_id.encode(), self.client.get(f"/cases/{case_id}").data)
        response = self.client.post("/cases/demo", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        with forensix.app.app_context():
            count = forensix.get_db().execute("SELECT COUNT(*) FROM timeline_events").fetchone()[0]
        self.assertEqual(count, 6)

    def test_import_hash_verify_and_timeline_order(self):
        case_id = self.create_case()
        payload = {
            "events": [
                {"timestamp": "2026-01-02T10:00:00+00:00", "event_type": "file_activity", "account": "tester", "host": "LAB-01", "details": "later"},
                {"timestamp": "2026-01-02T09:00:00+00:00", "event_type": "login_success", "account": "tester", "host": "LAB-01", "details": "earlier"},
            ]
        }
        content = json.dumps(payload).encode()
        response = self.client.post(
            "/evidence",
            data={"case_id": case_id, "file": (io.BytesIO(content), "events.json")},
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        with forensix.app.app_context():
            evidence = forensix.get_db().execute("SELECT * FROM evidence").fetchone()
            self.assertEqual(evidence["sha256"], hashlib.sha256(content).hexdigest())
            evidence_id = evidence["id"]
        response = self.client.post(f"/evidence/{evidence_id}/verify", follow_redirects=True)
        self.assertIn(b"Integrity verified", response.data)
        timeline = self.client.get(f"/timeline?case_id={case_id}")
        self.assertLess(timeline.data.index(b"09:00:00"), timeline.data.index(b"10:00:00"))

    def test_cross_evidence_correlation_and_timeline_gap_review(self):
        case_id = self.create_case()
        source_a = json.dumps(
            {
                "events": [
                    {
                        "timestamp": "2026-01-02T09:00:00+00:00",
                        "event_type": "login_failed",
                        "account": "demo-account",
                        "source_ip": "192.0.2.25",
                        "host": "LAB-A",
                    },
                    {
                        "timestamp": "2026-01-02T09:10:00+00:00",
                        "event_type": "file_activity",
                        "account": "demo-account",
                        "host": "LAB-A",
                    },
                ]
            }
        ).encode()
        source_b = json.dumps(
            {
                "events": [
                    {
                        "timestamp": "2026-01-02T09:20:00+00:00",
                        "event_type": "login_success",
                        "account": "demo-account",
                        "source_ip": "192.0.2.25",
                        "host": "LAB-B",
                    },
                    {
                        "timestamp": "2026-01-02T12:30:00+00:00",
                        "event_type": "process_start",
                        "account": "other-account",
                        "host": "LAB-C",
                    },
                ]
            }
        ).encode()
        for filename, content in (
            ("auth-export.json", source_a),
            ("endpoint-export.json", source_b),
        ):
            response = self.client.post(
                "/evidence",
                data={"case_id": case_id, "file": (io.BytesIO(content), filename)},
                content_type="multipart/form-data",
                follow_redirects=True,
            )
            self.assertEqual(response.status_code, 200)

        correlation_page = self.client.get(f"/cases/{case_id}/correlation")
        self.assertIn(b"same account across evidence records", correlation_page.data)
        self.assertIn(b"same source_ip across evidence records", correlation_page.data)
        self.assertIn(b"failed login followed by success within 30 minutes", correlation_page.data)
        self.assertIn(b"does not identify who initiated either event", correlation_page.data)
        self.assertIn(b"Timeline intervals", correlation_page.data)
        self.assertIn(b"190 minute interval", correlation_page.data)
        self.assertIn(b"does not prove that activity or records are missing", correlation_page.data)

        report = self.client.get(f"/cases/{case_id}/report")
        self.assertIn(b"Timeline intervals (60 minutes or more)", report.data)
        self.assertIn(b"190 minutes", report.data)

    def test_correlation_requires_distinct_evidence_sources_and_explicit_timezones(self):
        events = [
            {
                "id": "same-source-1",
                "evidence_id": "EV-SAME",
                "timestamp_sort": 1000.0,
                "timestamp_original": "1970-01-01T00:16:40+00:00",
                "event_type": "login_failed",
                "outcome": "failure",
                "account": "account",
                "host": "device",
                "source_ip": "192.0.2.3",
            },
            {
                "id": "same-source-2",
                "evidence_id": "EV-SAME",
                "timestamp_sort": 1100.0,
                "timestamp_original": "1970-01-01T00:18:20+00:00",
                "event_type": "login_success",
                "outcome": "success",
                "account": "account",
                "host": "device",
                "source_ip": "192.0.2.3",
            },
            {
                "id": "unknown-time",
                "evidence_id": "EV-OTHER",
                "timestamp_sort": None,
                "timestamp_original": "2026-01-02T09:00:00",
                "event_type": "login_success",
                "outcome": "success",
                "account": "",
                "host": "",
                "source_ip": "",
            },
            {
                "id": "known-time",
                "evidence_id": "EV-THIRD",
                "timestamp_sort": 1200.0,
                "timestamp_original": "1970-01-01T00:20:00+00:00",
                "event_type": "file_activity",
                "outcome": "",
                "account": "",
                "host": "",
                "source_ip": "",
            },
        ]
        matches, truncated = forensix.correlate_events(events)
        self.assertEqual(len(matches), 2)
        self.assertTrue(
            all(
                "timestamps within five minutes (UTC-normalized)" in match["matched"]
                for match in matches
            )
        )
        self.assertTrue(
            all(
                "unknown-time" not in {match["first"]["id"], match["second"]["id"]}
                for match in matches
            )
        )
        self.assertFalse(truncated)
        self.assertEqual(forensix.find_timeline_gaps(events), ([], False))

    def test_timeline_gap_display_limit_is_explicit(self):
        events = [
            {
                "id": f"event-{index}",
                "timestamp_sort": float(index * 7200),
            }
            for index in range(103)
        ]
        gaps, truncated = forensix.find_timeline_gaps(events)
        self.assertEqual(len(gaps), 100)
        self.assertTrue(truncated)

    def test_correlation_pair_limit_is_explicit(self):
        events = [
            {
                "id": f"event-{index}",
                "evidence_id": f"evidence-{index}",
                "timestamp_sort": None,
                "account": "shared-account",
                "host": "",
                "source_ip": "",
            }
            for index in range(25)
        ]
        matches, truncated = forensix.correlate_events(events)
        self.assertEqual(len(matches), forensix.MAX_CORRELATION_PAIRS)
        self.assertTrue(truncated)

    def test_malformed_upload_is_rejected_without_evidence_row(self):
        case_id = self.create_case()
        response = self.client.post(
            "/evidence",
            data={"case_id": case_id, "file": (io.BytesIO(b"{bad json"), "bad.json")},
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        self.assertIn(b"Malformed JSON", response.data)
        with forensix.app.app_context():
            count = forensix.get_db().execute("SELECT COUNT(*) FROM evidence").fetchone()[0]
        self.assertEqual(count, 0)

    def test_disallowed_upload_extension_is_rejected(self):
        case_id = self.create_case()
        response = self.client.post(
            "/evidence",
            data={"case_id": case_id, "file": (io.BytesIO(b"data"), "events.exe")},
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        self.assertIn(b"Only .csv and .json", response.data)
        with forensix.app.app_context():
            count = forensix.get_db().execute("SELECT COUNT(*) FROM evidence").fetchone()[0]
        self.assertEqual(count, 0)

    def test_csv_import_and_modified_file_fails_integrity_check(self):
        case_id = self.create_case()
        content = b"timestamp,event_type,account,host,details\n2026-01-02T09:00:00+00:00,login_success,analyst,LAB-02,synthetic\n"
        response = self.client.post(
            "/evidence",
            data={"case_id": case_id, "file": (io.BytesIO(content), "events.csv")},
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        with forensix.app.app_context():
            evidence = forensix.get_db().execute("SELECT * FROM evidence").fetchone()
            stored_path = self.evidence_dir / evidence["stored_filename"]
            evidence_id = evidence["id"]
        stored_path.write_bytes(b"modified")
        response = self.client.post(f"/evidence/{evidence_id}/verify", follow_redirects=True)
        self.assertIn(b"Integrity check failed", response.data)

    def test_state_changes_require_csrf_token(self):
        forensix.app.config["WTF_CSRF_ENABLED"] = True
        response = self.client.post("/cases", data={"title": "No token"})
        self.assertEqual(response.status_code, 302)
        with forensix.app.app_context():
            count = forensix.get_db().execute("SELECT COUNT(*) FROM cases").fetchone()[0]
        self.assertEqual(count, 0)
        forensix.app.config["WTF_CSRF_ENABLED"] = False

    def test_pdf_report_generation(self):
        response = self.client.post("/cases/demo", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        with forensix.app.app_context():
            case_id = forensix.get_db().execute("SELECT id FROM cases").fetchone()["id"]
        report = self.client.get(f"/cases/{case_id}/report.pdf")
        self.assertEqual(report.status_code, 200)
        self.assertEqual(report.mimetype, "application/pdf")
        self.assertTrue(report.data.startswith(b"%PDF"))

    def test_assistant_labels_missing_categories_as_unknown(self):
        case_id = self.create_case()
        response = self.client.post("/assistant", data={"case_id": case_id})
        self.assertIn(b"UNKNOWN:", response.data)
        self.assertIn(b"not a language model", response.data)
        self.assertIn(b"do not determine", response.data)

    def test_authentication_and_public_role_registration(self):
        anonymous = forensix.app.test_client()
        self.assertEqual(anonymous.get("/").status_code, 302)
        denied = anonymous.post(
            "/login", data={"identity": "missing", "password": "not-a-real-password"}
        )
        self.assertIn(b"username/email or password was not recognized", denied.data)
        signed_in = anonymous.post(
            "/login",
            data={
                "identity": "investigator@example.test",
                "password": "InvestigatorTest!2026",
            },
        )
        self.assertEqual(signed_in.status_code, 302)
        signed_out = anonymous.post("/logout", follow_redirects=True)
        self.assertEqual(signed_out.status_code, 200)
        self.assertIn(b"Sign in", signed_out.data)
        login_page = self.client.get("/login")
        self.assertIn(b"Show password", login_page.data)
        response = self.client.post(
            "/register",
            data={
                "username": "new-student",
                "email": "new-student@example.test",
                "password": "StudentAccount!2026",
                "role": "student",
            },
            follow_redirects=True,
        )
        self.assertIn(b"Account created", response.data)
        with forensix.app.app_context():
            registered = forensix.get_db().execute(
                "SELECT password_hash, role FROM users WHERE username = ?",
                ("new-student",),
            ).fetchone()
            self.assertEqual(registered["role"], "student")
            self.assertNotEqual(registered["password_hash"], "StudentAccount!2026")
        response = self.client.post(
            "/register",
            data={
                "username": "not-investigator",
                "email": "not-investigator@example.test",
                "password": "AnotherAccount!2026",
                "role": "investigator",
            },
            follow_redirects=True,
        )
        self.assertIn(b"only be Students or Personal Users", response.data)

    def test_student_cannot_access_investigator_routes(self):
        case_id = self.create_case()
        with forensix.app.app_context():
            student_id = forensix.create_user(
                "lab-student",
                "lab-student@example.test",
                "StudentAccount!2026",
                "student",
            )
        student = forensix.app.test_client()
        with student.session_transaction() as session:
            session["user_id"] = student_id
        self.assertEqual(student.get("/").status_code, 200)
        self.assertEqual(student.get("/student/lab").status_code, 200)
        self.assertEqual(student.get("/cases").status_code, 403)
        self.assertEqual(student.get(f"/cases/{case_id}").status_code, 403)
        self.assertEqual(student.get("/evidence").status_code, 403)
        self.assertEqual(student.get("/safety").status_code, 403)

    def test_student_sample_case_cards_open_synthetic_case_details(self):
        self.assertIn("student_case", forensix.app.view_functions)
        with forensix.app.test_request_context():
            self.assertEqual(
                forensix.url_for(
                    "student_case", slug="email-security-incident"
                ),
                "/student/cases/email-security-incident",
            )
        with forensix.app.app_context():
            student_id = forensix.create_user(
                "scenario-student",
                "scenario-student@example.test",
                "StudentAccount!2026",
                "student",
            )
        student = forensix.app.test_client()
        with student.session_transaction() as session:
            session["user_id"] = student_id

        dashboard = student.get("/")
        cases = forensix.STUDENT_SAMPLE_CASES
        for slug, scenario in cases.items():
            self.assertIn(f"/student/cases/{slug}".encode(), dashboard.data)
            response = student.get(f"/student/cases/{slug}")
            self.assertEqual(response.status_code, 200)
            self.assertIn(scenario["title"].encode(), response.data)
            self.assertIn(b"Fictional practice material only", response.data)
            self.assertIn(b"Available scenario evidence", response.data)
            self.assertIn(b"Scenario timeline", response.data)
            self.assertIn(b"Questions to investigate", response.data)
            self.assertIn(b"Guided investigation steps", response.data)
            self.assertIn(b"Back to Student Dashboard", response.data)
            for item in scenario["evidence"]:
                self.assertIn(item["reference"].encode(), response.data)

        self.assertEqual(student.get("/student/cases/not-a-scenario").status_code, 404)
        anonymous = forensix.app.test_client()
        self.assertEqual(anonymous.get("/student/cases/email-security-incident").status_code, 302)

        with forensix.app.app_context():
            user_id = forensix.create_user(
                "case-view-user",
                "case-view-user@example.test",
                "PersonalAccount!2026",
                "user",
            )
        personal_user = forensix.app.test_client()
        with personal_user.session_transaction() as session:
            session["user_id"] = user_id
        self.assertEqual(
            personal_user.get("/student/cases/email-security-incident").status_code,
            403,
        )

    def test_course_catalog_routes_filters_and_saves_private_lesson_progress(self):
        with forensix.app.app_context():
            student_id = forensix.create_user(
                "course-student",
                "course-student@example.test",
                "StudentAccount!2026",
                "student",
            )
            other_student_id = forensix.create_user(
                "other-course-student",
                "other-course-student@example.test",
                "StudentAccount!2026",
                "student",
            )
        student = forensix.app.test_client()
        with student.session_transaction() as session:
            session["user_id"] = student_id
        other_student = forensix.app.test_client()
        with other_student.session_transaction() as session:
            session["user_id"] = other_student_id

        dashboard = student.get("/")
        self.assertIn(b"Course catalog", dashboard.data)
        self.assertIn(b"/student/courses", dashboard.data)
        catalog = student.get("/student/courses")
        self.assertEqual(catalog.status_code, 200)
        self.assertGreaterEqual(len(forensix.STUDENT_COURSES), 20)
        self.assertIn(b"Cybersecurity Fundamentals", catalog.data)
        self.assertIn(b"Secure Evidence Handling and Chain of Custody", catalog.data)

        filtered = student.get("/student/courses?q=Email+Header&difficulty=Intermediate")
        self.assertIn(b"Email Header Analysis", filtered.data)
        self.assertNotIn(b"Cybersecurity Fundamentals", filtered.data)
        self.assertIn(b"No matching courses", student.get(
            "/student/courses?q=not-a-real-course"
        ).data)

        course_id = "email-header-analysis"
        detail = student.get(f"/student/courses/{course_id}")
        self.assertEqual(detail.status_code, 200)
        self.assertIn(b"Email Header Analysis", detail.data)
        self.assertIn(b"Learning material", student.get(
            f"/student/courses/{course_id}/lessons/0"
        ).data)
        self.assertEqual(
            student.get(f"/student/courses/{course_id}/lessons/99").status_code,
            404,
        )
        completed = student.post(
            f"/student/courses/{course_id}/lessons/0",
            follow_redirects=True,
        )
        self.assertIn(b"LESSON 2 OF 3", completed.data)
        self.assertIn(b"1 of 3 lessons", student.get("/student/courses").data)
        self.assertIn(b"0 of 3 lessons", other_student.get("/student/courses").data)
        self.assertEqual(other_student.get("/student/courses/not-a-course").status_code, 404)

        with forensix.app.app_context():
            rows = forensix.get_db().execute(
                "SELECT COUNT(*) FROM student_lesson_progress WHERE user_id = ?",
                (student_id,),
            ).fetchone()[0]
        self.assertEqual(rows, 1)

    def test_student_and_multilingual_safety_assistant_fallbacks(self):
        with forensix.app.app_context():
            student_id = forensix.create_user(
                "assistant-student",
                "assistant-student@example.test",
                "StudentAccount!2026",
                "student",
            )
            user_id = forensix.create_user(
                "assistant-user",
                "assistant-user@example.test",
                "PersonalAccount!2026",
                "user",
            )
        student = forensix.app.test_client()
        with student.session_transaction() as session:
            session["user_id"] = student_id
        self.assertIn(b"NO EXTERNAL AI", student.get("/student/assistant").data)
        answer = student.post(
            "/student/assistant",
            data={"question": "Can you explain Introduction to Digital Forensics?"},
        )
        self.assertIn(b"Course reference: Introduction to Digital Forensics", answer.data)
        self.assertIn(b"Evidence preservation", answer.data)
        self.assertEqual(student.get("/safety/assistant").status_code, 403)

        personal = forensix.app.test_client()
        with personal.session_transaction() as session:
            session["user_id"] = user_id
        self.assertIn(b"English", personal.get("/safety/assistant").data)
        answer = personal.post(
            "/safety/assistant",
            data={"language": "hi", "question": "मेरा खाता सुरक्षित है?"},
        )
        self.assertIn("आधिकारिक ऐप".encode("utf-8"), answer.data)
        self.assertIn(b"NO EXTERNAL AI", answer.data)
        self.assertIn("हाल के साइन-इन".encode("utf-8"), answer.data)
        self.assertNotIn("मेरा खाता सुरक्षित है?".encode("utf-8"), answer.data)
        self.assertIn(b'value="hi" selected', personal.get("/safety/assistant").data)
        self.assertEqual(personal.get("/student/assistant").status_code, 403)

    def test_investigators_cannot_open_another_investigators_case(self):
        case_id = self.create_case()
        with forensix.app.app_context():
            other_investigator_id = forensix.create_user(
                "other-investigator",
                "other-investigator@example.test",
                "OtherInvestigator!2026",
                "investigator",
            )
        other = forensix.app.test_client()
        with other.session_transaction() as session:
            session["user_id"] = other_investigator_id
        self.assertEqual(other.get("/cases").status_code, 200)
        self.assertNotIn(case_id.encode(), other.get("/cases").data)
        self.assertEqual(other.get(f"/cases/{case_id}").status_code, 404)

    def test_demo_seed_is_opt_in_hashed_and_grants_only_unassigned_cases(self):
        with forensix.app.app_context():
            db = forensix.get_db()
            with db:
                db.execute(
                    "INSERT INTO cases (id, title, description, status, created_at, updated_at) "
                    "VALUES ('LEGACY-1', 'Legacy case', '', 'Open', '2026-01-01', '2026-01-01')"
                )
        with patch.dict(os.environ, {"FORENSIX_DEMO_MODE": "1"}):
            forensix.init_db()
        with forensix.app.app_context():
            db = forensix.get_db()
            student = db.execute(
                "SELECT id, password_hash FROM users WHERE username = ?",
                ("student@forensix.local",),
            ).fetchone()
            investigator = db.execute(
                "SELECT id FROM users WHERE username = ?",
                ("investigator@forensix.local",),
            ).fetchone()
            self.assertNotEqual(student["password_hash"], "StudentDemo!2026")
            self.assertTrue(
                check_password_hash(student["password_hash"], "StudentDemo!2026")
            )
            assigned = db.execute(
                "SELECT 1 FROM case_access WHERE case_id = 'LEGACY-1' AND user_id = ?",
                (investigator["id"],),
            ).fetchone()
            self.assertIsNotNone(assigned)

    def test_personal_user_has_safety_guidance_not_investigator_cases(self):
        with forensix.app.app_context():
            user_id = forensix.create_user(
                "personal-user",
                "personal-user@example.test",
                "PersonalAccount!2026",
                "user",
            )
        client = forensix.app.test_client()
        with client.session_transaction() as session:
            session["user_id"] = user_id
        self.assertEqual(client.get("/").status_code, 200)
        self.assertIn(b"Manual check only", client.get("/").data)
        self.assertEqual(client.get("/cases").status_code, 403)
        response = client.post(
            "/safety",
            data={
                "category": "email",
                "failed_attempts": "3",
                "unrecognized_device": "yes",
            },
        )
        self.assertIn(b"3 failed attempts", response.data)
        self.assertIn(b"unfamiliar", response.data)

    def test_student_lab_detects_patterns_and_verifies_hash(self):
        payload = {
            "events": [
                {"timestamp": f"2026-01-02T09:0{minute}:00+00:00", "event_type": "login_failed", "source_ip": "192.0.2.10", "account": "student", "host": "LAB-01"}
                for minute in range(3)
            ] + [
                {"timestamp": "2026-01-02T12:00:00+00:00", "event_type": "file_activity", "source_ip": "192.0.2.10", "account": "student", "host": "LAB-01"}
            ]
        }
        content = json.dumps(payload).encode()
        digest = hashlib.sha256(content).hexdigest()
        student = forensix.app.test_client()
        with forensix.app.app_context():
            student_id = forensix.create_user(
                "analyzer",
                "analyzer@example.test",
                "StudentAccount!2026",
                "student",
            )
        with student.session_transaction() as session:
            session["user_id"] = student_id
        response = student.post(
            "/student/lab",
            data={
                "expected_hash": digest,
                "file": (io.BytesIO(content), "synthetic.json"),
            },
            content_type="multipart/form-data",
        )
        self.assertIn(b"3 failed-login record(s)", response.data)
        self.assertIn(digest.encode(), response.data)
        self.assertIn(b"does not prove authenticity", response.data)
        self.assertIn(b"192.0.2.10", response.data)
        self.assertIn(b"failure", response.data)
        self.assertIn(b"interval between available records", response.data)
        filtered = student.post(
            "/student/lab",
            data={
                "expected_hash": digest,
                "event_type_filter": "file",
                "file": (io.BytesIO(content), "synthetic.json"),
            },
            content_type="multipart/form-data",
        )
        self.assertNotIn(b"login_failed", filtered.data)


if __name__ == "__main__":
    unittest.main()
