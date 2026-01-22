
import os
import tempfile
import unittest
from urllib.parse import urlparse

class LearningStatDemoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Use a temp DB for tests
        cls.tmpdir = tempfile.TemporaryDirectory()
        cls.db_path = os.path.join(cls.tmpdir.name, "test.sqlite3")
        os.environ["LEARNINGSTAT_DB_PATH"] = cls.db_path
        os.environ["LEARNINGSTAT_SECRET_KEY"] = "test-secret"

        # Import app after env vars set
        import app as learning_app
        cls.app = learning_app.app
        cls.client = cls.app.test_client()

    @classmethod
    def tearDownClass(cls):
        cls.tmpdir.cleanup()

    def login(self, email, password):
        return self.client.post("/login", data={"email": email, "password": password}, follow_redirects=True)

    def test_end_to_end_workflow(self):
        # 1) Learner: login
        resp = self.login("learner_sales_01@abc.com", "Demo123!")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Learner Dashboard", resp.data)

        # Visit catalog, open first enrollment
        resp = self.client.get("/learner/catalog")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"My Learning", resp.data)

        # Find an enrollment_id by parsing a link (very lightweight)
        html = resp.data.decode("utf-8")
        import re
        m = re.search(r"/learner/course/(\d+)", html)
        self.assertIsNotNone(m)
        enrollment_id = int(m.group(1))

        # Open course
        resp = self.client.get(f"/learner/course/{enrollment_id}")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Actions", resp.data)

        # Mark complete
        resp = self.client.post(f"/learner/course/{enrollment_id}/complete", follow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Course marked complete", resp.data)

        # Take a POST assessment (if available); we can just find assessment link and submit
        resp = self.client.get(f"/learner/course/{enrollment_id}")
        html = resp.data.decode("utf-8")
        m2 = re.search(r"/learner/assessment/(\d+)/POST", html)
        if m2:
            assessment_id = int(m2.group(1))
            # load assessment page
            resp = self.client.get(f"/learner/assessment/{assessment_id}/POST")
            self.assertEqual(resp.status_code, 200)
            # submit all answers as option 0
            post_data = {"q0": "0", "q1": "0", "q2": "0"}
            resp = self.client.post(f"/learner/assessment/{assessment_id}/POST", data=post_data, follow_redirects=True)
            self.assertEqual(resp.status_code, 200)
            self.assertIn(b"Assessment submitted", resp.data)

        # Submit a reaction survey if available
        resp = self.client.get(f"/learner/course/{enrollment_id}")
        html = resp.data.decode("utf-8")
        m3 = re.search(r"/learner/survey/(\d+)", html)
        if m3:
            survey_id = int(m3.group(1))
            resp = self.client.get(f"/learner/survey/{survey_id}")
            self.assertEqual(resp.status_code, 200)
            # naive payload: try common keys used in seed data
            payload = {
                "relevance": "5",
                "quality": "4",
                "comment": "Applying immediately",
            }
            resp = self.client.post(f"/learner/survey/{survey_id}", data=payload, follow_redirects=True)
            self.assertEqual(resp.status_code, 200)
            self.assertIn(b"Thanks for your feedback", resp.data)

        # 2) Manager
        self.client.get("/logout", follow_redirects=True)
        resp = self.login("manager_sales@abc.com", "Demo123!")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Manager Dashboard", resp.data)

        # Observations page
        resp = self.client.get("/manager/observations")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Behaviour Observations", resp.data)

        # If there's a pending observation, submit one
        html = resp.data.decode("utf-8")
        mprog = re.search(r'name="program_id" value="(\d+)"', html)
        mlearner = re.search(r'name="learner_id" value="(\d+)"', html)
        if mprog and mlearner:
            program_id = int(mprog.group(1))
            learner_id = int(mlearner.group(1))
            resp = self.client.post(
                "/manager/observations",
                data={"program_id": str(program_id), "learner_id": str(learner_id), "rating": "4", "notes": "Observed improved behaviour"},
                follow_redirects=True,
            )
            self.assertEqual(resp.status_code, 200)
            self.assertIn(b"Observation submitted", resp.data)

        # 3) Finance approves a cost line
        self.client.get("/logout", follow_redirects=True)
        resp = self.login("finance@abc.com", "Demo123!")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Finance Dashboard", resp.data)

        # Open one ROI workspace and approve a cost line
        # Go to LD dashboard via direct route to get a program id (finance can open ROI workspace by known program ids)
        # We'll assume program 1 exists and open ROI workspace for /ld/program/1/roi
        resp = self.client.get("/ld/program/1/roi", follow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"ROI Workspace", resp.data)

        html = resp.data.decode("utf-8")
        mc = re.search(r'name="cost_id" value="(\d+)"', html)
        if mc:
            cost_id = int(mc.group(1))
            resp = self.client.post("/ld/program/1/roi", data={"action": "approve_cost", "cost_id": str(cost_id)}, follow_redirects=True)
            self.assertEqual(resp.status_code, 200)
            self.assertIn(b"Cost line approved", resp.data)

        # 4) Executive can view dashboard and ROI chart endpoint
        self.client.get("/logout", follow_redirects=True)
        resp = self.login("exec@abc.com", "Demo123!")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Executive Dashboard", resp.data)

        resp = self.client.get("/api/exec/roi")
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.is_json)

if __name__ == "__main__":
    unittest.main(verbosity=2)
