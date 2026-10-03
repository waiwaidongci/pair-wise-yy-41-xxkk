import tempfile, unittest
from pathlib import Path
from src.domain import ConflictError, PermissionDenied, ValidationError
from src.repository import Repository
from src.service import Service


class NoticeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Repository(str(Path(self.tmp.name) / "test.db"))
        self.service = Service(self.repo)
        self.item = self.service.create_item(
            {"title": "notice item", "description": "notice binding", "severity": "warning",
             "quantity": 5, "threshold": 10, "external_ref": "N-1", "bridge_ref": "BR-N"},
            "creator", "sensor_operator")
        self.notice = self.service.create_notice(
            {"bridge_ref": "BR-N", "title": "限行通告", "detail": "限行措施",
             "notice_no": "NN-1"}, "officer", "traffic_authority")

    def tearDown(self):
        self.repo.close(); self.tmp.cleanup()

    def to_warning(self):
        return self.service.transition(self.item["id"], "warning", 1, "op",
                                       "sensor_operator")

    def test_restricted_requires_valid_notice_of_same_bridge(self):
        current = self.to_warning()
        with self.assertRaises(ValidationError):
            self.service.transition(current["id"], "restricted", current["version"],
                                    "eng", "bridge_engineer")
        other = self.service.create_notice(
            {"bridge_ref": "BR-OTHER", "title": "他桥通告", "detail": "他桥"},
            "officer", "traffic_authority")
        with self.assertRaises(ConflictError):
            self.service.transition(current["id"], "restricted", current["version"],
                                    "eng", "bridge_engineer", notice_id=other["id"])
        self.service.withdraw_notice(self.notice["id"], "officer", "traffic_authority")
        with self.assertRaises(ConflictError):
            self.service.transition(current["id"], "restricted", current["version"],
                                    "eng", "bridge_engineer",
                                    notice_id=self.notice["id"])
        self.assertEqual(self.service.get_item(self.item["id"], "viewer")["status"],
                         "warning")

    def test_notice_roles(self):
        with self.assertRaises(PermissionDenied):
            self.service.create_notice({"bridge_ref": "BR-N", "title": "x", "detail": "y"},
                                       "op", "sensor_operator")
        with self.assertRaises(PermissionDenied):
            self.service.withdraw_notice(self.notice["id"], "op", "viewer")

    def test_withdraw_reverts_restricted_item_and_keeps_audit(self):
        current = self.to_warning()
        current = self.service.transition(current["id"], "restricted",
                                          current["version"], "eng", "bridge_engineer",
                                          notice_id=self.notice["id"])
        outcome = self.service.withdraw_notice(self.notice["id"], "officer",
                                               "traffic_authority")
        self.assertEqual(outcome["reverted_items"], [self.item["id"]])
        reverted = self.service.get_item(self.item["id"], "viewer")
        self.assertEqual(reverted["status"], "warning")
        with self.assertRaises(ConflictError):
            self.service.withdraw_notice(self.notice["id"], "officer", "traffic_authority")
        actions = [e["action"] for e in self.service.audit("viewer", self.item["id"])]
        self.assertIn("recompute", actions)
        notice_events = [e for e in self.repo.list_audit()
                         if e["entity_type"] == "交通通告"]
        self.assertEqual([e["action"] for e in notice_events],
                         ["notice_create", "notice_withdraw"])
        replacement = self.service.create_notice(
            {"bridge_ref": "BR-N", "title": "新通告", "detail": "重新限行"},
            "officer", "traffic_authority")
        current = self.service.transition(reverted["id"], "restricted",
                                          reverted["version"], "eng", "bridge_engineer",
                                          notice_id=replacement["id"])
        self.assertEqual(current["status"], "restricted")
        self.assertTrue(self.repo.verify_audit_chain())

    def test_open_record_change_after_restricted_triggers_recompute(self):
        current = self.to_warning()
        current = self.service.transition(current["id"], "restricted",
                                          current["version"], "eng", "bridge_engineer",
                                          notice_id=self.notice["id"])
        self.service.add_record(self.item["id"],
                                {"kind": "inspection", "detail": "new defect",
                                 "status": "open", "external_ref": "OP-1"},
                                "recorder", "bridge_engineer")
        self.assertEqual(self.service.get_item(self.item["id"], "viewer")["status"],
                         "warning")
        reasons = [e["detail"].get("reason") for e in
                   self.service.audit("viewer", self.item["id"])
                   if e["action"] == "recompute"]
        self.assertEqual(reasons, ["open_records_changed"])
        self.assertTrue(self.repo.verify_audit_chain())


if __name__ == "__main__":
    unittest.main()
