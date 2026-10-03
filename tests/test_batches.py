import tempfile, threading, unittest
from pathlib import Path
from unittest import mock
from src.domain import ConflictError, ValidationError
from src.repository import Repository
from src.service import Service


def batch_payload(gateway, batch_no, start, count, status="open", detail="reading"):
    return {"gateway_id": gateway, "batch_no": batch_no,
            "readings": [{"seq": start + i, "detail": f"{detail}-{start + i}",
                          "status": status} for i in range(count)]}


class BatchTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Repository(str(Path(self.tmp.name) / "test.db"))
        self.service = Service(self.repo)
        self.item = self.service.create_item(
            {"title": "batch item", "description": "batch chain", "severity": "warning",
             "quantity": 5, "threshold": 10, "external_ref": "B-1", "bridge_ref": "BR-B"},
            "creator", "sensor_operator")

    def tearDown(self):
        self.repo.close(); self.tmp.cleanup()

    def apply(self, payload):
        return self.service.apply_batch(self.item["id"], payload, "op", "sensor_operator")

    def test_same_batch_no_replay_reuses_first_result(self):
        payload = batch_payload("GW-1", 1, 1, 3)
        first = self.apply(payload)
        self.assertEqual(first["applied"], 3)
        self.assertEqual(first["next_seq"], 4)
        again = self.apply(payload)
        self.assertTrue(again["replayed"])
        self.assertEqual(again["applied"], 3)
        self.assertEqual(len(self.service.list_records(self.item["id"], "viewer")), 3)
        batch_events = [e for e in self.service.audit("viewer", self.item["id"])
                        if e["action"] == "batch"]
        self.assertEqual(len(batch_events), 1)
        self.assertTrue(self.repo.verify_audit_chain())

    def test_same_batch_no_different_content_rejected_with_positions(self):
        self.apply(batch_payload("GW-1", 1, 1, 3))
        bad = batch_payload("GW-1", 1, 1, 3)
        bad["readings"][1]["detail"] = "tampered"
        with self.assertRaises(ConflictError) as ctx:
            self.apply(bad)
        self.assertEqual([c["seq"] for c in ctx.exception.details["conflicts"]], [2])
        self.assertEqual(len(self.service.list_records(self.item["id"], "viewer")), 3)

    def test_overlap_conflict_rejects_whole_batch(self):
        self.apply(batch_payload("GW-1", 1, 1, 3))
        overlap = batch_payload("GW-1", 2, 3, 3)
        overlap["readings"][0]["detail"] = "different"
        with self.assertRaises(ConflictError) as ctx:
            self.apply(overlap)
        self.assertEqual([c["seq"] for c in ctx.exception.details["conflicts"]], [3])
        self.assertEqual(len(self.service.list_records(self.item["id"], "viewer")), 3)
        self.assertEqual(len(self.service.list_batches(self.item["id"], "viewer")), 1)

    def test_gap_cannot_skip_then_resume_with_same_batch_no(self):
        self.apply(batch_payload("GW-1", 1, 1, 2))
        skipped = batch_payload("GW-1", 2, 5, 2)
        with self.assertRaises(ConflictError) as ctx:
            self.apply(skipped)
        self.assertEqual(ctx.exception.details["missing_from"], 3)
        self.assertEqual(ctx.exception.details["missing_to"], 4)
        self.apply(batch_payload("GW-1", 3, 3, 2))
        resumed = self.apply(skipped)
        self.assertEqual(resumed["applied"], 2)
        self.assertEqual(resumed["next_seq"], 7)
        self.assertEqual(len(self.service.list_records(self.item["id"], "viewer")), 6)

    def test_write_failure_rolls_back_and_resumes_with_same_batch_no(self):
        payload = batch_payload("GW-1", 1, 1, 3)
        with mock.patch.object(self.repo, "_insert_audit",
                               side_effect=RuntimeError("db down")):
            with self.assertRaises(RuntimeError):
                self.apply(payload)
        self.assertEqual(self.service.list_records(self.item["id"], "viewer"), [])
        self.assertEqual(self.service.list_batches(self.item["id"], "viewer"), [])
        result = self.apply(payload)
        self.assertEqual(result["applied"], 3)
        self.assertEqual(len(self.service.list_records(self.item["id"], "viewer")), 3)
        self.assertTrue(self.repo.verify_audit_chain())

    def test_two_gateways_concurrent_backfill_recomputes_open_alerts(self):
        self.apply(batch_payload("GW-1", 1, 1, 2))
        barrier = threading.Barrier(2)
        results, errors = [], []

        def send(payload):
            try:
                barrier.wait(timeout=5)
                results.append(self.apply(payload))
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=send, args=(batch_payload("GW-1", 2, 3, 2),)),
                   threading.Thread(target=send, args=(batch_payload("GW-2", 1, 1, 3),))]
        for thread in threads: thread.start()
        for thread in threads: thread.join()
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 2)
        self.assertEqual(len(self.service.list_records(self.item["id"], "viewer")), 7)
        self.assertEqual(max(r["open_records"] for r in results), 7)
        self.assertTrue(self.repo.verify_audit_chain())

    def test_late_batch_keeps_records_without_downgrading_alert(self):
        self.apply(batch_payload("GW-1", 1, 1, 2, status="closed"))
        notice = self.service.create_notice(
            {"bridge_ref": "BR-B", "title": "限行通告", "detail": "限行"},
            "officer", "traffic_authority")
        current = self.service.transition(self.item["id"], "warning", 1, "op",
                                          "sensor_operator")
        current = self.service.transition(current["id"], "restricted",
                                          current["version"], "eng", "bridge_engineer",
                                          notice_id=notice["id"])
        late = self.apply(batch_payload("GW-1", 2, 1, 2, status="closed"))
        self.assertTrue(late["late"])
        self.assertEqual(late["applied"], 0)
        self.assertEqual(late["duplicates"], 2)
        older = self.apply(batch_payload("GW-1", 3, 0, 1, status="closed"))
        self.assertTrue(older["late"])
        self.assertEqual(older["applied"], 1)
        self.assertEqual(self.service.get_item(self.item["id"], "viewer")["status"],
                         "restricted")

    def test_frontier_batch_with_open_records_triggers_recompute(self):
        self.apply(batch_payload("GW-1", 1, 1, 2, status="closed"))
        notice = self.service.create_notice(
            {"bridge_ref": "BR-B", "title": "封闭通告", "detail": "封闭"},
            "officer", "traffic_authority")
        current = self.service.transition(self.item["id"], "warning", 1, "op",
                                          "sensor_operator")
        current = self.service.transition(current["id"], "restricted",
                                          current["version"], "eng", "bridge_engineer",
                                          notice_id=notice["id"])
        result = self.apply(batch_payload("GW-1", 2, 3, 2))
        self.assertTrue(result["recomputed"])
        self.assertEqual(result["item_status"], "warning")
        self.assertEqual(self.service.get_item(self.item["id"], "viewer")["status"],
                         "warning")
        reasons = [e["detail"].get("reason") for e in
                   self.service.audit("viewer", self.item["id"])
                   if e["action"] == "recompute"]
        self.assertEqual(reasons, ["open_records_changed"])
        self.assertTrue(self.repo.verify_audit_chain())

    def test_batch_validation(self):
        with self.assertRaises(ValidationError):
            self.apply({"gateway_id": "GW-1", "batch_no": 1, "readings": []})
        with self.assertRaises(ValidationError):
            self.apply({"gateway_id": "GW-1", "batch_no": 1,
                        "readings": [{"seq": 1, "detail": "a"},
                                     {"seq": 3, "detail": "b"}]})


if __name__ == "__main__":
    unittest.main()
