import tempfile
import unittest
from pathlib import Path

from src.domain import ConflictError
from src.repository import Repository
from src.service import Service


class ChainTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Repository(str(Path(self.tmp.name) / "test.db"))
        self.service = Service(self.repo)
        self.service.create_bridge({"code": "B1", "name": "一号桥"}, "eng", "bridge_engineer")

    def tearDown(self):
        self.repo.close()
        self.tmp.cleanup()

    def reading(self, sensor="S1", metric="strain", value=5.0, threshold=10.0,
                observed_at="2026-10-01T00:00:00Z"):
        return {"sensor": sensor, "metric": metric, "value": value,
                "threshold": threshold, "observed_at": observed_at}

    def batch(self, batch_no, gateway, seq, readings, bridge="B1"):
        return {"batch_no": batch_no, "gateway_no": gateway, "bridge_code": bridge,
                "seq": seq, "readings": readings}

    def submit(self, batch_no, gateway, seq, readings, bridge="B1"):
        return self.service.submit_batch(
            self.batch(batch_no, gateway, seq, readings, bridge), "op", "sensor_operator")

    def notice(self, notice_no, level, items, bridge="B1"):
        return self.service.create_notice(
            {"notice_no": notice_no, "bridge_code": bridge, "level": level,
             "items": items, "effective_from": "2026-10-01T00:00:00Z"},
            "tc", "traffic_authority")

    def test_01_gap_is_held_then_drained_in_order(self):
        # 缺口未补齐前不能跳过：seq=2 先到，挂起
        held = self.submit("B-2", "G1", 2, [self.reading(value=5.0)])
        self.assertEqual(held["status"], "pending")
        # seq=1 补齐后按序处理，seq=2 自动排空
        first = self.submit("B-1", "G1", 1, [self.reading(value=4.0)])
        self.assertEqual(first["status"], "processed")
        second = self.service.get_batch("B-2", "viewer")
        self.assertEqual(second["status"], "processed")
        state = self.repo.get_bridge_state(
            self.repo.find_bridge_by_code("B1")["id"])
        self.assertEqual(state["reading_count"], 2)
        self.assertTrue(self.repo.verify_audit_chain())

    def test_02_duplicate_batch_replay_uses_first_result(self):
        payload = self.batch("B-1", "G1", 1, [self.reading(value=12.0)])
        first = self.service.submit_batch(payload, "op", "sensor_operator")
        second = self.service.submit_batch(payload, "op", "sensor_operator")
        self.assertEqual(first["status"], "processed")
        self.assertEqual(second["status"], "processed")
        self.assertEqual(first["result"]["alert_id"], second["result"]["alert_id"])
        self.assertEqual(len(self.service.list_batches("viewer")), 1)
        alerts = self.service.list_alerts("viewer")
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["status"], "warning")
        self.assertTrue(self.repo.verify_audit_chain())

    def test_03_same_batch_no_different_content_rejected_with_location(self):
        self.submit("B-1", "G1", 1, [self.reading(value=5.0)])
        with self.assertRaises(ConflictError) as ctx:
            self.submit("B-1", "G1", 1, [self.reading(value=9.0)])
        message = str(ctx.exception)
        self.assertIn("index", message)
        self.assertIn("existing", message)
        # 第一次结果保持不变
        kept = self.service.get_batch("B-1", "viewer")
        self.assertEqual(kept["result"]["reading_count"], 1)
        self.assertTrue(self.repo.verify_audit_chain())

    def test_04_overlapping_reading_conflict_rejects_whole_batch(self):
        self.submit("B-1", "G1", 1, [self.reading(value=5.0, observed_at="T1")])
        with self.assertRaises(ConflictError) as ctx:
            self.submit("B-2", "G1", 2, [
                self.reading(value=5.0, observed_at="T0"),
                self.reading(value=9.0, observed_at="T1"),
            ])
        message = str(ctx.exception)
        self.assertIn("B-1", message)
        self.assertIn("index", message)
        # 冲突批次整批退回，不留监测记录
        self.assertIsNone(self.repo.find_batch("B-2"))
        self.assertTrue(self.repo.verify_audit_chain())

    def test_05_late_old_batch_archived_keeps_monitoring_only(self):
        self.submit("B-1", "G1", 1, [self.reading(value=12.0, observed_at="T1")])
        self.submit("B-2", "G1", 2, [self.reading(value=4.0, observed_at="T2")])
        alert = self.service.list_alerts("viewer")[0]
        self.assertEqual(alert["severity"], "critical")
        # 迟到的旧批次（新批次号复用旧序列）：只留监测记录
        late = self.submit("B-OLD", "G1", 1, [self.reading(value=1.0)])
        self.assertEqual(late["status"], "archived")
        self.assertEqual(len(late["readings"]), 1)
        # 已升级告警不降级，归档读数不参与重算
        alert = self.service.list_alerts("viewer")[0]
        self.assertEqual(alert["severity"], "critical")
        state = self.repo.get_bridge_state(alert["bridge_id"])
        self.assertEqual(state["reading_count"], 2)
        self.assertTrue(self.repo.verify_audit_chain())

    def test_06_two_gateways_recompute_from_latest_continuous_sequence(self):
        self.submit("A-1", "GA", 1, [self.reading(value=5.0, observed_at="A1")])
        self.submit("A-2", "GA", 2, [self.reading(value=5.0, observed_at="A2")])
        self.submit("B-1", "GB", 1, [self.reading(value=11.0, observed_at="B1")])
        alert = self.service.list_alerts("viewer")[0]
        self.assertEqual(alert["severity"], "critical")
        state = self.repo.get_bridge_state(alert["bridge_id"])
        self.assertEqual(state["reading_count"], 3)
        self.assertEqual(state["exceedance_count"], 1)
        # 另一网关补传序列，告警数量按最新连续序列重算
        self.submit("B-2", "GB", 2, [self.reading(value=1.0, observed_at="B2")])
        state = self.repo.get_bridge_state(alert["bridge_id"])
        self.assertEqual(state["reading_count"], 4)
        self.assertEqual(state["exceedance_count"], 1)
        self.assertTrue(self.repo.verify_audit_chain())

    def test_07_restricted_and_closed_require_valid_notice(self):
        self.submit("B-1", "G1", 1, [self.reading(value=12.0)])
        alert = self.service.list_alerts("viewer")[0]
        self.assertEqual(alert["status"], "warning")
        with self.assertRaises(ConflictError):
            self.service.transition(alert["id"], "restricted", alert["version"],
                                    "eng", "bridge_engineer")
        self.notice("N-1", "restriction", ["限速5t"])
        restricted = self.service.transition(alert["id"], "restricted", alert["version"],
                                             "eng", "bridge_engineer")
        self.assertEqual(restricted["status"], "restricted")
        # 封闭需要 closure 级通告，restriction 不够
        with self.assertRaises(ConflictError):
            self.service.transition(restricted["id"], "closed", restricted["version"],
                                    "tc", "traffic_authority")
        self.notice("N-2", "closure", ["封闭交通"])
        closed = self.service.transition(restricted["id"], "closed", restricted["version"],
                                         "tc", "traffic_authority")
        self.assertEqual(closed["status"], "closed")
        self.assertTrue(self.repo.verify_audit_chain())

    def test_08_notice_withdrawal_rolls_back_and_recalculates(self):
        self.submit("B-1", "G1", 1, [self.reading(value=12.0)])
        alert = self.service.list_alerts("viewer")[0]
        self.notice("N-1", "closure", ["封闭交通"])
        restricted = self.service.transition(alert["id"], "restricted", alert["version"],
                                             "eng", "bridge_engineer")
        closed = self.service.transition(restricted["id"], "closed", restricted["version"],
                                         "tc", "traffic_authority")
        withdrawn = self.service.withdraw_notice("N-1", "tc", "traffic_authority")
        self.assertEqual(withdrawn["status"], "withdrawn")
        rolled = self.service.get_item(closed["id"], "viewer")
        self.assertEqual(rolled["status"], "warning")
        # 通告撤回后，没有有效通告不能重新进入限行
        with self.assertRaises(ConflictError):
            self.service.transition(rolled["id"], "restricted", rolled["version"],
                                    "eng", "bridge_engineer")
        self.assertTrue(self.repo.verify_audit_chain())

    def test_09_notice_items_change_rolls_back_and_recalculates(self):
        self.submit("B-1", "G1", 1, [self.reading(value=12.0)])
        alert = self.service.list_alerts("viewer")[0]
        self.notice("N-1", "restriction", ["限速5t"])
        restricted = self.service.transition(alert["id"], "restricted", alert["version"],
                                             "eng", "bridge_engineer")
        updated = self.service.update_notice_items(
            "N-1", {"items": ["限速10t"]}, "tc", "traffic_authority")
        self.assertEqual(updated["version"], 2)
        rolled = self.service.get_item(restricted["id"], "viewer")
        self.assertEqual(rolled["status"], "warning")
        # 未关闭事项变化后退回重算，绑定解除
        self.assertIsNone(rolled["notice_id"])
        self.assertTrue(self.repo.verify_audit_chain())

    def test_10_resume_after_write_failure_by_batch_no(self):
        payload = self.batch("B-1", "G1", 1, [self.reading(value=12.0)])
        original = self.repo.insert_readings
        state = {"calls": 0}

        def fail_once(*args, **kwargs):
            state["calls"] += 1
            if state["calls"] == 1:
                raise RuntimeError("simulated write failure")
            return original(*args, **kwargs)

        self.repo.insert_readings = fail_once
        with self.assertRaises(RuntimeError):
            self.service.submit_batch(payload, "op", "sensor_operator")
        self.repo.insert_readings = original
        # 批次锚点保留为 pending，原记录可查
        anchored = self.service.get_batch("B-1", "viewer")
        self.assertEqual(anchored["status"], "pending")
        # 写入失败后按原批次号恢复续传
        result = self.service.submit_batch(payload, "op", "sensor_operator")
        self.assertEqual(result["status"], "processed")
        self.assertEqual(result["result"]["reading_count"], 1)
        self.assertEqual(result["result"]["severity"], "critical")
        self.assertTrue(self.repo.verify_audit_chain())

    def test_11_restore_requires_notice_withdrawn_first(self):
        self.submit("B-1", "G1", 1, [self.reading(value=12.0)])
        alert = self.service.list_alerts("viewer")[0]
        self.notice("N-1", "closure", ["封闭交通"])
        restricted = self.service.transition(alert["id"], "restricted", alert["version"],
                                             "eng", "bridge_engineer")
        closed = self.service.transition(restricted["id"], "closed", restricted["version"],
                                         "tc", "traffic_authority")
        # 通告仍有效时不能恢复
        with self.assertRaises(ConflictError):
            self.service.transition(closed["id"], "restored", closed["version"],
                                    "eng", "bridge_engineer")
        self.service.withdraw_notice("N-1", "tc", "traffic_authority")
        rolled = self.service.get_item(closed["id"], "viewer")
        self.assertEqual(rolled["status"], "warning")
        restored = self.service.transition(rolled["id"], "restored", rolled["version"],
                                            "eng", "bridge_engineer")
        self.assertEqual(restored["status"], "restored")
        self.assertTrue(self.repo.verify_audit_chain())


if __name__ == "__main__":
    unittest.main()
