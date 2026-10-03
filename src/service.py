from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional

from .domain import (ConflictError, NotFoundError, PermissionDenied, ValidationError,
                     ensure_role, normalize_severity, require_number, require_positive_int,
                     require_text)
from .repository import Repository
from .rules import (AUDIT_ROLES, BATCH_ROLES, BRIDGE_MANAGE_ROLES, CREATE_ROLES, ENTITY,
                    NOTICE_BIND_STATES, NOTICE_MANAGE_ROLES, NOTICE_ROLLBACK_TARGET,
                    NOTICE_LEVELS, RECORD_ROLES, SEVERITY_WEIGHT, TITLE, VIEW_ROLES,
                    completion_blockers, covers_level, escalation_required, max_severity,
                    priority_score, reading_severity, response_deadline_hours,
                    role_for_transition, validate_transition)


class Service:
    def __init__(self, repository: Repository):
        self.repository = repository

    def _view(self, role: str) -> None:
        ensure_role(role, VIEW_ROLES)

    def create_item(self, payload: Dict[str, Any], actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, CREATE_ROLES)
        actor = require_text(actor, "actor", 100)
        title = require_text(payload.get("title"), "title", 200)
        description = require_text(payload.get("description"), "description")
        severity = normalize_severity(payload.get("severity"))
        quantity = require_number(payload.get("quantity", 0), "quantity")
        threshold = require_number(payload.get("threshold", 1), "threshold", 0.000001)
        external_ref = payload.get("external_ref")
        if external_ref is not None:
            external_ref = require_text(external_ref, "external_ref", 100)
        item = self.repository.create_item(title, description, severity, quantity,
                                           threshold, external_ref, actor)
        self.repository.append_audit("create", ENTITY, item["id"], actor, {
            "title": title, "severity": severity, "quantity": quantity,
            "priority": priority_score(severity, quantity, threshold),
        })
        return self.enrich(item)

    def add_record(self, item_id: int, payload: Dict[str, Any], actor: str,
                   role: str) -> Dict[str, Any]:
        ensure_role(role, RECORD_ROLES)
        actor = require_text(actor, "actor", 100)
        kind = require_text(payload.get("kind"), "kind", 100)
        detail = require_text(payload.get("detail"), "detail")
        status = payload.get("status", "open")
        if status not in ("open", "closed"):
            raise ValueError("status必须是open或closed")
        external_ref = payload.get("external_ref")
        if external_ref is not None:
            external_ref = require_text(external_ref, "external_ref", 100)
        record = self.repository.add_record(item_id, kind, detail, status,
                                            external_ref, actor)
        self.repository.append_audit("record", ENTITY, item_id, actor, {
            "record_id": record["id"], "kind": kind, "status": status,
        })
        return record

    def transition(self, item_id: int, target: str, expected_version: int,
                   actor: str, role: str) -> Dict[str, Any]:
        actor = require_text(actor, "actor", 100)
        item = self.repository.get_item(item_id)
        validate_transition(item["status"], target)
        ensure_role(role, role_for_transition(target))
        if not isinstance(expected_version, int) or expected_version < 1:
            raise ValueError("expected_version必须是正整数")
        blockers = completion_blockers(target, self.repository.open_record_count(item_id))
        if blockers:
            raise ConflictError("；".join(blockers))
        notice = None
        if target in NOTICE_BIND_STATES and item.get("bridge_id"):
            # 进入限行/封闭：必须绑定同一座桥仍有效的交通通告
            notice = self._require_active_notice(item["bridge_id"], target)
        if target == "restored" and item.get("notice_id"):
            bound = self.repository.find_notice_by_id(item["notice_id"])
            if bound is not None and bound["status"] == "active":
                raise ConflictError("绑定的交通通告仍有效，恢复前需先撤回通告")
        updated = self.repository.transition_item(item_id, target, expected_version, actor)
        if notice is not None:
            self.repository.bind_item_notice(item_id, notice["id"])
            updated = self.repository.get_item(item_id)
        self.repository.append_audit("transition", ENTITY, item_id, actor, {
            "from": item["status"], "to": target,
            "escalation_required": escalation_required(
                item["severity"], item["quantity"], item["threshold"]),
            "notice_no": notice["notice_no"] if notice else None,
        })
        return self.enrich(updated)

    def get_item(self, item_id: int, role: str) -> Dict[str, Any]:
        self._view(role)
        return self.enrich(self.repository.get_item(item_id))

    def list_items(self, role: str, status: Optional[str] = None) -> list:
        self._view(role)
        return [self.enrich(item) for item in self.repository.list_items(status)]

    def list_records(self, item_id: int, role: str) -> list:
        self._view(role)
        return self.repository.list_records(item_id)

    def audit(self, role: str, item_id: Optional[int] = None) -> list:
        ensure_role(role, AUDIT_ROLES)
        return self.repository.list_audit(item_id)

    # ---------------- 桥梁 ----------------

    def create_bridge(self, payload: Dict[str, Any], actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, BRIDGE_MANAGE_ROLES)
        actor = require_text(actor, "actor", 100)
        code = require_text(payload.get("code"), "code", 100)
        name = require_text(payload.get("name"), "name", 200)
        bridge = self.repository.create_bridge(code, name, actor)
        self.repository.append_audit("bridge_created", "bridge", bridge["id"], actor,
                                     {"code": code, "name": name})
        return bridge

    def list_bridges(self, role: str) -> List[Dict[str, Any]]:
        self._view(role)
        return self.repository.list_bridges()

    # ---------------- 监测批次链接入 ----------------

    @staticmethod
    def _validate_readings(raw: Any) -> List[Dict[str, Any]]:
        if not isinstance(raw, list) or not raw:
            raise ValidationError("readings必须是非空数组")
        if len(raw) > 200:
            raise ValidationError("单批次读数不能超过200条")
        readings = []
        for i, item in enumerate(raw):
            if not isinstance(item, dict):
                raise ValidationError(f"readings[{i}]必须是对象")
            sensor = require_text(item.get("sensor"), f"readings[{i}].sensor", 100)
            metric = require_text(item.get("metric"), f"readings[{i}].metric", 100)
            value = require_number(item.get("value"), f"readings[{i}].value")
            threshold = require_number(item.get("threshold", 1), f"readings[{i}].threshold", 0.000001)
            observed_at = require_text(item.get("observed_at"), f"readings[{i}].observed_at", 100)
            readings.append({"sensor": sensor, "metric": metric, "value": float(value),
                             "threshold": float(threshold), "observed_at": observed_at})
        return readings

    @staticmethod
    def _locate_conflict(old: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Any]:
        old_readings = old.get("readings", [])
        new_readings = new.get("readings", [])
        if len(old_readings) != len(new_readings):
            return {"field": "readings_length", "existing": len(old_readings),
                    "new": len(new_readings)}
        for i, (a, b) in enumerate(zip(old_readings, new_readings)):
            for field in ("sensor", "metric", "observed_at", "value", "threshold"):
                if a.get(field) != b.get(field):
                    return {"index": i, "field": field,
                            "existing": a.get(field), "new": b.get(field)}
        return {"field": "unknown"}

    def submit_batch(self, payload: Dict[str, Any], actor: str,
                     role: str) -> Dict[str, Any]:
        ensure_role(role, BATCH_ROLES)
        actor = require_text(actor, "actor", 100)
        batch_no = require_text(payload.get("batch_no"), "batch_no", 100)
        gateway_no = require_text(payload.get("gateway_no"), "gateway_no", 100)
        bridge_code = require_text(payload.get("bridge_code"), "bridge_code", 100)
        seq = require_positive_int(payload.get("seq"), "seq")
        readings = self._validate_readings(payload.get("readings"))
        bridge = self.repository.find_bridge_by_code(bridge_code)
        if bridge is None:
            raise NotFoundError("桥梁不存在")
        batch_payload = {"batch_no": batch_no, "gateway_no": gateway_no,
                         "bridge_code": bridge_code, "seq": seq, "readings": readings}
        payload_hash = hashlib.sha256(
            json.dumps(batch_payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
        ).hexdigest()

        existing = self.repository.find_batch(batch_no)
        if existing is not None:
            if existing["payload_hash"] == payload_hash:
                # 同一批次号重传：沿用第一次结果；缺口已补齐的挂起批次在此续作
                if (existing["status"] == "pending"
                        and existing["seq"] == self.repository.get_cursor(
                            gateway_no, bridge["id"]) + 1):
                    return self._process_batch(existing, actor)
                self.repository.append_audit("batch_replayed", "batch", existing["id"], actor,
                                             {"batch_no": batch_no, "status": existing["status"]})
                return self._batch_view(existing)
            conflict = self._locate_conflict(existing["payload"], batch_payload)
            self.repository.append_audit("batch_conflict", "batch", existing["id"], actor,
                                         {"batch_no": batch_no, "conflict": conflict})
            raise ConflictError(f"批次内容冲突，位置：{json.dumps(conflict, ensure_ascii=False)}")

        # 跨批次重叠：同一监测键内容不同 → 整批退回并指出冲突位置
        for i, reading in enumerate(readings):
            overlap = self.repository.find_reading_overlap(
                bridge["id"], reading["sensor"], reading["metric"], reading["observed_at"])
            if overlap is not None and float(overlap["value"]) != reading["value"]:
                conflict = {"index": i, "sensor": reading["sensor"], "metric": reading["metric"],
                            "observed_at": reading["observed_at"],
                            "existing_batch_no": overlap["batch_no"],
                            "existing_value": overlap["value"], "new_value": reading["value"]}
                self.repository.append_audit("batch_conflict", "batch", 0, actor,
                                             {"batch_no": batch_no, "conflict": conflict})
                raise ConflictError(
                    f"批次与既有监测记录重叠冲突，位置：{json.dumps(conflict, ensure_ascii=False)}")

        cursor = self.repository.get_cursor(gateway_no, bridge["id"])
        if seq > cursor + 1:
            # 缺口未补齐前不能跳过：挂起为 pending，补齐后按序排空
            batch = self.repository.create_batch(
                batch_no, gateway_no, bridge["id"], seq, batch_payload, payload_hash,
                "pending", actor)
            self.repository.append_audit("batch_held", "batch", batch["id"], actor,
                                         {"expected_seq": cursor + 1, "got_seq": seq,
                                          "reason": "gap"})
            return self._batch_view(batch)
        if seq <= cursor:
            # 迟到的旧批次：只留监测记录，不参与重算，不能把已升级告警降级
            batch = self.repository.create_batch(
                batch_no, gateway_no, bridge["id"], seq, batch_payload, payload_hash,
                "archived", actor)
            self.repository.insert_readings(
                batch["id"], bridge["id"],
                [dict(r, severity=reading_severity(r["value"], r["threshold"])) for r in readings])
            self.repository.mark_batch_archived(
                batch["id"], {"reason": "late_old_batch", "continuous_seq": cursor})
            self.repository.append_audit("batch_archived", "batch", batch["id"], actor,
                                          {"seq": seq, "continuous_seq": cursor})
            return self._batch_view(self.repository.find_batch_by_id(batch["id"]))

        # seq == cursor + 1：建立批次锚点后进入处理；写入失败可按批次号续传
        batch = self.repository.create_batch(
            batch_no, gateway_no, bridge["id"], seq, batch_payload, payload_hash,
            "pending", actor)
        return self._process_batch(batch, actor)

    def _process_batch(self, batch: Dict[str, Any], actor: str) -> Dict[str, Any]:
        repo = self.repository
        payload = batch["payload"]
        readings = payload["readings"]
        if repo.batch_reading_count(batch["id"]) == 0:
            repo.insert_readings(
                batch["id"], batch["bridge_id"],
                [dict(r, severity=reading_severity(r["value"], r["threshold"])) for r in readings])
        repo.advance_cursor(batch["gateway_no"], batch["bridge_id"], batch["seq"])
        # 先置为已处理再重算，保证连续序列重算包含本批次
        repo.mark_batch_processed(batch["id"], {})
        state = self._recompute_bridge(batch["bridge_id"], actor)
        result = {"reading_count": state["reading_count"],
                 "exceedance_count": state["exceedance_count"],
                 "severity": state["severity"], "alert_id": state["alert_item_id"],
                 "seq": batch["seq"]}
        repo.mark_batch_processed(batch["id"], result)
        repo.append_audit("batch_processed", "batch", batch["id"], actor, result)
        # 排空：缺口补齐后，连续序列上挂起的批次按序处理
        while True:
            next_seq = repo.get_cursor(batch["gateway_no"], batch["bridge_id"]) + 1
            pending = repo.find_pending_batch(batch["gateway_no"], batch["bridge_id"], next_seq)
            if pending is None:
                break
            self._process_batch(pending, actor)
        return self._batch_view(repo.find_batch_by_id(batch["id"]))

    def _recompute_bridge(self, bridge_id: int, actor: str) -> Dict[str, Any]:
        """告警数量与等级只按各网关最新连续序列重算，等级单调不降。"""
        repo = self.repository
        bridge = repo.find_bridge_by_id(bridge_id)
        readings = repo.list_processed_readings(bridge_id)
        reading_count = len(readings)
        exceedance_count = sum(1 for r in readings if r["value"] >= r["threshold"])
        severity = "normal"
        quantity, threshold = 0.0, 1.0
        for r in readings:
            severity = max_severity(severity, r["severity"])
            ratio = r["value"] / r["threshold"] if r["threshold"] > 0 else 1.0
            cur_ratio = quantity / threshold if threshold > 0 else 0.0
            if ratio >= cur_ratio:
                quantity, threshold = r["value"], r["threshold"]
        state = repo.get_bridge_state(bridge_id)
        if state is None:
            item_id = repo.create_alert(
                bridge_id, f"{bridge['name']} 结构告警", severity, quantity, threshold, actor)
            escalated = severity in ("warning", "critical")
            if escalated:
                repo.update_alert(item_id, severity, quantity, threshold, True)
        else:
            item_id = state["alert_item_id"]
            severity = max_severity(state["severity"], severity)
            escalated = (state["severity"] == "normal" and severity in ("warning", "critical"))
            repo.update_alert(item_id, severity, quantity, threshold, escalated)
        repo.upsert_bridge_state(bridge_id, item_id, severity, reading_count, exceedance_count)
        return {"reading_count": reading_count, "exceedance_count": exceedance_count,
                "severity": severity, "alert_item_id": item_id, "escalated": escalated}

    def _batch_view(self, batch: Dict[str, Any]) -> Dict[str, Any]:
        bridge = self.repository.find_bridge_by_id(batch["bridge_id"])
        return {
            "id": batch["id"],
            "batch_no": batch["batch_no"],
            "gateway_no": batch["gateway_no"],
            "bridge_code": bridge["code"] if bridge else None,
            "seq": batch["seq"],
            "status": batch["status"],
            "readings": batch["payload"].get("readings", []),
            "result": batch["result"],
            "conflict": batch["conflict"],
            "created_by": batch["created_by"],
            "created_at": batch["created_at"],
            "processed_at": batch["processed_at"],
        }

    def get_batch(self, batch_no: str, role: str) -> Dict[str, Any]:
        self._view(role)
        batch = self.repository.find_batch(batch_no)
        if batch is None:
            raise NotFoundError("批次不存在")
        return self._batch_view(batch)

    def list_batches(self, role: str, status: Optional[str] = None,
                     bridge_code: Optional[str] = None) -> List[Dict[str, Any]]:
        self._view(role)
        bridge_id = None
        if bridge_code:
            bridge = self.repository.find_bridge_by_code(bridge_code)
            if bridge is None:
                raise NotFoundError("桥梁不存在")
            bridge_id = bridge["id"]
        return [self._batch_view(b) for b in self.repository.list_batches(status, bridge_id)]

    def list_alerts(self, role: str) -> List[Dict[str, Any]]:
        self._view(role)
        return [self.enrich(a) for a in self.repository.list_alerts()]

    # ---------------- 交通通告 ----------------

    def create_notice(self, payload: Dict[str, Any], actor: str,
                      role: str) -> Dict[str, Any]:
        ensure_role(role, NOTICE_MANAGE_ROLES)
        actor = require_text(actor, "actor", 100)
        notice_no = require_text(payload.get("notice_no"), "notice_no", 100)
        bridge_code = require_text(payload.get("bridge_code"), "bridge_code", 100)
        level = payload.get("level")
        if level not in NOTICE_LEVELS:
            raise ValidationError("level必须是restriction或closure")
        raw_items = payload.get("items", [])
        if not isinstance(raw_items, list):
            raise ValidationError("items必须是数组")
        items = [require_text(x, "item", 500) for x in raw_items]
        effective_from = require_text(payload.get("effective_from"), "effective_from", 100)
        effective_to = payload.get("effective_to")
        if effective_to is not None:
            effective_to = require_text(effective_to, "effective_to", 100)
        bridge = self.repository.find_bridge_by_code(bridge_code)
        if bridge is None:
            raise NotFoundError("桥梁不存在")
        notice = self.repository.create_notice(
            notice_no, bridge["id"], level, items, effective_from, effective_to, actor)
        self.repository.append_audit("notice_created", "notice", notice["id"], actor,
                                     {"notice_no": notice_no, "bridge_code": bridge_code,
                                      "level": level})
        return notice

    def list_notices(self, role: str, bridge_code: Optional[str] = None,
                     status: Optional[str] = None) -> List[Dict[str, Any]]:
        self._view(role)
        bridge_id = None
        if bridge_code:
            bridge = self.repository.find_bridge_by_code(bridge_code)
            if bridge is None:
                raise NotFoundError("桥梁不存在")
            bridge_id = bridge["id"]
        return self.repository.list_notices(bridge_id, status)

    def _require_active_notice(self, bridge_id: int, target_state: str) -> Dict[str, Any]:
        for notice in self.repository.list_notices(bridge_id, "active"):
            if covers_level(notice["level"], target_state):
                return notice
        raise ConflictError("进入限行或封闭必须绑定同一座桥仍有效的交通通告")

    def _rollback_bound_alerts(self, notice_id: int, actor: str,
                               reason: str) -> List[int]:
        rolled = []
        for item in self.repository.list_items_by_notice(notice_id):
            self.repository.rollback_item(item["id"])
            self.repository.append_audit("alert_rollback", "alert", item["id"], actor,
                                         {"from": item["status"],
                                          "to": NOTICE_ROLLBACK_TARGET,
                                          "notice_id": notice_id, "reason": reason})
            rolled.append(item["id"])
        return rolled

    def withdraw_notice(self, notice_no: str, actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, NOTICE_MANAGE_ROLES)
        actor = require_text(actor, "actor", 100)
        notice = self.repository.find_notice(notice_no)
        if notice is None:
            raise NotFoundError("通告不存在")
        if notice["status"] != "active":
            raise ConflictError("通告已撤回")
        self.repository.withdraw_notice(notice["id"])
        rolled = self._rollback_bound_alerts(notice["id"], actor, "notice_withdrawn")
        self.repository.append_audit("notice_withdrawn", "notice", notice["id"], actor,
                                     {"notice_no": notice_no, "rolled_back_alerts": rolled})
        return self.repository.find_notice(notice_no)

    def update_notice_items(self, notice_no: str, payload: Dict[str, Any],
                            actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, NOTICE_MANAGE_ROLES)
        actor = require_text(actor, "actor", 100)
        notice = self.repository.find_notice(notice_no)
        if notice is None:
            raise NotFoundError("通告不存在")
        if notice["status"] != "active":
            raise ConflictError("通告已撤回，不能变更未关闭事项")
        raw_items = payload.get("items")
        if not isinstance(raw_items, list):
            raise ValidationError("items必须是数组")
        items = [require_text(x, "item", 500) for x in raw_items]
        self.repository.update_notice_items(notice["id"], items)
        rolled = self._rollback_bound_alerts(notice["id"], actor, "notice_items_changed")
        self.repository.append_audit("notice_items_updated", "notice", notice["id"], actor,
                                     {"notice_no": notice_no, "rolled_back_alerts": rolled})
        return self.repository.find_notice(notice_no)

    @staticmethod
    def enrich(item: Dict[str, Any]) -> Dict[str, Any]:
        result = dict(item)
        result["priority"] = priority_score(
            item["severity"], item["quantity"], item["threshold"])
        result["deadline_hours"] = response_deadline_hours(
            item["severity"], item["quantity"], item["threshold"])
        result["escalation_required"] = escalation_required(
            item["severity"], item["quantity"], item["threshold"])
        return result
