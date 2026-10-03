from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional

from .domain import (ConflictError, ValidationError, ensure_role,
                     normalize_severity, require_int, require_number, require_text)
from .repository import Repository
from .rules import (AUDIT_ROLES, BATCH_ROLES, CREATE_ROLES, ENTITY, NOTICE_BOUND_STATES,
                    NOTICE_ENTITY, NOTICE_ROLES, RECORD_ROLES, TITLE,
                    VIEW_ROLES, completion_blockers, escalation_required,
                    priority_score, response_deadline_hours, role_for_transition,
                    validate_transition)


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
        bridge_ref = payload.get("bridge_ref")
        if bridge_ref is not None:
            bridge_ref = require_text(bridge_ref, "bridge_ref", 100)
        item = self.repository.create_item(title, description, severity, quantity,
                                           threshold, external_ref, actor, bridge_ref)
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
        if status == "open":
            self.repository.revert_for_recompute(
                item_id, actor, "open_records_changed",
                {"record_id": record["id"]})
        return record

    def transition(self, item_id: int, target: str, expected_version: int,
                   actor: str, role: str, notice_id: Optional[int] = None) -> Dict[str, Any]:
        actor = require_text(actor, "actor", 100)
        item = self.repository.get_item(item_id)
        validate_transition(item["status"], target)
        ensure_role(role, role_for_transition(target))
        if not isinstance(expected_version, int) or expected_version < 1:
            raise ValueError("expected_version必须是正整数")
        if target in NOTICE_BOUND_STATES:
            if notice_id is None:
                raise ValidationError("进入限行或封闭必须绑定交通通告")
            if isinstance(notice_id, bool) or not isinstance(notice_id, int):
                raise ValidationError("notice_id必须是整数")
            notice = self.repository.get_notice(notice_id)
            if notice["status"] != "active":
                raise ConflictError("交通通告已撤回，限行判断需退回重算")
            if not item.get("bridge_ref") or notice["bridge_ref"] != item["bridge_ref"]:
                raise ConflictError("交通通告与告警不属于同一座桥")
        blockers = completion_blockers(target, self.repository.open_record_count(item_id))
        if blockers:
            raise ConflictError("；".join(blockers))
        updated = self.repository.transition_item(
            item_id, target, expected_version, actor,
            notice_id if target in NOTICE_BOUND_STATES else None)
        detail = {
            "from": item["status"], "to": target,
            "escalation_required": escalation_required(
                item["severity"], item["quantity"], item["threshold"]),
        }
        if target in NOTICE_BOUND_STATES:
            detail["notice_id"] = notice_id
        self.repository.append_audit("transition", ENTITY, item_id, actor, detail)
        return self.enrich(updated)

    def apply_batch(self, item_id: int, payload: Dict[str, Any], actor: str,
                    role: str) -> Dict[str, Any]:
        ensure_role(role, BATCH_ROLES)
        actor = require_text(actor, "actor", 100)
        gateway_id = require_text(payload.get("gateway_id"), "gateway_id", 100)
        batch_no = require_int(payload.get("batch_no"), "batch_no", 1)
        readings = self._normalize_readings(payload)
        content_hash = hashlib.sha256(
            json.dumps(readings, ensure_ascii=False, sort_keys=True).encode("utf-8")
        ).hexdigest()
        result = self.repository.apply_batch(item_id, gateway_id, batch_no, readings,
                                             content_hash, actor)
        item = self.repository.get_item(item_id)
        result["priority"] = priority_score(item["severity"], item["quantity"],
                                            item["threshold"], result["open_records"])
        result["escalation_required"] = escalation_required(
            item["severity"], item["quantity"], item["threshold"])
        return result

    @staticmethod
    def _normalize_readings(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        readings = payload.get("readings")
        if not isinstance(readings, list) or not readings:
            raise ValidationError("readings不能为空")
        if len(readings) > 10000:
            raise ValidationError("readings超过单批上限")
        normalized = []
        for entry in readings:
            if not isinstance(entry, dict):
                raise ValidationError("reading必须是JSON对象")
            seq = require_int(entry.get("seq"), "seq", 0)
            detail = require_text(entry.get("detail"), "detail")
            kind = require_text(entry.get("kind", "monitoring"), "kind", 100)
            status = entry.get("status", "open")
            if status not in ("open", "closed"):
                raise ValidationError("status必须是open或closed")
            normalized.append({"seq": seq, "kind": kind, "detail": detail,
                               "status": status})
        normalized.sort(key=lambda r: r["seq"])
        seqs = [r["seq"] for r in normalized]
        if len(set(seqs)) != len(seqs):
            raise ValidationError("reading序列重复")
        if seqs != list(range(seqs[0], seqs[0] + len(seqs))):
            raise ValidationError("reading序列必须连续")
        start_seq = payload.get("start_seq")
        if start_seq is not None and require_int(start_seq, "start_seq", 0) != seqs[0]:
            raise ValidationError("start_seq与readings序列不一致")
        return normalized

    def list_batches(self, item_id: int, role: str) -> list:
        self._view(role)
        return self.repository.list_batches(item_id)

    def create_notice(self, payload: Dict[str, Any], actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, NOTICE_ROLES)
        actor = require_text(actor, "actor", 100)
        bridge_ref = require_text(payload.get("bridge_ref"), "bridge_ref", 100)
        title = require_text(payload.get("title"), "title", 200)
        detail = require_text(payload.get("detail"), "detail")
        notice_no = payload.get("notice_no")
        if notice_no is not None:
            notice_no = require_text(notice_no, "notice_no", 100)
        notice = self.repository.create_notice(bridge_ref, title, detail, notice_no, actor)
        self.repository.append_audit("notice_create", NOTICE_ENTITY, notice["id"], actor, {
            "bridge_ref": bridge_ref, "title": title,
        })
        return notice

    def withdraw_notice(self, notice_id: int, actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, NOTICE_ROLES)
        actor = require_text(actor, "actor", 100)
        return self.repository.withdraw_notice(notice_id, actor)

    def list_notices(self, role: str, bridge_ref: Optional[str] = None) -> list:
        self._view(role)
        return self.repository.list_notices(bridge_ref)

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
