from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from .audit import make_entry, utc_now
from .domain import ConflictError, NotFoundError
from .rules import ENTITY, ID_PREFIX, NOTICE_ENTITY, RECOMPUTE_STATES, RECOMPUTE_TARGET, STATES


class Repository:
    def __init__(self, db_path: str):
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA journal_mode = WAL")
        self._create_schema()

    def _create_schema(self) -> None:
        statuses = ",".join("'" + s.replace("'", "''") + "'" for s in STATES)
        with self.conn:
            self.conn.executescript(f"""
                CREATE TABLE IF NOT EXISTS items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    quantity REAL NOT NULL DEFAULT 0,
                    threshold REAL NOT NULL DEFAULT 1,
                    status TEXT NOT NULL CHECK(status IN ({statuses})),
                    version INTEGER NOT NULL DEFAULT 1,
                    external_ref TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE UNIQUE INDEX IF NOT EXISTS ux_items_external_ref
                    ON items(external_ref) WHERE external_ref IS NOT NULL;
                CREATE TABLE IF NOT EXISTS records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                    kind TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'open'
                        CHECK(status IN ('open','closed')),
                    external_ref TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(item_id, external_ref)
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action TEXT NOT NULL,
                    entity_type TEXT NOT NULL,
                    entity_id INTEGER NOT NULL,
                    actor TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS notices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    bridge_ref TEXT NOT NULL,
                    title TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    notice_no TEXT,
                    status TEXT NOT NULL DEFAULT 'active'
                        CHECK(status IN ('active','withdrawn')),
                    version INTEGER NOT NULL DEFAULT 1,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE UNIQUE INDEX IF NOT EXISTS ux_notices_notice_no
                    ON notices(notice_no) WHERE notice_no IS NOT NULL;
                CREATE TABLE IF NOT EXISTS notice_bindings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                    notice_id INTEGER NOT NULL REFERENCES notices(id) ON DELETE CASCADE,
                    target TEXT NOT NULL,
                    active INTEGER NOT NULL DEFAULT 1,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS gateway_sequences (
                    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                    gateway_id TEXT NOT NULL,
                    next_seq INTEGER NOT NULL,
                    PRIMARY KEY (item_id, gateway_id)
                );
                CREATE TABLE IF NOT EXISTS batches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                    gateway_id TEXT NOT NULL,
                    batch_no INTEGER NOT NULL,
                    start_seq INTEGER NOT NULL,
                    end_seq INTEGER NOT NULL,
                    reading_count INTEGER NOT NULL,
                    content_hash TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(item_id, gateway_id, batch_no)
                );
            """)
        columns = [row["name"] for row in
                   self.conn.execute("PRAGMA table_info(items)").fetchall()]
        if "bridge_ref" not in columns:
            with self.conn:
                self.conn.execute("ALTER TABLE items ADD COLUMN bridge_ref TEXT")

    @staticmethod
    def _item(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    def create_item(self, title: str, description: str, severity: str,
                    quantity: float, threshold: float, external_ref: Optional[str],
                    actor: str, bridge_ref: Optional[str] = None) -> Dict[str, Any]:
        now = utc_now()
        try:
            with self._lock, self.conn:
                cur = self.conn.execute(
                    """INSERT INTO items(title, description, severity, quantity, threshold,
                       status, version, external_ref, bridge_ref, created_by, created_at, updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (title, description, severity, quantity, threshold, STATES[0], 1,
                     external_ref, bridge_ref, actor, now, now),
                )
                item_id = int(cur.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise ConflictError("external_ref已存在") from exc
        return self.get_item(item_id)

    def get_item(self, item_id: int) -> Dict[str, Any]:
        with self._lock:
            row = self.conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
        if row is None:
            raise NotFoundError("项目不存在")
        return self._item(row)

    def list_items(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM items"
        params: tuple = ()
        if status:
            sql += " WHERE status=?"
            params = (status,)
        sql += " ORDER BY id DESC"
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        return [self._item(row) for row in rows]

    def transition_item(self, item_id: int, target: str, expected_version: int,
                        actor: str, notice_id: Optional[int] = None) -> Dict[str, Any]:
        now = utc_now()
        with self._lock, self.conn:
            cur = self.conn.execute(
                """UPDATE items SET status=?, version=version+1, updated_at=?
                   WHERE id=? AND version=?""",
                (target, now, item_id, expected_version),
            )
            if cur.rowcount == 0:
                exists = self.conn.execute("SELECT 1 FROM items WHERE id=?", (item_id,)).fetchone()
                if exists is None:
                    raise NotFoundError("项目不存在")
                raise ConflictError("版本冲突，请刷新后重试")
            if notice_id is not None:
                self.conn.execute(
                    "UPDATE notice_bindings SET active=0 WHERE item_id=? AND active=1",
                    (item_id,))
                self.conn.execute(
                    """INSERT INTO notice_bindings(item_id, notice_id, target, active,
                       created_by, created_at) VALUES(?,?,?,1,?,?)""",
                    (item_id, notice_id, target, actor, now),
                )
        return self.get_item(item_id)

    def add_record(self, item_id: int, kind: str, detail: str, status: str,
                   external_ref: Optional[str], actor: str) -> Dict[str, Any]:
        now = utc_now()
        self.get_item(item_id)
        try:
            with self._lock, self.conn:
                cur = self.conn.execute(
                    """INSERT INTO records(item_id, kind, detail, status, external_ref,
                       created_by, created_at) VALUES(?,?,?,?,?,?,?)""",
                    (item_id, kind, detail, status, external_ref, actor, now),
                )
                record_id = int(cur.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise ConflictError("记录唯一标识已存在") from exc
        with self._lock:
            row = self.conn.execute("SELECT * FROM records WHERE id=?", (record_id,)).fetchone()
        return dict(row)

    def list_records(self, item_id: int) -> List[Dict[str, Any]]:
        self.get_item(item_id)
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM records WHERE item_id=? ORDER BY id", (item_id,)
            ).fetchall()
        return [dict(row) for row in rows]

    def open_record_count(self, item_id: int) -> int:
        with self._lock:
            row = self.conn.execute(
                "SELECT COUNT(*) AS n FROM records WHERE item_id=? AND status='open'",
                (item_id,),
            ).fetchone()
        return int(row["n"])

    def _insert_audit(self, action: str, entity_type: str, entity_id: int,
                      actor: str, detail: dict) -> Dict[str, Any]:
        row = self.conn.execute(
            "SELECT entry_hash FROM audit_events ORDER BY id DESC LIMIT 1"
        ).fetchone()
        previous = row["entry_hash"] if row else "GENESIS"
        event = make_entry(action, entity_type, entity_id, actor, detail, previous)
        cur = self.conn.execute(
            """INSERT INTO audit_events(action, entity_type, entity_id, actor, detail,
               previous_hash, entry_hash, created_at) VALUES(?,?,?,?,?,?,?,?)""",
            (event["action"], event["entity_type"], event["entity_id"], event["actor"],
             json.dumps(event["detail"], ensure_ascii=False, sort_keys=True),
             event["previous_hash"], event["entry_hash"], event["created_at"]),
        )
        event["id"] = int(cur.lastrowid)
        return event

    def append_audit(self, action: str, entity_type: str, entity_id: int,
                     actor: str, detail: dict) -> Dict[str, Any]:
        with self._lock, self.conn:
            return self._insert_audit(action, entity_type, entity_id, actor, detail)

    def list_audit(self, entity_id: Optional[int] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM audit_events"
        params: tuple = ()
        if entity_id is not None:
            sql += " WHERE entity_id=?"
            params = (entity_id,)
        sql += " ORDER BY id"
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["detail"] = json.loads(item["detail"])
            result.append(item)
        return result

    def verify_audit_chain(self) -> bool:
        from .audit import calculate_hash
        with self._lock:
            rows = self.conn.execute("SELECT * FROM audit_events ORDER BY id").fetchall()
        previous = "GENESIS"
        for row in rows:
            if row["previous_hash"] != previous:
                return False
            payload = {
                "action": row["action"], "entity_type": row["entity_type"],
                "entity_id": row["entity_id"], "actor": row["actor"],
                "detail": json.loads(row["detail"]), "created_at": row["created_at"],
            }
            if calculate_hash(previous, payload) != row["entry_hash"]:
                return False
            previous = row["entry_hash"]
        return True

    def create_notice(self, bridge_ref: str, title: str, detail: str,
                      notice_no: Optional[str], actor: str) -> Dict[str, Any]:
        now = utc_now()
        try:
            with self._lock, self.conn:
                cur = self.conn.execute(
                    """INSERT INTO notices(bridge_ref, title, detail, notice_no, status,
                       version, created_by, created_at, updated_at)
                       VALUES(?,?,?,?,'active',1,?,?,?)""",
                    (bridge_ref, title, detail, notice_no, actor, now, now),
                )
                notice_id = int(cur.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise ConflictError("通告编号已存在") from exc
        return self.get_notice(notice_id)

    def get_notice(self, notice_id: int) -> Dict[str, Any]:
        with self._lock:
            row = self.conn.execute("SELECT * FROM notices WHERE id=?", (notice_id,)).fetchone()
        if row is None:
            raise NotFoundError("交通通告不存在")
        return dict(row)

    def list_notices(self, bridge_ref: Optional[str] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM notices"
        params: tuple = ()
        if bridge_ref:
            sql += " WHERE bridge_ref=?"
            params = (bridge_ref,)
        sql += " ORDER BY id DESC"
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        return [dict(row) for row in rows]

    def withdraw_notice(self, notice_id: int, actor: str) -> Dict[str, Any]:
        now = utc_now()
        with self._lock, self.conn:
            row = self.conn.execute("SELECT * FROM notices WHERE id=?", (notice_id,)).fetchone()
            if row is None:
                raise NotFoundError("交通通告不存在")
            if row["status"] != "active":
                raise ConflictError("通告已撤回")
            self.conn.execute(
                "UPDATE notices SET status='withdrawn', version=version+1, updated_at=? WHERE id=?",
                (now, notice_id))
            bindings = self.conn.execute(
                """SELECT b.id AS binding_id, b.item_id AS item_id, i.status AS item_status
                   FROM notice_bindings b JOIN items i ON i.id=b.item_id
                   WHERE b.notice_id=? AND b.active=1""",
                (notice_id,)).fetchall()
            reverted = []
            for binding in bindings:
                self.conn.execute("UPDATE notice_bindings SET active=0 WHERE id=?",
                                  (binding["binding_id"],))
                if binding["item_status"] in RECOMPUTE_STATES:
                    self.conn.execute(
                        """UPDATE items SET status=?, version=version+1, updated_at=?
                           WHERE id=?""",
                        (RECOMPUTE_TARGET, now, binding["item_id"]))
                    reverted.append(binding["item_id"])
                    self._insert_audit("recompute", ENTITY, binding["item_id"], actor, {
                        "reason": "notice_withdrawn", "notice_id": notice_id,
                        "from": binding["item_status"], "to": RECOMPUTE_TARGET,
                    })
            self._insert_audit("notice_withdraw", NOTICE_ENTITY, notice_id, actor, {
                "bridge_ref": row["bridge_ref"], "reverted_items": reverted,
            })
        return {"notice": self.get_notice(notice_id), "reverted_items": reverted}

    def revert_for_recompute(self, item_id: int, actor: str, reason: str,
                             detail: Optional[dict] = None) -> Optional[Dict[str, Any]]:
        now = utc_now()
        with self._lock, self.conn:
            row = self.conn.execute("SELECT status FROM items WHERE id=?", (item_id,)).fetchone()
            if row is None:
                raise NotFoundError("项目不存在")
            if row["status"] not in RECOMPUTE_STATES:
                return None
            self.conn.execute(
                """UPDATE items SET status=?, version=version+1, updated_at=?
                   WHERE id=?""",
                (RECOMPUTE_TARGET, now, item_id))
            self.conn.execute(
                "UPDATE notice_bindings SET active=0 WHERE item_id=? AND active=1",
                (item_id,))
            payload = {"reason": reason, "from": row["status"], "to": RECOMPUTE_TARGET}
            payload.update(detail or {})
            self._insert_audit("recompute", ENTITY, item_id, actor, payload)
        return self.get_item(item_id)

    def apply_batch(self, item_id: int, gateway_id: str, batch_no: int,
                    readings: List[Dict[str, Any]], content_hash: str,
                    actor: str) -> Dict[str, Any]:
        now = utc_now()
        start_seq = readings[0]["seq"]
        end_seq = readings[-1]["seq"]
        with self._lock, self.conn:
            item = self.conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
            if item is None:
                raise NotFoundError("项目不存在")
            existing_batch = self.conn.execute(
                """SELECT * FROM batches WHERE item_id=? AND gateway_id=? AND batch_no=?""",
                (item_id, gateway_id, batch_no)).fetchone()
            if existing_batch is not None:
                if existing_batch["content_hash"] == content_hash:
                    result = json.loads(existing_batch["result_json"])
                    result["replayed"] = True
                    return result
                conflicts = self._reading_conflicts(item_id, gateway_id, readings)
                raise ConflictError(
                    f"批次号{batch_no}已接收，重传内容不一致，整批退回",
                    details={"batch_no": batch_no, "conflicts": conflicts})
            row = self.conn.execute(
                "SELECT next_seq FROM gateway_sequences WHERE item_id=? AND gateway_id=?",
                (item_id, gateway_id)).fetchone()
            frontier = row["next_seq"] if row else None
            if frontier is not None and start_seq > frontier:
                raise ConflictError(
                    f"序列缺口未补齐：缺少[{frontier}..{start_seq - 1}]，不能跳过",
                    details={"missing_from": frontier, "missing_to": start_seq - 1})
            conflicts, duplicates, new_readings = [], 0, []
            refs = {f"{gateway_id}#{r['seq']}": r for r in readings}
            placeholders = ",".join("?" for _ in refs)
            existing_rows = self.conn.execute(
                f"SELECT * FROM records WHERE item_id=? AND external_ref IN ({placeholders})",
                (item_id, *refs.keys())).fetchall() if refs else []
            by_ref = {r["external_ref"]: r for r in existing_rows}
            for ref, reading in refs.items():
                existing = by_ref.get(ref)
                if existing is None:
                    new_readings.append(reading)
                elif (existing["kind"] == reading["kind"]
                      and existing["detail"] == reading["detail"]
                      and existing["status"] == reading["status"]):
                    duplicates += 1
                else:
                    conflicts.append({
                        "seq": reading["seq"],
                        "existing": {"kind": existing["kind"], "detail": existing["detail"],
                                     "status": existing["status"]},
                        "received": {"kind": reading["kind"], "detail": reading["detail"],
                                     "status": reading["status"]},
                    })
            if conflicts:
                conflicts.sort(key=lambda c: c["seq"])
                raise ConflictError("批次重叠内容不一致，整批退回",
                                    details={"conflicts": conflicts})
            open_before = self._open_record_count(item_id)
            try:
                for reading in new_readings:
                    self.conn.execute(
                        """INSERT INTO records(item_id, kind, detail, status, external_ref,
                           created_by, created_at) VALUES(?,?,?,?,?,?,?)""",
                        (item_id, reading["kind"], reading["detail"], reading["status"],
                         f"{gateway_id}#{reading['seq']}", actor, now))
            except sqlite3.IntegrityError as exc:
                raise ConflictError("监测记录唯一标识冲突") from exc
            new_frontier = end_seq + 1 if frontier is None else max(frontier, end_seq + 1)
            self.conn.execute(
                """INSERT INTO gateway_sequences(item_id, gateway_id, next_seq) VALUES(?,?,?)
                   ON CONFLICT(item_id, gateway_id) DO UPDATE SET next_seq=excluded.next_seq""",
                (item_id, gateway_id, new_frontier))
            late = frontier is not None and end_seq < frontier
            open_after = self._open_record_count(item_id)
            recomputed = False
            item_status = item["status"]
            if not late and open_after != open_before and item_status in RECOMPUTE_STATES:
                self.conn.execute(
                    """UPDATE items SET status=?, version=version+1, updated_at=?
                       WHERE id=?""",
                    (RECOMPUTE_TARGET, now, item_id))
                self.conn.execute(
                    "UPDATE notice_bindings SET active=0 WHERE item_id=? AND active=1",
                    (item_id,))
                item_status = RECOMPUTE_TARGET
                recomputed = True
                self._insert_audit("recompute", ENTITY, item_id, actor, {
                    "reason": "open_records_changed", "from": item["status"],
                    "to": RECOMPUTE_TARGET, "open_records": open_after,
                })
            result = {
                "item_id": item_id, "gateway_id": gateway_id, "batch_no": batch_no,
                "applied": len(new_readings), "duplicates": duplicates, "late": late,
                "next_seq": new_frontier, "open_records": open_after,
                "recomputed": recomputed, "item_status": item_status,
                "content_hash": content_hash,
            }
            self.conn.execute(
                """INSERT INTO batches(item_id, gateway_id, batch_no, start_seq, end_seq,
                   reading_count, content_hash, result_json, created_by, created_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (item_id, gateway_id, batch_no, start_seq, end_seq, len(readings),
                 content_hash, json.dumps(result, ensure_ascii=False, sort_keys=True),
                 actor, now))
            self._insert_audit("batch", ENTITY, item_id, actor, {
                "gateway_id": gateway_id, "batch_no": batch_no,
                "applied": len(new_readings), "duplicates": duplicates,
                "late": late, "next_seq": new_frontier,
            })
        return result

    def _reading_conflicts(self, item_id: int, gateway_id: str,
                           readings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        refs = {f"{gateway_id}#{r['seq']}": r for r in readings}
        if not refs:
            return []
        placeholders = ",".join("?" for _ in refs)
        rows = self.conn.execute(
            f"SELECT * FROM records WHERE item_id=? AND external_ref IN ({placeholders})",
            (item_id, *refs.keys())).fetchall()
        by_ref = {row["external_ref"]: row for row in rows}
        conflicts = []
        for ref, reading in refs.items():
            existing = by_ref.get(ref)
            if existing is not None and (
                    existing["kind"] != reading["kind"]
                    or existing["detail"] != reading["detail"]
                    or existing["status"] != reading["status"]):
                conflicts.append({
                    "seq": reading["seq"],
                    "existing": {"kind": existing["kind"], "detail": existing["detail"],
                                 "status": existing["status"]},
                    "received": {"kind": reading["kind"], "detail": reading["detail"],
                                 "status": reading["status"]},
                })
        conflicts.sort(key=lambda c: c["seq"])
        return conflicts

    def _open_record_count(self, item_id: int) -> int:
        row = self.conn.execute(
            "SELECT COUNT(*) AS n FROM records WHERE item_id=? AND status='open'",
            (item_id,)).fetchone()
        return int(row["n"])

    def list_batches(self, item_id: int) -> List[Dict[str, Any]]:
        self.get_item(item_id)
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM batches WHERE item_id=? ORDER BY id", (item_id,)).fetchall()
        result = []
        for row in rows:
            batch = dict(row)
            batch["result"] = json.loads(batch.pop("result_json"))
            result.append(batch)
        return result

    def close(self) -> None:
        with self._lock:
            self.conn.close()
