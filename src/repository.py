from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from .audit import make_entry, utc_now
from .domain import ConflictError, NotFoundError
from .rules import ID_PREFIX, STATES


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
                    bridge_id INTEGER,
                    notice_id INTEGER,
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
                CREATE TABLE IF NOT EXISTS bridges (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    code TEXT NOT NULL UNIQUE,
                    name TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS monitoring_batches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    batch_no TEXT NOT NULL UNIQUE,
                    gateway_no TEXT NOT NULL,
                    bridge_id INTEGER NOT NULL REFERENCES bridges(id),
                    seq INTEGER NOT NULL,
                    payload TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending'
                        CHECK(status IN ('pending','processed','rejected','archived')),
                    result TEXT,
                    conflict TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    processed_at TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_batches_gateway_seq
                    ON monitoring_batches(gateway_no, bridge_id, seq);
                CREATE TABLE IF NOT EXISTS batch_readings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    batch_id INTEGER NOT NULL REFERENCES monitoring_batches(id) ON DELETE CASCADE,
                    bridge_id INTEGER NOT NULL REFERENCES bridges(id),
                    seq INTEGER NOT NULL,
                    sensor TEXT NOT NULL,
                    metric TEXT NOT NULL,
                    value REAL NOT NULL,
                    threshold REAL NOT NULL,
                    observed_at TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS gateway_cursors (
                    gateway_no TEXT NOT NULL,
                    bridge_id INTEGER NOT NULL REFERENCES bridges(id),
                    continuous_seq INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY(gateway_no, bridge_id)
                );
                CREATE TABLE IF NOT EXISTS traffic_notices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    notice_no TEXT NOT NULL UNIQUE,
                    bridge_id INTEGER NOT NULL REFERENCES bridges(id),
                    status TEXT NOT NULL DEFAULT 'active'
                        CHECK(status IN ('active','withdrawn')),
                    level TEXT NOT NULL CHECK(level IN ('restriction','closure')),
                    items TEXT NOT NULL,
                    effective_from TEXT NOT NULL,
                    effective_to TEXT,
                    version INTEGER NOT NULL DEFAULT 1,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    withdrawn_at TEXT
                );
                CREATE TABLE IF NOT EXISTS bridge_state (
                    bridge_id INTEGER PRIMARY KEY REFERENCES bridges(id),
                    alert_item_id INTEGER REFERENCES items(id),
                    severity TEXT NOT NULL DEFAULT 'normal',
                    reading_count INTEGER NOT NULL DEFAULT 0,
                    exceedance_count INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL
                );
            """)
        # 旧库迁移：items 补充桥梁与通告绑定列
        for stmt in (
            "ALTER TABLE items ADD COLUMN bridge_id INTEGER",
            "ALTER TABLE items ADD COLUMN notice_id INTEGER",
        ):
            try:
                with self._lock, self.conn:
                    self.conn.execute(stmt)
            except sqlite3.OperationalError:
                pass

    @staticmethod
    def _item(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    def create_item(self, title: str, description: str, severity: str,
                    quantity: float, threshold: float, external_ref: Optional[str],
                    actor: str) -> Dict[str, Any]:
        now = utc_now()
        try:
            with self._lock, self.conn:
                cur = self.conn.execute(
                    """INSERT INTO items(title, description, severity, quantity, threshold,
                       status, version, external_ref, created_by, created_at, updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                    (title, description, severity, quantity, threshold, STATES[0], 1,
                     external_ref, actor, now, now),
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
                        actor: str) -> Dict[str, Any]:
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

    def append_audit(self, action: str, entity_type: str, entity_id: int,
                     actor: str, detail: dict) -> Dict[str, Any]:
        with self._lock, self.conn:
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
            event_id = int(cur.lastrowid)
        event["id"] = event_id
        return event

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

    def close(self) -> None:
        with self._lock:
            self.conn.close()

    # ---------------- 桥梁 ----------------

    def create_bridge(self, code: str, name: str, actor: str) -> Dict[str, Any]:
        now = utc_now()
        try:
            with self._lock, self.conn:
                cur = self.conn.execute(
                    "INSERT INTO bridges(code, name, created_by, created_at) VALUES(?,?,?,?)",
                    (code, name, actor, now),
                )
                bridge_id = int(cur.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise ConflictError("桥梁编号已存在") from exc
        return self.find_bridge_by_id(bridge_id)

    def find_bridge_by_id(self, bridge_id: int) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute("SELECT * FROM bridges WHERE id=?", (bridge_id,)).fetchone()
        return dict(row) if row else None

    def find_bridge_by_code(self, code: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute("SELECT * FROM bridges WHERE code=?", (code,)).fetchone()
        return dict(row) if row else None

    def list_bridges(self) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute("SELECT * FROM bridges ORDER BY id").fetchall()
        return [dict(row) for row in rows]

    # ---------------- 监测批次 ----------------

    @staticmethod
    def _batch(row: Optional[sqlite3.Row]) -> Optional[Dict[str, Any]]:
        if row is None:
            return None
        item = dict(row)
        item["payload"] = json.loads(item["payload"])
        if item.get("result"):
            item["result"] = json.loads(item["result"])
        if item.get("conflict"):
            item["conflict"] = json.loads(item["conflict"])
        return item

    def create_batch(self, batch_no: str, gateway_no: str, bridge_id: int, seq: int,
                     payload: Dict[str, Any], payload_hash: str, status: str,
                     actor: str) -> Dict[str, Any]:
        now = utc_now()
        try:
            with self._lock, self.conn:
                cur = self.conn.execute(
                    """INSERT INTO monitoring_batches(batch_no, gateway_no, bridge_id, seq,
                       payload, payload_hash, status, created_by, created_at)
                       VALUES(?,?,?,?,?,?,?,?,?)""",
                    (batch_no, gateway_no, bridge_id, seq, json.dumps(payload, ensure_ascii=False),
                     payload_hash, status, actor, now),
                )
                batch_id = int(cur.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise ConflictError("批次号已存在或该网关序列已被占用") from exc
        return self.find_batch_by_id(batch_id)

    def find_batch_by_id(self, batch_id: int) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM monitoring_batches WHERE id=?", (batch_id,)).fetchone()
            return self._batch(row)

    def find_batch(self, batch_no: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM monitoring_batches WHERE batch_no=?", (batch_no,)).fetchone()
            return self._batch(row)

    def list_batches(self, status: Optional[str] = None,
                     bridge_id: Optional[int] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM monitoring_batches WHERE 1=1"
        params: List[Any] = []
        if status:
            sql += " AND status=?"
            params.append(status)
        if bridge_id:
            sql += " AND bridge_id=?"
            params.append(bridge_id)
        sql += " ORDER BY id"
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        return [self._batch(row) for row in rows]

    def batch_reading_count(self, batch_id: int) -> int:
        with self._lock:
            row = self.conn.execute(
                "SELECT COUNT(*) AS n FROM batch_readings WHERE batch_id=?", (batch_id,)).fetchone()
            return int(row["n"])

    def insert_readings(self, batch_id: int, bridge_id: int,
                        readings: List[Dict[str, Any]]) -> None:
        """写入批次读数；失败时批次行保留为续传锚点，重试按批次号恢复。"""
        now = utc_now()
        with self._lock, self.conn:
            self.conn.executemany(
                """INSERT INTO batch_readings(batch_id, bridge_id, seq, sensor, metric,
                   value, threshold, observed_at, severity, created_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?)""",
                [(batch_id, bridge_id, i, r["sensor"], r["metric"], r["value"],
                  r["threshold"], r["observed_at"], r["severity"], now)
                 for i, r in enumerate(readings)],
            )

    def list_readings(self, bridge_id: int) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM batch_readings WHERE bridge_id=? ORDER BY id", (bridge_id,)
            ).fetchall()
        return [dict(row) for row in rows]

    def list_processed_readings(self, bridge_id: int) -> List[Dict[str, Any]]:
        """只取已处理（进入连续序列）批次的读数；归档的迟到批次不计入重算。"""
        with self._lock:
            rows = self.conn.execute(
                """SELECT br.* FROM batch_readings br
                   JOIN monitoring_batches mb ON mb.id = br.batch_id
                   WHERE br.bridge_id=? AND mb.status='processed'
                   ORDER BY br.id""",
                (bridge_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def find_reading_overlap(self, bridge_id: int, sensor: str, metric: str,
                             observed_at: str) -> Optional[Dict[str, Any]]:
        """跨批次同监测键（传感器+指标+时刻）的重叠读数。"""
        with self._lock:
            row = self.conn.execute(
                """SELECT br.*, mb.batch_no AS batch_no, mb.status AS batch_status
                   FROM batch_readings br
                   JOIN monitoring_batches mb ON mb.id = br.batch_id
                   WHERE br.bridge_id=? AND br.sensor=? AND br.metric=? AND br.observed_at=?
                     AND mb.status IN ('processed','archived')
                   LIMIT 1""",
                (bridge_id, sensor, metric, observed_at),
            ).fetchone()
        return dict(row) if row else None

    def mark_batch_processed(self, batch_id: int, result: Dict[str, Any]) -> None:
        now = utc_now()
        with self._lock, self.conn:
            self.conn.execute(
                "UPDATE monitoring_batches SET status='processed', result=?, processed_at=? WHERE id=?",
                (json.dumps(result, ensure_ascii=False), now, batch_id),
            )

    def mark_batch_archived(self, batch_id: int, result: Dict[str, Any]) -> None:
        now = utc_now()
        with self._lock, self.conn:
            self.conn.execute(
                "UPDATE monitoring_batches SET status='archived', result=?, processed_at=? WHERE id=?",
                (json.dumps(result, ensure_ascii=False), now, batch_id),
            )

    # ---------------- 网关连续序列游标 ----------------

    def get_cursor(self, gateway_no: str, bridge_id: int) -> int:
        with self._lock:
            row = self.conn.execute(
                "SELECT continuous_seq FROM gateway_cursors WHERE gateway_no=? AND bridge_id=?",
                (gateway_no, bridge_id),
            ).fetchone()
        return int(row["continuous_seq"]) if row else 0

    def advance_cursor(self, gateway_no: str, bridge_id: int, seq: int) -> None:
        now = utc_now()
        with self._lock, self.conn:
            self.conn.execute(
                """INSERT INTO gateway_cursors(gateway_no, bridge_id, continuous_seq, updated_at)
                   VALUES(?,?,?,?)
                   ON CONFLICT(gateway_no, bridge_id) DO UPDATE SET
                     continuous_seq=excluded.continuous_seq,
                     updated_at=excluded.updated_at
                   WHERE excluded.continuous_seq > gateway_cursors.continuous_seq""",
                (gateway_no, bridge_id, seq, now),
            )

    def find_pending_batch(self, gateway_no: str, bridge_id: int,
                            seq: int) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute(
                """SELECT * FROM monitoring_batches
                   WHERE gateway_no=? AND bridge_id=? AND seq=? AND status='pending'
                   ORDER BY id LIMIT 1""",
                (gateway_no, bridge_id, seq),
            ).fetchone()
        return self._batch(row)

    # ---------------- 桥状态（连续序列重算结果） ----------------

    def get_bridge_state(self, bridge_id: int) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM bridge_state WHERE bridge_id=?", (bridge_id,)).fetchone()
        return dict(row) if row else None

    def upsert_bridge_state(self, bridge_id: int, alert_item_id: int, severity: str,
                            reading_count: int, exceedance_count: int) -> None:
        now = utc_now()
        with self._lock, self.conn:
            self.conn.execute(
                """INSERT INTO bridge_state(bridge_id, alert_item_id, severity,
                   reading_count, exceedance_count, updated_at)
                   VALUES(?,?,?,?,?,?)
                   ON CONFLICT(bridge_id) DO UPDATE SET
                     alert_item_id=excluded.alert_item_id,
                     severity=excluded.severity,
                     reading_count=excluded.reading_count,
                     exceedance_count=excluded.exceedance_count,
                     updated_at=excluded.updated_at""",
                (bridge_id, alert_item_id, severity, reading_count, exceedance_count, now),
            )

    # ---------------- 交通通告 ----------------

    @staticmethod
    def _notice(row: Optional[sqlite3.Row]) -> Optional[Dict[str, Any]]:
        if row is None:
            return None
        item = dict(row)
        item["items"] = json.loads(item["items"])
        return item

    def create_notice(self, notice_no: str, bridge_id: int, level: str,
                      items: List[str], effective_from: str,
                      effective_to: Optional[str], actor: str) -> Dict[str, Any]:
        now = utc_now()
        try:
            with self._lock, self.conn:
                cur = self.conn.execute(
                    """INSERT INTO traffic_notices(notice_no, bridge_id, status, level, items,
                       effective_from, effective_to, version, created_by, created_at)
                       VALUES(?, ?, 'active', ?, ?, ?, ?, 1, ?, ?)""",
                    (notice_no, bridge_id, level, json.dumps(items, ensure_ascii=False),
                     effective_from, effective_to, actor, now),
                )
                notice_id = int(cur.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise ConflictError("通告编号已存在") from exc
        return self.find_notice_by_id(notice_id)

    def find_notice_by_id(self, notice_id: int) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM traffic_notices WHERE id=?", (notice_id,)).fetchone()
            return self._notice(row)

    def find_notice(self, notice_no: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM traffic_notices WHERE notice_no=?", (notice_no,)).fetchone()
            return self._notice(row)

    def list_notices(self, bridge_id: Optional[int] = None,
                     status: Optional[str] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM traffic_notices WHERE 1=1"
        params: List[Any] = []
        if bridge_id:
            sql += " AND bridge_id=?"
            params.append(bridge_id)
        if status:
            sql += " AND status=?"
            params.append(status)
        sql += " ORDER BY id"
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        return [self._notice(row) for row in rows]

    def withdraw_notice(self, notice_id: int) -> None:
        now = utc_now()
        with self._lock, self.conn:
            self.conn.execute(
                """UPDATE traffic_notices SET status='withdrawn', version=version+1,
                   withdrawn_at=? WHERE id=?""",
                (now, notice_id),
            )

    def update_notice_items(self, notice_id: int, items: List[str]) -> None:
        with self._lock, self.conn:
            self.conn.execute(
                "UPDATE traffic_notices SET items=?, version=version+1 WHERE id=?",
                (json.dumps(items, ensure_ascii=False), notice_id),
            )

    # ---------------- 告警与通告绑定 / 退回 ----------------

    def create_alert(self, bridge_id: int, title: str, severity: str, quantity: float,
                     threshold: float, actor: str) -> int:
        now = utc_now()
        with self._lock, self.conn:
            cur = self.conn.execute(
                """INSERT INTO items(title, description, severity, quantity, threshold,
                   status, version, external_ref, bridge_id, created_by, created_at, updated_at)
                   VALUES(?,?,?,?,?, 'normal', 1, ?, ?, ?, ?, ?)""",
                (title, "网关监测批次自动生成的结构告警", severity, quantity, threshold,
                 f"ALERT:{bridge_id}", bridge_id, actor, now, now),
            )
            return int(cur.lastrowid)

    def update_alert(self, item_id: int, severity: str, quantity: float,
                     threshold: float, escalate: bool) -> None:
        now = utc_now()
        with self._lock, self.conn:
            if escalate:
                self.conn.execute(
                    """UPDATE items SET severity=?, quantity=?, threshold=?, status='warning',
                       version=version+1, updated_at=?
                       WHERE id=? AND status='normal'""",
                    (severity, quantity, threshold, now, item_id),
                )
            else:
                self.conn.execute(
                    "UPDATE items SET severity=?, quantity=?, threshold=?, updated_at=? WHERE id=?",
                    (severity, quantity, threshold, now, item_id),
                )

    def bind_item_notice(self, item_id: int, notice_id: int) -> None:
        with self._lock, self.conn:
            self.conn.execute(
                "UPDATE items SET notice_id=? WHERE id=?", (notice_id, item_id))

    def rollback_item(self, item_id: int) -> None:
        now = utc_now()
        with self._lock, self.conn:
            self.conn.execute(
                """UPDATE items SET status='warning', notice_id=NULL, version=version+1,
                   updated_at=? WHERE id=?""",
                (now, item_id),
            )

    def list_items_by_notice(self, notice_id: int) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM items WHERE notice_id=? AND status IN ('restricted','closed')",
                (notice_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def list_alerts(self) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM items WHERE bridge_id IS NOT NULL ORDER BY id DESC"
            ).fetchall()
        return [dict(row) for row in rows]
