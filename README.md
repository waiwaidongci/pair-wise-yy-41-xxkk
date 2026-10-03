# 桥梁结构监测与限行决策

融合传感、巡检、交通荷载和天气数据，生成限载限行或恢复建议。

## 模块结构

- `app.py`：参数解析、依赖组装和HTTP服务启动。
- `src/domain.py`：数据结构、错误、状态和基础校验。
- `src/rules.py`：状态机、角色矩阵、优先级、期限和关闭不变量。
- `src/repository.py`：SQLite建表、事务、版本控制和审计链。
- `src/service.py`：权限检查、用例编排、并发控制和审计。
- `src/http_api.py`：JSON路由和统一错误响应。
- `src/audit.py`：UTC时间和SHA-256审计事件。
- `static/index.html`：最小演示页。
- `tests/`：完整流程、规则和失败测试。

## 初始化与启动

```bash
python3 app.py --db ./data.db --port 8318
```

默认端口为`8318`，首次启动自动建库。使用`X-Actor`和`X-Role`请求头传递身份。

## 主要接口

- `GET /health`
- `GET /api/items`
- `POST /api/items`，可提交`bridge_ref`标记所属桥梁
- `GET /api/items/{id}`
- `POST /api/items/{id}/records`
- `POST /api/items/{id}/batches`，网关上送监测批次
- `GET /api/items/{id}/batches`
- `POST /api/items/{id}/transition`，必须提交`expected_version`；进入`restricted`/`closed`必须提交`notice_id`
- `POST /api/notices`，`GET /api/notices`，`POST /api/notices/{id}/withdraw`
- `GET /api/audit`

允许角色：sensor_operator, bridge_engineer, traffic_authority, viewer。监测偏差与预警阈值之比和多条异常记录决定告警等级；限行与封闭决策必须绑定同一座桥仍有效的交通通告。

## 批次处置链

- 批次按`(网关号, 批次号)`幂等：同一批次号重传且内容一致时沿用第一次结果（`replayed=true`），不重复落记录、不重复审计。
- 批次内容按序列逐条比对：同一批次号内容不一致，或与其他已接收批次重叠序列内容不一致，整批退回并在`details.conflicts`中指出冲突序列位置。
- 每个网关维护连续序列前沿：起始序列越过前沿即存在缺口，缺口未补齐前不能跳过，`details`给出缺失区间；补齐后可按原批次号恢复续传。
- 批次写入是单事务：写入失败整体回滚，用原批次号重发即可续传；审计链与原始监测记录保持可查。
- 两个网关同时补传时按最新连续序列重算未关闭告警数；迟到的旧批次（不推进前沿）只留监测记录，已升级的限行/封闭不会被降级。
- 进入限行或封闭的告警绑定同桥有效通告；通告撤回或未关闭事项变化后，告警自动退回`warning`重算，并写入`recompute`审计事件。

## 测试

```bash
python3 -m unittest discover -s tests -v
```
