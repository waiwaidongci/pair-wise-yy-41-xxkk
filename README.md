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
- `POST /api/items`
- `GET /api/items/{id}`
- `POST /api/items/{id}/records`
- `POST /api/items/{id}/transition`，必须提交`expected_version`
- `GET /api/audit`
- `GET /api/bridges`、`POST /api/bridges`
- `GET /api/batches`（可按`status`、`bridge_code`过滤）、`POST /api/batches`、`GET /api/batches/{batch_no}`
- `GET /api/notices`、`POST /api/notices`、`POST /api/notices/{notice_no}/withdraw`、`POST /api/notices/{notice_no}/items`
- `GET /api/alerts`

允许角色：sensor_operator, bridge_engineer, traffic_authority, viewer。监测偏差与预警阈值之比和多条异常记录决定告警等级；限行与封闭决策必须绑定交通通告记录。

## 批次链接入规则

- 批次带`batch_no`、`gateway_no`、`bridge_code`、`seq`（网关内序列）。同一批次号重传且内容一致时沿用第一次结果；内容不一致则整批退回并指出冲突位置（读数下标/字段/既有值/新值）。
- 序列缺口未补齐前批次挂起（`pending`），不得跳过；补齐后按序排空。两个网关同时补传时，告警数量与等级按各网关最新连续序列重算，等级只升不降。
- 迟到的旧批次（新批次号复用旧序列）只归档为监测记录（`archived`），不参与重算，不能把已升级告警降级。
- 进入限行或封闭的告警必须绑定同一座桥仍有效的交通通告（closure 覆盖封闭+限行，restriction 只覆盖限行）；通告撤回或未关闭事项变化后，相关告警退回预警并重算。
- 写入失败后批次锚点保留为`pending`，按原批次号重传即从断点续传；审计哈希链与批次、读数、通告记录始终可查。

## 测试

```bash
python3 -m unittest discover -s tests -v
```
