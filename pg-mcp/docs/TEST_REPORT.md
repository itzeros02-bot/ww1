# 测试报告 — SQL 安全链路（AI 辅助测试）

> 项目：pg-mcp 0.2.1 · 测试执行日期：2026-09-09
> 执行环境：Windows 10 Pro · Python 3.14.7 · sqlglot 28.5.0 · PostgreSQL 16.4 (EDB Advanced Server) @ localhost:5444
> 执行命令：`pytest tests/ --cov=src`（全量）· 一键复跑：`run_tests.bat`

## 1. 结论

| 指标 | 结果 | 门禁 | 判定 |
|------|------|------|------|
| 测试总数 | 435 | — | — |
| 通过 | **432** | 全绿目标 | ⚠️ 3 失败（预存，非本次范围，见 §5） |
| 失败 | 3（基线即存在） | — | 与安全无关 |
| 总覆盖率 | **83.77%** | ≥80% | ✅ |
| sql_validator（安全模块） | 91% | ≥95%（目标） | ⚠️ 见 §6 遗留项 |
| sql_executor（安全模块） | **99%** | ≥95%（目标） | ✅ |
| 新发现缺陷 | 5 个 | — | 4 已修复，1 已知局限 |

## 2. 本次交付物

| 类别 | 文件 | 说明 |
|------|------|------|
| 对抗测试套件 | `tests/security/test_adversarial_validator.py` | 126 用例：CTE 写逃逸、EXPLAIN ANALYZE、SELECT INTO、函数混淆、语句走私、多语句注入、边界/健壮性 |
| 集成测试 | `tests/integration/test_security_integration.py` | 15 用例：真实 PG 上验证只读事务、行数上限、超时、类型序列化、端到端链路 |
| 缺陷修复 | `src/pg_mcp/services/sql_validator.py` | D1 全树递归检查 / D2 EXPLAIN ANALYZE 拒绝 / D3 SELECT INTO 拒绝 / D5 NUL 字节拒绝 |
| 用例矩阵 | `docs/TEST_CASES.md` | 全量用例 ID ↔ 输入 ↔ 预期 ↔ 结果，含设计技术映射 |
| 缺陷报告 | `docs/DEFECT_REPORT.md` | 5 个缺陷的复现、影响、修复、纵深防御评估 |
| 部署方案 | `deployment/DEPLOYMENT.md` | 环境矩阵 / 本地一键 / CI / Docker / 生产要点 |
| CI 流水线 | `.github/workflows/test.yml` | lint → unit → security → integration(真实 PG service) → coverage 门禁 |
| 一键脚本 | `run_tests.bat` / `run_tests.sh` | lint + 单测 + 安全 + 集成，`quick` 模式免数据库 |

## 3. 缺陷修复验证（修复前 → 修复后）

| 缺陷 | 攻击向量（代表） | 修复前 | 修复后 |
|------|-----------------|--------|--------|
| D1 严重 | `WITH d AS (DELETE FROM users RETURNING *) SELECT * FROM d` | **放行** | 拒绝（12 变体全拦截，良性 CTE 无误报） |
| D2 严重 | `EXPLAIN ANALYZE DELETE FROM users` | **放行且真实执行** | 拒绝（8 变体全拦截，纯 EXPLAIN 不受影响） |
| D3 中危 | `SELECT * INTO tmp FROM users` | 放行 | 拒绝（TEMP/UNLOGGED 变体含） |
| D4 中危 | `SELECT * FROM users` 绕过列黑名单 | 放行 | 已知局限（行为固化 + 部署层缓解方案） |
| D5 低危 | `SELECT 1\x00`（NUL 字节） | 放行 | 拒绝 |

原单元测试中固化 D2 错误行为的 `test_explain_analyze_allowed` 已重写为 `test_explain_analyze_rejected`。

## 4. 测试执行明细

| 套件 | 用例数 | 结果 | 耗时 |
|------|--------|------|------|
| `tests/unit`（含既有 56 例 validator 回归） | 294 | 291 通过 / 3 失败（预存） | ~195s |
| `tests/security`（新增对抗套件） | 126 | **126 通过** | ~19s |
| `tests/integration/test_security_integration.py`（新增，真实 PG） | 15 | **15 通过** | ~11s |
| **合计** | **435** | **432 / 435** | 3m30s |

覆盖率（关键模块）：

| 模块 | 行覆盖 | 分支 |
|------|--------|------|
| services/sql_validator.py | 91% | 82 stmts 面上 8 partial |
| services/sql_executor.py | 99% | 0 partial |
| services/orchestrator.py | 96% | 2 partial |
| resilience/circuit_breaker.py | 100% | 0 partial |
| **总计** | **83.77%** | 门禁 80% 达标 |

## 5. 未尽事项（诚实披露）

1. **3 个预存失败**（`tests/unit/test_config.py`）：断言"默认值"，但 `SettingsConfigDict` 会读取 `.env`（端口 5444、log_format=text）覆盖默认值——是**测试隔离缺陷**，非功能缺陷。本次不在范围内未修；建议修法：测试内 `monkeypatch.delenv` + 隔离 env_file，或 CI 中不挂载 .env。
2. **sql_validator 覆盖率 91% < 95% 目标**：未覆盖的 10 行集中在防御性异常分支（如 `WITH` 无主查询、normalize/extract 的异常路径）。可补 3~5 个直调用例拉满。
3. **D4（SELECT * 绕过列黑名单）**：AST 层无 schema 无法根治，推荐数据库层 `REVOKE SELECT(password) ...` 兜底（见 DEFECT_REPORT.md §D4）。
4. **e2e 套件依赖 OpenAI key**：`.env` 中 `OPENAI_API_KEY` 为占位符，NL→SQL 生成链路的真实 LLM 路径未在本轮覆盖（现有 e2e 测试为宽松断言，可运行但 LLM 分支未验证）。

## 6. 复现方式

```bash
cd pg-mcp
uv sync --extra dev          # 或直接使用 .venv
run_tests.bat                # Windows 全量
run_tests.bat quick          # 无数据库模式
pytest tests/security -q     # 仅对抗安全套件
```
