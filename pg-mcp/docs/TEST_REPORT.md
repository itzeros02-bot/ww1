# 测试报告 — SQL 安全链路（AI 辅助测试）

> 项目：pg-mcp 0.2.1 · 测试执行日期：第 1 轮 2026-09-09 · 第 2 轮（评审响应）2026-10-14
> 执行环境：Windows 10 Pro · Python 3.14.7 · sqlglot 28.5.0 · PostgreSQL 16.4 (EDB Advanced Server) @ localhost:5444
> 执行命令：`pytest tests/ --cov=src`（全量）· 一键复跑：`run_tests.bat`

## 1. 结论

| 指标 | 接手基线（第 1 轮前） | 第 1 轮交付 | **第 2 轮当前** | 门禁 | 判定 |
|------|----------------------|------------|----------------|------|------|
| 测试总数 | 294 | 435 | **453** | — | — |
| 通过 / 失败 | 291 / 3（历史遗留失败） | 432 / 3（预存失败未修） | **453 / 0** | 全绿 | ✅ |
| 总覆盖率 | — | 83.77% | **84%** | ≥80% | ✅ |
| sql_validator（安全模块） | — | 91% | **92%** | ≥95%（目标） | ⚠️ 见 §6 遗留项 |
| sql_executor（安全模块） | — | 99% | **99%** | ≥95%（目标） | ✅ |
| 新发现缺陷 | — | 5 个 | 5 个 | — | 4 已修复，1 已知局限 |

> 说明：基线的 3 个失败为 `tests/unit/test_config.py` 的测试隔离缺陷（断言"默认值"却被 `.env` 覆盖），**已在第 2 轮修复**——测试内 `_env_file=None` 隔离本地环境，其中 `log_format` 断言与代码默认值矛盾处一并纠正。当前仓库全量测试 **453 通过 / 0 失败**。

## 2. 交付物

### 第 1 轮（安全对抗测试，2026-09-09）

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

### 第 2 轮（评审主线补齐，2026-10-14，commit `4b62652`）

| 类别 | 文件 | 说明 |
|------|------|------|
| 多数据库支持 | `config/settings.py` + `server.py` + `services/orchestrator.py` | `DATABASE_DATABASES`（附加库）/ `DATABASE_ALL_DATABASES`（实例级自动发现）；每库独立连接池 + 执行器；orchestrator 按请求目标库路由；真实实例冒烟通过（发现 3 库全建池） |
| 安全开关配置化 | `config/settings.py` + `services/sql_validator.py` | 新增 `SECURITY_BLOCKED_TABLES / BLOCKED_COLUMNS / ALLOWED_SCHEMAS / ALLOW_EXPLAIN / ALLOW_EXPLAIN_ANALYZE`，validator 全部默认从 config 注入（原先硬编码）；D2 修复保持默认拒绝，显式开启才放行 |
| 限流配置化 | `config/settings.py` + `server.py` | 新增 `RateLimitConfig`（`RATE_LIMIT_MAX_CONCURRENT_QUERIES=10` / `_LLM=5`），替换硬编码 `MultiRateLimiter(10, 5)` |
| 健壮配置解析 | `config/settings.py` | `NoDecode` + 共享解析器：空串 / 逗号分隔 / JSON 数组三种格式统一支持（修复 Docker 空环境变量崩溃） |
| 配置测试 | `tests/unit/test_config.py` | 修复 3 个失真默认值测试；新增 TestMultiDatabaseConfig（4）/ TestSecurityAccessControlConfig（3）/ TestRateLimitConfig（4） |
| 开关用例 | `tests/security/test_adversarial_validator.py` | 新增 SEC-CFG-001~004 / 011~013 共 7 例，锁定 settings ↔ validator 接线 |
| 文档同步 | `.env.example` / `README.md` / `docker-compose.yml` | 新配置项全部入册（含 `SELECT *` 绕过列黑名单的部署层缓解提示） |

## 3. 缺陷修复验证（修复前 → 修复后）

| 缺陷 | 攻击向量（代表） | 修复前 | 修复后 |
|------|-----------------|--------|--------|
| D1 严重 | `WITH d AS (DELETE FROM users RETURNING *) SELECT * FROM d` | **放行** | 拒绝（12 变体全拦截，良性 CTE 无误报） |
| D2 严重 | `EXPLAIN ANALYZE DELETE FROM users` | **放行且真实执行** | 拒绝（8 变体全拦截，纯 EXPLAIN 不受影响；可经 `SECURITY_ALLOW_EXPLAIN_ANALYZE` 显式开启） |
| D3 中危 | `SELECT * INTO tmp FROM users` | 放行 | 拒绝（TEMP/UNLOGGED 变体含） |
| D4 中危 | `SELECT * FROM users` 绕过列黑名单 | 放行 | 已知局限（行为固化 + 部署层缓解方案） |
| D5 低危 | `SELECT 1\x00`（NUL 字节） | 放行 | 拒绝 |

原单元测试中固化 D2 错误行为的 `test_explain_analyze_allowed` 已重写为 `test_explain_analyze_rejected`。

## 4. 测试执行明细（第 2 轮全量，2026-10-14）

| 套件 | 用例数 | 结果 | 说明 |
|------|--------|------|------|
| `tests/unit` | 259 | **259 通过** | 含既有 56 例 validator 回归 + 修复的 3 个 config 默认值测试 + 新增 11 个配置测试 |
| `tests/security`（对抗套件） | 133 | **133 通过** | 126 例（第 1 轮）+ 7 例 SEC-CFG（第 2 轮） |
| `tests/integration` | 34 | **34 通过** | 15 例新增安全集成（真实 PG）+ 19 例既有 full-flow 回归 |
| `tests/e2e` | 27 | **27 通过** | MCP 协议端到端 |
| **合计** | **453** | **453 / 453（0 失败）** | 3m36s |

覆盖率（关键模块，`--cov=src` 实测）：

| 模块 | 覆盖 | 说明 |
|------|------|------|
| services/sql_validator.py | 92% | 未覆盖行为防御性异常分支（见 §6） |
| services/sql_executor.py | 99% | 0 partial |
| services/orchestrator.py | 97% | |
| config/settings.py | 98% | 第 2 轮新增配置全在测 |
| resilience/circuit_breaker.py | 100% | |
| **总计** | **84%** | 门禁 80% 达标 |

## 5. 主线补齐验证（第 2 轮）

| 评审问题 | 修复 | 验证方式 |
|----------|------|----------|
| settings 仅单库，无 databases/all_databases | `DatabaseConfig.databases` + `all_databases` + `database_names` 属性；server 按配置发现并建池 | 11 个单测 + 真实实例冒烟（发现 `blog_small/edb/postgres` 三库全建池） |
| SecurityConfig 无 blocked_tables/blocked_columns | 五个安全开关入配置，validator 默认从 config 取值 | SEC-CFG-004 接线锁定 |
| 配置与实现脱节 | `allow_explain_analyze` / `allowed_schemas` 在 validator 落地实现 | SEC-CFG-001~003 / 011~013 |
| 限流字段未配置化 | `RateLimitConfig` 全链路接线 | 默认/自定义/非法值 4 测试 |
| orchestrator 只用主库 executor | 新增 `sql_executors` 字典，按解析出的目标库路由执行 | 453 全量回归无破坏（可选参数，向后兼容） |

## 6. 未尽事项（诚实披露）

1. **sql_validator 覆盖率 92% < 95% 目标**：未覆盖行为集中在防御性异常分支（如 `WITH` 无主查询、normalize/extract 的异常路径）。可补 3~5 个直调用例拉满。
2. **D4（SELECT * 绕过列黑名单）**：AST 层无 schema 无法根治，推荐数据库层 `REVOKE SELECT(password) ...` 兜底（见 DEFECT_REPORT.md §D4）。
3. **e2e 套件依赖 OpenAI key**：`.env` 中 `OPENAI_API_KEY` 为占位符，NL→SQL 生成链路的真实 LLM 路径未覆盖（现有 e2e 为宽松断言，可运行但 LLM 分支未验证）。
4. **多库执行的跨库集成用例**：orchestrator 按库路由有单测与冒烟验证，但"一次会话跨两库查询"的端到端用例待真实第二业务库就绪后补充。

## 7. 复现方式

```bash
cd pg-mcp
uv sync --extra dev          # 或直接使用 .venv
run_tests.bat                # Windows 全量
run_tests.bat quick          # 无数据库模式
pytest tests/security -q     # 仅对抗安全套件
```
