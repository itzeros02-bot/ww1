# 测试报告 — SQL 安全链路（AI 辅助测试）

> 项目：pg-mcp 0.2.1 · 测试执行日期：第 1 轮 2026-09-09 · 第 2 轮（评审响应）2026-10-14
> 执行环境：Windows 10 Pro · Python 3.14.7 · sqlglot 28.5.0 · PostgreSQL 16.4 (EDB Advanced Server) @ localhost:5444
> 执行命令：`pytest tests/ --cov=src`（全量）· 一键复跑：`run_tests.bat`

## 1. 结论

| 指标 | 接手基线（第 1 轮前） | 第 1 轮交付 | **第 3 轮当前（2026-10-15）** | 门禁 | 判定 |
|------|----------------------|------------|------------------------------|------|------|
| 测试总数 | 294 | 435 | **461** | — | — |
| 通过 / 失败 | 291 / 3（历史遗留失败） | 432 / 3（预存失败未修） | **461 / 0** | 全绿 | ✅ |
| 总覆盖率 | — | 83.77% | **85%** | ≥80% | ✅ |
| sql_validator（安全模块） | — | 91% | **100%**（148/148 行 + 分支全覆盖） | ≥95% | ✅ |
| sql_executor（安全模块） | — | 99% | **99%** | ≥95% | ✅ |
| 新发现缺陷 | — | 5 个 | 5 个 | — | 4 已修复，1 已知局限 |

> 说明：基线的 3 个失败为 `tests/unit/test_config.py` 的测试隔离缺陷（断言"默认值"却被 `.env` 覆盖），已在第 2 轮修复——测试内 `_env_file=None` 隔离本地环境，其中 `log_format` 断言与代码默认值矛盾处一并纠正。第 3 轮补齐 validator 防御分支用例后，安全模块门禁全部达标，仓库全量测试 **461 通过 / 0 失败**。

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

### 第 3 轮（安全门禁收口，2026-10-15）

| 类别 | 文件 | 说明 |
|------|------|------|
| 防御分支用例 | `tests/unit/test_sql_validator.py` | 新增 `TestDefensiveBranches` 8 例：空解析结果、无主查询 WITH、非 SELECT 子查询体、顶级 WITH 主查询、禁语句直调检查、无名 Table 遍历等——全部为公开输入难达的防御性路径（AST 注入 + 解析器打桩），sql_validator 覆盖率 92% → **100%**，安全模块 ≥95% 门禁达成 |

## 3. 缺陷修复验证（修复前 → 修复后）

| 缺陷 | 攻击向量（代表） | 修复前 | 修复后 |
|------|-----------------|--------|--------|
| D1 严重 | `WITH d AS (DELETE FROM users RETURNING *) SELECT * FROM d` | **放行** | 拒绝（12 变体全拦截，良性 CTE 无误报） |
| D2 严重 | `EXPLAIN ANALYZE DELETE FROM users` | **放行且真实执行** | 拒绝（8 变体全拦截，纯 EXPLAIN 不受影响；可经 `SECURITY_ALLOW_EXPLAIN_ANALYZE` 显式开启） |
| D3 中危 | `SELECT * INTO tmp FROM users` | 放行 | 拒绝（TEMP/UNLOGGED 变体含） |
| D4 中危 | `SELECT * FROM users` 绕过列黑名单 | 放行 | 已知局限（行为固化 + 部署层缓解方案） |
| D5 低危 | `SELECT 1\x00`（NUL 字节） | 放行 | 拒绝 |

原单元测试中固化 D2 错误行为的 `test_explain_analyze_allowed` 已重写为 `test_explain_analyze_rejected`。

## 4. 测试执行明细（第 3 轮全量，2026-10-15）

| 套件 | 用例数 | 结果 | 说明 |
|------|--------|------|------|
| `tests/unit` | 267 | **267 通过** | 含既有 56 例 validator 回归 + 修复的 3 个 config 默认值测试 + 11 个配置测试 + 8 个防御分支测试 |
| `tests/security`（对抗套件） | 133 | **133 通过** | 126 例（第 1 轮）+ 7 例 SEC-CFG（第 2 轮） |
| `tests/integration` | 34 | **34 通过** | 15 例新增安全集成（真实 PG）+ 19 例既有 full-flow 回归 |
| `tests/e2e` | 27 | **27 通过** | MCP 协议端到端 |
| **合计** | **461** | **461 / 461（0 失败）** | 3m35s |

覆盖率（关键模块，`--cov=src` 实测）：

| 模块 | 覆盖 | 说明 |
|------|------|------|
| services/sql_validator.py | **100%** | 148/148 行 + 分支全覆盖（第 3 轮补齐防御路径） |
| services/sql_executor.py | 99% | |
| config/settings.py | 98% | |
| services/orchestrator.py | 97% | |
| resilience/circuit_breaker.py | 100% | |
| **总计** | **85%** | 门禁 80% 达标；未覆盖部分集中在真实进程入口 / LLM 路径 / 可观测性设施（见 §6） |

## 5. 主线补齐验证（第 2 轮）

| 评审问题 | 修复 | 验证方式 |
|----------|------|----------|
| settings 仅单库，无 databases/all_databases | `DatabaseConfig.databases` + `all_databases` + `database_names` 属性；server 按配置发现并建池 | 11 个单测 + 真实实例冒烟（发现 `blog_small/edb/postgres` 三库全建池） |
| SecurityConfig 无 blocked_tables/blocked_columns | 五个安全开关入配置，validator 默认从 config 取值 | SEC-CFG-004 接线锁定 |
| 配置与实现脱节 | `allow_explain_analyze` / `allowed_schemas` 在 validator 落地实现 | SEC-CFG-001~003 / 011~013 |
| 限流字段未配置化 | `RateLimitConfig` 全链路接线 | 默认/自定义/非法值 4 测试 |
| orchestrator 只用主库 executor | 新增 `sql_executors` 字典，按解析出的目标库路由执行 | 453 全量回归无破坏（可选参数，向后兼容） |

## 6. 未尽事项（诚实披露）

1. **D4（SELECT * 绕过列黑名单）**：AST 层无 schema 无法根治，推荐数据库层 `REVOKE SELECT(password) ...` 兜底（见 DEFECT_REPORT.md §D4）。
2. **e2e 套件依赖 OpenAI key**：`.env` 中 `OPENAI_API_KEY` 为占位符，NL→SQL 生成链路的真实 LLM 路径未覆盖（现有 e2e 为宽松断言，可运行但 LLM 分支未验证）。
3. **多库执行的跨库集成用例**：orchestrator 按库路由有单测与冒烟验证，但"一次会话跨两库查询"的端到端用例待真实第二业务库就绪后补充。
4. **总覆盖率 85% 而非 100%**：剩余未覆盖行为真实进程入口（`__main__`/lifespan）、真实 LLM 路径、可观测性设施（tracing/logging/metrics）——属于"测 mock 而非测代码"的范畴，刻意不追（详见 §1 门禁策略：总体 ≥80% 达标，安全模块 ≥95% 已 100% 达标）。

## 7. 复现方式

```bash
cd pg-mcp
uv sync --extra dev          # 或直接使用 .venv
run_tests.bat                # Windows 全量
run_tests.bat quick          # 无数据库模式
pytest tests/security -q     # 仅对抗安全套件
```
