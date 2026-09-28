# SQL 安全链路测试用例矩阵

> 项目：pg-mcp（PostgreSQL MCP Server）
> 被测对象：`src/pg_mcp/services/sql_validator.py`（第一道防线）+ `sql_executor.py`（第二道防线）
> 用例生成方式：AI 辅助生成（对抗性输入枚举 + 等价类/边界值分析），人工评审确认
> 关联文档：[DEFECT_REPORT.md](DEFECT_REPORT.md) · [TEST_REPORT.md](TEST_REPORT.md)

## 1. 测试范围与策略

| 层级 | 模块 | 测试类型 | 用例文件 |
|------|------|----------|----------|
| L1 校验 | SQLValidator | 单元/安全（纯函数，无需 DB） | `tests/security/test_adversarial_validator.py` |
| L2 执行 | SQLExecutor | 集成（真实 PostgreSQL） | `tests/integration/test_security_integration.py` |
| 回归 | 既有 56 例 | 单元 | `tests/unit/test_sql_validator.py` |

设计技术：**错误推测/对抗性枚举**（攻击者视角）、**等价类划分**（合法 SELECT / 非法 DDL+DML / 混淆变体）、**边界值**（行数上限、超时阈值、超长输入、NUL 字节）。

## 2. 用例矩阵（安全对抗，`tests/security/`）

> 完整参数化清单见测试文件，此处列出每组代表用例。**结果**列为修复后最终状态。

### SEC-CTE 数据修改 CTE（关联 DEFECT-01，严重）

| 用例 ID | 输入（代表） | 预期 | 结果 |
|---------|-------------|------|------|
| SEC-CTE-001 | `WITH d AS (DELETE FROM users RETURNING *) SELECT * FROM d` | 拒绝 | ✅ 拒绝（修复前**放行**） |
| SEC-CTE-002 | `WITH d AS (DELETE FROM users) SELECT 1` | 拒绝 | ✅ 拒绝（修复前**放行**） |
| SEC-CTE-003~005 | INSERT/UPDATE 形式 CTE | 拒绝 | ✅ 拒绝（修复前**放行**） |
| SEC-CTE-006 | 多 CTE 混合（读+写） | 拒绝 | ✅ 拒绝 |
| SEC-CTE-007~008 | CTE 嵌套子查询 / 嵌套 CTE | 拒绝 | ✅ 拒绝 |
| SEC-CTE-010~011 | CTE 内 DROP / CREATE TABLE AS | 拒绝 | ✅ 拒绝 |
| SEC-CTE-012 | 全小写变体 | 拒绝 | ✅ 拒绝 |
| SEC-CTE-101~103 | 良性只读 CTE（含 RECURSIVE） | 放行 | ✅ 放行（无误报） |

### SEC-EXP EXPLAIN 执行绕过（关联 DEFECT-02，严重）

| 用例 ID | 输入（代表） | 预期 | 结果 |
|---------|-------------|------|------|
| SEC-EXP-001~003 | `EXPLAIN ANALYZE DELETE/UPDATE/INSERT ...` | 拒绝 | ✅ 拒绝（修复前**放行并会真实执行**） |
| SEC-EXP-004~005 | `EXPLAIN (ANALYZE ...)` 括号选项形式 | 拒绝 | ✅ 拒绝 |
| SEC-EXP-006~008 | 小写 / 多空白变体 | 拒绝 | ✅ 拒绝 |
| SEC-EXP-101 | 纯 `EXPLAIN SELECT`（仅生成计划） | 放行 | ✅ 放行（无误报） |
| SEC-EXP-102 | 默认配置下任何 EXPLAIN | 拒绝 | ✅ 拒绝 |

### SEC-INTO SELECT INTO 建表（关联 DEFECT-03，中危）

| 用例 ID | 输入 | 预期 | 结果 |
|---------|------|------|------|
| SEC-INTO-001~003 | `SELECT * INTO tmp FROM users`（含 TEMP/UNLOGGED） | 拒绝 | ✅ 拒绝（修复前**放行**） |
| SEC-INTO-101 | `into` 作普通列名前缀（`into_col`） | 放行 | ✅ 放行（无误报） |

### SEC-COL SELECT * 绕过列黑名单（关联 DEFECT-04，中危·已知局限）

| 用例 ID | 输入 | 预期 | 结果 |
|---------|------|------|------|
| SEC-COL-001 | 黑名单含 `password` 时 `SELECT * FROM users` | 拒绝（理想） | ⚠️ 放行 — **已知局限**，需 schema 感知或 DB 列级授权（`REVOKE`） |
| SEC-COL-002~003 | 显式/限定列名引用 | 拒绝 | ✅ 拒绝 |
| SEC-COL-004 | `users.*` 形式 | 拒绝（理想） | ⚠️ 放行 — 同 DEFECT-04 |

### SEC-FN 危险函数混淆

| 用例 ID | 输入（代表） | 预期 | 结果 |
|---------|-------------|------|------|
| SEC-FN-001~005 | `pg_sleep` 原样/大小写/双引号 | 拒绝 | ✅ 拒绝 |
| SEC-FN-006~007 | `pg_catalog.pg_sleep` schema 限定 | 拒绝 | ✅ 拒绝 |
| SEC-FN-008~010 | 注释穿插/多余空白 | 拒绝 | ✅ 拒绝 |
| SEC-FN-011~014 | 子查询/ORDER BY/CTE/CASE 内调用 | 拒绝 | ✅ 拒绝 |
| SEC-FN-015~018 | `lo_export`/`dblink`/`pg_read_file`/`pg_terminate_backend` | 拒绝 | ✅ 拒绝 |
| SEC-FN-019 | 配置黑名单大小写不敏感 | 拒绝 | ✅ 拒绝 |
| SEC-FN-101~105 | 良性函数（count/lower/now 等） | 放行 | ✅ 放行 |

### SEC-SMUG 语句走私（sqlglot 语法回退路径）

PREPARE、EXECUTE、CALL、DO 匿名块、VACUUM、SET、BEGIN/COMMIT、FETCH/CLOSE/DECLARE 游标、CREATE TABLE AS、TRUNCATE、REINDEX、CHECKPOINT、CLUSTER、COMMENT、LISTEN/NOTIFY、INSERT、UPDATE、DELETE、DROP、ALTER、GRANT/REVOKE、MERGE —— **27 例全部拒绝** ✅（SEC-SMUG-001~027）

### SEC-MS 多语句与注入载荷

| 用例 ID | 输入 | 预期 | 结果 |
|---------|------|------|------|
| SEC-MS-001~003 | `SELECT 1; DROP/DELETE/INSERT ...` | 拒绝 | ✅ 拒绝 |
| SEC-MS-004~005 | `;;;` / `SELECT 1;;SELECT 2` | 拒绝 | ✅ 拒绝 |
| SEC-MS-101~104 | 语句后尾随注释 / 尾分号 / 空白（合法单语句） | 放行 | ✅ 放行（无误报） |

### SEC-TBL / SEC-COL 表与列访问控制

黑名单表 10 种变体（大小写、双引号、schema 限定、JOIN、子查询、CTE）全部拒绝 ✅；非黑名单表/列放行 ✅。

### SEC-EDGE 解析器边界

| 用例 ID | 输入 | 预期 | 结果 |
|---------|------|------|------|
| SEC-EDGE-001~004 | 空/空白/纯注释 | 拒绝 | ✅ 拒绝 |
| SEC-EDGE-005 | 裸 `SELECT`（sqlglot 宽松解析） | — | ✅ 放行已固化（PG 端仍会拒，非安全洞） |
| SEC-EDGE-006~008 | 残缺/乱语法 | 拒绝 | ✅ 拒绝 |
| SEC-EDGE-009 | `SELECT 1\x00`（NUL 字节） | 拒绝 | ✅ 拒绝（加固前**放行**，见 DEFECT-05） |
| SEC-EDGE-010 | 1 MB 超长查询 | 给出判定不崩溃 | ✅ 通过 |
| SEC-EDGE-101~104 | Unicode 转义串/dollar-quote/中文 | 放行 | ✅ 放行 |

## 3. 用例矩阵（集成，`tests/integration/`，真实 PostgreSQL）

| 用例 ID | 场景 | 验证点 | 结果 |
|---------|------|--------|------|
| SEC-INT-001 | 直连执行 DELETE | 抛 DatabaseError，行数不变 | ✅ |
| SEC-INT-002 | 写 CTE 执行（假设 L1 失守） | 只读事务拦截，数据不变 | ✅ |
| SEC-INT-003 | SELECT INTO 执行 | 建表失败且 `hacked_users` 不存在 | ✅ |
| SEC-INT-004~005 | UPDATE / INSERT | 拦截 | ✅ |
| SEC-INT-006 | 行数上限截断 | 返回 10 行、总数如实报告 50 | ✅ |
| SEC-INT-007 | 默认上限 10000 | 12000 行截断至 10000，总数 12000 | ✅ |
| SEC-INT-008 | 查询超时（pg_sleep 10s / timeout 1s） | ExecutionTimeoutError | ✅ |
| SEC-INT-009 | 快速查询 + 超时配置 | 正常返回 | ✅ |
| SEC-INT-010 | timestamp/numeric/uuid/bool 序列化 | ISO 串/float/str/bool | ✅ |
| SEC-INT-011 | NULL 序列化 | None | ✅ |
| SEC-INT-012 | 中文文本往返 | 无乱码 | ✅ |
| SEC-INT-013 | 校验通过 → 执行（端到端正向） | 有数据返回 | ✅ |
| SEC-INT-014 | 校验拒绝 → 不触达 DB | 短路 | ✅ |
| SEC-INT-015 | schema 限定读取 | 与基准计数一致 | ✅ |

## 4. 统计

| 指标 | 数量 |
|------|------|
| 对抗安全用例（新增） | 126 |
| 集成用例（新增） | 15 |
| 既有回归用例 | 294 |
| **总计** | **435** |
| 发现缺陷 | 5（4 个已修复，1 个已知局限，见 DEFECT_REPORT.md） |
