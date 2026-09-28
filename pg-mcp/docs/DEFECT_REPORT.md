# 缺陷报告 — SQL 安全验证链路

> 发现方式：AI 对抗性测试用例生成（`tests/security/test_adversarial_validator.py`）
> 测试环境：Windows 10 / Python 3.14 / sqlglot 28.5.0 / PostgreSQL 16.4 (EDB)
> 状态标记：✅ 已修复 · ⚠️ 已知局限

---

## DEFECT-01（严重）数据修改 CTE 绕过只读校验

- **状态**：✅ 已修复
- **位置**：`src/pg_mcp/services/sql_validator.py` → `validate_or_raise()`
- **描述**：PostgreSQL 允许在 CTE 中执行 DML（`WITH d AS (DELETE FROM users RETURNING *) SELECT * FROM d`），整条语句顶层是 SELECT。原实现的 `_check_statement_type` 只检查语法树根节点，`_check_subquery_safety` 只遍历 `exp.Subquery` 节点，而 CTE 是 `exp.CTE` 节点——写操作因此完全绕过校验。
- **复现**：`WITH i AS (INSERT INTO users VALUES (1) RETURNING *) SELECT * FROM i` → 修复前返回"校验通过"
- **影响**：绕过第一道防线。若第二道防线（executor 只读事务）同样失守或未来被移除，即可任意写库。
- **修复**：新增 `_check_tree_for_forbidden()`，`statement.walk()` 全树递归扫描 `FORBIDDEN_STATEMENT_TYPES`，CTE/子查询/嵌套表达式内的 DML/DDL 一律拒绝。
- **回归**：SEC-CTE-001~012 全部拒绝；良性只读 CTE（SEC-CTE-101~103）不受影响。

## DEFECT-02（严重）EXPLAIN ANALYZE 真实执行内部语句

- **状态**：✅ 已修复
- **位置**：`sql_validator.py` → EXPLAIN 分支
- **描述**：`EXPLAIN <stmt>` 只生成执行计划、不执行语句，是安全的；但 **`EXPLAIN ANALYZE <stmt>` 会真实执行语句**。原实现（及其单元测试 `test_explain_analyze_allowed`）将一切 EXPLAIN 视为安全，且因 sqlglot 对 EXPLAIN 语法回退为 `Command` 节点而不检查内部 SQL。
- **复现**：`EXPLAIN ANALYZE DELETE FROM users`（`allow_explain=True` 时）→ 修复前放行且**删除真实发生**
- **影响**：配置允许 EXPLAIN 时可执行任意写操作；即使 executor 只读事务会拦截，`EXPLAIN ANALYZE SELECT pg_terminate_backend(pid)` 这类有副作用的函数调用也是暴露面。
- **修复**：EXPLAIN 分支检查 `statement.expression` 原文，包含 `ANALYZE` 关键字（大小写不敏感）即拒绝。fail-closed：极端情况下字符串字面量含 "ANALYZE" 的良性 EXPLAIN 也会被拒（安全优先）。
- **附带修正**：原单元测试 `test_explain_analyze_allowed` 固化了错误行为，已重写为 `test_explain_analyze_rejected`（这本身是一个值得记录的发现——**错误的安全假设被测试固化**）。

## DEFECT-03（中危）SELECT INTO 建表绕过

- **状态**：✅ 已修复
- **位置**：`sql_validator.py` → `_check_statement_type()`
- **描述**：`SELECT * INTO tmp FROM users` 在 sqlglot 中解析为 `exp.Select`（带 `into` 参数），通过顶层类型检查。该语句会创建新表。
- **影响**：越权建表（数据外带/持久化），executor 只读事务可兜底拦截。
- **修复**：`_check_statement_type` 中检测 `exp.Select.args["into"]`，存在即拒绝。`into_col` 这类普通标识符不受影响（SEC-INTO-101 无误报）。

## DEFECT-04（中危·已知局限）SELECT * 绕过列黑名单

- **状态**：⚠️ 已知局限，未修复
- **位置**：`sql_validator.py` → `_check_blocked_columns()`
- **描述**：列黑名单基于 AST 中的显式 `exp.Column` 引用。`SELECT * FROM users` 无显式列引用，星号在服务端展开，黑名单列（如 `password`）照样返回。`users.*` 同理。
- **影响**：若把列黑名单当作敏感列保护的唯一手段，存在数据泄露。表/行级控制不受影响。
- **缓解（现状）**：第二道防线不针对此问题——这是**纵深防御中的真实缺口**。
- **建议方案**（任选其一）：
  1. 校验器注入 schema 信息，遇星号时展开为物理列后再比对黑名单（推荐）；
  2. 数据库层 `REVOKE SELECT(password) ON users FROM readonly_role`（最可靠，零代码）；
  3. 配置 blocked_columns 时直接拒绝含 `*` 的查询（最保守，误杀率高）。
- **测试固化**：SEC-COL-001/004 将当前行为固化，防止未来静默变化。

## DEFECT-05（低危）NUL 字节未被拒绝

- **状态**：✅ 已修复（加固）
- **位置**：`sql_validator.py` → `validate_or_raise()`
- **描述**：`SELECT 1\x00` 被 sqlglot 宽松接受并校验通过。SQL 文本中 NUL 永远非法，且部分下游 C/Rust 层可能在 NUL 处截断输入。
- **修复**：入口处显式检查 `"\x00" in sql`，命中即抛 `SQLParseError`（fail-closed）。

---

## 防御纵深评估

| 防线 | 机制 | 修复前状态 | 修复后状态 |
|------|------|-----------|-----------|
| L1 校验 | SQLValidator（AST 白名单） | 4 处可绕过 | 对抗套件 126 例全绿（D4 列黑名单除外） |
| L2 执行 | 只读事务 + statement_timeout + search_path | 有效 | 有效（SEC-INT-001~005 实测拦截） |
| L3 配置 | blocked_functions 黑名单 | 有效 | 有效 |

## 经验教训

1. **顶层类型检查 ≠ 语义安全**：PostgreSQL 中"看起来是 SELECT 的语句"可以通过 CTE 携带任意写操作，必须全树检查。
2. **"只读"子命令可能有副作用**：EXPLAIN 安全但 EXPLAIN ANALYZE 不安全，差异只在选项里。
3. **错误的安全假设会被测试固化**：原测试套件明确断言 `EXPLAIN ANALYZE` 放行——测试写错了比没有测试更危险。
4. **黑名单类控制需要 schema 感知才能对抗通配符**：纯 AST 检查对 `SELECT *` 无能为力。
