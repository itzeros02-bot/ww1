# 部署方案 — pg-mcp 测试与运行环境

> 适用版本：pg-mcp 0.2.1 · Windows/Linux · Python 3.14 (uv 管理)
> 本方案覆盖三层环境：本地开发、CI 流水线、Docker 容器化。

## 1. 环境矩阵

| 环境 | 用途 | 数据库 | 触发方式 | 入口 |
|------|------|--------|----------|------|
| local-dev | 日常开发/调试 | 本机 PostgreSQL（本项目：EDB 16.4 @ localhost:5444） | 手动 | `run_tests.bat` / `run_tests.sh` |
| ci | PR 门禁 | CI 服务容器（postgres:16-alpine） | push/PR 自动 | `.github/workflows/test.yml` |
| docker-test | 隔离集成验证 | docker-compose 内 postgres | 手动 | `docker compose --profile test up` |
| production | 对外服务 | 托管 PostgreSQL | 发布流程 | `docker-compose.yml`（仓库根目录） |

## 2. 本地一键运行（Windows / Linux）

```bat
:: Windows
run_tests.bat            :: 全量：lint → 单元 → 安全 → 集成 → 覆盖率
run_tests.bat quick      :: 跳过集成（无数据库时）
```

```bash
# Linux / macOS
./run_tests.sh           # 全量
./run_tests.sh quick     # 跳过集成
```

前置条件：
1. `uv sync --extra dev` 安装依赖（含 pytest/ruff/coverage）；
2. `.env` 中 `DATABASE_*` 指向可用的 PostgreSQL（当前本地环境：`localhost:5444/blog_small`，EDB Postgres 16.4 已作为 Windows 服务运行）；
3. 集成测试在数据库不可达时**自动 skip**，不阻塞其余测试。

## 3. CI 流水线（GitHub Actions）

`.github/workflows/test.yml`，流程：

```
push / PR ──► lint (ruff check + format)
         ──► unit        （无外部依赖，秒级反馈）
         ──► security    （对抗套件，纯函数）
         ──► integration （services: postgres:16-alpine 起真实库）
         ──► coverage    （汇总报告，<80% 失败，artifact 留存）
```

关键设计：
- **数据库即服务容器**：CI 中以 `services.postgres` 提供 postgres:16-alpine，健康检查通过后才跑集成测试；
- **分层失败隔离**：四个 job 并行，任一失败即 PR 红灯，且能从 job 名直接定位是哪层失守；
- **覆盖率门禁**：`--cov-fail-under=80`（pyproject 已配置），报告上传 artifact 供回溯；
- **安全套件永远执行**：security job 不依赖数据库，任何环境都无法跳过。

## 4. Docker 化测试栈

仓库根目录 `docker-compose.yml` 已定义 postgres + pg-mcp。测试时建议独立 profile（不污染生产编排）：

```bash
# 起隔离的测试数据库并跑集成测试
docker compose --profile test up -d postgres-test
DATABASE_HOST=localhost DATABASE_PORT=5433 ./run_tests.sh
docker compose --profile test down -v
```

注意事项：
- 容器栈与本地 EDB 共存时**必须错开端口**（EDB 占 5444，容器用 5433）；
- `fixtures/` 下有 small/medium/large 三档初始化数据，容器首启挂载到 `/docker-entrypoint-initdb.d/` 即可复现标准数据集。

## 5. 生产部署要点（摘要）

1. **只读账号**：应用连接使用仅 SELECT 权限的 role，`SECURITY_READONLY_ROLE` 配置后 executor 每事务 `SET ROLE`；
2. **列级授权兜底**：对敏感列执行 `REVOKE SELECT(password) ON users FROM readonly_role`，弥补 DEFECT-04（SELECT * 绕过列黑名单）；
3. **禁用 EXPLAIN**：生产保持 `allow_explain=false`（默认）；如需开启，DEFECT-02 修复后仍建议仅诊断环境使用；
4. **密钥管理**：`OPENAI_API_KEY` 等经环境变量/secret manager 注入，不落盘 .env；
5. **监控**：metrics 端口 9090（Prometheus 格式），可用 `docker-compose.yml` 中注释掉的 Prometheus + Grafana 段落启用；
6. **回滚**：镜像化部署（`Dockerfile`），回滚 = 回退镜像 tag；数据库无 schema 变更，无回滚脚本需求。

## 6. 质量门禁汇总

| 门禁 | 工具 | 阈值 |
|------|------|------|
| 代码风格 | ruff check / ruff format | 0 error |
| 单元+安全测试 | pytest | 100% 通过 |
| 集成测试 | pytest (真实 PG) | 100% 通过（DB 不可达时 skip 并告警） |
| 覆盖率 | pytest-cov | 总体 ≥ 80%（安全模块目标 ≥ 95%） |
