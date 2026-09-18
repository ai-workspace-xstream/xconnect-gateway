# Gateway 同步间隔与 ACK 心跳（Gateway 仓库的任务卡）

> **Status**: ⬜ 未开始（迭代 I-1）
> **Date**: 2026-09-18
> **Related PRs**: 待填
> **完整跨仓规划**: `xconnect-edge-agent/docs/tasks/2026-09-18-xconnect-edge-convergence-plan.md`（规则、交付循环和验收以那份文档为准）

## 为什么要改

accounts 判定 `recent_ack` 的窗口是 5 分钟（`internal/overlay/service.go:37`）。本仓的 `packaging/systemd/xconnect-gateway-sync.timer` 设置为 `OnUnitActiveSec=5min`，systemd 默认还有 1 分钟的 AccuracySec，同步周期不短于判定窗口，所以面板上的 gateway 状态会在 recent_ack 和 stale 之间反复跳动。

## I-1 / A1 任务

1. **RED**
   - `internal/gateway/packaging_test.go`：断言 timer 的 `OnUnitActiveSec + AccuracySec <= 100s`。
   - `client_test.go`：同一个 generation 连续 sync 两次，应该发出 2 次 ACK。
   - ACK 失败时，`sync` 返回非 0。
2. **GREEN**
   - timer 改为 `OnBootSec=30s`、`OnUnitActiveSec=60s`、`AccuracySec=5s`。
   - 配置未变化时照常发 ACK。
   - 更新 `README.md` 和 `docs/self-hosted-install-and-validation.md`。
3. **PR → 合并 main → 打 `v0.1.9` 标签**，由 “CI and release” 发布。
4. **UAT 部署**
   - 可通过 `https://github.com/ai-workspace-infra/platform-ops-toolkit/actions/workflows/daily-main-snapshot.yaml` 控制 UAT 环境发版更新验证：
     ```bash
     gh workflow run daily-main-snapshot.yaml -R ai-workspace-infra/platform-ops-toolkit \
       -f deploy_env=uat \
       -f xconnect_gateway_release_tag=v0.1.9
     ```
   - 或者用 platform-ops-toolkit 的 `xconnect-one-uat.yaml`，传 `gateway_release_tag=v0.1.9`，先 dry-run 再 apply。apply 前需要用户确认，因为 tw-xconnect 同时承载 proxy 流量。
   - 如果这个 workflow 不会更新 timer unit，就在 playbooks 仓库配套提 PR；或者经用户批准，按总规划 A1 的 drop-in 手动加覆盖。
5. **Goal**
   - `gw-uat-tw-xconnect` 连续 30 分钟、7 次采样都是 `recent_ack`。
   - `journalctl -u xconnect-gateway-sync.service` 显示每 60±5 秒一次 sync，且 ACK 成功。
