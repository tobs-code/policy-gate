# Deployment Guide — policy-gate

**Safety Action SA-022 — External Process Watchdog (DA-01)**

This document specifies the mandatory external watchdog requirements for production deployments of `policy-gate`. It addresses the gap between the internal Rust watchdog (FSM-internal hangs) and OS-level thread starvation (DA-01, DC-GAP-04).

> **Key distinction:** The internal 50 ms watchdog (SA-004) detects FSM-internal hangs. It does **not** protect against OS preemption, VM live-migration, SIGSTOP, or OOM-kill, where the thread never resumes and the internal watchdog never fires. An external process watchdog is required for full DA-01 coverage.

---

## 1. systemd Deployment (Linux)

### Service Unit

```ini
# /etc/systemd/system/policy-gate.service
[Unit]
Description=policy-gate safety gate
After=network.target
Requires=network.target

[Service]
Type=notify
ExecStart=/usr/local/bin/your-app-using-firewall
Restart=on-failure
RestartSec=2s

# DA-01: External process watchdog — firewall must respond within 5 s.
# The application must call sd_notify(0, "WATCHDOG=1") at least every 2.5 s
# (WatchdogSec / 2 is the recommended ping interval per systemd documentation).
WatchdogSec=5s
NotifyAccess=main

# Resource limits — prevent OOM-triggered starvation (DA-05)
MemoryMax=512M
CPUQuota=80%

# Isolation
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

### Application Watchdog Ping (Node.js)

```typescript
import { notify } from 'sd-notify'; // npm install sd-notify

// Ping systemd every 2 s (well under the 5 s WatchdogSec deadline)
const WATCHDOG_INTERVAL_MS = 2_000;

setInterval(() => {
  notify(false, 'WATCHDOG=1');
}, WATCHDOG_INTERVAL_MS);
```

### Verify

```bash
systemctl start policy-gate
systemctl status policy-gate       # confirm WatchdogSec appears
journalctl -u policy-gate -f       # monitor watchdog events
```

---

## 2. Kubernetes Deployment

### Liveness Probe

The application must expose a `GET /health` endpoint that returns `HTTP 200` when `init()` has succeeded and the firewall is operational.

```typescript
// Minimal health endpoint (Express example)
import express from 'express';
import { isInitialised } from './firewall'; // wrapper around firewall-core init()

const app = express();

app.get('/health', (_req, res) => {
  if (isInitialised()) {
    res.status(200).json({ status: 'ok' });
  } else {
    res.status(503).json({ status: 'initialising' });
  }
});
```

### Deployment YAML

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: policy-gate-app
spec:
  replicas: 2
  selector:
    matchLabels:
      app: policy-gate-app
  template:
    metadata:
      labels:
        app: policy-gate-app
    spec:
      containers:
        - name: app
          image: your-registry/policy-gate-app:latest
          ports:
            - containerPort: 3000

          # DA-01: Liveness probe — kills and restarts the pod if the process
          # stops responding. Covers OS-level starvation and deadlocks that the
          # internal Rust watchdog cannot detect.
          livenessProbe:
            httpGet:
              path: /health
              port: 3000
            initialDelaySeconds: 10   # allow time for firewall init()
            periodSeconds: 5          # check every 5 s
            failureThreshold: 3       # restart after 3 consecutive failures (15 s)
            timeoutSeconds: 2

          # Readiness probe — only route traffic after init() succeeds (SR-006)
          readinessProbe:
            httpGet:
              path: /health
              port: 3000
            initialDelaySeconds: 5
            periodSeconds: 3
            failureThreshold: 2

          resources:
            requests:
              memory: "128Mi"
              cpu: "100m"
            limits:
              memory: "512Mi"     # DA-05: prevent OOM-triggered starvation
              cpu: "500m"
```

---

## 3. Docker Healthcheck (standalone)

```dockerfile
FROM node:22-slim
WORKDIR /app
COPY . .
RUN npm ci && npm run build

# DA-01: Docker built-in healthcheck as minimal external watchdog.
# Not a replacement for systemd WatchdogSec or Kubernetes livenessProbe
# in production, but suitable for development and testing environments.
HEALTHCHECK --interval=10s --timeout=3s --start-period=15s --retries=3 \
  CMD curl -fs http://localhost:3000/health || exit 1

CMD ["node", "dist/index.js"]
```

---

## 4. Process Restart on Crash

Regardless of the watchdog mechanism, configure automatic restart:

| Environment | Restart mechanism |
|---|---|
| systemd | `Restart=on-failure`, `RestartSec=2s` |
| Kubernetes | `restartPolicy: Always` (default) |
| Docker Compose | `restart: unless-stopped` |
| PM2 (Node.js) | `pm2 start app.js --watch` |

---

## 5. Operational Checklist

| Ref | Requirement | How to satisfy |
|-----|-------------|----------------|
| DA-01 | External process watchdog | systemd `WatchdogSec=5s` OR Kubernetes `livenessProbe` |
| DA-05 | OOM protection | `MemoryMax` (systemd) / `resources.limits.memory` (k8s) |
| OC-01 | `init()` before any `evaluate()` | Checked by `INIT_RESULT OnceLock` in `firewall-core` + napi guard |
| OC-03 | Audit entries persisted | Application must persist `AuditEntry` before acting on verdict |
| OC-04 | `DiagnosticDisagreement` alerting within 24 h | Wire `onDisagreement` callback to alerting infrastructure |
| OC-05 | `DiagnosticAgreement` review within 72 h | Wire `onAudit` + filter by `verdict_kind == DiagnosticAgreement` |
| SR-006 | Fail if `init()` returns error | Application must not start evaluation if `firewall_init()` fails |

---

## 6. Safety Evidence

This deployment guidance closes:
- **SA-022** — External process watchdog specification
- **DC-GAP-04** — OS-level starvation not covered by internal watchdog
- **PFH-05** — External process watchdog specification (§9.6)

The internal 50 ms Rust watchdog (SA-004) remains active and provides FSM-internal hang detection orthogonal to the external watchdog. Both mechanisms are complementary.

---

*See [SAFETY_MANUAL.md](./SAFETY_MANUAL.md) §8.2 DA-01 and §8.2 DA-01 for the corresponding safety argumentation.*

---

## 7. Egress Testing

The egress firewall includes comprehensive test coverage in `crates/firewall-core/tests/egress_channel_tests.rs` with **37 tests**:

### Channel E: FSM-based PII/Leakage Detection
- **Sliding window leakage detection** (5 tests): System prompt leakage, partial token leakage, boundary conditions at response start/end, overlapping window matches
- **Contextual PII detection** (8 PII types): Credit Cards, SSN, Email, US Phone, International Phone, IPv4, IPv6, IBAN
- **False positive prevention** (2 tests): Boilerplate code, factual responses
- **Edge cases** (3 tests): Short prompts, empty responses, minimal responses
- **Unicode/encoding variations** (2 tests): International phone detection, normalization handling

### Channel F: Rule-based Entropy/Framing Detection
- **Entropy detection** (4 tests): Base64, Hex encoded data, context-aware detection
- **Framing detection** (5 tests): "The system prompt", "hidden instructions", "secret key", "private_key =", "secret_key ="
- **Boundary cases** (2 tests): Base64 threshold, multiple framing patterns
- **Pass cases** (3 tests): Encoding discussions, system prompt explanations, code without secrets

### Combined E + F Integration Tests
- **Channel interaction** (3 tests): Combined PII+framing, framing-only detection, safe response verification

The 1oo2D voter requires both channels to agree on Pass, with either channel able to block independently (fail-closed).
