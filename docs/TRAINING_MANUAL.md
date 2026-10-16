# Localized Onboarding & Operational Guide
**Version:** 2.0.0 — Enterprise client deployments
**Languages:** English, Español, Français, Português, Deutsch, Italiano, العربية (RTL)

## 1. Onboarding Sequence

### Step 1 — Permissions (all optional, each gates one module)
- **Local VPN** → enables the NetworkWarden cohort (packet inspection on-device).
- **File access** → enables the topological ransomware interceptor.
- **Notifications** → threat-isolation alerts in the device language.
- Declining any permission degrades gracefully; the core never crashes on denial.

### Step 2 — Operational profile
- **Nominal Defense (default):** governor floats density 5 ↔ 15 with thermals.
- **Maximum Security Enclosure (Pro):** pins 15 agents; requires a validated
  store receipt (`swarm_set_subscription_tier(1)` after Apple/Google verification).

## 2. What the user sees

| State | English | Español | العربية |
|---|---|---|---|
| Nominal | System status nominal. 15 agents synchronized. | Estado del sistema nominal. 15 agentes sincronizados. | حالة النظام طبيعية. جميع الوكلاء الـ 15 متزامنون. |
| Throttled | Thermal throttle: core running on 5 executive agents. | Limitación térmica: núcleo en 5 agentes ejecutivos. | اختناق حراري: النواة تعمل بخمسة وكلاء تنفيذيين. |
| Threat isolated | Threat isolated inside memory boundaries. | Amenaza aislada dentro de los límites de memoria. | تم عزل التهديد داخل حدود الذاكرة. |

Strings are served from the native `swarm_localized_disclosure` matrix
(zero-allocation); the platform resource files under `android/res/` and
`ios/*.lproj` mirror them for system UI.

## 3. Battery expectations
Under 1%/hr nominal. If a user reports drain: check they haven't force-stopped
the app (which defeats the governor and causes restart churn), and confirm the
OEM battery-saver exemption is set so the governor — not the OS — schedules work.
