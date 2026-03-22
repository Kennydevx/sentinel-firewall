# 🛡️ Cryo-Corona: Sentinel Firewall
### Next-Gen AI-Powered gRPC Network Defense

Sentinel is a lightweight, proactive firewall agent powered by the **Cryo-C++ Neural Engine**. It monitors network traffic and behavioral patterns in real-time to intercept threats before they reach your core infrastructure.

![Sentinel Visual](https://raw.githubusercontent.com/Kennydevx/cryo-saas-portal/main/assets/banner_sentinel.png) *(Placeholder for Banner)*

---

## 🚀 Key Features
- **Neural Anomaly Detection**: Uses "Surprise" metrics from the Cryo-Engine to identify zero-day exploits.
- **gRPC Native**: Built-in support for ultra-low latency gRPC security checks.
- **Plug-and-Play**: Minimal configuration required via `config.json`.
- **Global Sync**: Automatically synchronizes blocks and threats with the Cryo-SaaS central dashboard.

## 📦 Quick Start

### 1. Prerequisites
- Python 3.8+
- Active API Key from [cryo-saas.com](https://cryo-saas.com)

### 2. Configuration
Edit `config.json` with your credentials:
```json
{
    "server": "cryo-saas.com:50505",
    "api_key": "YOUR_API_KEY_HERE",
    "threshold": 0.7
}
```

### 3. Run
Just double-click `run.bat` or run via CLI:
```bash
python sentinel_agent.py
```

## 🛠️ Usage Example (Python)

Integrate Sentinel into your own applications:

```python
from sentinel_agent import SentinelClient

client = SentinelClient(server="cryo-saas.com:50505", api_key="YOUR_KEY")

# Check if a request is safe
is_safe = client.check_request(ip="1.2.3.4", payload="GET /admin")
if not is_safe:
    print("🚫 Blocked by Cryo-Sentinel")
```

## 🏗️ Architecture
Sentinel acts as a middleware between your clients and the **Cryo-SaaS Gateway**. It uses a stateful Graph Neural Network (GNN) implemented in high-performance C++ to score requests based on latent behavioral patterns.

---
**Developed by Kennedy Guimaraes**  
© 2026 Cryo-Corona Ecosystem. All rights reserved.
