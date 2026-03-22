<div align="center">
  <img src="https://raw.githubusercontent.com/kennydevx/sentinel-firewall/main/assets/sentinel_logo.png" width="300" alt="Sentinel Logo" />
  <h1>🛡️ Sentinel Firewall</h1>
  <p><b>Neural Web Application Firewall (WAF) using Shannon Entropy</b></p>
  
  [![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square)](https://python.org)
  [![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
  [![CryoEngine](https://img.shields.io/badge/Powered%20By-Cryo%20Engine%20v3-7000ff?style=flat-square)](https://cryo-corona.com)
</div>

---

## What is Sentinel?

Sentinel is a next-generation WAF that acts as a drop-in middleware for your web applications (Flask, Django, Express). Instead of using thousands of slow, static RegEx rules to block attacks, Sentinel uses the **Cryo-Corona Neural Engine** to learn your normal traffic patterns.

It calculates the **Shannon Entropy** of incoming User-Agents, HTTP methods, and payload sizes, converting each request into a 5D state tensor. The engine calculates an anomaly score (*Surprise*). If the request is too surprising, it's blocked.

## 🚀 Quick Start (For Non-Programmers)

1. Clone this repository.
2. Run the interactive setup wizard:
   ```bash
   python setup_wizard.py
   ```
3. Type in your API key and desired security threshold. It will auto-generate your `.env` file.

## 💻 Developer Integration

Integrating Sentinel takes exactly 4 lines of code in Python.

### Flask Integration
```python
from flask import Flask, request, abort
from sentinel_agent import SentinelFirewall

app = Flask(__name__)

# Initialize (loads from .env automatically)
sentinel = SentinelFirewall()

@app.before_request
def firewall():
    if not sentinel.analyze(request):
        abort(403) # Block anomalous request
```

### Django Integration
Add the middleware to your `settings.py`:
```python
# Create middleware.py
from sentinel_agent import SentinelFirewall
sentinel = SentinelFirewall()

class SentinelMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if not sentinel.analyze(request):
            from django.http import HttpResponseForbidden
            return HttpResponseForbidden("Blocked by Sentinel Neural WAF")
        return self.get_response(request)
```

## ⚙️ Configuration Properties

You can customize the strictness of the firewall via `.env`:
- `SENTINEL_THRESHOLD=0.5` (Paranoid - blocks almost all unexpected traffic)
- `SENTINEL_THRESHOLD=0.7` (Recommended - balanced protection)
- `SENTINEL_THRESHOLD=0.9` (Tolerant - only blocks obvious DDoS/scrapers)

## 🏗️ Fail-Open Architecture
If your connection to the Cryo-SaaS engine is lost, Sentinel defaults to a **fail-open** state (allowing traffic). It will never break your production app if the AI goes offline.

## 🤝 Contributing
Contributions are welcome for adding native middleware support for Node.js (Express/Fastify), Go, and Ruby.

## 📄 License
[MIT](https://choosealicense.com/licenses/mit/)
