# Cryo-Corona — Sentinel Firewall Agent v1.0
# Neural WAF that learns normal traffic patterns and blocks anomalies.
# Runs on the CLIENT's server as HTTP middleware.
# Proprietary — Do not redistribute.

import os
import sys
import time
import hashlib
import math
import logging
from collections import defaultdict
from threading import Lock

# ── Import Cryo SDK ─────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(__file__))
import cryo_pb2
import cryo_pb2_grpc
import grpc

def load_config():
    """Loads configuration from config.json if available."""
    import json
    config = {
        "server": "api.cryo-saas.com:50505",
        "api_key": "71e6236b046a8b8c72fee2dd5285a9c0",
        "threshold": 0.7,
        "session_prefix": "sentinel"
    }
    config_path = os.path.join(os.path.dirname(__file__), "config.json")
    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                loaded = json.load(f)
                config.update(loaded)
                print(f"[Sentinel] Config loaded from {config_path}")
        except Exception as e:
            print(f"[Sentinel] Error loading config: {e}")
    return config

# ── Configuration ───────────────────────────────────────────────
_CONFIG = load_config()
CRYO_SERVER = os.getenv("CRYO_SERVER", _CONFIG["server"])
CRYO_API_KEY = os.getenv("CRYO_API_KEY", _CONFIG["api_key"])
SURPRISE_THRESHOLD = float(os.getenv("SENTINEL_THRESHOLD", str(_CONFIG["threshold"])))
SESSION_PREFIX = _CONFIG["session_prefix"]

logging.basicConfig(level=logging.INFO, format="[Sentinel] %(asctime)s %(message)s")
log = logging.getLogger("sentinel")


class SentinelFirewall:
    """
    Neural Web Application Firewall.
    
    Converts each HTTP request into a 5-float state vector and sends it
    to the Cryo Engine via gRPC. If the engine's 'surprise' metric exceeds
    the threshold, the request is flagged as anomalous and blocked.
    
    Usage (Flask example):
        from sentinel_agent import SentinelFirewall
        sentinel = SentinelFirewall()
        
        @app.before_request
        def firewall():
            if not sentinel.analyze(request):
                abort(403)
    """

    METHODS = {"GET": 0.0, "POST": 0.25, "PUT": 0.5, "DELETE": 0.75, "PATCH": 1.0}

    def __init__(self, server=None, api_key=None, threshold=None):
        self.server = server or CRYO_SERVER
        self.api_key = api_key or CRYO_API_KEY
        self.threshold = threshold or SURPRISE_THRESHOLD

        self._channel = grpc.insecure_channel(self.server)
        self._stub = cryo_pb2_grpc.CryoEngineStub(self._channel)

        # IP rate tracking (local, for vector building)
        self._ip_counts = defaultdict(list)
        self._lock = Lock()

        # Session management
        self._session_id = None
        self._registered_ips = set()
        self._init_session()

        log.info(f"🛡️  Sentinel Firewall Online → {self.server} (threshold={self.threshold})")

    def _init_session(self):
        """Create a persistent session on the Cryo Engine."""
        try:
            resp = self._stub.CreateSession(cryo_pb2.Empty(), timeout=10)
            self._session_id = resp.session_id
            log.info(f"Session created: {self._session_id}")
        except Exception as e:
            log.error(f"Failed to create session: {e}")
            self._session_id = f"{SESSION_PREFIX}_fallback"

    # ── Public API ──────────────────────────────────────────────

    def analyze(self, request) -> bool:
        """
        Analyze an incoming HTTP request.
        Returns True if allowed, False if blocked.
        
        Works with Flask, Django, and raw WSGI request objects.
        """
        ip = self._get_ip(request)
        method = self._get_method(request)
        body_size = self._get_body_size(request)
        user_agent = self._get_ua(request)

        vector = self._build_vector(ip, method, body_size, user_agent)

        unit_id = f"ip_{ip.replace('.', '_')}"

        # Register unit if first time seeing this IP
        if unit_id not in self._registered_ips:
            self._register_ip(unit_id)

        # Send to Cryo Engine
        result = self._fast_step(unit_id, vector)

        if result is None:
            # Engine unreachable — fail open (allow)
            log.warning(f"Engine unreachable, allowing {ip} (fail-open)")
            return True

        surprise = result.get("surprise", 0.0)

        if surprise > self.threshold:
            log.warning(f"🚨 BLOCKED {ip} | method={method} | surprise={surprise:.3f}")
            return False

        return True

    def get_report(self) -> dict:
        """Get the current session report from the engine."""
        try:
            req = cryo_pb2.ReportRequest(
                api_key=self.api_key,
                session_id=self._session_id
            )
            resp = self._stub.GetReport(req, timeout=10)
            import json
            return json.loads(resp.json_report)
        except Exception as e:
            log.error(f"Report failed: {e}")
            return {}

    # ── Internal Methods ────────────────────────────────────────

    def _build_vector(self, ip, method, body_size, user_agent):
        """Convert HTTP metadata into a 5-float state vector."""
        method_id = self.METHODS.get(method.upper(), 0.5)
        payload_norm = min(body_size / 10000.0, 1.0)
        freq = self._get_request_rate(ip)
        geo_hash = float(int(hashlib.md5(ip.encode()).hexdigest()[:4], 16) % 1000) / 1000.0
        ua_entropy = self._ua_entropy(user_agent)

        return [method_id, payload_norm, freq, geo_hash, ua_entropy]

    def _get_request_rate(self, ip):
        """Calculate requests/second for this IP (sliding window)."""
        now = time.time()
        with self._lock:
            # Clean old entries (older than 10s)
            self._ip_counts[ip] = [t for t in self._ip_counts[ip] if now - t < 10]
            self._ip_counts[ip].append(now)
            rate = len(self._ip_counts[ip]) / 10.0
        return min(rate, 1.0)

    @staticmethod
    def _ua_entropy(ua_string):
        """Calculate Shannon entropy of the User-Agent string (bots have low entropy)."""
        if not ua_string:
            return 0.0
        freq = defaultdict(int)
        for c in ua_string:
            freq[c] += 1
        length = len(ua_string)
        entropy = -sum((count / length) * math.log2(count / length)
                       for count in freq.values() if count > 0)
        # Normalize to 0-1 range (typical browser UA entropy is ~4.0-5.0)
        return min(entropy / 5.0, 1.0)

    def _register_ip(self, unit_id):
        """Register a new IP unit in the Cryo Engine."""
        try:
            pb_units = [cryo_pb2.UnitData(
                unit_id=unit_id,
                z_state=cryo_pb2.FloatArray(values=[0.0] * 5)
            )]
            req = cryo_pb2.FastStepRequest(
                api_key=self.api_key,
                session_id=self._session_id,
                register_units=pb_units
            )
            self._stub.FastStep(req, timeout=10)
            self._registered_ips.add(unit_id)
        except Exception as e:
            log.error(f"Registration failed for {unit_id}: {e}")

    def _fast_step(self, unit_id, vector):
        """Send a state update to the Cryo Engine and return metrics."""
        try:
            updates = {
                unit_id: cryo_pb2.FloatArray(values=vector)
            }
            req = cryo_pb2.FastStepRequest(
                api_key=self.api_key,
                session_id=self._session_id,
                state_updates=updates
            )
            resp = self._stub.FastStep(req, timeout=10)
            return {
                "surprise": resp.surprise,
                "active_units": resp.active_units,
                "trigger_slow": resp.trigger_slow
            }
        except Exception as e:
            log.error(f"FastStep failed: {e}")
            return None

    # ── Framework Adapters ──────────────────────────────────────

    @staticmethod
    def _get_ip(request):
        """Extract client IP from various framework request objects."""
        # Flask / Werkzeug
        if hasattr(request, 'remote_addr'):
            return request.remote_addr
        # Django
        if hasattr(request, 'META'):
            return request.META.get('REMOTE_ADDR', '0.0.0.0')
        # Raw WSGI environ dict
        if isinstance(request, dict):
            return request.get('REMOTE_ADDR', '0.0.0.0')
        return '0.0.0.0'

    @staticmethod
    def _get_method(request):
        if hasattr(request, 'method'):
            return request.method
        if isinstance(request, dict):
            return request.get('REQUEST_METHOD', 'GET')
        return 'GET'

    @staticmethod
    def _get_body_size(request):
        if hasattr(request, 'content_length') and request.content_length:
            return request.content_length
        if hasattr(request, 'data'):
            return len(request.data or b"")
        return 0

    @staticmethod
    def _get_ua(request):
        if hasattr(request, 'headers'):
            return request.headers.get('User-Agent', '')
        if hasattr(request, 'META'):
            return request.META.get('HTTP_USER_AGENT', '')
        if isinstance(request, dict):
            return request.get('HTTP_USER_AGENT', '')
        return ''

    def __del__(self):
        if hasattr(self, '_channel'):
            self._channel.close()


# ── Standalone Test Mode ────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("  Sentinel Firewall Agent — Standalone Test")
    print("=" * 60)

    sentinel = SentinelFirewall()

    # Simulate requests
    class FakeRequest:
        def __init__(self, ip, method="GET", ua="Mozilla/5.0", body_size=0):
            self.remote_addr = ip
            self.method = method
            self.content_length = body_size
            self.headers = {"User-Agent": ua}
            self.data = b"x" * body_size

    print("\n🛡️  Starting Live Monitoring Simulation (Ctrl+C to stop)...\n")
    
    cycle = 1
    try:
        while True:
            # Randomly pick normal or suspicious
            is_suspicious = (cycle % 4 == 0) # Every 4th request is suspicious
            
            if not is_suspicious:
                ip = f"192.168.1.{10 + (cycle % 5)}"
                req = FakeRequest(ip, "GET", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
                type_str = "NORMAL"
            else:
                ip = f"10.0.0.{90 + (cycle % 10)}"
                req = FakeRequest(ip, "POST", "python-requests/2.25.1", body_size=85000)
                type_str = "⚠️  SUSPICIOUS"
            
            result = sentinel.analyze(req)
            status = "✅ ALLOWED" if result else "❌ BLOCKED"
            
            print(f"  Cycle {cycle:02d} | IP: {ip:<12} | Type: {type_str:<12} | Action: {status}")
            
            time.sleep(1.0)
            cycle += 1
    except KeyboardInterrupt:
        print("\n\n🛡️  Sentinel Standalone Test Stopped.")

