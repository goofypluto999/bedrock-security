# PROBE REGRESSION FIXTURE — intentionally vulnerable. NOT real code.
# Every WATCHED static check must FAIL on this file (true-positive guard).
import os, jwt, logging
from Crypto.Cipher import DES
logger = logging.getLogger(__name__)
JWT_SECRET = os.getenv("JWT_SECRET", "realfallbacksecret123")     # PATTERN-003: hardcoded fallback secret
def run(u): return eval(u)                                        # FLOOR-A08: eval on input
cipher = DES.new(b"8bytekey0")                                    # FLOOR-A02: weak cipher (DES)
def auth(token, key): return jwt.decode(token, key, verify=False) # PATTERN-004: verification disabled
async def limit(request): await check_rate_limit(request.client.host, limit=5)  # PATTERN-001: limiter on raw IP
def log_it(password): logger.info(f"login password={password}")  # FLOOR-A09: secret interpolated into log
def expose(user): return jsonify(user)                            # EXCESSDATA-001: raw object returned
if __name__ == "__main__": app.run(debug=True)                    # FLOOR-A05: debug in prod entrypoint
