# PROBE REGRESSION FIXTURE — benign code shapes that previously FALSE-fired.
# NONE of the watched checks may FAIL on this file (false-positive guard).
import os, jwt
from sqlalchemy import select
MODEL = os.getenv("ANTHROPIC_CLASSIFIER_MODEL", "claude-haiku-4-5-20251001")  # model name, not a secret
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")                        # empty default = no fallback
def fit_eval(corpus, hold): return sum(corpus)                                # function name contains the substring, not the builtin call
DEMO_CODES = {"FORESAY-ACCESS-005": 115, "FORESAY-ACCESS-006": 115}           # "coDES" is not the DES cipher
def auth(token, key): return jwt.decode(token, key, algorithms=["HS256"], options={"require_exp": True})  # hardened
# No-key APIs: CDC BRFSS, ONS (UK), Bank of England, Eurostat, ECB, World Bank   # ECB = central bank, not cipher
error_triggers = [("POST", "/api/auth/login", {"email": "x", "password": "y"})]  # test payload, not a log
payloads = ["1; SELECT * FROM information_schema.tables", "' OR '1'='1", "${7*7}"]  # attack strings, not real queries
stmt = select(Invite).where(Invite.token == token)                           # ORM filter, not a secret compare
logger.warning("Google ID token verification failed", extra={"err_class": "ValueError"})  # "token" is a word here
# Test/dev: no trusted proxy. Use TCP peer (request.client.host).            # comment, not a limiter
