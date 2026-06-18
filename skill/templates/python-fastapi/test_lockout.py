"""
LOCK-001 — Per-account lockout at threshold, before the password hash (OWASP API4:2023, ASVS V2.2.1).

PROVE: N failed logins against ONE email — sent FROM MANY IPs with VALID-SHAPED but wrong
passwords — get throttled by the EMAIL identity, not merely by IP. An attacker rotating
source IPs must still be locked out. The wrong passwords are well-formed (so input
validation can't mask the test), and the lockout check must run BEFORE the bcrypt/argon2
verify (so a locked account doesn't burn CPU / leak timing). Falsifiable failure: the
(N+1)th attempt from a fresh IP still returns 401 (credential check) instead of 429.

Wire the TODOs (login route, threshold N, a victim email).
"""
import pytest

LOGIN_PATH = "/api/login"
THRESHOLD = 5
VICTIM_EMAIL = "victim@example.com"   # TODO: an email that EXISTS (user_a's), to test real identity
WRONG_BUT_VALID = "Wrong-Passw0rd!"   # valid shape: passes any length/charset policy


def _attempt(client, ip, password=WRONG_BUT_VALID, email=VICTIM_EMAIL):
    """One login attempt from a forged source IP."""
    return client.post(
        LOGIN_PATH,
        json={"email": email, "password": password},
        headers={"X-Forwarded-For": ip, "X-Real-IP": ip},
    )


def test_lockout_keys_on_identity_not_ip(client):
    """Each failed attempt comes from a DIFFERENT IP — only the email is constant."""
    codes = [_attempt(client, f"203.0.113.{i}").status_code for i in range(THRESHOLD)]
    assert all(c in (400, 401) for c in codes), f"expected auth failures pre-lock, got {codes}"
    locked = _attempt(client, "198.51.100.99")  # brand-new IP, same email
    assert locked.status_code == 429, (
        f"IP-rotation bypass: attempt {THRESHOLD + 1} from a fresh IP returned {locked.status_code}, "
        f"not 429. Key the lockout on email and gate it BEFORE the password hash."
    )


def test_correct_password_blocked_while_locked(client):
    """Lockout must hold even for the right password (proves identity throttle, not
    a credential check) — TODO: pass the victim's REAL password here."""
    for i in range(THRESHOLD + 1):
        _attempt(client, f"192.0.2.{i}")
    real = _attempt(client, "192.0.2.250", password="TODO-correct-password")
    assert real.status_code == 429, "account not actually locked — throttle is per-credential, not per-identity"


def test_other_account_unaffected(client):
    """Over-correction guard: locking the victim must NOT lock a bystander.
    A different email from a fresh IP must still reach the credential check."""
    for i in range(THRESHOLD + 1):
        _attempt(client, f"203.0.113.{i}")
    other = _attempt(client, "198.51.100.1", email="bystander@example.com")
    assert other.status_code in (400, 401), f"collateral lockout: bystander got {other.status_code}"
