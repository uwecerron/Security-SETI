import pytest

from security_seti.scope import Authorization, Scope, ScopeError


def test_deny_by_default():
    s = Scope(None)
    assert not s.is_target_authorized("example.com")
    assert not s.is_argv_allowed(["nmap", "example.com"])
    assert s.needs_approval("anything")  # unknown -> must ask


def test_cidr_targets():
    s = Scope(Authorization(targets=["10.0.0.0/24"]))
    assert s.is_target_authorized("10.0.0.5")
    assert s.is_target_authorized("http://10.0.0.5:8080/path")
    assert not s.is_target_authorized("10.0.1.5")


def test_domain_targets_and_subdomains():
    s = Scope(Authorization(targets=["example.com"]))
    assert s.is_target_authorized("example.com")
    assert s.is_target_authorized("api.example.com")
    assert not s.is_target_authorized("notexample.com")
    assert not s.is_target_authorized("evil.com")


def test_require_target_raises():
    s = Scope(Authorization(targets=["example.com"]))
    with pytest.raises(ScopeError):
        s.require_target("evil.com")


def test_argv_allow_and_deny():
    s = Scope(Authorization(
        targets=["example.com"],
        allow_argv_prefixes=["nmap ", "httpx"],
        deny_argv_prefixes=["rm ", "nmap --script vuln"],
    ))
    assert s.is_argv_allowed(["nmap", "-sV", "example.com"])
    assert s.is_argv_allowed(["httpx", "-u", "example.com"])
    assert not s.is_argv_allowed(["curl", "example.com"])       # not allow-listed
    assert not s.is_argv_allowed(["rm", "-rf", "/"])            # deny wins
    assert not s.is_argv_allowed(["nmap", "--script", "vuln"])  # deny wins


def test_lab_helper_denies_dangerous():
    s = Scope(Authorization.unrestricted_lab(targets=["127.0.0.1"]))
    assert s.is_target_authorized("127.0.0.1")
    assert not s.is_argv_allowed(["rm", "-rf", "/"])
    assert s.needs_approval("exploit")
