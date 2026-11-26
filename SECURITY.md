# Security & responsible use

security_seti orchestrates offensive security tooling. That makes responsible use
non-negotiable.

## Authorized targets only

Only ever point this at assets you **own** or have **written authorization** to
test. The mesh enforces this in three places:

- **Scope gate** (`security_seti.scope`): deny-by-default. No authorization
  loaded ⇒ every target and every command is refused.
- **Store** (`security_seti.store`): a finding whose target is outside scope is
  rejected at write time, so out-of-scope results can't be recorded as sanctioned.
- **Approval gate**: intrusive action classes (`exploit`, `write`, `lateral`,
  `exfil`) require a human `APPROVAL_RES` before they run. The default policy is
  auto-deny (fail safe).

Define your scope in `AUTHORIZATION.yaml` (see `AUTHORIZATION.example.yaml`) and
keep it out of version control.

## No exploits in this repo

security_seti contains **no exploit code**. Adapters drive tools you already run
under your own authorization (Metasploit, ARTEX, scanners, your scripts). Keep it
that way: contributions that add weaponized payloads or target non-consenting
third parties will be rejected.

## Reporting a vulnerability

Found a security issue in security_seti itself? Please report it privately to the
maintainer rather than opening a public issue, and allow reasonable time for a fix
before disclosure.

## Legal

Unauthorized access to computer systems is illegal in most jurisdictions. You are
responsible for operating within the law and your rules of engagement. The AGPL-3.0
license disclaims all warranty.
