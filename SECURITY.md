# Security Policy

## Supported Versions

Only the latest version on the default branch (`master`) is currently supported
with security updates.

Older releases, forks, or modified deployments are **not supported**.

| Version        | Supported |
| -------------- | --------- |
| Latest (master)  | :white_check_mark:    |
| Latest Prod Release| :white_check_mark:  |
| Non-prod, pre-release | :x:   |
| Older releases | :x:   |

If you are running an older version, you are strongly encouraged to upgrade
before reporting a security issue.

---

## Reporting a Vulnerability

Please **do not report security vulnerabilities through public GitHub issues**.

If you believe you have found a security vulnerability in this project, report
it responsibly using **one of the following private channels**:

- GitHub Security Advisories (preferred)
- Email: `debagnik@debagnik.in`

### What to include
When reporting, please include:
- A clear description of the vulnerability
- Steps to reproduce (proof-of-concept if possible)
- Affected endpoints, files, or components
- The version or commit hash tested

### Response timeline
- **Initial acknowledgment:** within 72 hours
- **Status update:** within 15 days
- **Fix or mitigation:** best-effort, depending on severity and complexity

### Disclosure policy
- Please allow reasonable time for the issue to be investigated and fixed
  before any public disclosure.
- Coordinated disclosure is appreciated.
- Vulnerabilities that are already publicly disclosed may be deprioritized.

### Scope
The following are **out of scope**:
- Denial of Service via excessive traffic
- Issues caused by modified deployments or third-party plugins
- Vulnerabilities in dependencies without a demonstrable impact on this project

---

## Security Best Practices

While this project follows reasonable security practices, it is provided
**as-is** without warranty. Users are responsible for securing their own
deployments, secrets, and infrastructure.

If you are unsure whether an issue is security-related, report it privately
anyway.
