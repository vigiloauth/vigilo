# Security Policy

## Reporting a Vulnerability

The VigiloAuth team takes security vulnerabilities seriously. We appreciate your efforts to responsibly disclose your findings and will make every effort to acknowledge your contributions.

### How to Report

**Please do NOT report security vulnerabilities through public GitHub issues.** Instead, please report security vulnerabilities using one of these following methods:

#### Option 1: GitHub Security Advisories (Recommended):
Use GitHub's private vulnerability reporting feature:
1. Go to the [security tab](https://github.com/vigiloauth/vigilo/security)
2. Click "Report a vulnerability"
3. Fill out the security advisory form with the details listed below

#### Option 2: Private Discussion
1. Go to the [discussions tab](https://github.com/vigiloauth/vigilo/discussions)
2. Start a new discussion in the "Security" category
3. **Mark the discussion as private** and include the details listed below

Include the following information in your report:
- **Type of issue** (e.g., buffer overflow, SQL injection, cross-site scripting, etc.)
- **Full paths of source file(s)** related to the manifestation of the issue
- **The location of the affected source code** (tag/branch/commit or direct URL, etc.)
- **Any special configuration required** to reproduce the issue
- **Proof-of-concept or exploit code** (if possible)
- **Impact of the issue**, including how an attacker might exploit the issue

### What to Expect

After you submit a report, here's what you can expect:

1. **Acknowledgment:** We'll acknowledge your report within **48 hours**.
2. **Initial Assessment:** We'll provide an initial assessment of the report within **5 business days**, including:
   - Whether we can reproduce the issue
   - Our assessment of the severity
   - An estimated timeline for a fix
3. **Updates:** We'll keep you informed of our progress toward resolving the issue.
4. **Resolution:** Once we've resolved the issue, we'll notify you and may ask you to verify the fix.

### Our Commitment

- We will respond to your report promptly and work with you to understand and resolve the issue quickly
- We will keep you updated on our progress toward resolving the issue
- We will credit you for your discovery when we announce the fix (unless you prefer to remain anonymous)
- We will not take legal action against researchers who discover and report vulnerabilities responsibly

### Security Best Practices

When using VigiloAuth in a production environment, we recommend following these security best practices:

#### Configuration Security

- Always use HTTPS in production environments
- Use strong, randomly generated secrets and keys
- Regularly rotate any secrets and certificates
- Keep your VigiloAuth instance updates to the latest version

#### Infrastructure Security

- Implement proper backup and disaster recovery procedures
- Monitor system resources and set up appropriate alerting

### Security Updates

Security updates will be released as soon as possible after a vulnerability is confirmed and fixed. We will:

1. Release a patched version
2. Publish a security advisory describing the vulnerability and its impact
3. Update this document if necessary
4. Notify users through our communication channels

### Scope

This security policy applies to:

-  The main VigiloAuth server (this repository)
-  Official VigiloAuth Docker images
-  Documentation that could impact security

This policy does not cover:

- Third-party integrations or plugins
- Configurations or deployments not following our documentation
- Issues in dependencies (please report these to the respective projects)

### Contact

For questions about this security policy or general security concerns, please contact:

- **Security Questions:** Use GitHub Security Advisories or private discussions (see reporting section above)
- **General Questions:** [GitHub Discussions](https://github.com/vigiloauth/vigilo/discussions)
- **Non-Security Issues:** [GitHub Issues](https://github.com/vigiloauth/vigilo/issues)

---

  *This security policy is based on industry best practices and may be updated periodically to reflect changes in our security posture and procedures.*
