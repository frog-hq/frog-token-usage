# Security policy

Report vulnerabilities privately through GitHub Security Advisories. Do not
attach real session logs, prompts, responses, credentials, or private paths.
Use synthetic JSONL fixtures in reproductions.

The supported security boundary is: no credential-store access, no network
access, no raw-content output, no followed symlinks, and bounded untrusted-log
parsing. Changes to that boundary require an explicit design review.
