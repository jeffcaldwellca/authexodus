# Security

authexodus handles some of the most sensitive data a person has: every two-factor secret in their Authy account, their Authy backup password and, on the Bitwarden path, their Bitwarden master password. Security reports are very welcome.

## Reporting a problem

Please report vulnerabilities privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability**. Do not open a public issue for a security problem.

Include what you found, how to reproduce it, and what an attacker could do with it. Never send real codes, backup passwords, Authy backups or account details: a made-up example is always enough.

## What is in scope

- Anything that could expose a person's codes, backup password, master password or the per-run certificate's key, on the Mac, over the network or to the app's window.
- The proxy: anything that lets it read traffic other than Authy's API, or lets another device on the network use it to reach places it should not.
- The download and execution of Bitwarden's command-line tool.
- Claims in the README or the app that the code does not back up.

## Supported versions

Only the latest release, and the `main` branch, receive fixes. authexodus is pre-release software.
