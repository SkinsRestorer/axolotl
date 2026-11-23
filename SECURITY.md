# Security reports

Do not report a vulnerability in a public issue. Email [contact@skinsrestorer.net](mailto:contact@skinsrestorer.net) with the details.

This policy covers Axolotl: this repository, the `ghcr.io/skinsrestorer/axolotl` image, and the hosted service at `axolotl.skinsrestorer.net`. For a vulnerability in the SkinsRestorer plugin, use [private vulnerability reporting in the SkinsRestorer repository](https://github.com/SkinsRestorer/SkinsRestorer/security/advisories/new).

Examples of problems to report:

- A way to read or use the MineSkin API key, `AES_SECRET_KEY`, or the Discord webhook URL.
- A way to decrypt, forge, or change an encrypted `skinsrestorer-axolotl://` URL without the key.
- A way to make Axolotl send requests to a host other than MineSkin or the configured webhook.
- A request that uses much more memory, CPU, or MineSkin quota than the upload limits allow.

## What to include

- The commit or image tag, and whether you tested a local build or the hosted service.
- The impact and what an attacker needs, such as network access or a valid request.
- A minimal reproduction with synthetic data.
- A suggested fix or mitigation, if you have one.

Remove real credentials and personal data. Share proof of concept code only through the private channel that you agree on with the maintainers.

## Supported versions

Only the newest commit on `main` gets security fixes. The published image follows `main`, and there are no release branches. Tell us whether the problem also occurs on the newest commit.

The maintainers assess each report and agree on a fix and a disclosure plan with the reporter. This policy does not promise a response time.

Ordinary bugs and setup questions belong in [the support guide](SUPPORT.md).
