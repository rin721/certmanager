# Third-party notices

CertMate combines third-party components under permissive open-source licenses. The exact transitive dependency set is locked by `go.sum` and `web/package-lock.json`; run `make license` to generate the dependency-level report for the current lockfiles.

## Runtime and direct application dependencies

- acme.sh 3.1.4 — GPL-3.0; its complete source and license are retained under `/opt/acme.sh` in the runtime image.
- Alpine Linux packages, OpenSSL, CA Certificates, tzdata, curl and socat — their package metadata and applicable license terms are provided by Alpine Linux and the respective upstream projects.
- chi, Gorilla CSRF/Sessions, goose, robfig/cron, golang.org/x/crypto and modernc SQLite — MIT, BSD-3-Clause or Apache-2.0 family licenses as reported by `go-licenses`.
- React, Material UI, TanStack Query, React Hook Form, React Router, Zod and Emotion — MIT licensed direct frontend dependencies.

The CertMate application itself is distributed under the MIT License in `LICENSE`. This notice is informational and does not replace the full license texts shipped by each upstream component.
