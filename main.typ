// VulnSight AI portfolio/project overview.
// Uses the skill-owned report theme; screenshots and logo are local assets.
#import "report-theme.typ": report-accent, report-theme

#show: report-theme.with(
  title: "VulnSight AI — Project Overview",
  author: "VulnSight AI project",
  rhythm: "report",
  running-header: true,
)
#set text(lang: "en", region: "us")

// ---------- Cover page ----------
#page(
  fill: rgb("#0B1020"),
  margin: (top: 2.3cm, bottom: 2.2cm, x: 2.2cm),
  numbering: none,
  header: none,
)[
  #set par(justify: false, first-line-indent: 0pt, spacing: 0pt, leading: 1.1em)
  #v(1.2cm)
  #align(center)[
    #image("assets/logo.svg", width: 1.7cm)
    #v(0.8cm)
    #text(size: 31pt, weight: "bold", fill: rgb("#F4F8FC"))[VulnSight AI]
    #v(0.25cm)
    #text(size: 15pt, fill: rgb("#22D3EE"))[See the risk. Fix the weakness.]
    #v(0.6cm)
    #line(length: 48%, stroke: 1.3pt + rgb("#22D3EE"))
    #v(0.6cm)
    #text(size: 12pt, fill: rgb("#D3DFEA"))[Project Overview · Security & Architecture Brief]
    #v(0.25cm)
    #text(size: 10pt, fill: rgb("#9BB0C5"))[Portfolio edition · October 2026]
  ]

  #v(1.6cm)
  #grid(
    columns: (1fr, 1fr),
    gutter: 10pt,
    block(fill: rgb("#121A2B"), stroke: 0.6pt + rgb("#244053"), inset: 12pt, radius: 5pt)[
      #text(size: 9pt, weight: "bold", fill: rgb("#22D3EE"))[FULL-STACK]
      #v(4pt)
      #text(size: 10pt, fill: rgb("#EAF1F8"))[React, TypeScript, FastAPI, and SQLite]
    ],
    block(fill: rgb("#121A2B"), stroke: 0.6pt + rgb("#244053"), inset: 12pt, radius: 5pt)[
      #text(size: 9pt, weight: "bold", fill: rgb("#22D3EE"))[EVIDENCE-LED]
      #v(4pt)
      #text(size: 10pt, fill: rgb("#EAF1F8"))[Persisted checks, findings, and reports]
    ],
    block(fill: rgb("#121A2B"), stroke: 0.6pt + rgb("#244053"), inset: 12pt, radius: 5pt)[
      #text(size: 9pt, weight: "bold", fill: rgb("#22D3EE"))[AUTHORIZED USE]
      #v(4pt)
      #text(size: 10pt, fill: rgb("#EAF1F8"))[Scope-checked passive assessment]
    ],
    block(fill: rgb("#121A2B"), stroke: 0.6pt + rgb("#244053"), inset: 12pt, radius: 5pt)[
      #text(size: 9pt, weight: "bold", fill: rgb("#22D3EE"))[REAL WORKFLOWS]
      #v(4pt)
      #text(size: 10pt, fill: rgb("#EAF1F8"))[Background jobs, progress, and cancellation]
    ],
  )

  #v(1.2cm)
  #block(
    width: 100%,
    inset: 12pt,
    fill: rgb("#102331"),
    stroke: (left: 3pt + rgb("#22D3EE")),
    radius: 3pt,
  )[
    #text(size: 10pt, weight: "bold", fill: rgb("#F3F7FA"))[AUTHORIZED ASSESSMENTS ONLY]
    #v(4pt)
    #text(size: 9pt, fill: rgb("#C7D5E2"))[Use only on public targets you own or have explicit permission to assess. VulnSight rejects private and local networks and enforces bounded request and redirect policies.]
  ]
  #v(1fr)
  #align(center)[#text(size: 9pt, fill: rgb("#91A4B8"))[A defensive security assessment workspace · Not an exploitation tool]]
]

// ---------- Contents ----------
#page(numbering: none, header: none)[
  #outline(title: [Contents], indent: 1.5em)
]

// ---------- Main body ----------
#counter(page).update(1)

= Executive summary

VulnSight AI is a full-stack application for bounded, evidence-led web security checks on explicitly authorized public targets. It brings target registration, passive scanning, findings review, history, and report generation into one workspace. Its dashboard and scan progress are driven by persisted records and actual backend events; the application does not seed fabricated scan results.

#block(
  width: 100%,
  inset: 11pt,
  fill: rgb("#EEF7FA"),
  stroke: (left: 3pt + rgb("#22D3EE")),
  radius: 3pt,
)[
  *Project goal.* Make common web-security observations understandable and actionable while keeping authorization, scope, request limits, evidence, and product limitations visible.
]

== Intended users

The project is intended for learners and operators assessing websites they own or are authorized to test. It is not a public scanning service and does not replace a qualified security review.

== What makes the implementation substantive

The interface is connected to a real API and SQLite persistence layer. Scan jobs have bounded concurrency, saved lifecycle state, event-derived progress, actual findings, and cancellation. Reports are generated from stored scan records and are owner-checked on preview and download.

= Product capabilities

#figure(
  table(
    columns: (2.8cm, 5.0cm, 8.0cm),
    stroke: none,
    inset: (x: 6pt, y: 6pt),
    fill: (x, y) => if y == 0 { rgb("#E9F1F8") } else if calc.even(y) { rgb("#F7F9FC") } else { white },
    table.hline(stroke: 1pt + report-accent),
    table.header([*Area*], [*Capability*], [*Implementation detail*]),
    table.hline(stroke: 0.5pt + luma(180)),
    [Targets], [Authorization and exact-host scope], [Owner-scoped records; server-side hostname, DNS, port, and redirect validation.],
    [Scanning], [Bounded passive checks], [Headers, HTTPS/TLS metadata, cookie attributes, benign GET reflection, and selected response configuration.],
    [Progress], [Real job lifecycle], [Persisted scan state and completed-check events; cooperative cancellation; no timer-generated progress.],
    [Findings], [Evidence and remediation], [Severity, confidence, verification status, expected-versus-observed evidence, and status history.],
    [Reports], [PDF and JSON downloads], [Generated from saved results, with owner checks and report integrity metadata.],
    [Workspace], [Dashboard and history], [Metrics, activity, targets, scans, and findings are based on the current user's stored records.],
    table.hline(stroke: 1pt + report-accent),
  ),
  caption: [Core application areas and their verified behavior],
)

== Assessment profiles

*Quick* checks selected HTTPS/redirect behavior, TLS/certificate metadata, HTTP headers, and cookie attributes. *Standard* adds a narrow, benign GET reflection check and selected response-configuration checks. *Advanced* is the broadest passive profile; it does not activate exploit scans or launch OWASP ZAP.

Severity values are configurable deployment-level triage labels—not CVSS scores. Reflection is treated as suspected evidence, not proof that a script executed.

= Architecture and data flow

The application is served as a same-origin full-stack service. React, TypeScript, and Vite provide the browser interface. FastAPI exposes validated JSON endpoints and serves the compiled frontend. SQLAlchemy and Alembic manage SQLite records. A bounded in-process worker executes scans and persists events and findings as they occur.

#block(
  width: 100%,
  inset: 12pt,
  fill: rgb("#F2F6FA"),
  stroke: 0.6pt + rgb("#D4DEE8"),
  radius: 4pt,
)[
  #align(center)[
    #text(weight: "bold", fill: report-accent)[Browser UI]
    #text(fill: rgb("#22D3EE"))[  →  ]
    #text(weight: "bold", fill: report-accent)[FastAPI]
    #text(fill: rgb("#22D3EE"))[  →  ]
    #text(weight: "bold", fill: report-accent)[Authorized scan worker]
    #text(fill: rgb("#22D3EE"))[  →  ]
    #text(weight: "bold", fill: report-accent)[SQLite + private reports]
  ]
]

== Persistent records

SQLite stores users, sessions, targets, scans, scan events, findings, finding-status history, reports, and audit logs. User ownership is derived from the authenticated server context—not from a client-supplied owner ID. Report artifacts are stored privately on disk and tied to persisted report metadata.

== Main technology

#table(
  columns: (3.2cm, 12.6cm),
  stroke: none,
  inset: (x: 6pt, y: 5pt),
  fill: (x, y) => if calc.even(y) { rgb("#F5F8FB") } else { white },
  table.hline(stroke: 1pt + report-accent),
  table.header([*Layer*], [*Implementation*]),
  table.hline(stroke: 0.5pt + luma(180)),
  [Frontend], [React 19 · TypeScript · Vite · React Router · Recharts · Lucide],
  [API and workers], [Python 3.12+ · FastAPI · Pydantic · bounded background workers],
  [Persistence], [SQLAlchemy 2 · Alembic migrations · SQLite],
  [Authentication], [Argon2id password hashing · opaque server-side sessions · CSRF protection · owner-scoped access],
  table.hline(stroke: 1pt + report-accent),
)

= Security controls and boundaries

== Authorization and network safety

- Targets require explicit authorization and an exact allowed-host scope.
- Production rejects localhost, private, loopback, link-local, multicast, reserved, and cloud-metadata destinations.
- DNS answers are validated and pinned; every redirect is rechecked against the permitted scope.
- Only standard public HTTP(S) ports 80 and 443 are accepted.
- Request count, redirects, timeout, response size, scan duration, concurrency, and per-user start rate are bounded.
- Scanner requests do not carry a user's browser credentials; cookie values and the reflection marker are not retained as finding evidence.

== Application security

Passwords are stored as Argon2id hashes. Sessions are opaque random values whose hashes are persisted server-side. Protected operations apply CSRF controls where appropriate, rate limits, per-user ownership checks, safe validation errors, and audit records. No password, raw session token, or integration secret belongs in a screenshot or public repository.

== Known limitations

VulnSight does not perform active exploitation, credential attacks, arbitrary crawling, destructive payloads, data extraction, denial-of-service checks, authenticated-state scanning, or OWASP ZAP integration. A single TLS handshake and a bounded sample of responses cannot establish security across every route, user state, or possible TLS configuration. Worker and rate-limit state are process-local; this edition is intended for one application process, and unfinished jobs are marked interrupted after restart rather than resumed.

Severity labels express contextual triage and are not CVSS. The application is not a penetration-testing suite and cannot guarantee complete security.

= Interface snapshots

These screenshots are direct captures of the actual VulnSight authentication pages. They contain no personal account details, real targets, scan results, or seeded demo records.

#grid(
  columns: (1fr, 1fr),
  gutter: 12pt,
  block(
    width: 100%,
    inset: 7pt,
    fill: rgb("#F6F8FA"),
    stroke: 0.5pt + luma(210),
    radius: 4pt,
  )[
    #image("assets/sign-in.png", width: 100%)
    #v(4pt)
    #align(center)[#text(size: 9pt, weight: "bold")[Sign-in screen]]
  ],
  block(
    width: 100%,
    inset: 7pt,
    fill: rgb("#F6F8FA"),
    stroke: 0.5pt + luma(210),
    radius: 4pt,
  )[
    #image("assets/create-account.png", width: 100%)
    #v(4pt)
    #align(center)[#text(size: 9pt, weight: "bold")[Create-account screen]]
  ],
)

#block(
  width: 100%,
  inset: 10pt,
  fill: rgb("#FFF7E8"),
  stroke: (left: 3pt + rgb("#D98C10")),
  radius: 3pt,
)[
  *Responsible-use notice.* Verify explicit permission and exact scope before every assessment. Technical safeguards reduce risk but do not replace authorization, professional judgment, or a comprehensive security review.
]
