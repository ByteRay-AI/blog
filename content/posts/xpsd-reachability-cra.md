Title: Xpsd: Knowing Which CVEs Actually Reach Your Code
Date: 2026-08-05 12:00
Slug: xpsd-reachability-cra
Author: ByteRay
Category: Product
Tags: xpsd, appsec, cra, sbom, github-actions, reachability
Summary: Xpsd is our open-source reachability layer for scanner noise. It sits on Grype, Trivy, OSV-Scanner, Snyk, or any SARIF report and asks whether each finding is actually reachable in your tree, then lands verdicts in the GitHub Security tab. Here is how it works, how to use it, and how it helps teams preparing for CRA-era vulnerability handling.


Most security programmes already run a dependency scanner. The report arrives, the severity column turns red, and someone has to decide what to do with forty "critical" findings before Friday. Many of those findings describe a vulnerable package version that is present in the build, not a path an attacker can actually take through your product.

A scanner answers: *is this component in the tree?* It does not answer: *can attacker-controlled input reach the vulnerable code in this repository?* That second question is where triage time goes, and where real risk hides under a pile of alerts that look equally urgent on paper.

We built Xpsd to close that gap. It is open source under Apache 2.0, ships as a GitHub Action and CLI, and is part of the work we do at ByteRay around practical vulnerability analysis. This post explains what it is, how it works, how teams use it, who benefits, and how it fits the engineering side of preparing for the EU Cyber Resilience Act without pretending to be a compliance stamp.

## What Xpsd is

Xpsd is a reachability analyzer for reported vulnerabilities. You give it either a single CVE description or a full scanner report. It runs a focused analysis over your source tree and produces structured verdicts, markdown reports, and SARIF that GitHub code scanning can ingest.

It is designed to sit on top of tools you already trust:

* Grype
* Trivy
* OSV-Scanner
* Snyk (single project or `--all-projects`)
* Any SARIF 2.1.0 producer

Format detection is automatic in the common cases. You do not have to replace your scanner. You add a step that asks a sharper question about the findings that matter most.

Xpsd is not a replacement for human review on uncertain cases, and it is not a promise that every "not reachable" verdict is forever true in every deployment. It is a disciplined way to turn scanner output into evidence-backed priorities inside the same Security tab your team already watches.

## How it works

At a high level the pipeline is simple:

1. Parse the scan report into a normalised list of findings.
2. Optionally enrich and filter (severity, CVSS, remote-only, exploited-only, caps).
3. Analyse each selected finding in its own session.
4. Emit verdicts and SARIF for `upload-sarif`.

Each finding gets its own agent session. The model does not get a dump of your repository in context. That would be expensive and noisy. Instead it works through a read-only toolset: structural search with ast-grep, ordinary grep and file reads, OSV lookups, page fetches for advisories and fixing commits, and dependency fetching when the vulnerable component is pulled at build time rather than vendored in-tree.

The analysis is deliberately cheapest-first. Roughly:

1. Is our version even in the affected range?
2. Is the vulnerable package or symbol actually used here?
3. Can external input reach that use?
4. If yes, what is the call path, with file and line evidence?

Most findings exit early. A package that is never imported does not need a novel exploit story. A version outside the affected range does not need a path search. That is how a run stays affordable: cost is per finding, so filtering and early exits are part of the design, not an afterthought.

Decisive verdicts also go through a second, smaller review pass that tries to overturn the first answer using source tools only. When the reviewer disagrees with evidence, that answer wins, and the overturned rationale stays in the report. The point is not theatre. It is a cheap second look before you mark something quiet in the Security tab.

When a finding is ruled not reachable, Xpsd still files it, but as a low / informational alert rather than letting the original CVSS criticality dominate the board. The real score and the reasoning remain available. A critical that nothing can reach is what buries the one that can.

## How to use it

If your organisation already has GitHub Copilot enabled, the Action can authenticate with the workflow's built-in token. Grant `copilot-requests: write` alongside the usual `contents: read` and `security-events: write` for SARIF upload. Usage bills with the rest of your Copilot spend. If you prefer your own key, set `provider-type` and `api-key` for Anthropic, OpenAI, or Azure and leave the rest of the workflow the same.

A typical pattern is SBOM, scan, Xpsd, upload:

```yaml
permissions:
  contents: read
  security-events: write
  copilot-requests: write

jobs:
  reachability:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: anchore/sbom-action@v0
        with: {format: cyclonedx-json, output-file: sbom.cdx.json, upload-artifact: false}

      - uses: anchore/scan-action@v6
        with: {sbom: sbom.cdx.json, output-format: json, output-file: scan.json, fail-build: false}

      - uses: byteray-ai/xpsd@v1
        id: xpsd
        with:
          scan-file: scan.json
          model: gpt-5.3-codex
          min-severity: high
          max-findings: "10"

      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: ${{ steps.xpsd.outputs.sarif-file }}
          category: xpsd-reachability
```

Swap Grype for Trivy, OSV-Scanner, Snyk, or a SARIF export from whatever you already run. Useful knobs include `min-severity`, `min-cvss`, `max-findings`, `only`, `is-remote` (CVSS `AV:N` with positive evidence), `is-exploited` (CVSS-BT), and `fail-on` when you want a reachable verdict to fail the job. The `guidance` input is for ground truth the code cannot show on its own, for example that a listener binds only to localhost.

Full integration notes live in the repository docs. The short version: keep your scanner, add Xpsd, let the Security tab show what still deserves attention.

## Who it helps

**Programmers.** You already know the pain of a dependency bump that "must" happen because a CVE is critical, even when the vulnerable API is never called from your service. Xpsd gives you a concrete rationale and a call path (or a clear "not used here") you can attach to a ticket or a PR discussion. Less ritual upgrading. More time on the bugs that touch your entry points.

**Security and AppSec teams.** Triage queues grow faster than headcount. Xpsd does not remove judgment, but it ranks and documents. Reachable findings stay loud. Ruled-out findings stop competing for the same attention. Re-runs refresh the same alerts in place, so the board stays current instead of accumulating stale criticals.

**CISOs and security leadership.** The board does not need another chart of CVE counts. It needs a story about residual risk that engineering can defend: what we ship, what is known vulnerable, what is actually reachable in our products, and what we are doing about the rest. Xpsd turns scanner volume into that story without asking the organisation to abandon tools it has already standardised on.

**Manufacturers and product teams shipping into the EU.** If you sell products with digital elements, your vulnerability handling process will be under more formal pressure over the next two years. Xpsd will not write your technical documentation for you. It can help the engineering layer underneath: from inventory and scan, to documented decisions about which issues demand immediate remediation in *this* codebase.

## The CRA angle, carefully

The EU Cyber Resilience Act (Regulation (EU) 2024/2847) is no longer a distant slide. Two dates matter for planning:

* **11 September 2026.** Reporting obligations for actively exploited vulnerabilities and severe incidents begin. Early warning is measured in hours (24 hours for the first signal, with follow-up within 72 hours where required). When an exploited issue lands in a component you ship, you will not have a leisurely sprint to discover whether it touches your product.
* **11 December 2027.** Full application of the remaining obligations, including the essential cybersecurity requirements, conformity assessment pathways, and the enforceable expectation of a machine-readable SBOM covering at least top-level dependencies, kept current and available to authorities on request.

Annex I Part II asks manufacturers to identify and document vulnerabilities and components, including by drawing up that SBOM, and to handle vulnerabilities with real process: updates, disclosure policy, testing, and timely remediation. The regulation does **not** name "reachability analysis" as a checkbox. What it does demand is seriousness about component risk and the ability to act under time pressure.

That is where Xpsd belongs in a CRA-era toolchain:

1. Maintain an SBOM (CycloneDX or SPDX are the usual engineering choices).
2. Continuously identify known vulnerabilities in those components with the scanner you already run.
3. Use reachability to separate "present in the bill of materials" from "on a path that matters in this product," and keep the evidence with the finding.

That sequence does not make anyone "CRA compliant." Compliance is a legal and organisational programme. This is the engineering step after "we have an SBOM and a scan," so that 24-hour clocks and backlog meetings are not spent rediscovering whether a library is imported. Treat this section as engineering guidance, not legal advice.

## Try it

Xpsd is Apache 2.0 and lives at [github.com/ByteRay-AI/xpsd](https://github.com/ByteRay-AI/xpsd). Point it at a real scan from a repository you care about, keep `max-findings` modest on the first run, and read the SARIF in the Security tab beside your existing alerts.

If a verdict looks wrong, that is useful signal. Open an issue. The goal is not a perfect oracle. It is a clearer board, a shorter path from "CVE exists" to "this one can touch us," and a habit of documenting why the others can wait.

We built Xpsd because scanner noise was burying the findings that deserved a bad day. If that sounds familiar, we would rather you spend the bad day on the reachable ones.
