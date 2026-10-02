# Source and contribution record

Technical source: [CIRCL/yara-validator](https://github.com/CIRCL/yara-validator) at fixed commit `2cbcea8a9470023a49fc6c620493e23a041f563a`. License: `GPL-3.0-only`; the original license text and original copyright notices are preserved.

This is a Codex-assisted implementation of the explicitly selected standalone scope below. It is not presented as original ownership of the upstream algorithms or as a full rewrite of an upstream platform. No source files have merely been renamed into the runtime package.

Scope: Complete local rule-source validation wrapper: direct source or bounded explicit namespace/include mapping, compiler subprocess with wall/CPU limits, compiler errors/warnings and private-safe verdict/count output.

The upstream entry points, format layouts and relevant default file/network/execution paths were inspected in the fixed files listed in SOURCE_MANIFEST.json. Complete new runtime files are reviewed separately; this does not imply audit of unselected upstream platform code.

Excluded upstream capabilities: Sample scanning, Rules.match, automatic rule repairs, remote retrieval, disk buffering and filesystem includes.

The repository owner must verify their actual contribution and authorization before using this record in an application. No CVE, rejected-model task, CVP acceptance or personal identity evidence has been invented.

Compiler dependency provenance: official VirusTotal/yara-python commit `c1cdca5a1b1413f68d7af008bf43ab310d6f19a7` (Apache-2.0), with official VirusTotal/yara gitlink `84b0e3cc0e42f8f8e6b84d19c97ec3ac6ff8aee8` (BSD-3-Clause, native 4.5.8). These are installed dependencies, not rewritten runtime code or applicant-owned algorithms. Distribution 4.5.5 and embedded native 4.5.8 are recorded separately. Upstream licenses remain in the installed official dependency.
