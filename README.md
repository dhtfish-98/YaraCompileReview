# YaraCompileReview

Validates defensive detection rule deployment inputs without scanning or executing target content. yara-python remains an attributed external compiler dependency, not a rewritten compiler.

## Supported project scope

Complete local rule-source validation wrapper: direct source or bounded explicit namespace/include mapping, compiler subprocess with wall/CPU limits, compiler errors/warnings and private-safe verdict/count output.

This repository implements that entire selected standalone scope. It does not claim that the original upstream platform has been rewritten in full.

## Use

```sh
python -m pip install .
yaracompilereview examples/valid.bin
```

Supply one local regular file. No symlinks or automatic artifact discovery are accepted. The CLI prints JSON; exit 0 means supported checks completed, exit 1 means a structural failure, and exit 2 means unsupported/incomplete analysis. Each successful read includes the input SHA-256 and byte count. Paths, contents, report messages and identities are suppressed. The input is never modified.

## Explicit limits and boundaries

Input limit: 16 MiB. Record limit: 100,000. Additional format-specific limits are enforced in the source.  YARA compilation uses a 5-second wall deadline and 3-second CPU limit; compilation warnings fail validation. Includes are disabled unless the supplied mapping explicitly names authorized in-memory content.

Excluded capabilities: Sample scanning, Rules.match, automatic rule repairs, remote retrieval, disk buffering and filesystem includes.

PASS only describes the recorded checks. It does not prove real-world safety, historical activity, authenticity, applicant contribution or CVP approval. CVP application suitability/qualification remains OPEN until the applicant supplies the real authorized work, relevant restriction evidence and identity/organization facts.

## Provenance and validation

See [ORIGIN.md](ORIGIN.md), [SOURCE_MANIFEST.json](SOURCE_MANIFEST.json), [VALIDATION.md](VALIDATION.md) and the preserved [LICENSE](LICENSE).
