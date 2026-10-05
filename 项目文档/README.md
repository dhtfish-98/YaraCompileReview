> 目录已整理：文档在「项目文档」，构建、缓存与暂存输入在「Build」。从仓库根目录运行 `python3 构建.py --build`；如需使用本文原有源码命令，先运行 `python3 构建.py --stage --ci`，再进入 `Build/源码`。暂存会恢复原输入路径。现有版本和历史验证记录按各自提交理解。

# YaraCompileReview

New implementation author: **dhtfish98**. Current package version: **1.0.3**.

Validates defensive detection rule deployment inputs without scanning or executing target content. yara-python remains an attributed external compiler dependency, not a rewritten compiler.

## Supported project scope

Complete local rule-source validation wrapper: direct source or bounded explicit namespace/include mapping, compiler subprocess with wall/CPU limits, compiler errors/warnings and private-safe verdict/count output.

This repository implements that entire selected standalone scope. It does not claim that the original upstream platform has been rewritten in full.

## Use

```sh
python -m pip install .
yaracompilereview examples/valid.bin
```

Supply one local regular file. The file CLI requires OS `O_NOFOLLOW` and `O_NONBLOCK` support; missing safety flags return OPEN before opening the path. This file-reader contract was verified on macOS/Linux; native Windows file reading is outside the validated profile. No symlinks or automatic artifact discovery are accepted. The CLI prints JSON; exit 0 means supported checks completed, exit 1 means a structural failure, and exit 2 means unsupported/incomplete analysis. Each successful read includes the input SHA-256 and byte count. Paths, contents, report messages and identities are suppressed. The input is never modified.

## Explicit limits and boundaries

The compiler binding is the official VirusTotal/yara-python source at fixed commit `c1cdca5a1b1413f68d7af008bf43ab310d6f19a7`, with official libyara submodule `84b0e3cc0e42f8f8e6b84d19c97ec3ac6ff8aee8` (4.5.8). Installation requires Git and a native C build toolchain. There is no fallback to the older PyPI wheel. The actual embedded `yara.YARA_VERSION` must be a recognized numeric version at least 4.5.8; older/unknown native versions return OPEN before `yara.compile`. The Python distribution version (4.5.5 for this commit) is separate from the native compiler version.

This version requirement closes the compiler-reachable INT64_MIN constant-folding issue documented in [official YARA #2211](https://github.com/VirusTotal/yara/pull/2211). A finite set of successful tests does not prove the absence of other native compiler defects. The private compiler is invoked through Python isolated mode (`-I`), which excludes the caller working directory, `PYTHONPATH` and user site from module lookup. A real installed package is required, including when testing source changes; if the isolated child cannot import the installed compiler, analysis remains OPEN. The subprocess provides wall/CPU limits and, on Linux, a 512 MiB address-space limit. It is not an OS privilege or network sandbox; macOS has no imposed address-space limit here. No sample scanning, compiled-rule loading or YARA virtual-machine execution is performed.

Input limit: 16 MiB. Record limit: 100,000. Additional format-specific limits are enforced in the source.  YARA compilation uses a 5-second wall deadline and 3-second CPU limit; compilation warnings fail validation. Includes are disabled unless the supplied mapping explicitly names authorized in-memory content.

Excluded capabilities: Sample scanning, Rules.match, automatic rule repairs, remote retrieval, disk buffering and filesystem includes.

PASS only describes the recorded checks. It does not prove real-world safety, historical activity, authenticity, applicant contribution or CVP approval. CVP application suitability/qualification remains OPEN until the applicant supplies the real authorized work, relevant restriction evidence and identity/organization facts.

## Provenance and validation

See [ORIGIN.md](<ORIGIN.md>), [SOURCE_MANIFEST.json](<SOURCE_MANIFEST.json>), [VALIDATION.md](<VALIDATION.md>) and the preserved [LICENSE](<LICENSE>).
