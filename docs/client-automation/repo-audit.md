# Nel-client repository audit

Audit date: 2026-10-22
Repository: https://github.com/boredape874/Nel-client
Default branch: main
Starting commit: 0cb60bfd363dd8cd458d18b7e373bea308d495d7

## Observed
- The repository currently contains only `.gitignore` and a minimal `README.md`.
- No client DLL, launcher/loader, CMake or MSBuild files, tests, signature table, supported-version list, or CI workflow is present.
- Project kind is stated by the owner as a Minecraft Bedrock native client; Windows x64 is an initial hypothesis from the project description, not yet verified from source.
- No Minecraft client binary inputs or game runtime environment are present in the repository.

## M1 decisions
- Add offline tooling that identifies PE files by structure and SHA-256, and scans only explicitly supplied patterns.
- Keep the active target catalogue empty until real client source or a reviewed manifest supplies targets. Empty means `bootstrap_required`, never “all targets passed”.
- Do not download or redistribute Minecraft binaries, install the game, run the game, or infer patterns/offsets.
- BDS analysis is out of scope for this client catalogue. It may only be added later as separate supporting evidence.

## Blocked
- Real old/new client comparison: blocked until approved client binary inputs and provenance are supplied.
- Active signature scan: blocked until genuine targets are extracted from the client source.
- Build/runtime checks: not applicable yet; no buildable client code or supported loader has been provided.

## Next evidence needed
1. Client source and its existing build instructions.
2. A known-good client binary identity and a new client binary identity, supplied through an approved private input path.
3. Actual signature/offset registration code and version-selection behavior.
