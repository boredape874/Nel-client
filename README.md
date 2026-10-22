# Nel-client

An open-source Minecraft Bedrock native client project.

## Client compatibility tooling

This repository includes an initial offline tool for recording Windows PE identity and checking explicitly supplied byte patterns. It does not download or run Minecraft, and it does not claim game compatibility. The target catalogue is intentionally empty until real project signatures are added and reviewed.

Run the fixture tests with Python 3.12 or newer:

```bash
python -m unittest discover -s tests -v
```

To inspect a locally supplied client executable:

```bash
python scripts/mcbe_compat.py path/to/client.exe --targets compat/targets.json --output report.json
```

The current repository has no client source/build project or real signature catalogue yet. See [the audit](docs/client-automation/repo-audit.md) before treating any report as compatibility evidence.
