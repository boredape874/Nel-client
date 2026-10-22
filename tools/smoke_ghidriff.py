"""Exercise the real image with tiny self-authored C programs, never game files."""
import json
from pathlib import Path
import subprocess
import tempfile
from bedrock_analysis import ROOT, deep_diff

with tempfile.TemporaryDirectory(prefix='nel-ghidriff-fixture-') as directory:
    work = Path(directory)
    inputs = work / 'inputs'
    inputs.mkdir()
    for name, value in [('old', 7), ('new', 11)]:
        source = work / f'{name}.c'
        source.write_text(f'int compute(int x) {{ return x * {value} + 3; }}\nint main(void) {{ return compute(2); }}\n')
        subprocess.run(['gcc', '-O0', '-g', '-o', str(inputs / f'{name}.elf'), str(source)], check=True)
    settings = json.loads((ROOT / 'analysis/settings.json').read_text())
    settings['deep_timeout_seconds'] = 480
    try:
        print(json.dumps(deep_diff(work, inputs / 'old.elf', inputs / 'new.elf', settings), indent=2))
    except Exception:
        log = work / 'engine.log'
        if log.exists():
            print(log.read_text(errors='replace')[-18000:])
        raise
