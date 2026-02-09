# Capture Decode CLI

Live packet capture and decode CLI that prints compact summaries or structured JSON.

## What it does
- Captures packets from a specified network interface using Scapy.
- Decodes each packet into a structured record (L2-L4, addresses, ports, flags, stack summary).
- Supports capture filters (BPF) and post-decode filter expressions.
- Outputs in table, JSON, or JSONL formats.
- Can write JSON/JSONL output to a file.

## Requirements
- Python 3.8+
- Dependencies in `requirements.txt`:
  - `click`
  - `scapy`

## Install
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Usage
```powershell
python run.py --interface <name> [options]
```

### Options
- `-i, --interface` (required): Interface to capture from.
- `-d, --duration`: Duration in seconds (default: run until limit).
- `-f, --filter`: BPF capture filter (e.g., `"tcp port 80"`).
- `--packet-filter, --filter-expr`: Filter expression applied after decoding.
- `--limit`: Max packets to decode (`0` = no limit). Default: `50`.
- `--show-quality`: Show decode quality flags.
- `--format`: Output format: `table`, `json`, `jsonl`. Default: `table`.
- `--output`: Write JSON/JSONL output to file.

### Examples
Capture 100 packets on Ethernet and print a table:
```powershell
python run.py -i "Ethernet" --limit 100
```

Capture for 30 seconds with a BPF filter and JSON output:
```powershell
python run.py -i "Ethernet" -d 30 -f "tcp port 443" --format json
```

Capture and write JSONL to a file:
```powershell
python run.py -i "Ethernet" --format jsonl --output out.jsonl
```

## Notes
- Administrative privileges may be required for packet capture on some systems.
- Use `Ctrl+C` to stop early; JSON output will still be emitted when possible.
