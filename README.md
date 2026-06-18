# hunt-ops-reports

Public threat hunt reports with machine-readable artifacts. Each report ships a STIX 2.1 bundle, Sigma detection rules, an ATT&CK Navigator layer, a Unified Kill Chain mapping, and platform-specific hunting queries ready to paste into your SIEM or EDR.

---

## What This Is

Curated threat intelligence reports covering real exploits, malware, and attacker techniques. Each entry is self-contained under `reports/<date>_<name>/` and includes:

| Artifact | File | Purpose |
|---|---|---|
| Human-readable report | `report.md` | Full narrative analysis, attack chain, IOC table, detection guidance |
| Machine-readable IOCs | `iocs.csv` | Flat CSV for bulk import or scripting |
| STIX 2.1 bundle | `stix/bundle.json` | Import into MISP, OpenCTI, or any STIX-aware platform |
| ATT&CK Navigator layer | `mappings/mitre-layer.json` | Upload to Navigator for visual coverage view |
| Unified Kill Chain mapping | `mappings/ukc.md` | 18-phase UKC coverage table |
| Sigma rules | `sigma/*.yml` | Convert to any SIEM/EDR with sigma-cli |
| Platform queries | `queries/elastic.kql`, `queries/splunk.spl`, `queries/mde.kql` | Ready-to-run detection queries |

---

## Repo Structure

```
threat-reports/
├── README.md
└── reports/
    └── YYYY-MM-DD_<name>/
        ├── report.md
        ├── iocs.csv
        ├── stix/
        │   ├── config.yml
        │   └── bundle.json
        ├── mappings/
        │   ├── mitre-layer.json
        │   └── ukc.md
        ├── sigma/
        │   └── *.yml
        └── queries/
            ├── elastic.kql
            ├── splunk.spl
            └── mde.kql
```

---

## How to Use the STIX Bundles

### Import into MISP

```bash
python -c "
from pymisp import PyMISP
api = PyMISP('https://your-misp/', 'YOUR_KEY')
api.upload_stix('reports/2026-06-18_rogueplanet-defender-lpe/stix/bundle.json')
"
```

### Import into OpenCTI

1. Navigate to **Data → Import** in the OpenCTI UI.
2. Select **STIX 2.1** as the import format.
3. Upload `stix/bundle.json`.

---

## How to Use Sigma Rules

Install [sigma-cli](https://github.com/SigmaHQ/sigma-cli) and the relevant backend:

```bash
pip install sigma-cli
pip install pySigma-backend-elasticsearch
pip install pySigma-backend-splunk
pip install pySigma-backend-microsoft365defender
```

Convert a single rule:

```bash
# Elastic (ECS/Lucene)
sigma convert -t lucene -p ecs_windows \
  reports/2026-06-18_rogueplanet-defender-lpe/sigma/rogueplanet_named_pipe.yml

# Splunk
sigma convert -t splunk -p windows \
  reports/2026-06-18_rogueplanet-defender-lpe/sigma/rogueplanet_named_pipe.yml

# MDE (KQL)
sigma convert -t microsoft365defender \
  reports/2026-06-18_rogueplanet-defender-lpe/sigma/rogueplanet_named_pipe.yml
```

Convert all rules in a report:

```bash
sigma convert -t lucene -p ecs_windows \
  reports/2026-06-18_rogueplanet-defender-lpe/sigma/
```

---

## How to Load the ATT&CK Navigator Layer

1. Open [https://mitre-attack.github.io/attack-navigator/](https://mitre-attack.github.io/attack-navigator/).
2. Click **Open Existing Layer → Upload from local**.
3. Select `reports/<report-dir>/mappings/mitre-layer.json`.

---

## Reports Index

| Date | Name | Type | Severity | ATT&CK Techniques |
|---|---|---|---|---|
| 2026-06-18 | [RoguePlanet Windows Defender LPE](reports/2026-06-18_rogueplanet-defender-lpe/report.md) | LPE | Critical | T1068, T1053.005, T1036, T1564.004, T1559.001, T1548, T1553 |

---

## License

All content in this repository is released under [CC0 1.0 Universal](https://creativecommons.org/publicdomain/zero/1.0/) — no rights reserved. Use freely.
