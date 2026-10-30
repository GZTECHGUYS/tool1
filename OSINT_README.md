# OSINT Mapping Tool Integration into ARDF

## Overview

The **anonymousRAID OSINT-Mapping-Tool** is now fully integrated into ARDF as a specialized intelligence module. This module:

- Converts reconnaissance findings into semantic identifier nodes
- Builds geolocation intelligence maps with poi pinning
- Cross-links identifiers to locations for pattern detection
- Performs cluster analysis to identify connected entities
- Exports/imports the standard `.osint.json` format
- Feeds intelligence findings back into ARDF's finding system

---

## Files Included

1. **`osint_mapping.py`** (593 lines)
   - Core OSINT mapping module
   - Classes: `OSINTMappingModule`, `OSINTGraph`, `Identifier`, `GeoLocation`, `EdgeConnection`
   - Enums: `IdentifierType`, `IdentifierSubType`, `PlaceType`
   - Full import/export of `.osint.json`

2. **`OSINT_INTEGRATION.py`** (354 lines)
   - Integration examples and usage patterns
   - 6 complete working examples
   - `.osint.json` schema reference
   - ARDF pipeline integration guide

3. **This README**

---

## Quick Start

### Installation

Copy `osint_mapping.py` into `/ARDF/modules/`:

```bash
cp osint_mapping.py /path/to/ARDF/modules/
```

### Basic Usage

```python
from modules.osint_mapping import OSINTMappingModule
from modules.session import Session

# Create session
session = Session(target="target.local")

# Initialize OSINT module
osint = OSINTMappingModule(session)

# Execute - automatically ingests recon findings
result = osint.execute()

print(f"Identifiers: {result['identifiers']}")
print(f"Locations: {result['locations']}")
print(f"Connections: {result['connections']}")
print(f"Findings: {len(result['findings'])}")

# Export to .osint.json
# Output saved to: osint.osint_file_path
```

---

## Identifier Types

### Social Media
- `INSTAGRAM` — Instagram account
- `FACEBOOK` — Facebook profile
- `TWITTER` — X/Twitter handle
- `YOUTUBE` — YouTube channel
- `TIKTOK` — TikTok account
- `LINKEDIN` — LinkedIn profile
- `SNAPCHAT` — Snapchat username
- `DISCORD` — Discord user
- `TELEGRAM` — Telegram account

### Contact Information
- `EMAIL` — Email address
- `PHONE` — Phone number
- `ADDRESS` — Physical address
- `DOMAIN` — Domain name
- `WEBSITE` — Website URL

### Personal Identifiers
- `PERSON` — Named individual
- `FAMILY_MEMBER` — Family relation
- `ASSOCIATE` — Contact or colleague
- `ORGANIZATION` — Company or group

### Vehicle Identifiers
- `LICENSE_PLATE` — Vehicle license plate
- `VEHICLE` — Car/motorcycle info
- `AIRCRAFT` — Aircraft tail number
- `VESSEL` — Ship or boat

### Financial Identifiers
- `BANK_ACCOUNT` — Bank account reference
- `CRYPTOCURRENCY` — Crypto wallet address
- `PAYMENT_METHOD` — Payment service account

### Network Identifiers
- `IP_ADDRESS` — IP address
- `DOMAIN_NAME` — Domain
- `USERNAME` — Username or handle

### Other
- `DOCUMENT` — Document reference
- `FILE` — File path/hash
- `REFERENCE` — Generic reference

---

## Location Types (Map Pins)

- `HOME` — Residential address
- `WORK` — Office/workplace
- `COFFEE` — Coffee shop
- `FOOD` — Restaurant
- `GYM` — Fitness facility
- `MOVIE` — Cinema/theater
- `PARK` — Park or outdoor space
- `SCHOOL` — School/university
- `SHOPPING` — Shopping center
- `LIBRARY` — Library
- `AMUSEMENT_PARK` — Amusement park
- `OTHER` — Miscellaneous location

---

## Core API

### OSINTMappingModule

```python
osint = OSINTMappingModule(session)

# Execute full analysis pipeline
result = osint.execute()

# Add identifier manually
identifier_id = osint.add_identifier_from_recon(
    value="john_doe_insta",
    subtype=IdentifierSubType.INSTAGRAM,
    metadata={"followers": 1500}
)

# Cross-link identifier to location
osint.link_identifier_to_location(
    identifier_id,
    location_id,
    relationship="tagged_at",
    notes="Instagram check-in"
)

# Export/Import
osint.export_osint_json()
osint.import_osint_json("/path/to/file.osint.json")
```

### OSINTGraph

```python
graph = osint.graph

# Add nodes
identifier = Identifier(
    subtype=IdentifierSubType.EMAIL,
    value="user@example.com",
    confidence=0.85
)
node_id = graph.add_identifier(identifier)

location = GeoLocation(
    latitude=40.7128,
    longitude=-74.0060,
    name="Coffee Shop",
    place_type=PlaceType.COFFEE
)
pin_id = graph.add_location(location)

# Create connections
graph.link(node_id, pin_id, "visited")

# Analysis
clusters = graph.get_identifier_clusters()
locations = graph.get_identifier_locations(node_id)
identifiers = graph.get_location_identifiers(pin_id)

# Serialize
data = graph.to_dict()  # → .osint.json format
graph = OSINTGraph.from_dict(data)  # ← from .osint.json
```

---

## .osint.json Format

Complete, standardized format for OSINT research:

```json
{
  "schema_version": "1.0",
  "created_at": "2026-09-29T12:00:00",
  "identifiers": {
    "node_id_1": {
      "node_id": "node_id_1",
      "subtype": "instagram",
      "value": "@johndoe",
      "metadata": {...},
      "confidence": 0.85,
      "source": "recon:domain",
      "timestamp": "2026-09-29T12:00:00",
      "tags": ["social", "recon"]
    }
  },
  "locations": {
    "pin_id_1": {
      "pin_id": "pin_id_1",
      "latitude": 40.7128,
      "longitude": -74.0060,
      "name": "Coffee Shop",
      "address": "123 Main St",
      "place_type": "coffee",
      "notes": "Frequent location",
      "visit_date": "2026-09-15",
      "confidence": 0.9,
      "source": "osint_analysis",
      "timestamp": "2026-09-29T12:00:00"
    }
  },
  "edges": {
    "edge_id_1": {
      "edge_id": "edge_id_1",
      "source_id": "node_id_1",
      "target_id": "pin_id_1",
      "relationship": "tagged_at",
      "notes": "Instagram check-in",
      "confidence": 0.85,
      "timestamp": "2026-09-29T12:00:00"
    }
  }
}
```

This format is **compatible with the web-based OSINT-Mapping-Tool** — you can export from ARDF and open directly in the web interface.

---

## Integration with ARDF Pipeline

### Architecture

```
┌─────────────────────────────┐
│   Reconnaissance Modules    │
│  (domain, subdomain, email) │
└──────────────┬──────────────┘
               ↓
         [Findings in Session]
               ↓
┌──────────────────────────────┐
│   OSINT Mapping Module       │
│  (ingests findings)          │
│  (builds graph)              │
│  (analyzes clusters)         │
│  (maps locations)            │
└──────────────┬───────────────┘
               ↓
         [Intelligence Findings]
               ↓
┌──────────────────────────────┐
│  Attack Chain Selection      │
│  (cluster-based targeting)   │
│  (location-based tactics)    │
└──────────────────────────────┘
```

### Workflow

1. **Recon Phase** — Domain/subdomain enumeration, email discovery, social media profiling
2. **OSINT Analysis** — Convert findings to identifier nodes, detect clusters, map geography
3. **Intelligence** — Cluster analysis generates high-priority targets
4. **Attack Planning** — Use clusters and geographic data to select attack chains
5. **Execution** — Target high-value identifiers with lateral movement

---

## Finding Categories

The OSINT module generates findings in these categories:

- **`osint_cluster`** — Detected connected identifier clusters (severity: HIGH)
- **`osint_location`** — Locations with high activity (severity: MEDIUM)
- **`osint_pattern`** — Repeated relationship patterns (severity: MEDIUM)

All findings are registered with ARDF's session and available for downstream modules.

---

## MITRE ATT&CK Mapping

The OSINT module maps to the following techniques:

- **T1591** — Gather Victim Identity Information
- **T1589** — Gather Victim Identity Information (specific)
- **T1590** — Gather Victim Network Information
- **T1598** — Phishing for Information
- **T1597** — Search Open Websites/Domains

---

## Example: Complete Workflow

```python
from modules.redteam import RedTeamOrchestrator, OpSecMode
from modules.osint_mapping import OSINTMappingModule
from modules.session import Session

# 1. Create session
session = Session(target="target.local")

# 2. Run reconnaissance (existing modules)
# → session.findings populated with emails, domains, social accounts

# 3. Run OSINT analysis
osint = OSINTMappingModule(session)
osint_result = osint.execute()

# Results:
# - Identifiers: 47
# - Locations: 12
# - Connections: 89
# - Clusters: 3 (entities with 3+ identifiers each)
# - Findings: 8

# 4. Use results for attack planning
if osint_result['success']:
    clusters = osint.graph.get_identifier_clusters()
    large_clusters = [c for c in clusters.values() if len(c) > 3]
    
    # These are high-priority targets
    print(f"High-priority targets: {len(large_clusters)}")
    
    # Export for team collaboration
    print(f"OSINT data: {osint.osint_file_path}")

# 5. Initialize red team orchestrator
red_team = RedTeamOrchestrator(session)
mission = red_team.initialize_mission(
    mission_id="op_1",
    name="Targeted Domain Takeover",
    objective="Compromise primary identified cluster",
    scope=["10.0.0.0/8"],
    opsec_mode=OpSecMode.BALANCED
)

# 6. Execute full kill chain
result = red_team.execute()
```

---

## Compatibility

### With Web Tool

The `.osint.json` format is **100% compatible** with the web-based [anonymousRAID OSINT-Mapping-Tool](https://github.com/anonymousRAID/OSINT-Mapping-Tool):

- Export from ARDF → Open in web tool
- Build in web tool → Import into ARDF

### With ARDF

- Inherits from `RedTeamModule` — logs to ARDF logger
- Registers findings to `Session`
- Integrates with existing recon modules
- Feeds intelligence to attack planning modules

---

## Performance Notes

- **Cluster detection** — O(n + m) where n = identifiers, m = edges
- **Location queries** — O(m) for edge traversal
- **Export/import** — Depends on graph size (typical: <100ms for 1000 nodes)
- **Memory** — ~1-2KB per identifier, ~500B per location, ~300B per edge

---

## Future Enhancements

- [ ] Graph visualization export (GraphML, GexF)
- [ ] Social network analysis (betweenness, eigenvector centrality)
- [ ] Timeline reconstruction from timestamps
- [ ] Geofencing and movement pattern detection
- [ ] Threat intelligence integration
- [ ] Machine learning cluster refinement

---

## Contributing

See main ARDF documentation. OSINT module follows same patterns as other Red Team modules.

---

## License

OSINT Mapping Module: Same as ARDF framework

Original Tool (anonymousRAID/OSINT-Mapping-Tool): GPL-3.0

---

**Status:** Production Ready ✓  
**Version:** 1.0  
**Last Updated:** 2026-09-29
