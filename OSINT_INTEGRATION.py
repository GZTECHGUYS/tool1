"""
OSINT-ARDF Integration Guide
═════════════════════════════

Integrates anonymousRAID/OSINT-Mapping-Tool into ARDF pipeline.

The OSINT mapping tool is now a full module in ARDF that:
  - Consumes recon findings and converts to identifier nodes
  - Builds geolocation intelligence maps
  - Cross-links identifiers to locations
  - Generates intelligence clusters
  - Exports standard .osint.json format
  - Feeds findings back into ARDF session
"""

from modules.osint_mapping import (
    OSINTMappingModule,
    OSINTGraph,
    Identifier,
    GeoLocation,
    IdentifierSubType,
    PlaceType,
)
from modules.session import Session


# ═══════════════════════════════════════════════════════════════════════════
# EXAMPLE 1: Basic OSINT Mapping from Recon Findings
# ═══════════════════════════════════════════════════════════════════════════

def example_basic_mapping():
    """Ingest recon findings and build OSINT graph."""
    
    # Create session
    session = Session(target="target.local")
    
    # Initialize OSINT module
    osint = OSINTMappingModule(session)
    
    # Module will automatically:
    # 1. Ingest all findings from session.findings (from prior recon)
    # 2. Convert to identifier nodes
    # 3. Analyze clusters
    # 4. Map locations
    # 5. Generate findings
    
    result = osint.execute()
    
    print(f"Status: {result['success']}")
    print(f"Identifiers found: {result['identifiers']}")
    print(f"Locations identified: {result['locations']}")
    print(f"Connections: {result['connections']}")
    print(f"Intelligence findings: {len(result['findings'])}")


# ═══════════════════════════════════════════════════════════════════════════
# EXAMPLE 2: Manual Identifier and Location Addition
# ═══════════════════════════════════════════════════════════════════════════

def example_manual_entry():
    """Manually build OSINT graph without recon module."""
    
    session = Session(target="target.local")
    osint = OSINTMappingModule(session)
    
    # Add identifiers manually
    john_id = osint.add_identifier_from_recon(
        value="john_doe_insta",
        subtype=IdentifierSubType.INSTAGRAM,
        metadata={
            "followers": 1500,
            "posts": 234,
            "bio": "Travel enthusiast",
        }
    )
    
    # Add location
    coffee_shop = GeoLocation(
        latitude=40.7128,
        longitude=-74.0060,
        name="The Daily Grind Coffee",
        address="123 Main St, NYC",
        place_type=PlaceType.COFFEE,
        notes="Tagged in IG story 3 times",
        visit_date="2026-09-15",
    )
    location_id = osint.graph.add_location(coffee_shop)
    
    # Cross-link them
    osint.link_identifier_to_location(
        john_id,
        location_id,
        relationship="tagged_at",
        notes="Instagram story check-in"
    )
    
    # Add another identifier and link it to same location
    email_id = osint.add_identifier_from_recon(
        value="john.doe@company.com",
        subtype=IdentifierSubType.EMAIL,
        metadata={"domain": "company.com"}
    )
    
    osint.link_identifier_to_location(
        email_id,
        location_id,
        relationship="work_location",
        notes="LinkedIn profile lists this coffee shop as frequent location"
    )
    
    # Execute analysis
    result = osint.execute()
    
    # Export to .osint.json
    print(f"OSINT mapping exported to: {osint.osint_file_path}")


# ═══════════════════════════════════════════════════════════════════════════
# EXAMPLE 3: Import .osint.json and Continue Analysis
# ═══════════════════════════════════════════════════════════════════════════

def example_import_and_extend():
    """Load saved OSINT mapping and extend it."""
    
    session = Session(target="target.local")
    osint = OSINTMappingModule(session)
    
    # Load existing mapping
    success = osint.import_osint_json("/path/to/existing/mapping.osint.json")
    
    if success:
        # Add new findings
        twitter_id = osint.add_identifier_from_recon(
            value="@johndoe",
            subtype=IdentifierSubType.TWITTER,
            metadata={"followers": 500}
        )
        
        # Re-analyze with new data
        result = osint.execute()
        
        print(f"Extended graph with new identifier: {twitter_id}")
        print(f"Total identifiers now: {result['identifiers']}")


# ═══════════════════════════════════════════════════════════════════════════
# EXAMPLE 4: Cluster Analysis and Intelligence Synthesis
# ═══════════════════════════════════════════════════════════════════════════

def example_cluster_analysis():
    """Analyze identifier clusters to find connected entities."""
    
    session = Session(target="target.local")
    osint = OSINTMappingModule(session)
    
    # Build graph (would normally come from recon)
    person1_id = osint.add_identifier_from_recon(
        value="alice_linkedin",
        subtype=IdentifierSubType.LINKEDIN,
    )
    
    person2_id = osint.add_identifier_from_recon(
        value="alice@email.com",
        subtype=IdentifierSubType.EMAIL,
    )
    
    phone_id = osint.add_identifier_from_recon(
        value="+1-555-1234",
        subtype=IdentifierSubType.PHONE,
    )
    
    # Link them together
    osint.graph.link(person1_id, person2_id, "belongs_to_person")
    osint.graph.link(person2_id, phone_id, "belongs_to_person")
    
    # Analyze
    clusters = osint.graph.get_identifier_clusters()
    
    # All three should be in same cluster
    for node_id, cluster in clusters.items():
        if node_id == person1_id:
            print(f"Cluster containing alice_linkedin has {len(cluster)} members:")
            for member_id in cluster:
                member = osint.graph.identifiers[member_id]
                print(f"  - {member.value} ({member.subtype.value})")


# ═══════════════════════════════════════════════════════════════════════════
# EXAMPLE 5: Geographic Intelligence
# ═══════════════════════════════════════════════════════════════════════════

def example_geographic_intelligence():
    """Build geographic intelligence from locations."""
    
    session = Session(target="target.local")
    osint = OSINTMappingModule(session)
    
    # Add locations
    home = GeoLocation(
        latitude=40.7128,
        longitude=-74.0060,
        name="Apartment 4B",
        place_type=PlaceType.HOME,
    )
    
    work = GeoLocation(
        latitude=40.7489,
        longitude=-73.9680,
        name="Tech Company HQ",
        place_type=PlaceType.WORK,
    )
    
    gym = GeoLocation(
        latitude=40.7505,
        longitude=-73.9972,
        name="FitZone Gym",
        place_type=PlaceType.GYM,
    )
    
    home_id = osint.graph.add_location(home)
    work_id = osint.graph.add_location(work)
    gym_id = osint.graph.add_location(gym)
    
    # Add person
    person_id = osint.add_identifier_from_recon(
        value="target_person",
        subtype=IdentifierSubType.PERSON,
    )
    
    # Link person to multiple locations
    osint.link_identifier_to_location(person_id, home_id, "lives_at")
    osint.link_identifier_to_location(person_id, work_id, "works_at")
    osint.link_identifier_to_location(person_id, gym_id, "frequent_visitor")
    
    # Get locations for this person
    locations = osint.graph.get_identifier_locations(person_id)
    
    print(f"Person has {len(locations)} linked locations:")
    for loc_id, relationship in locations:
        loc = osint.graph.locations[loc_id]
        print(f"  - {loc.name} ({relationship})")


# ═══════════════════════════════════════════════════════════════════════════
# EXAMPLE 6: Integration with ARDF Recon Pipeline
# ═══════════════════════════════════════════════════════════════════════════

def example_ardf_pipeline_integration():
    """
    Shows how OSINT mapping fits into complete ARDF workflow:
    
    Recon Modules → OSINT Mapping Module → Attack Planning
    """
    
    # 1. Create session
    session = Session(target="target.local")
    
    # 2. Run recon modules (simulated)
    # (In real workflow: domain recon, subdomain enum, email hunt, etc)
    # These populate session.findings
    
    # 3. Run OSINT mapping module
    osint = OSINTMappingModule(session)
    osint_result = osint.execute()
    
    # 4. Use results for attack planning
    if osint_result['success']:
        # Findings from OSINT now feed into attack chain selection
        graph_data = osint_result['output']['graph']
        
        # Identify high-value targets from clusters
        clusters = osint.graph.get_identifier_clusters()
        large_clusters = [c for c in clusters.values() if len(c) > 3]
        
        print(f"Found {len(large_clusters)} clusters with 3+ identifiers")
        print("These clusters are high-priority for targeted attacks")
        
        # Export for next phase
        print(f"\nOSINT data available at: {osint.osint_file_path}")
        print("Ready for attack chain selection and lateral movement planning")


# ═══════════════════════════════════════════════════════════════════════════
# SCHEMA: .osint.json Format
# ═════════════════════════════════════════════════════════════════════════════

"""
{
  "schema_version": "1.0",
  "created_at": "2026-09-29T12:00:00",
  "identifiers": {
    "node_abc123": {
      "node_id": "node_abc123",
      "subtype": "instagram",
      "value": "@johndoe",
      "metadata": {"followers": 1500, "posts": 234},
      "confidence": 0.85,
      "source": "recon:domain_recon",
      "timestamp": "2026-09-29T12:00:00",
      "tags": ["social", "recon", "high"]
    }
  },
  "locations": {
    "pin_xyz789": {
      "pin_id": "pin_xyz789",
      "latitude": 40.7128,
      "longitude": -74.0060,
      "name": "The Daily Grind Coffee",
      "address": "123 Main St, New York, NY",
      "place_type": "coffee",
      "notes": "Frequent check-ins via Instagram",
      "visit_date": "2026-09-15",
      "confidence": 0.9,
      "source": "osint_analysis",
      "timestamp": "2026-09-29T12:00:00"
    }
  },
  "edges": {
    "edge_def456": {
      "edge_id": "edge_def456",
      "source_id": "node_abc123",
      "target_id": "pin_xyz789",
      "relationship": "tagged_at",
      "notes": "Instagram story check-in",
      "confidence": 0.85,
      "timestamp": "2026-09-29T12:00:00"
    }
  }
}
"""


# ═══════════════════════════════════════════════════════════════════════════
# INTEGRATION CHECKLIST
# ═════════════════════════════════════════════════════════════════════════════

"""
✓ OSINT Mapping Module created (modules/osint_mapping.py)
✓ Inherits from RedTeamModule - logs to ARDF logger
✓ Converts recon findings → identifier nodes
✓ Manages location intelligence via geolocation pins
✓ Builds cross-link graph between identifiers and locations
✓ Cluster analysis for connected entity detection
✓ Exports/imports .osint.json format (compatible with web tool)
✓ Generates ARDF findings from OSINT analysis
✓ MITRE ATT&CK mapping (T1591, T1589, T1590, T1598, T1597)

READY FOR:
  - Standalone OSINT research
  - Recon pipeline integration
  - Intelligence synthesis
  - Cluster-based attack planning
  - Geographic targeting
"""
