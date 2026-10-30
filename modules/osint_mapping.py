"""
modules/osint_mapping.py
────────────────────────
OSINT data organization and mapping integration.

Wraps the anonymousRAID OSINT-Mapping-Tool logic into ARDF:
  - Node graph for identifiers (social, contact, personal, vehicle)
  - Geolocation mapping with pins
  - Cross-linking between identifiers and locations
  - OSINT findings aggregation
  - .osint.json format export/import
  - Intelligence synthesis
"""

import json
import uuid
from typing import Any, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, asdict, field
from enum import Enum
from datetime import datetime
from collections import defaultdict

from modules.redteam_base import RedTeamModule
from modules.session import Session, Finding, SeverityLevel
from modules.logger import ARDFLogger, get_logger


class IdentifierType(Enum):
    """Categories of identifiers."""
    SOCIAL = "social"
    CONTACT = "contact"
    PERSONAL = "personal"
    VEHICLE = "vehicle"
    FINANCIAL = "financial"
    NETWORK = "network"
    OTHER = "other"


class IdentifierSubType(Enum):
    """Specific identifier types."""
    # Social
    INSTAGRAM = "instagram"
    FACEBOOK = "facebook"
    TWITTER = "twitter"
    YOUTUBE = "youtube"
    TIKTOK = "tiktok"
    LINKEDIN = "linkedin"
    SNAPCHAT = "snapchat"
    DISCORD = "discord"
    TELEGRAM = "telegram"
    
    # Contact
    EMAIL = "email"
    PHONE = "phone"
    ADDRESS = "address"
    DOMAIN = "domain"
    WEBSITE = "website"
    
    # Personal
    PERSON = "person"
    FAMILY_MEMBER = "family_member"
    ASSOCIATE = "associate"
    ORGANIZATION = "organization"
    
    # Vehicle
    LICENSE_PLATE = "license_plate"
    VEHICLE = "vehicle"
    AIRCRAFT = "aircraft"
    VESSEL = "vessel"
    
    # Financial
    BANK_ACCOUNT = "bank_account"
    CRYPTOCURRENCY = "cryptocurrency"
    PAYMENT_METHOD = "payment_method"
    
    # Network
    IP_ADDRESS = "ip_address"
    DOMAIN_NAME = "domain_name"
    USERNAME = "username"
    
    # Other
    DOCUMENT = "document"
    FILE = "file"
    REFERENCE = "reference"


class PlaceType(Enum):
    """Categories of map locations."""
    HOME = "home"
    WORK = "work"
    COFFEE = "coffee"
    FOOD = "food"
    GYM = "gym"
    MOVIE = "movie"
    PARK = "park"
    SCHOOL = "school"
    SHOPPING = "shopping"
    LIBRARY = "library"
    AMUSEMENT_PARK = "amusement_park"
    OTHER = "other"


@dataclass
class Identifier:
    """Node in the OSINT graph: an identifier."""
    
    node_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    subtype: IdentifierSubType = IdentifierSubType.PERSON
    value: str = ""  # The actual identifier (handle, number, etc)
    metadata: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.5  # 0.0 - 1.0 confidence level
    source: Optional[str] = None  # Where this came from (recon module, manual, etc)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    tags: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "subtype": self.subtype.value,
            "value": self.value,
            "metadata": self.metadata,
            "confidence": self.confidence,
            "source": self.source,
            "timestamp": self.timestamp,
            "tags": self.tags,
        }


@dataclass
class GeoLocation:
    """Pin on the map: a location."""
    
    pin_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    latitude: float = 0.0
    longitude: float = 0.0
    name: str = ""
    address: str = ""
    place_type: PlaceType = PlaceType.OTHER
    notes: str = ""
    visit_date: Optional[str] = None  # ISO format
    confidence: float = 0.5
    source: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "pin_id": self.pin_id,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "name": self.name,
            "address": self.address,
            "place_type": self.place_type.value,
            "notes": self.notes,
            "visit_date": self.visit_date,
            "confidence": self.confidence,
            "source": self.source,
            "timestamp": self.timestamp,
        }


@dataclass
class EdgeConnection:
    """Link between two nodes or nodes and locations."""
    
    edge_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    source_id: str = ""  # node_id or pin_id
    target_id: str = ""  # node_id or pin_id
    relationship: str = "related_to"  # Type of relationship
    notes: str = ""
    confidence: float = 0.5
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "edge_id": self.edge_id,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "relationship": self.relationship,
            "notes": self.notes,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
        }


class OSINTGraph:
    """Manages the OSINT node graph and location map."""
    
    def __init__(self):
        self.identifiers: Dict[str, Identifier] = {}
        self.locations: Dict[str, GeoLocation] = {}
        self.edges: Dict[str, EdgeConnection] = {}
        self.schema_version = "1.0"
        self.created_at = datetime.now().isoformat()
    
    def add_identifier(self, identifier: Identifier) -> str:
        """Add an identifier node."""
        self.identifiers[identifier.node_id] = identifier
        return identifier.node_id
    
    def add_location(self, location: GeoLocation) -> str:
        """Add a map pin."""
        self.locations[location.pin_id] = location
        return location.pin_id
    
    def link(
        self,
        source_id: str,
        target_id: str,
        relationship: str = "related_to",
        notes: str = "",
    ) -> str:
        """Create a connection between nodes/locations."""
        edge = EdgeConnection(
            source_id=source_id,
            target_id=target_id,
            relationship=relationship,
            notes=notes,
        )
        self.edges[edge.edge_id] = edge
        return edge.edge_id
    
    def get_identifier_clusters(self) -> Dict[str, Set[str]]:
        """Find connected identifier clusters."""
        clusters = defaultdict(set)
        visited = set()
        
        for node_id in self.identifiers.keys():
            if node_id in visited:
                continue
            
            # BFS to find cluster
            cluster = {node_id}
            visited.add(node_id)
            queue = [node_id]
            
            while queue:
                current = queue.pop(0)
                
                # Find all connected nodes
                for edge in self.edges.values():
                    if edge.source_id == current and edge.target_id in self.identifiers:
                        neighbor = edge.target_id
                        if neighbor not in visited:
                            visited.add(neighbor)
                            cluster.add(neighbor)
                            queue.append(neighbor)
                    elif edge.target_id == current and edge.source_id in self.identifiers:
                        neighbor = edge.source_id
                        if neighbor not in visited:
                            visited.add(neighbor)
                            cluster.add(neighbor)
                            queue.append(neighbor)
            
            clusters[node_id] = cluster
        
        return clusters
    
    def get_identifier_locations(self, node_id: str) -> List[Tuple[str, str]]:
        """Get all locations linked to an identifier."""
        locations = []
        for edge in self.edges.values():
            if edge.source_id == node_id and edge.target_id in self.locations:
                locations.append((edge.target_id, edge.relationship))
            elif edge.target_id == node_id and edge.source_id in self.locations:
                locations.append((edge.source_id, edge.relationship))
        return locations
    
    def get_location_identifiers(self, pin_id: str) -> List[Tuple[str, str]]:
        """Get all identifiers linked to a location."""
        identifiers = []
        for edge in self.edges.values():
            if edge.source_id == pin_id and edge.target_id in self.identifiers:
                identifiers.append((edge.target_id, edge.relationship))
            elif edge.target_id == pin_id and edge.source_id in self.identifiers:
                identifiers.append((edge.source_id, edge.relationship))
        return identifiers
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize to .osint.json format."""
        return {
            "schema_version": self.schema_version,
            "created_at": self.created_at,
            "identifiers": {
                node_id: node.to_dict()
                for node_id, node in self.identifiers.items()
            },
            "locations": {
                pin_id: loc.to_dict()
                for pin_id, loc in self.locations.items()
            },
            "edges": {
                edge_id: edge.to_dict()
                for edge_id, edge in self.edges.items()
            },
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "OSINTGraph":
        """Load from .osint.json format."""
        graph = cls()
        
        # Restore identifiers
        for node_id, node_data in data.get("identifiers", {}).items():
            ident = Identifier(
                node_id=node_data["node_id"],
                subtype=IdentifierSubType(node_data["subtype"]),
                value=node_data.get("value", ""),
                metadata=node_data.get("metadata", {}),
                confidence=node_data.get("confidence", 0.5),
                source=node_data.get("source"),
                timestamp=node_data.get("timestamp"),
                tags=node_data.get("tags", []),
            )
            graph.identifiers[ident.node_id] = ident
        
        # Restore locations
        for pin_id, loc_data in data.get("locations", {}).items():
            loc = GeoLocation(
                pin_id=loc_data["pin_id"],
                latitude=loc_data.get("latitude", 0.0),
                longitude=loc_data.get("longitude", 0.0),
                name=loc_data.get("name", ""),
                address=loc_data.get("address", ""),
                place_type=PlaceType(loc_data.get("place_type", "other")),
                notes=loc_data.get("notes", ""),
                visit_date=loc_data.get("visit_date"),
                confidence=loc_data.get("confidence", 0.5),
                source=loc_data.get("source"),
                timestamp=loc_data.get("timestamp"),
            )
            graph.locations[loc.pin_id] = loc
        
        # Restore edges
        for edge_id, edge_data in data.get("edges", {}).items():
            edge = EdgeConnection(
                edge_id=edge_data["edge_id"],
                source_id=edge_data.get("source_id", ""),
                target_id=edge_data.get("target_id", ""),
                relationship=edge_data.get("relationship", "related_to"),
                notes=edge_data.get("notes", ""),
                confidence=edge_data.get("confidence", 0.5),
                timestamp=edge_data.get("timestamp"),
            )
            graph.edges[edge.edge_id] = edge
        
        return graph


class OSINTMappingModule(RedTeamModule):
    """OSINT graph and mapping analysis."""
    
    def __init__(self, session: Session, logger: Optional[ARDFLogger] = None):
        super().__init__(session, logger)
        self.graph = OSINTGraph()
        self.osint_file_path: Optional[str] = None
    
    def execute(self) -> Dict[str, Any]:
        """Execute OSINT mapping analysis."""
        self.log_info("Starting OSINT mapping and analysis")
        
        try:
            # Analyze existing findings from recon
            self._ingest_findings()
            
            # Build identifier graph
            clusters = self._analyze_clusters()
            
            # Map locations
            locations = self._analyze_locations()
            
            # Cross-link identifiers and locations
            connections = self._analyze_connections()
            
            # Generate intelligence summary
            summary = self._generate_summary(clusters, locations, connections)
            
            # Export to OSINT JSON
            self._export_osint_json()
            
            return {
                "success": True,
                "findings": self.findings,
                "identifiers": len(self.graph.identifiers),
                "locations": len(self.graph.locations),
                "connections": len(self.graph.edges),
                "clusters": len(clusters),
                "output": {
                    "graph": self.graph.to_dict(),
                    "summary": summary,
                }
            }
        except Exception as e:
            self.log_error(f"OSINT mapping failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "findings": self.findings,
            }
    
    def _ingest_findings(self) -> None:
        """Convert recon findings into identifiers."""
        self.log_info("Ingesting recon findings")
        
        # Get all recon findings from session
        for finding in self.session.findings:
            if finding.category == "recon":
                # Map finding metadata to identifier
                metadata = finding.metadata or {}
                
                # Determine identifier type
                if "email" in finding.title.lower():
                    subtype = IdentifierSubType.EMAIL
                elif "phone" in finding.title.lower():
                    subtype = IdentifierSubType.PHONE
                elif "instagram" in finding.title.lower():
                    subtype = IdentifierSubType.INSTAGRAM
                elif "social" in finding.title.lower():
                    subtype = IdentifierSubType.TWITTER
                elif "address" in finding.title.lower():
                    subtype = IdentifierSubType.ADDRESS
                elif "domain" in finding.title.lower():
                    subtype = IdentifierSubType.DOMAIN
                elif "ip" in finding.title.lower():
                    subtype = IdentifierSubType.IP_ADDRESS
                else:
                    subtype = IdentifierSubType.REFERENCE
                
                ident = Identifier(
                    subtype=subtype,
                    value=metadata.get("value", finding.title),
                    metadata=metadata,
                    confidence=0.7 if finding.severity == SeverityLevel.HIGH else 0.5,
                    source=f"recon:{finding.category}",
                    tags=[finding.category, finding.severity.value],
                )
                
                self.graph.add_identifier(ident)
                self.log_debug(f"Added identifier: {ident.value} ({subtype.value})")
    
    def _analyze_clusters(self) -> Dict[str, Set[str]]:
        """Find connected identifier clusters (people, organizations, etc)."""
        clusters = self.graph.get_identifier_clusters()
        
        # Report clusters
        for representative, cluster in clusters.items():
            if len(cluster) > 1:
                cluster_identifiers = [
                    self.graph.identifiers[node_id].value
                    for node_id in cluster
                    if node_id in self.graph.identifiers
                ]
                
                self.add_finding(
                    title="Identifier Cluster Detected",
                    description=f"Found {len(cluster)} connected identifiers: {', '.join(cluster_identifiers[:5])}",
                    severity=SeverityLevel.HIGH,
                    category="osint_cluster",
                    metadata={"cluster_size": len(cluster), "members": list(cluster)},
                )
        
        return clusters
    
    def _analyze_locations(self) -> List[Dict[str, Any]]:
        """Analyze geographic data."""
        locations_data = []
        
        for pin_id, location in self.graph.locations.items():
            # Check for patterns
            linked_ids = self.graph.get_location_identifiers(pin_id)
            
            location_data = {
                "pin_id": pin_id,
                "name": location.name,
                "coordinates": (location.latitude, location.longitude),
                "linked_identifiers": len(linked_ids),
            }
            locations_data.append(location_data)
            
            if len(linked_ids) > 3:
                self.add_finding(
                    title="High-Activity Location",
                    description=f"Location '{location.name}' linked to {len(linked_ids)} identifiers",
                    severity=SeverityLevel.MEDIUM,
                    category="osint_location",
                    metadata=location_data,
                )
        
        return locations_data
    
    def _analyze_connections(self) -> List[Dict[str, Any]]:
        """Analyze relationships between identifiers and locations."""
        connections = []
        
        # Count bidirectional relationships
        relationships = defaultdict(int)
        for edge in self.graph.edges.values():
            relationships[edge.relationship] += 1
        
        for relationship, count in relationships.items():
            connections.append({
                "relationship": relationship,
                "count": count,
            })
            
            if count > 5:
                self.add_finding(
                    title=f"Repeated Relationship Pattern: {relationship}",
                    description=f"Found {count} instances of '{relationship}' relationship",
                    severity=SeverityLevel.MEDIUM,
                    category="osint_pattern",
                )
        
        return connections
    
    def _generate_summary(
        self,
        clusters: Dict[str, Set[str]],
        locations: List[Dict[str, Any]],
        connections: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Generate intelligence summary."""
        return {
            "total_identifiers": len(self.graph.identifiers),
            "total_locations": len(self.graph.locations),
            "total_edges": len(self.graph.edges),
            "clusters": len([c for c in clusters.values() if len(c) > 1]),
            "average_cluster_size": sum(len(c) for c in clusters.values()) / len(clusters) if clusters else 0,
            "high_activity_locations": len([l for l in locations if l["linked_identifiers"] > 3]),
            "relationship_types": len(connections),
        }
    
    def _export_osint_json(self) -> None:
        """Export to .osint.json format."""
        try:
            output_path = self.session.output_dir / "osint_mapping.osint.json"
            
            with open(output_path, "w") as f:
                json.dump(self.graph.to_dict(), f, indent=2)
            
            self.osint_file_path = str(output_path)
            self.log_info(f"Exported OSINT mapping to {output_path}")
        except Exception as e:
            self.log_error(f"Export failed: {e}")
    
    def import_osint_json(self, filepath: str) -> bool:
        """Load OSINT mapping from file."""
        try:
            with open(filepath, "r") as f:
                data = json.load(f)
            
            self.graph = OSINTGraph.from_dict(data)
            self.osint_file_path = filepath
            self.log_info(f"Imported OSINT mapping from {filepath}")
            return True
        except Exception as e:
            self.log_error(f"Import failed: {e}")
            return False
    
    def add_identifier_from_recon(
        self,
        value: str,
        subtype: IdentifierSubType,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Add identifier from recon module output."""
        ident = Identifier(
            subtype=subtype,
            value=value,
            metadata=metadata or {},
            confidence=0.7,
            source="recon_module",
        )
        return self.graph.add_identifier(ident)
    
    def link_identifier_to_location(
        self,
        identifier_id: str,
        location_id: str,
        relationship: str = "seen_at",
        notes: str = "",
    ) -> str:
        """Cross-link an identifier to a location."""
        return self.graph.link(identifier_id, location_id, relationship, notes)
    
    def get_mitre_techniques(self) -> List[str]:
        """Return MITRE techniques used."""
        return [
            "T1591",  # Gather Victim Identity Information
            "T1589",  # Gather Victim Identity Information
            "T1590",  # Gather Victim Network Information
            "T1598",  # Phishing for Information
            "T1597",  # Search Open Websites/Domains
        ]
