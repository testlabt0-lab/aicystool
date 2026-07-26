"""
Advanced Security Event Correlation Engine
Uses graph analysis and pattern matching to detect complex attack chains
"""
import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
import networkx as nx

logger = logging.getLogger(__name__)

@dataclass
class SecurityEvent:
    event_id: str
    timestamp: datetime
    event_type: str
    source_ip: str
    target_ip: Optional[str]
    user: Optional[str]
    details: Dict
    severity: float
    tags: List[str] = field(default_factory=list)

@dataclass
class AttackChain:
    chain_id: str
    events: List[SecurityEvent]
    attack_type: str
    confidence: float
    start_time: datetime
    end_time: datetime
    affected_assets: List[str]
    attacker_profile: Dict

class CorrelationEngine:
    """Advanced event correlation for detecting multi-stage attacks"""
    
    def __init__(self):
        self.event_buffer: List[SecurityEvent] = []
        self.max_buffer_size = 10000
        self.time_window = 3600  # 1 hour
        self.attack_graph = nx.DiGraph()
        self.detected_chains: List[AttackChain] = []
        
        # Attack patterns
        self.patterns = {
            'reconnaissance': self._detect_reconnaissance,
            'lateral_movement': self._detect_lateral_movement,
            'data_exfiltration': self._detect_exfiltration,
            'privilege_escalation': self._detect_privilege_escalation,
            'persistence': self._detect_persistence,
        }
    
    def add_event(self, event: SecurityEvent):
        """Add security event to correlation engine"""
        self.event_buffer.append(event)
        
        # Add to graph
        self.attack_graph.add_node(
            event.event_id,
            event=event,
            timestamp=event.timestamp
        )
        
        # Create edges based on relationships
        self._create_relationships(event)
        
        # Trim buffer if too large
        if len(self.event_buffer) > self.max_buffer_size:
            self._trim_buffer()
        
        # Run correlation
        asyncio.create_task(self._run_correlation())
    
    def _create_relationships(self, event: SecurityEvent):
        """Create graph edges between related events"""
        # Find events from same source IP
        for prev_event in reversed(self.event_buffer[-100:]):
            if prev_event.event_id == event.event_id:
                continue
            
            # Same source IP
            if prev_event.source_ip == event.source_ip:
                time_diff = (event.timestamp - prev_event.timestamp).total_seconds()
                if time_diff < 300:  # Within 5 minutes
                    self.attack_graph.add_edge(
                        prev_event.event_id,
                        event.event_id,
                        relationship='same_source',
                        weight=1.0
                    )
            
            # Same target
            if (prev_event.target_ip and event.target_ip and 
                prev_event.target_ip == event.target_ip):
                self.attack_graph.add_edge(
                    prev_event.event_id,
                    event.event_id,
                    relationship='same_target',
                    weight=0.8
                )
            
            # Sequential actions (login -> command execution)
            if (prev_event.event_type == 'authentication' and 
                event.event_type == 'command_execution' and
                prev_event.user == event.user):
                self.attack_graph.add_edge(
                    prev_event.event_id,
                    event.event_id,
                    relationship='sequential',
                    weight=0.9
                )
    
    async def _run_correlation(self):
        """Run correlation analysis on recent events"""
        await asyncio.sleep(5)  # Allow batch processing
        
        for pattern_name, detector in self.patterns.items():
            chains = detector()
            for chain in chains:
                if not self._is_duplicate_chain(chain):
                    self.detected_chains.append(chain)
                    logger.warning(
                        f"Detected attack chain: {chain.attack_type} "
                        f"(confidence: {chain.confidence:.2f})"
                    )
    
    def _detect_reconnaissance(self) -> List[AttackChain]:
        """Detect reconnaissance activities"""
        chains = []
        
        # Look for port scanning patterns
        scan_events = [
            e for e in self.event_buffer
            if e.event_type in ['port_scan', 'service_scan', 'host_discovery']
        ]
        
        if len(scan_events) >= 3:
            # Group by source IP
            by_source = defaultdict(list)
            for event in scan_events:
                by_source[event.source_ip].append(event)
            
            for source_ip, events in by_source.items():
                if len(events) >= 3:
                    time_span = (events[-1].timestamp - events[0].timestamp).total_seconds()
                    if time_span < 300:  # Rapid scanning
                        chain = AttackChain(
                            chain_id=f"recon_{source_ip}_{datetime.now().timestamp()}",
                            events=events,
                            attack_type='reconnaissance',
                            confidence=min(0.5 + len(events) * 0.1, 0.95),
                            start_time=events[0].timestamp,
                            end_time=events[-1].timestamp,
                            affected_assets=list(set(e.target_ip for e in events if e.target_ip)),
                            attacker_profile={'source_ip': source_ip, 'technique': 'scanning'}
                        )
                        chains.append(chain)
        
        return chains
    
    def _detect_lateral_movement(self) -> List[AttackChain]:
        """Detect lateral movement patterns"""
        chains = []
        
        # Look for authentication followed by access to multiple systems
        auth_events = [
            e for e in self.event_buffer
            if e.event_type == 'authentication' and e.details.get('success', True)
        ]
        
        if len(auth_events) >= 2:
            by_user = defaultdict(list)
            for event in auth_events:
                if event.user:
                    by_user[event.user].append(event)
            
            for user, events in by_user.items():
                targets = set(e.target_ip for e in events if e.target_ip)
                if len(targets) >= 3:
                    time_span = (events[-1].timestamp - events[0].timestamp).total_seconds()
                    if time_span < 600:  # Multiple systems in 10 minutes
                        chain = AttackChain(
                            chain_id=f"lateral_{user}_{datetime.now().timestamp()}",
                            events=events,
                            attack_type='lateral_movement',
                            confidence=min(0.6 + len(targets) * 0.1, 0.95),
                            start_time=events[0].timestamp,
                            end_time=events[-1].timestamp,
                            affected_assets=list(targets),
                            attacker_profile={'user': user, 'technique': 'credential_use'}
                        )
                        chains.append(chain)
        
        return chains
    
    def _detect_exfiltration(self) -> List[AttackChain]:
        """Detect data exfiltration patterns"""
        chains = []
        
        # Look for large data transfers or unusual outbound connections
        transfer_events = [
            e for e in self.event_buffer
            if e.event_type in ['data_transfer', 'outbound_connection']
        ]
        
        if len(transfer_events) >= 2:
            by_source = defaultdict(list)
            for event in transfer_events:
                by_source[event.source_ip].append(event)
            
            for source_ip, events in by_source.items():
                total_data = sum(e.details.get('bytes', 0) for e in events)
                if total_data > 100 * 1024 * 1024:  # >100MB
                    chain = AttackChain(
                        chain_id=f"exfil_{source_ip}_{datetime.now().timestamp()}",
                        events=events,
                        attack_type='data_exfiltration',
                        confidence=min(0.7 + (total_data / 1024/1024/1024) * 0.1, 0.95),
                        start_time=events[0].timestamp,
                        end_time=events[-1].timestamp,
                        affected_assets=[source_ip],
                        attacker_profile={
                            'source_ip': source_ip,
                            'data_volume': total_data,
                            'technique': 'exfiltration'
                        }
                    )
                    chains.append(chain)
        
        return chains
    
    def _detect_privilege_escalation(self) -> List[AttackChain]:
        """Detect privilege escalation attempts"""
        chains = []
        
        # Look for failed admin access followed by success
        priv_events = [
            e for e in self.event_buffer
            if e.event_type in ['privilege_change', 'admin_access', 'sudo_attempt']
        ]
        
        if len(priv_events) >= 2:
            by_user = defaultdict(list)
            for event in priv_events:
                if event.user:
                    by_user[event.user].append(event)
            
            for user, events in by_user.items():
                failures = [e for e in events if not e.details.get('success', True)]
                successes = [e for e in events if e.details.get('success', True)]
                
                if len(failures) >= 2 and len(successes) >= 1:
                    all_events = sorted(failures + successes, key=lambda x: x.timestamp)
                    chain = AttackChain(
                        chain_id=f"privesc_{user}_{datetime.now().timestamp()}",
                        events=all_events,
                        attack_type='privilege_escalation',
                        confidence=min(0.6 + len(failures) * 0.1, 0.9),
                        start_time=all_events[0].timestamp,
                        end_time=all_events[-1].timestamp,
                        affected_assets=[user],
                        attacker_profile={'user': user, 'technique': 'brute_force'}
                    )
                    chains.append(chain)
        
        return chains
    
    def _detect_persistence(self) -> List[AttackChain]:
        """Detect persistence mechanisms"""
        chains = []
        
        # Look for creation of scheduled tasks, services, or startup items
        persist_events = [
            e for e in self.event_buffer
            if e.event_type in ['scheduled_task', 'service_install', 'startup_modification', 'registry_change']
        ]
        
        if len(persist_events) >= 1:
            by_source = defaultdict(list)
            for event in persist_events:
                by_source[event.source_ip].append(event)
            
            for source_ip, events in by_source.items():
                chain = AttackChain(
                    chain_id=f"persist_{source_ip}_{datetime.now().timestamp()}",
                    events=events,
                    attack_type='persistence',
                    confidence=0.75,
                    start_time=events[0].timestamp,
                    end_time=events[-1].timestamp,
                    affected_assets=[source_ip],
                    attacker_profile={'source_ip': source_ip, 'technique': 'persistence'}
                )
                chains.append(chain)
        
        return chains
    
    def _is_duplicate_chain(self, chain: AttackChain) -> bool:
        """Check if this attack chain is already detected"""
        for existing in self.detected_chains[-10:]:
            if (existing.attack_type == chain.attack_type and
                existing.attacker_profile.get('source_ip') == chain.attacker_profile.get('source_ip') and
                abs((chain.start_time - existing.start_time).total_seconds()) < 60):
                return True
        return False
    
    def _trim_buffer(self):
        """Trim old events from buffer"""
        cutoff = datetime.now() - timedelta(seconds=self.time_window)
        self.event_buffer = [
            e for e in self.event_buffer
            if e.timestamp > cutoff
        ]
    
    def get_attack_chains(self, limit: int = 50) -> List[Dict]:
        """Get recent attack chains"""
        sorted_chains = sorted(
            self.detected_chains,
            key=lambda c: c.end_time,
            reverse=True
        )[:limit]
        
        return [
            {
                'chain_id': c.chain_id,
                'attack_type': c.attack_type,
                'confidence': c.confidence,
                'start_time': c.start_time.isoformat(),
                'end_time': c.end_time.isoformat(),
                'affected_assets': c.affected_assets,
                'event_count': len(c.events),
                'attacker_profile': c.attacker_profile
            }
            for c in sorted_chains
        ]
    
    def get_statistics(self) -> Dict:
        """Get correlation engine statistics"""
        return {
            'buffer_size': len(self.event_buffer),
            'graph_nodes': self.attack_graph.number_of_nodes(),
            'graph_edges': self.attack_graph.number_of_edges(),
            'detected_chains': len(self.detected_chains),
            'chains_by_type': self._count_chains_by_type()
        }
    
    def _count_chains_by_type(self) -> Dict:
        """Count detected chains by attack type"""
        counts = defaultdict(int)
        for chain in self.detected_chains:
            counts[chain.attack_type] += 1
        return dict(counts)

# Singleton instance
correlation_engine = CorrelationEngine()
