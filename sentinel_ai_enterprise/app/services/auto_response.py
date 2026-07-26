"""
Automated Incident Response System
Provides automatic containment and remediation actions
"""
import asyncio
import logging
from datetime import datetime
from typing import Dict, List, Optional, Callable
from enum import Enum
from dataclasses import dataclass
import json

logger = logging.getLogger(__name__)

class ResponseAction(Enum):
    BLOCK_IP = "block_ip"
    QUARANTINE_HOST = "quarantine_host"
    KILL_PROCESS = "kill_process"
    DISABLE_USER = "disable_user"
    ISOLATE_NETWORK = "isolate_network"
    COLLECT_FORENSICS = "collect_forensics"
    SEND_ALERT = "send_alert"
    ROLLBACK_CHANGE = "rollback_change"

@dataclass
class IncidentResponse:
    incident_id: str
    threat_type: str
    confidence: float
    affected_assets: List[str]
    attacker_ip: Optional[str]
    recommended_actions: List[ResponseAction]
    auto_executed: bool
    execution_time: datetime
    status: str

class AutomatedResponseSystem:
    """Advanced automated incident response with human-in-the-loop options"""
    
    def __init__(self):
        self.response_rules: Dict[str, dict] = {}
        self.executed_responses: List[IncidentResponse] = []
        self.blocked_ips: set = set()
        self.quarantined_hosts: set = set()
        self.disabled_users: set = set()
        self.webhook_callbacks: List[Callable] = []
        self.auto_response_enabled = True
        self.require_approval_threshold = 0.8
        
    def add_response_rule(self, threat_type: str, rule: dict):
        """Add automated response rule for a threat type"""
        self.response_rules[threat_type] = {
            'actions': rule.get('actions', []),
            'auto_execute': rule.get('auto_execute', False),
            'min_confidence': rule.get('min_confidence', 0.7),
            'max_impact': rule.get('max_impact', 'medium'),
            'notification_channels': rule.get('notifications', ['log']),
            'rollback_supported': rule.get('rollback', False)
        }
        logger.info(f"Added response rule for {threat_type}")
    
    async def evaluate_and_respond(self, incident: dict) -> Optional[IncidentResponse]:
        """Evaluate incident and execute automated response if warranted"""
        threat_type = incident.get('threat_type', 'unknown')
        confidence = incident.get('confidence', 0.0)
        
        # Check if we have a rule for this threat type
        if threat_type not in self.response_rules:
            logger.debug(f"No response rule for threat type: {threat_type}")
            return None
        
        rule = self.response_rules[threat_type]
        
        # Check confidence threshold
        if confidence < rule['min_confidence']:
            logger.info(f"Confidence {confidence} below threshold {rule['min_confidence']}")
            return None
        
        # Determine if auto-execution is allowed
        auto_execute = (
            rule['auto_execute'] and 
            self.auto_response_enabled and
            confidence >= self.require_approval_threshold
        )
        
        # Generate response
        response = IncidentResponse(
            incident_id=incident.get('incident_id', f"inc_{datetime.now().timestamp()}"),
            threat_type=threat_type,
            confidence=confidence,
            affected_assets=incident.get('affected_assets', []),
            attacker_ip=incident.get('attacker_ip'),
            recommended_actions=[ResponseAction(a) for a in rule['actions']],
            auto_executed=auto_execute,
            execution_time=datetime.now(),
            status='pending'
        )
        
        # Execute or queue for approval
        if auto_execute:
            await self._execute_response(response)
        else:
            response.status = 'awaiting_approval'
            await self._notify_for_approval(response)
        
        self.executed_responses.append(response)
        return response
    
    async def _execute_response(self, response: IncidentResponse):
        """Execute the response actions"""
        logger.warning(f"Executing automated response for {response.incident_id}")
        
        for action in response.recommended_actions:
            try:
                if action == ResponseAction.BLOCK_IP:
                    await self._block_ip(response.attacker_ip)
                elif action == ResponseAction.QUARANTINE_HOST:
                    await self._quarantine_host(response.affected_assets)
                elif action == ResponseAction.DISABLE_USER:
                    await self._disable_user(response.affected_assets)
                elif action == ResponseAction.ISOLATE_NETWORK:
                    await self._isolate_network(response.affected_assets)
                elif action == ResponseAction.SEND_ALERT:
                    await self._send_alert(response)
                elif action == ResponseAction.COLLECT_FORENSICS:
                    await self._collect_forensics(response)
                
                logger.info(f"Executed action {action.value} for {response.incident_id}")
                
            except Exception as e:
                logger.error(f"Failed to execute {action.value}: {e}")
                response.status = 'partial_failure'
        
        response.status = 'completed'
    
    async def _block_ip(self, ip: Optional[str]):
        """Block an IP address at firewall level"""
        if not ip:
            return
        
        # Integration with firewall (example: iptables, pfSense, etc.)
        # In production, this would call actual firewall API
        self.blocked_ips.add(ip)
        logger.warning(f"Blocked IP: {ip}")
        
        # Example iptables command (would need proper integration)
        # cmd = f"iptables -A INPUT -s {ip} -j DROP"
        # await asyncio.create_subprocess_shell(cmd)
    
    async def _quarantine_host(self, hosts: List[str]):
        """Isolate compromised hosts from network"""
        for host in hosts:
            self.quarantined_hosts.add(host)
            logger.warning(f"Quarantined host: {host}")
            
            # In production, would integrate with network switches/NAC
    
    async def _disable_user(self, assets: List[str]):
        """Disable compromised user accounts"""
        # Extract usernames from assets (implementation depends on directory service)
        for asset in assets:
            if asset.startswith('user:'):
                username = asset.split(':')[1]
                self.disabled_users.add(username)
                logger.warning(f"Disabled user: {username}")
                
                # Would integrate with Active Directory, LDAP, etc.
    
    async def _isolate_network(self, hosts: List[str]):
        """Complete network isolation of affected systems"""
        logger.critical(f"Network isolation initiated for: {hosts}")
        # Would integrate with SDN controllers, firewalls, etc.
    
    async def _send_alert(self, response: IncidentResponse):
        """Send security alert to configured channels"""
        alert_data = {
            'incident_id': response.incident_id,
            'threat_type': response.threat_type,
            'confidence': response.confidence,
            'affected_assets': response.affected_assets,
            'actions_taken': [a.value for a in response.recommended_actions],
            'timestamp': response.execution_time.isoformat()
        }
        
        # Send to webhooks
        for callback in self.webhook_callbacks:
            try:
                await callback(alert_data)
            except Exception as e:
                logger.error(f"Webhook callback failed: {e}")
        
        # Log alert
        logger.critical(f"SECURITY ALERT: {json.dumps(alert_data)}")
    
    async def _collect_forensics(self, response: IncidentResponse):
        """Collect forensic evidence from affected systems"""
        logger.info(f"Collecting forensics for {response.incident_id}")
        
        # Would collect:
        # - Memory dumps
        # - Process lists
        # - Network connections
        # - File system snapshots
        # - Log files
        
        forensics_data = {
            'incident_id': response.incident_id,
            'collection_time': datetime.now().isoformat(),
            'affected_assets': response.affected_assets,
            'data_collected': ['memory', 'processes', 'network', 'files']
        }
        
        # Store in secure location
        logger.info(f"Forensics collected: {forensics_data}")
    
    async def _notify_for_approval(self, response: IncidentResponse):
        """Send notification requiring human approval"""
        logger.warning(f"Response requires approval: {response.incident_id}")
        
        # Would send to Slack, email, ticketing system, etc.
        approval_request = {
            'incident_id': response.incident_id,
            'threat_type': response.threat_type,
            'confidence': response.confidence,
            'recommended_actions': [a.value for a in response.recommended_actions],
            'approval_url': f"/api/v1/incidents/{response.incident_id}/approve"
        }
        
        logger.info(f"Approval request: {json.dumps(approval_request)}")
    
    async def approve_response(self, incident_id: str):
        """Manually approve a pending response"""
        for response in self.executed_responses:
            if response.incident_id == incident_id and response.status == 'awaiting_approval':
                response.status = 'approved'
                await self._execute_response(response)
                logger.info(f"Approved and executed response for {incident_id}")
                return True
        return False
    
    async def rollback_response(self, incident_id: str):
        """Rollback an automated response if needed"""
        for response in self.executed_responses:
            if response.incident_id == incident_id:
                # Rollback actions
                if ResponseAction.BLOCK_IP in response.recommended_actions and response.attacker_ip:
                    self.blocked_ips.discard(response.attacker_ip)
                    logger.info(f"Unblocked IP: {response.attacker_ip}")
                
                if ResponseAction.QUARANTINE_HOST in response.recommended_actions:
                    for host in response.affected_assets:
                        self.quarantined_hosts.discard(host)
                    logger.info(f"Released hosts from quarantine")
                
                response.status = 'rolled_back'
                logger.info(f"Rolled back response for {incident_id}")
                return True
        return False
    
    def get_response_statistics(self) -> Dict:
        """Get automated response statistics"""
        return {
            'total_responses': len(self.executed_responses),
            'auto_executed': sum(1 for r in self.executed_responses if r.auto_executed),
            'awaiting_approval': sum(1 for r in self.executed_responses if r.status == 'awaiting_approval'),
            'completed': sum(1 for r in self.executed_responses if r.status == 'completed'),
            'blocked_ips': len(self.blocked_ips),
            'quarantined_hosts': len(self.quarantined_hosts),
            'disabled_users': len(self.disabled_users),
            'responses_by_type': self._count_by_threat_type()
        }
    
    def _count_by_threat_type(self) -> Dict:
        """Count responses by threat type"""
        counts = {}
        for response in self.executed_responses:
            threat_type = response.threat_type
            counts[threat_type] = counts.get(threat_type, 0) + 1
        return counts
    
    def add_webhook_callback(self, callback: Callable):
        """Add webhook callback for alerts"""
        self.webhook_callbacks.append(callback)

# Singleton instance
automated_response = AutomatedResponseSystem()

# Configure default response rules
automated_response.add_response_rule('ddos_attack', {
    'actions': ['block_ip', 'send_alert'],
    'auto_execute': True,
    'min_confidence': 0.85,
    'notifications': ['log', 'webhook']
})

automated_response.add_response_rule('malware_detected', {
    'actions': ['quarantine_host', 'collect_forensics', 'send_alert'],
    'auto_execute': True,
    'min_confidence': 0.9,
    'notifications': ['log', 'webhook', 'email']
})

automated_response.add_response_rule('brute_force', {
    'actions': ['block_ip', 'disable_user', 'send_alert'],
    'auto_execute': False,
    'min_confidence': 0.8,
    'notifications': ['log', 'webhook']
})

automated_response.add_response_rule('lateral_movement', {
    'actions': ['isolate_network', 'collect_forensics', 'send_alert'],
    'auto_execute': False,
    'min_confidence': 0.85,
    'notifications': ['log', 'webhook', 'email']
})

automated_response.add_response_rule('data_exfiltration', {
    'actions': ['block_ip', 'isolate_network', 'collect_forensics', 'send_alert'],
    'auto_execute': True,
    'min_confidence': 0.95,
    'notifications': ['log', 'webhook', 'email']
})
