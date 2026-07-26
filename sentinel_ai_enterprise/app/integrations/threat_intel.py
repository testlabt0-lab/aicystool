"""
Threat Intelligence Integration for Sentinel AI Enterprise
Integrates with external threat feeds and provides IP reputation scoring
"""
import aiohttp
import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, asdict
from app.core.config import settings

logger = logging.getLogger(__name__)

@dataclass
class ThreatIntelReport:
    ip: str
    is_malicious: bool
    confidence: float
    categories: List[str]
    country: str
    asn: str
    last_seen: Optional[datetime]
    sources: List[str]
    tags: List[str]

class ThreatIntelligenceService:
    """Advanced threat intelligence aggregation service"""
    
    def __init__(self):
        self.cache: Dict[str, ThreatIntelReport] = {}
        self.cache_ttl = 3600  # 1 hour
        self.blocked_ips: Set[str] = set()
        self.malicious_ips: Set[str] = set()
        self.feeds_data: Dict[str, list] = {}
        
    async def initialize(self):
        """Initialize threat intelligence feeds"""
        if not settings.THREAT_INTEL_ENABLED:
            logger.info("Threat intelligence disabled")
            return
            
        logger.info("Initializing threat intelligence feeds...")
        await self._fetch_all_feeds()
        
        # Schedule periodic updates
        asyncio.create_task(self._periodic_feed_update())
    
    async def _fetch_all_feeds(self):
        """Fetch data from all configured threat feeds"""
        feed_urls = [
            "https://rules.emergingthreats.net/open/suricata/emerging-all.rules",
            "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/bitcoin_nodes_1d.ipset",
            "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/2.txt",
        ]
        
        async with aiohttp.ClientSession() as session:
            tasks = [self._fetch_feed(session, url) for url in feed_urls]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for i, result in enumerate(results):
                if isinstance(result, list):
                    self.feeds_data[f"feed_{i}"] = result
                    logger.info(f"Fetched {len(result)} entries from feed {i}")
                else:
                    logger.error(f"Failed to fetch feed {i}: {result}")
    
    async def _fetch_feed(self, session: aiohttp.ClientSession, url: str) -> List[str]:
        """Fetch a single threat feed"""
        try:
            async with session.get(url, timeout=30) as response:
                if response.status == 200:
                    content = await response.text()
                    ips = []
                    for line in content.split('\n'):
                        line = line.strip()
                        if line and not line.startswith('#'):
                            # Extract IP addresses
                            parts = line.split()
                            if parts:
                                ip = parts[0].split('/')[0]  # Remove CIDR if present
                                if self._is_valid_ip(ip):
                                    ips.append(ip)
                    return ips
        except Exception as e:
            logger.error(f"Error fetching feed {url}: {e}")
        return []
    
    async def _periodic_feed_update(self):
        """Periodically update threat feeds"""
        while True:
            await asyncio.sleep(86400)  # Update daily
            await self._fetch_all_feeds()
            logger.info("Threat feeds updated")
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False
    
    async def get_threat_report(self, ip: str) -> Optional[ThreatIntelReport]:
        """Get comprehensive threat report for an IP"""
        # Check cache first
        if ip in self.cache:
            report = self.cache[ip]
            # Check if cache is still valid
            # (In production, you'd check timestamp)
            return report
        
        # Query multiple sources
        tasks = [
            self._query_abuseipdb(ip),
            self._query_virustotal(ip),
            self._check_local_lists(ip),
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Aggregate results
        is_malicious = False
        max_confidence = 0.0
        categories = set()
        sources = []
        tags = []
        
        for result in results:
            if isinstance(result, dict):
                if result.get('is_malicious'):
                    is_malicious = True
                    max_confidence = max(max_confidence, result.get('confidence', 0))
                    categories.update(result.get('categories', []))
                    if result.get('source'):
                        sources.append(result['source'])
                    tags.extend(result.get('tags', []))
        
        if is_malicious or max_confidence > 0.5:
            report = ThreatIntelReport(
                ip=ip,
                is_malicious=is_malicious,
                confidence=max_confidence,
                categories=list(categories),
                country="Unknown",  # Would need GeoIP lookup
                asn="Unknown",
                last_seen=datetime.now(),
                sources=sources,
                tags=list(set(tags))
            )
            
            self.cache[ip] = report
            if is_malicious:
                self.malicious_ips.add(ip)
            
            return report
        
        return None
    
    async def _query_abuseipdb(self, ip: str) -> Dict:
        """Query AbuseIPDB API"""
        if not settings.THREAT_INTEL_API_KEY:
            return {}
        
        try:
            async with aiohttp.ClientSession() as session:
                headers = {
                    'Key': settings.THREAT_INTEL_API_KEY,
                    'Accept': 'application/json'
                }
                params = {'ipAddress': ip, 'maxAgeInDays': 90}
                
                async with session.get(
                    'https://api.abuseipdb.com/api/v2/check',
                    headers=headers,
                    params=params,
                    timeout=10
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        abuse_score = data.get('data', {}).get('abuseConfidenceScore', 0)
                        return {
                            'is_malicious': abuse_score > 50,
                            'confidence': abuse_score / 100,
                            'categories': [str(c) for c in data.get('data', {}).get('categories', [])],
                            'source': 'AbuseIPDB',
                            'tags': ['abuse']
                        }
        except Exception as e:
            logger.error(f"AbuseIPDB query failed: {e}")
        return {}
    
    async def _query_virustotal(self, ip: str) -> Dict:
        """Query VirusTotal API"""
        # Implementation would require VT API key
        return {}
    
    def _check_local_lists(self, ip: str) -> Dict:
        """Check against local blocklists"""
        is_malicious = False
        confidence = 0.0
        sources = []
        
        # Check internal malicious IPs
        if ip in self.malicious_ips:
            is_malicious = True
            confidence = 0.8
            sources.append('internal')
        
        # Check fetched feeds
        for feed_name, ips in self.feeds_data.items():
            if ip in ips:
                is_malicious = True
                confidence = max(confidence, 0.7)
                sources.append(feed_name)
        
        return {
            'is_malicious': is_malicious,
            'confidence': confidence,
            'source': ','.join(sources) if sources else None,
            'categories': ['blocklist'] if is_malicious else []
        }
    
    def block_ip(self, ip: str, reason: str = "Manual block"):
        """Manually block an IP"""
        self.blocked_ips.add(ip)
        self.malicious_ips.add(ip)
        logger.warning(f"Blocked IP {ip}: {reason}")
    
    def unblock_ip(self, ip: str):
        """Unblock an IP"""
        self.blocked_ips.discard(ip)
        logger.info(f"Unblocked IP {ip}")
    
    def is_blocked(self, ip: str) -> bool:
        """Check if IP is blocked"""
        return ip in self.blocked_ips
    
    def get_statistics(self) -> Dict:
        """Get threat intelligence statistics"""
        return {
            'total_cached_ips': len(self.cache),
            'malicious_ips': len(self.malicious_ips),
            'blocked_ips': len(self.blocked_ips),
            'active_feeds': len(self.feeds_data),
            'feeds_total_entries': sum(len(ips) for ips in self.feeds_data.values())
        }
    
    async def enrich_event(self, event: Dict) -> Dict:
        """Enrich a security event with threat intelligence"""
        ip = event.get('source_ip') or event.get('attacker_ip')
        if ip:
            report = await self.get_threat_report(ip)
            if report:
                event['threat_intel'] = asdict(report)
        return event

# Singleton instance
threat_intel_service = ThreatIntelligenceService()
