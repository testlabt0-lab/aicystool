"""
Advanced Honeypot System for Sentinel AI Enterprise
Captures attacker behavior and collects threat intelligence
"""
import asyncio
import json
import socket
import logging
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
import aiohttp
from app.core.config import settings

logger = logging.getLogger(__name__)

@dataclass
class AttackSession:
    session_id: str
    attacker_ip: str
    port: int
    protocol: str
    start_time: datetime
    commands: List[str]
    payload: Optional[str]
    duration: float
    risk_score: float

class HoneypotService:
    """Advanced honeypot system with multiple service emulators"""
    
    def __init__(self):
        self.sessions: Dict[str, AttackSession] = {}
        self.attacker_profiles: Dict[str, dict] = {}
        self.enabled_ports = settings.HONEYPOT_PORTS
        self.running = False
        
    async def start(self):
        """Start honeypot services on configured ports"""
        if not settings.HONEYPOT_ENABLED:
            logger.info("Honeypot disabled in configuration")
            return
            
        self.running = True
        logger.info(f"Starting honeypot on ports: {self.enabled_ports}")
        
        tasks = []
        for port in self.enabled_ports:
            if port == 22:
                tasks.append(self._run_ssh_honeypot(port))
            elif port in [80, 443]:
                tasks.append(self._run_http_honeypot(port))
            elif port in [3306, 5432]:
                tasks.append(self._run_database_honeypot(port))
            else:
                tasks.append(self._run_generic_honeypot(port))
                
        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _run_ssh_honeypot(self, port: int):
        """Emulate SSH service to capture brute force and command execution"""
        server = await asyncio.start_server(
            self._handle_ssh_client, '0.0.0.0', port
        )
        logger.info(f"SSH honeypot listening on port {port}")
        async with server:
            while self.running:
                await asyncio.sleep(3600)
    
    async def _handle_ssh_client(self, reader, writer):
        """Handle SSH client connections"""
        peername = writer.get_extra_info('peername')
        attacker_ip = peername[0] if peername else 'unknown'
        session_id = f"ssh_{attacker_ip}_{datetime.now().timestamp()}"
        
        logger.warning(f"SSH connection from {attacker_ip}")
        
        # Send fake SSH banner
        writer.write(b'SSH-2.0-OpenSSH_8.2p1 Ubuntu\r\n')
        await writer.drain()
        
        commands = []
        start_time = datetime.now()
        
        try:
            # Capture login attempts
            line = await reader.readline()
            username = line.decode().strip() if line else 'unknown'
            
            line = await reader.readline()
            password = line.decode().strip() if line else 'unknown'
            
            logger.warning(f"SSH credentials attempt: {username}:{password} from {attacker_ip}")
            
            # Fake successful login
            writer.write(b'Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-80-generic x86_64)\r\n')
            writer.write(b'$ ')
            await writer.drain()
            
            # Capture commands
            while True:
                cmd = await reader.readline()
                if not cmd:
                    break
                command = cmd.decode().strip()
                commands.append(command)
                logger.warning(f"Command from {attacker_ip}: {command}")
                
                # Respond with fake output
                response = self._get_fake_command_output(command)
                writer.write(response.encode() + b'\r\n$ ')
                await writer.drain()
                
        except Exception as e:
            logger.error(f"SSH session error: {e}")
        finally:
            duration = (datetime.now() - start_time).total_seconds()
            self._save_session(session_id, attacker_ip, port, 'SSH', 
                             start_time, commands, None, duration)
            writer.close()
            await writer.wait_closed()
    
    def _get_fake_command_output(self, command: str) -> str:
        """Generate realistic fake command outputs"""
        fake_outputs = {
            'whoami': 'root',
            'uname -a': 'Linux honeypot 5.4.0-80-generic #90-Ubuntu SMP Fri Jul 9 22:49:44 UTC 2021 x86_64',
            'ls': 'bin  boot  dev  etc  home  lib  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var',
            'cat /etc/passwd': 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin',
            'wget': 'usage: wget [OPTION]... [URL]...',
            'curl': 'usage: curl [options...] <url>',
        }
        return fake_outputs.get(command.split()[0] if command else '', 'command not found')
    
    async def _run_http_honeypot(self, port: int):
        """Emulate HTTP/HTTPS service to capture web attacks"""
        server = await asyncio.start_server(
            self._handle_http_client, '0.0.0.0', port
        )
        logger.info(f"HTTP honeypot listening on port {port}")
        async with server:
            while self.running:
                await asyncio.sleep(3600)
    
    async def _handle_http_client(self, reader, writer):
        """Handle HTTP client connections"""
        peername = writer.get_extra_info('peername')
        attacker_ip = peername[0] if peername else 'unknown'
        session_id = f"http_{attacker_ip}_{datetime.now().timestamp()}"
        
        start_time = datetime.now()
        payload = ""
        
        try:
            request_line = await reader.readline()
            payload = request_line.decode()
            
            # Read headers
            while True:
                line = await reader.readline()
                if line == b'\r\n' or not line:
                    break
                payload += line.decode()
            
            logger.warning(f"HTTP request from {attacker_ip}: {payload[:200]}")
            
            # Send fake response
            response = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/html\r\n"
                "Server: Apache/2.4.41 (Ubuntu)\r\n"
                "\r\n"
                "<html><body><h1>Welcome</h1></body></html>"
            )
            writer.write(response.encode())
            await writer.drain()
            
        except Exception as e:
            logger.error(f"HTTP session error: {e}")
        finally:
            duration = (datetime.now() - start_time).total_seconds()
            self._save_session(session_id, attacker_ip, port, 'HTTP',
                             start_time, [], payload, duration)
            writer.close()
            await writer.wait_closed()
    
    async def _run_database_honeypot(self, port: int):
        """Emulate database service to capture SQL injection and unauthorized access"""
        service = "MySQL" if port == 3306 else "PostgreSQL"
        server = await asyncio.start_server(
            lambda r, w: self._handle_db_client(r, w, service), '0.0.0.0', port
        )
        logger.info(f"{service} honeypot listening on port {port}")
        async with server:
            while self.running:
                await asyncio.sleep(3600)
    
    async def _handle_db_client(self, reader, writer, service: str):
        """Handle database client connections"""
        peername = writer.get_extra_info('peername')
        attacker_ip = peername[0] if peername else 'unknown'
        session_id = f"db_{attacker_ip}_{datetime.now().timestamp()}"
        
        start_time = datetime.now()
        queries = []
        
        try:
            # Send fake greeting
            if service == "MySQL":
                writer.write(b'\x4a\x00\x00\x00\x0a\x38\x2e\x30\x2e\x32\x36\x00')
            else:
                writer.write(b'N')
            await writer.drain()
            
            # Capture queries
            while True:
                data = await reader.read(4096)
                if not data:
                    break
                query = data.decode('utf-8', errors='ignore')
                queries.append(query)
                logger.warning(f"{service} query from {attacker_ip}: {query[:200]}")
                
        except Exception as e:
            logger.error(f"Database session error: {e}")
        finally:
            duration = (datetime.now() - start_time).total_seconds()
            self._save_session(session_id, attacker_ip, 
                             3306 if service == "MySQL" else 5432, 
                             service, start_time, queries, None, duration)
            writer.close()
            await writer.wait_closed()
    
    async def _run_generic_honeypot(self, port: int):
        """Generic honeypot for other ports"""
        server = await asyncio.start_server(
            self._handle_generic_client, '0.0.0.0', port
        )
        logger.info(f"Generic honeypot listening on port {port}")
        async with server:
            while self.running:
                await asyncio.sleep(3600)
    
    async def _handle_generic_client(self, reader, writer):
        """Handle generic client connections"""
        peername = writer.get_extra_info('peername')
        attacker_ip = peername[0] if peername else 'unknown'
        session_id = f"gen_{attacker_ip}_{datetime.now().timestamp()}"
        
        start_time = datetime.now()
        data_received = ""
        
        try:
            data = await reader.read(4096)
            data_received = data.decode('utf-8', errors='ignore')
            logger.warning(f"Connection on generic port from {attacker_ip}: {data_received[:200]}")
        except Exception as e:
            logger.error(f"Generic session error: {e}")
        finally:
            duration = (datetime.now() - start_time).total_seconds()
            port = writer.get_extra_info('sockname')[1]
            self._save_session(session_id, attacker_ip, port, 'TCP',
                             start_time, [], data_received, duration)
            writer.close()
            await writer.wait_closed()
    
    def _save_session(self, session_id: str, attacker_ip: str, port: int,
                     protocol: str, start_time: datetime, commands: List[str],
                     payload: Optional[str], duration: float):
        """Save attack session and update attacker profile"""
        risk_score = self._calculate_risk_score(commands, payload, protocol)
        
        session = AttackSession(
            session_id=session_id,
            attacker_ip=attacker_ip,
            port=port,
            protocol=protocol,
            start_time=start_time,
            commands=commands,
            payload=payload,
            duration=duration,
            risk_score=risk_score
        )
        
        self.sessions[session_id] = session
        
        # Update attacker profile
        if attacker_ip not in self.attacker_profiles:
            self.attacker_profiles[attacker_ip] = {
                'first_seen': start_time.isoformat(),
                'total_sessions': 0,
                'total_commands': 0,
                'protocols_tried': set(),
                'max_risk_score': 0,
                'last_seen': None
            }
        
        profile = self.attacker_profiles[attacker_ip]
        profile['total_sessions'] += 1
        profile['total_commands'] += len(commands)
        profile['protocols_tried'].add(protocol)
        profile['max_risk_score'] = max(profile['max_risk_score'], risk_score)
        profile['last_seen'] = datetime.now().isoformat()
        profile['protocols_tried'] = list(profile['protocols_tried'])
        
        logger.info(f"Saved session {session_id}, risk score: {risk_score}")
    
    def _calculate_risk_score(self, commands: List[str], payload: Optional[str], 
                            protocol: str) -> float:
        """Calculate risk score based on attacker behavior"""
        score = 0.0
        
        dangerous_commands = ['rm', 'wget', 'curl', 'nc', 'nmap', 'chmod', 
                            'sudo', 'su', 'passwd', 'shadow', 'eval', 'exec']
        
        for cmd in commands:
            for dangerous in dangerous_commands:
                if dangerous in cmd.lower():
                    score += 0.1
        
        if payload:
            sql_keywords = ['SELECT', 'UNION', 'DROP', 'INSERT', 'DELETE', 'UPDATE']
            for keyword in sql_keywords:
                if keyword in payload.upper():
                    score += 0.15
            
            xss_patterns = ['<script', 'javascript:', 'onerror=', 'onload=']
            for pattern in xss_patterns:
                if pattern in payload.lower():
                    score += 0.15
        
        # Protocol-specific scoring
        if protocol == 'SSH':
            score += 0.2  # SSH access is inherently risky
        
        return min(score, 1.0)
    
    def get_attacker_profile(self, ip: str) -> Optional[dict]:
        """Get detailed profile of an attacker"""
        if ip in self.attacker_profiles:
            profile = self.attacker_profiles[ip].copy()
            profile['sessions'] = [
                asdict(s) for s in self.sessions.values() 
                if s.attacker_ip == ip
            ]
            return profile
        return None
    
    def get_all_sessions(self, limit: int = 100) -> List[dict]:
        """Get recent attack sessions"""
        sorted_sessions = sorted(
            self.sessions.values(), 
            key=lambda s: s.start_time, 
            reverse=True
        )[:limit]
        return [asdict(s) for s in sorted_sessions]
    
    def stop(self):
        """Stop all honeypot services"""
        self.running = False
        logger.info("Honeypot services stopped")

# Singleton instance
honeypot_service = HoneypotService()
