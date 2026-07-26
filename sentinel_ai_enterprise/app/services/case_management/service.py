"""
Sentinel AI Enterprise - Incident Case Management System
نظام إدارة الحوادث الأمنية المتقدم
"""

from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any
from enum import Enum
import json
import uuid
from pydantic import BaseModel, Field
from sqlalchemy import Column, String, Integer, DateTime, Text, ForeignKey, Boolean, Float
from sqlalchemy.orm import relationship, Session
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class IncidentStatus(str, Enum):
    NEW = "new"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    CLOSED = "closed"

class IncidentSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"

class IncidentPriority(str, Enum):
    P1 = "p1"  # Critical
    P2 = "p2"  # High
    P3 = "p3"  # Medium
    P4 = "p4"  # Low

class IncidentType(str, Enum):
    DDOS_ATTACK = "ddos_attack"
    MALWARE_INFECTION = "malware_infection"
    SQL_INJECTION = "sql_injection"
    BRUTE_FORCE = "brute_force"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    DATA_EXFILTRATION = "data_exfiltration"
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    POLICY_VIOLATION = "policy_violation"
    OTHER = "other"

class Incident(Base):
    """نموذج قاعدة البيانات لإدارة الحوادث"""
    __tablename__ = "incidents"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    title = Column(String(500), nullable=False)
    description = Column(Text)
    status = Column(String(50), default=IncidentStatus.NEW.value)
    severity = Column(String(50), default=IncidentSeverity.MEDIUM.value)
    priority = Column(String(10), default=IncidentPriority.P3.value)
    incident_type = Column(String(100), default=IncidentType.OTHER.value)
    
    # معلومات الكشف
    detection_source = Column(String(200))  # مصدر الكشف (DDoS Engine, Honeypot, etc.)
    confidence_score = Column(Float, default=0.0)  # درجة الثقة في الكشف
    threat_intel_indicators = Column(Text)  # مؤشرات التهديد من مصادر خارجية
    
    # التوقيت
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    detected_at = Column(DateTime)
    contained_at = Column(DateTime)
    resolved_at = Column(DateTime)
    closed_at = Column(DateTime)
    
    # التعيين والمتابعة
    assigned_to = Column(String(200))  # المحقق المسؤول
    assigned_at = Column(DateTime)
    escalated_to = Column(String(200))  # تم التصعيد إلى
    escalation_reason = Column(Text)
    
    # الاستجابة والإجراءات
    auto_response_actions = Column(Text)  # الإجراءات التلقائية المنفذة
    manual_actions = Column(Text)  # الإجراءات اليدوية
    evidence_collected = Column(Text)  # الأدلة المجمعة
    root_cause = Column(Text)  # السبب الجذري
    lessons_learned = Column(Text)  # الدروس المستفادة
    
    # العلاقات
    affected_assets = Column(Text)  # الأصول المتأثرة
    iocs = Column(Text)  # مؤشرات الاختراق (IPs, Domains, Hashes)
    
    # التعليقات والملاحظات
    comments = relationship("IncidentComment", back_populates="incident", cascade="all, delete-orphan")
    timeline_events = relationship("IncidentTimeline", back_populates="incident", cascade="all, delete-orphan")
    attachments = relationship("IncidentAttachment", back_populates="incident", cascade="all, delete-orphan")
    
    # SLA
    sla_deadline = Column(DateTime)  # موعد التسليم حسب SLA
    sla_breached = Column(Boolean, default=False)  # هل تم تجاوز SLA؟
    breach_reason = Column(Text)

class IncidentComment(Base):
    """تعليقات على الحادث"""
    __tablename__ = "incident_comments"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_id = Column(String, ForeignKey("incidents.id"), nullable=False)
    author = Column(String(200), nullable=False)
    content = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    is_internal = Column(Boolean, default=True)  # تعليق داخلي فقط
    
    incident = relationship("Incident", back_populates="comments")

class IncidentTimeline(Base):
    """خط زمني لأحداث الحادث"""
    __tablename__ = "incident_timeline"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_id = Column(String, ForeignKey("incidents.id"), nullable=False)
    event_type = Column(String(100), nullable=False)  # detection, assignment, action, escalation, etc.
    event_description = Column(Text, nullable=False)
    actor = Column(String(200))  # من نفذ الحدث (نظام أو مستخدم)
    timestamp = Column(DateTime, default=datetime.utcnow)
    metadata = Column(Text)  # بيانات إضافية بصيغة JSON
    
    incident = relationship("Incident", back_populates="timeline_events")

class IncidentAttachment(Base):
    """مرفقات الحادث"""
    __tablename__ = "incident_attachments"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_id = Column(String, ForeignKey("incidents.id"), nullable=False)
    filename = Column(String(500), nullable=False)
    file_type = Column(String(100))
    file_size = Column(Integer)  # بالبايت
    file_hash = Column(String(100))  # SHA256
    uploaded_by = Column(String(200))
    uploaded_at = Column(DateTime, default=datetime.utcnow)
    storage_path = Column(String(1000))
    
    incident = relationship("Incident", back_populates="attachments")

# Pydantic Models للـ API
class IncidentCreate(BaseModel):
    title: str = Field(..., min_length=5, max_length=500)
    description: Optional[str] = None
    incident_type: IncidentType = IncidentType.OTHER
    severity: IncidentSeverity = IncidentSeverity.MEDIUM
    detection_source: Optional[str] = None
    confidence_score: float = 0.0
    detected_at: Optional[datetime] = None
    iocs: Optional[List[str]] = None
    affected_assets: Optional[List[str]] = None

class IncidentUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[IncidentStatus] = None
    severity: Optional[IncidentSeverity] = None
    priority: Optional[IncidentPriority] = None
    assigned_to: Optional[str] = None
    escalated_to: Optional[str] = None
    escalation_reason: Optional[str] = None
    root_cause: Optional[str] = None
    lessons_learned: Optional[str] = None

class IncidentCommentCreate(BaseModel):
    content: str = Field(..., min_length=1)
    is_internal: bool = True

class IncidentResponse(BaseModel):
    id: str
    title: str
    description: Optional[str]
    status: str
    severity: str
    priority: str
    incident_type: str
    detection_source: Optional[str]
    confidence_score: float
    created_at: datetime
    updated_at: datetime
    detected_at: Optional[datetime]
    assigned_to: Optional[str]
    sla_deadline: Optional[datetime]
    sla_breached: bool
    comments_count: int = 0
    timeline_events_count: int = 0
    
    class Config:
        from_attributes = True

class CaseManagementService:
    """خدمة إدارة الحوادث الأمنية"""
    
    def __init__(self, db_session: Session):
        self.db = db_session
    
    def create_incident(self, incident_data: IncidentCreate, auto_detected: bool = False) -> Incident:
        """إنشاء حادث أمني جديد"""
        
        # حساب الأولوية تلقائياً بناءً على الشدة ونوع الهجوم
        priority = self._calculate_priority(
            incident_data.severity, 
            incident_data.incident_type,
            incident_data.confidence_score
        )
        
        # حساب موعد SLA بناءً على الأولوية
        sla_hours = self._get_sla_hours(priority)
        sla_deadline = datetime.utcnow() + timedelta(hours=sla_hours)
        
        incident = Incident(
            title=incident_data.title,
            description=incident_data.description,
            incident_type=incident_data.incident_type.value,
            severity=incident_data.severity.value,
            priority=priority.value,
            detection_source=incident_data.detection_source,
            confidence_score=incident_data.confidence_score,
            detected_at=incident_data.detected_at or datetime.utcnow(),
            iocs=json.dumps(incident_data.iocs) if incident_data.iocs else None,
            affected_assets=json.dumps(incident_data.affected_assets) if incident_data.affected_assets else None,
            sla_deadline=sla_deadline,
            auto_response_actions=json.dumps({"auto_created": auto_detected}) if auto_detected else None
        )
        
        self.db.add(incident)
        self.db.commit()
        self.db.refresh(incident)
        
        # إضافة حدث لخط الزمن
        self._add_timeline_event(
            incident.id,
            "incident_created",
            f"تم إنشاء الحادث تلقائياً" if auto_detected else "تم إنشاء الحادث يدوياً",
            "system" if auto_detected else "user"
        )
        
        # إضافة حدث للكشف إذا كان تلقائياً
        if auto_detected and incident_data.detection_source:
            self._add_timeline_event(
                incident.id,
                "detection",
                f"تم الكشف عن التهديد بواسطة: {incident_data.detection_source}",
                incident_data.detection_source,
                {"confidence_score": incident_data.confidence_score}
            )
        
        return incident
    
    def update_incident(self, incident_id: str, update_data: IncidentUpdate, user: str) -> Incident:
        """تحديث معلومات الحادث"""
        
        incident = self.db.query(Incident).filter(Incident.id == incident_id).first()
        if not incident:
            raise ValueError(f"Incident {incident_id} not found")
        
        update_changes = []
        
        # تحديث الحقول المسموح بها
        for field, value in update_data.dict(exclude_unset=True).items():
            if value is not None:
                old_value = getattr(incident, field)
                new_value = value.value if hasattr(value, 'value') else value
                
                if old_value != new_value:
                    setattr(incident, field, new_value if not hasattr(value, 'value') else value.value)
                    update_changes.append(f"{field}: {old_value} → {new_value}")
                    
                    # أحداث خاصة للتغييرات المهمة
                    if field == "status":
                        self._handle_status_change(incident, new_value, user)
                    elif field == "assigned_to" and value:
                        incident.assigned_at = datetime.utcnow()
                        self._add_timeline_event(
                            incident.id,
                            "assignment",
                            f"تم تعيين الحادث إلى {value}",
                            user
                        )
                    elif field == "escalated_to" and value:
                        self._add_timeline_event(
                            incident.id,
                            "escalation",
                            f"تم تصعيد الحادث إلى {value}. السبب: {update_data.escalation_reason or 'غير محدد'}",
                            user
                        )
        
        if update_changes:
            incident.updated_at = datetime.utcnow()
            self._add_timeline_event(
                incident.id,
                "update",
                f"تم تحديث الحادث: {', '.join(update_changes)}",
                user
            )
        
        self.db.commit()
        self.db.refresh(incident)
        return incident
    
    def add_comment(self, incident_id: str, comment_data: IncidentCommentCreate, author: str) -> IncidentComment:
        """إضافة تعليق على الحادث"""
        
        incident = self.db.query(Incident).filter(Incident.id == incident_id).first()
        if not incident:
            raise ValueError(f"Incident {incident_id} not found")
        
        comment = IncidentComment(
            incident_id=incident_id,
            author=author,
            content=comment_data.content,
            is_internal=comment_data.is_internal
        )
        
        self.db.add(comment)
        self._add_timeline_event(
            incident_id,
            "comment_added",
            f"أضاف {author} تعليقاً جديداً",
            author
        )
        
        self.db.commit()
        self.db.refresh(comment)
        return comment
    
    def _add_timeline_event(self, incident_id: str, event_type: str, description: str, actor: str, metadata: dict = None):
        """إضافة حدث لخط الزمن"""
        
        event = IncidentTimeline(
            incident_id=incident_id,
            event_type=event_type,
            event_description=description,
            actor=actor,
            metadata=json.dumps(metadata) if metadata else None
        )
        
        self.db.add(event)
    
    def _handle_status_change(self, incident: Incident, new_status: str, user: str):
        """معالجة تغييرات حالة الحادث"""
        
        now = datetime.utcnow()
        
        if new_status == IncidentStatus.CONTAINED.value:
            incident.contained_at = now
            self._add_timeline_event(
                incident.id,
                "contained",
                f"تم احتواء الحادث بواسطة {user}",
                user
            )
        
        elif new_status == IncidentStatus.RESOLVED.value:
            incident.resolved_at = now
            self._add_timeline_event(
                incident.id,
                "resolved",
                f"تم حل الحادث بواسطة {user}",
                user
            )
            
            # التحقق من SLA
            if incident.sla_deadline and now > incident.sla_deadline:
                incident.sla_breached = True
                incident.breach_reason = "تم الحل بعد موعد SLA المحدد"
        
        elif new_status == IncidentStatus.CLOSED.value:
            incident.closed_at = now
            self._add_timeline_event(
                incident.id,
                "closed",
                f"تم إغلاق الحادث بواسطة {user}",
                user
            )
    
    def _calculate_priority(self, severity: IncidentSeverity, incident_type: IncidentType, confidence: float) -> IncidentPriority:
        """حساب الأولوية تلقائياً"""
        
        # أولويات أساسية حسب الشدة
        severity_priority = {
            IncidentSeverity.CRITICAL: IncidentPriority.P1,
            IncidentSeverity.HIGH: IncidentPriority.P2,
            IncidentSeverity.MEDIUM: IncidentPriority.P3,
            IncidentSeverity.LOW: IncidentPriority.P4,
            IncidentSeverity.INFORMATIONAL: IncidentPriority.P4
        }
        
        base_priority = severity_priority.get(severity, IncidentPriority.P3)
        
        # تعديل الأولوية بناءً على نوع الهجوم
        high_impact_types = [
            IncidentType.DATA_EXFILTRATION,
            IncidentType.LATERAL_MOVEMENT,
            IncidentType.PRIVILEGE_ESCALATION,
            IncidentType.MALWARE_INFECTION
        ]
        
        if incident_type in high_impact_types and base_priority in [IncidentPriority.P3, IncidentPriority.P4]:
            # رفع الأولوية درجة واحدة
            priority_map = {IncidentPriority.P4: IncidentPriority.P3, IncidentPriority.P3: IncidentPriority.P2}
            base_priority = priority_map.get(base_priority, base_priority)
        
        # تعديل بناءً على درجة الثقة
        if confidence >= 0.95 and base_priority in [IncidentPriority.P3, IncidentPriority.P4]:
            priority_map = {IncidentPriority.P4: IncidentPriority.P3, IncidentPriority.P3: IncidentPriority.P2}
            base_priority = priority_map.get(base_priority, base_priority)
        
        return base_priority
    
    def _get_sla_hours(self, priority: IncidentPriority) -> int:
        """الحصول على ساعات SLA بناءً على الأولوية"""
        
        sla_hours = {
            IncidentPriority.P1: 4,   # Critical: 4 ساعات
            IncidentPriority.P2: 24,  # High: يوم واحد
            IncidentPriority.P3: 72,  # Medium: 3 أيام
            IncidentPriority.P4: 168  # Low: أسبوع
        }
        
        return sla_hours.get(priority, 72)
    
    def get_incident_stats(self) -> dict:
        """الحصول على إحصائيات الحوادث"""
        
        total = self.db.query(Incident).count()
        
        by_status = self.db.query(
            Incident.status, 
            func.count(Incident.id)
        ).group_by(Incident.status).all()
        
        by_severity = self.db.query(
            Incident.severity, 
            func.count(Incident.id)
        ).group_by(Incident.severity).all()
        
        by_type = self.db.query(
            Incident.incident_type, 
            func.count(Incident.id)
        ).group_by(Incident.incident_type).all()
        
        sla_breached = self.db.query(Incident).filter(Incident.sla_breached == True).count()
        
        avg_resolution_time = self.db.query(
            func.avg(Incident.resolved_at - Incident.created_at)
        ).filter(Incident.resolved_at != None).scalar()
        
        return {
            "total_incidents": total,
            "by_status": {status: count for status, count in by_status},
            "by_severity": {severity: count for severity, count in by_severity},
            "by_type": {incident_type: count for incident_type, count in by_type},
            "sla_breached": sla_breached,
            "sla_compliance_rate": ((total - sla_breached) / total * 100) if total > 0 else 100,
            "avg_resolution_time_hours": avg_resolution_time.total_seconds() / 3600 if avg_resolution_time else None
        }

# دالة مساعدة للاستيراد
from sqlalchemy import func
