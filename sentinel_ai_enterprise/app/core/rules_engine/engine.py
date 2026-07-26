"""
Sentinel AI Enterprise - Advanced Rules Engine
محرك القواعد المتقدم للكشف عن التهديدات المخصصة
"""

from typing import Dict, List, Any, Optional, Callable
from datetime import datetime, timedelta
from enum import Enum
import json
import re
from pydantic import BaseModel, Field
from sqlalchemy import Column, String, Integer, DateTime, Text, Boolean, Float, ForeignKey
from sqlalchemy.orm import relationship, Session
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class RuleOperator(str, Enum):
    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    GREATER_THAN = "greater_than"
    LESS_THAN = "less_than"
    CONTAINS = "contains"
    REGEX_MATCH = "regex_match"
    IN_LIST = "in_list"
    NOT_IN_LIST = "not_in_list"
    EXISTS = "exists"
    NOT_EXISTS = "not_exists"

class RuleActionType(str, Enum):
    ALERT = "alert"
    BLOCK = "block"
    RATE_LIMIT = "rate_limit"
    QUARANTINE = "quarantine"
    NOTIFY = "notify"
    EXECUTE_SCRIPT = "execute_script"
    CREATE_INCIDENT = "create_incident"
    ENRICH_DATA = "enrich_data"
    TAG_EVENT = "tag_event"

class RuleSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"

class SecurityRule(Base):
    """نموذج قاعدة البيانات للقواعد الأمنية"""
    __tablename__ = "security_rules"
    
    id = Column(String, primary_key=True)
    name = Column(String(500), nullable=False, unique=True)
    description = Column(Text)
    enabled = Column(Boolean, default=True)
    
    # معلومات القاعدة
    category = Column(String(100))  # DDoS, Malware, SQLi, etc.
    severity = Column(String(50), default=RuleSeverity.MEDIUM.value)
    confidence_threshold = Column(Float, default=0.7)  # عتبة الثقة للتطبيق
    
    # شروط القاعدة
    conditions = Column(Text, nullable=False)  # JSON: قائمة الشروط
    condition_logic = Column(String(10), default="AND")  # AND, OR
    
    # الإجراءات
    actions = Column(Text, nullable=False)  # JSON: قائمة الإجراءات
    
    # التوقيت
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = Column(String(200))
    last_triggered_at = Column(DateTime)
    trigger_count = Column(Integer, default=0)
    
    # أولوية التنفيذ
    priority = Column(Integer, default=100)  # أقل رقم = أعلى أولوية
    
    # نافذة زمنية للتطبيق
    time_window_seconds = Column(Integer, default=300)  # 5 دقائق افتراضياً
    min_occurrences = Column(Integer, default=1)  # الحد الأدنى لعدد المرات
    
    # قيود التطبيق
    target_sources = Column(Text)  # مصادر محددة لتطبيق القاعدة
    target_destinations = Column(Text)  # وجهات محددة
    exclude_sources = Column(Text)  # مصادر مستبعدة
    exclude_destinations = Column(Text)  # وجهات مستبعدة
    
    # التعليقات والملاحظات
    comments = relationship("RuleComment", back_populates="rule", cascade="all, delete-orphan")

class RuleComment(Base):
    """تعليقات على القواعد"""
    __tablename__ = "rule_comments"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    rule_id = Column(String, ForeignKey("security_rules.id"), nullable=False)
    author = Column(String(200), nullable=False)
    content = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    rule = relationship("SecurityRule", back_populates="comments")

# Pydantic Models
class RuleCondition(BaseModel):
    field: str = Field(..., description="الحقل المراد فحصه")
    operator: RuleOperator = Field(..., description="عامل المقارنة")
    value: Any = Field(..., description="القيمة للمقارنة")
    case_sensitive: bool = Field(default=False, description="حساسية حالة الأحرف")

class RuleAction(BaseModel):
    action_type: RuleActionType = Field(..., description="نوع الإجراء")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="معاملات الإجراء")
    
class RuleCreate(BaseModel):
    name: str = Field(..., min_length=3, max_length=500)
    description: Optional[str] = None
    category: Optional[str] = None
    severity: RuleSeverity = RuleSeverity.MEDIUM
    confidence_threshold: float = Field(default=0.7, ge=0.0, le=1.0)
    conditions: List[RuleCondition] = Field(..., min_items=1)
    condition_logic: str = Field(default="AND", regex="^(AND|OR)$")
    actions: List[RuleAction] = Field(..., min_items=1)
    priority: int = Field(default=100, ge=1, le=1000)
    time_window_seconds: int = Field(default=300, ge=60, le=86400)
    min_occurrences: int = Field(default=1, ge=1)
    target_sources: Optional[List[str]] = None
    target_destinations: Optional[List[str]] = None
    exclude_sources: Optional[List[str]] = None
    exclude_destinations: Optional[List[str]] = None

class RuleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    enabled: Optional[bool] = None
    severity: Optional[RuleSeverity] = None
    confidence_threshold: Optional[float] = None
    conditions: Optional[List[RuleCondition]] = None
    condition_logic: Optional[str] = None
    actions: Optional[List[RuleAction]] = None
    priority: Optional[int] = None
    time_window_seconds: Optional[int] = None
    min_occurrences: Optional[int] = None

class RuleMatchResult(BaseModel):
    rule_id: str
    rule_name: str
    matched: bool
    matched_conditions: List[int] = []  # مؤشرات الشروط المطابقة
    confidence: float = 0.0
    triggered_actions: List[str] = []
    execution_time_ms: float = 0.0

class RulesEngine:
    """محرك القواعد المتقدم لتقييم وتطبيق القواعد الأمنية"""
    
    def __init__(self, db_session: Session):
        self.db = db_session
        self._compiled_rules: Dict[str, dict] = {}
        self._event_buffer: Dict[str, List[dict]] = {}  # مخزن مؤقت للأحداث حسب المصدر
    
    def load_rules(self, enabled_only: bool = True) -> List[SecurityRule]:
        """تحميل القواعد من قاعدة البيانات"""
        
        query = self.db.query(SecurityRule)
        if enabled_only:
            query = query.filter(SecurityRule.enabled == True)
        
        rules = query.order_by(SecurityRule.priority).all()
        
        # تجميع القواعد المحملة
        for rule in rules:
            self._compile_rule(rule)
        
        return rules
    
    def _compile_rule(self, rule: SecurityRule):
        """تجميع وتحضير القاعدة للتقييم السريع"""
        
        try:
            conditions = json.loads(rule.conditions)
            actions = json.loads(rule.actions)
            
            self._compiled_rules[rule.id] = {
                "rule": rule,
                "conditions": conditions,
                "actions": actions,
                "compiled_regexes": {}  # تخزين patterns regex المجمعة
            }
            
            # تجميع أنماط Regex مسبقاً
            for i, cond in enumerate(conditions):
                if cond.get("operator") == RuleOperator.REGEX_MATCH.value:
                    pattern = cond.get("value")
                    flags = 0 if cond.get("case_sensitive", False) else re.IGNORECASE
                    try:
                        self._compiled_rules[rule.id]["compiled_regexes"][i] = re.compile(pattern, flags)
                    except re.error as e:
                        print(f"Invalid regex in rule {rule.name}: {e}")
        
        except Exception as e:
            print(f"Error compiling rule {rule.name}: {e}")
    
    def evaluate_event(self, event: Dict[str, Any]) -> List[RuleMatchResult]:
        """تقييم حدث ضد جميع القواعد النشطة"""
        
        results = []
        source = event.get("source_ip") or event.get("source") or "unknown"
        
        # إضافة الحدث للمخزن المؤقت
        if source not in self._event_buffer:
            self._event_buffer[source] = []
        
        self._event_buffer[source].append({
            "event": event,
            "timestamp": datetime.utcnow()
        })
        
        # تنظيف الأحداث القديمة
        self._cleanup_event_buffer(source)
        
        # تقييم كل قاعدة
        for rule_id, compiled in self._compiled_rules.items():
            rule = compiled["rule"]
            
            # التحقق من القيود الزمنية وعدد المرات
            if not self._check_time_window(rule, source):
                continue
            
            # تقييم القاعدة
            result = self._evaluate_rule(compiled, event, source)
            results.append(result)
            
            # إذا تم تطبيق القاعدة، تحديث الإحصائيات
            if result.matched:
                self._update_rule_stats(rule_id)
                
                # تنفيذ الإجراءات
                self._execute_actions(result, event, compiled["actions"])
        
        return results
    
    def _evaluate_rule(self, compiled: dict, event: Dict[str, Any], source: str) -> RuleMatchResult:
        """تقييم قاعدة واحدة ضد حدث"""
        
        start_time = datetime.utcnow()
        rule = compiled["rule"]
        conditions = compiled["conditions"]
        
        matched_conditions = []
        
        # التحقق من قيود المصادر/الوجهات
        if not self._check_target_restrictions(rule, event):
            return RuleMatchResult(
                rule_id=rule.id,
                rule_name=rule.name,
                matched=False
            )
        
        # تقييم كل شرط
        for i, condition in enumerate(conditions):
            if self._evaluate_condition(condition, event, compiled["compiled_regexes"].get(i)):
                matched_conditions.append(i)
        
        # تحديد إذا كانت القاعدة مطابقة بناءً على المنطق (AND/OR)
        all_matched = len(matched_conditions) == len(conditions)
        any_matched = len(matched_conditions) > 0
        
        is_matched = (
            (rule.condition_logic == "AND" and all_matched) or
            (rule.condition_logic == "OR" and any_matched)
        )
        
        # حساب درجة الثقة
        confidence = 0.0
        if is_matched:
            confidence = len(matched_conditions) / len(conditions) if conditions else 0.0
            
            # تعزيز الثقة إذا تطابق جميع الشروط
            if all_matched:
                confidence = min(1.0, confidence + 0.1)
        
        execution_time = (datetime.utcnow() - start_time).total_seconds() * 1000
        
        return RuleMatchResult(
            rule_id=rule.id,
            rule_name=rule.name,
            matched=is_matched and confidence >= rule.confidence_threshold,
            matched_conditions=matched_conditions,
            confidence=confidence,
            execution_time_ms=execution_time
        )
    
    def _evaluate_condition(self, condition: dict, event: Dict[str, Any], compiled_regex: re.Pattern = None) -> bool:
        """تقييم شرط واحد"""
        
        field = condition.get("field")
        operator = condition.get("operator")
        value = condition.get("value")
        case_sensitive = condition.get("case_sensitive", False)
        
        # استخراج قيمة الحقل من الحدث (يدعم الحقول المتداخلة مثل request.headers.user_agent)
        event_value = self._get_nested_field(event, field)
        
        if event_value is None:
            # الحقل غير موجود
            if operator == RuleOperator.NOT_EXISTS.value:
                return True
            elif operator == RuleOperator.EXISTS.value:
                return False
            else:
                return False
        
        # تحويل القيم للمقارنة
        if not case_sensitive and isinstance(event_value, str) and isinstance(value, str):
            event_value = event_value.lower()
            value = value.lower()
        
        # تنفيذ عملية المقارنة
        try:
            if operator == RuleOperator.EQUALS.value:
                return event_value == value
            elif operator == RuleOperator.NOT_EQUALS.value:
                return event_value != value
            elif operator == RuleOperator.GREATER_THAN.value:
                return float(event_value) > float(value)
            elif operator == RuleOperator.LESS_THAN.value:
                return float(event_value) < float(value)
            elif operator == RuleOperator.CONTAINS.value:
                return str(value) in str(event_value)
            elif operator == RuleOperator.REGEX_MATCH.value and compiled_regex:
                return bool(compiled_regex.search(str(event_value)))
            elif operator == RuleOperator.IN_LIST.value:
                return event_value in value
            elif operator == RuleOperator.NOT_IN_LIST.value:
                return event_value not in value
            elif operator == RuleOperator.EXISTS.value:
                return event_value is not None
            elif operator == RuleOperator.NOT_EXISTS.value:
                return event_value is None
        except (ValueError, TypeError):
            return False
        
        return False
    
    def _get_nested_field(self, obj: dict, field_path: str) -> Any:
        """استخراج قيمة حقل متداخل من قاموس"""
        
        keys = field_path.split(".")
        current = obj
        
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return None
        
        return current
    
    def _check_target_restrictions(self, rule: SecurityRule, event: Dict[str, Any]) -> bool:
        """التحقق من قيود المصادر والوجهات"""
        
        source = event.get("source_ip") or event.get("source")
        destination = event.get("destination_ip") or event.get("destination")
        
        # التحقق من المصادر المستهدفة
        if rule.target_sources:
            targets = json.loads(rule.target_sources)
            if source and source not in targets:
                return False
        
        # التحقق من الوجهات المستهدفة
        if rule.target_destinations:
            targets = json.loads(rule.target_destinations)
            if destination and destination not in targets:
                return False
        
        # التحقق من المصادر المستبعدة
        if rule.exclude_sources:
            excludes = json.loads(rule.exclude_sources)
            if source and source in excludes:
                return False
        
        # التحقق من الوجهات المستبعدة
        if rule.exclude_destinations:
            excludes = json.loads(rule.exclude_destinations)
            if destination and destination in excludes:
                return False
        
        return True
    
    def _check_time_window(self, rule: SecurityRule, source: str) -> bool:
        """التحقق من نافذة الزمنية وعدد المرات"""
        
        if source not in self._event_buffer:
            return rule.min_occurrences <= 1
        
        now = datetime.utcnow()
        window_start = now - timedelta(seconds=rule.time_window_seconds)
        
        # عد الأحداث في النافذة الزمنية
        recent_events = [
            e for e in self._event_buffer[source]
            if e["timestamp"] >= window_start
        ]
        
        return len(recent_events) >= rule.min_occurrences
    
    def _cleanup_event_buffer(self, source: str, max_age_seconds: int = 600):
        """تنظيف الأحداث القديمة من المخزن المؤقت"""
        
        if source not in self._event_buffer:
            return
        
        cutoff = datetime.utcnow() - timedelta(seconds=max_age_seconds)
        self._event_buffer[source] = [
            e for e in self._event_buffer[source]
            if e["timestamp"] >= cutoff
        ]
    
    def _update_rule_stats(self, rule_id: str):
        """تحديث إحصائيات القاعدة بعد التطبيق"""
        
        rule = self.db.query(SecurityRule).filter(SecurityRule.id == rule_id).first()
        if rule:
            rule.trigger_count += 1
            rule.last_triggered_at = datetime.utcnow()
            self.db.commit()
    
    def _execute_actions(self, result: RuleMatchResult, event: Dict[str, Any], actions_config: List[dict]):
        """تنفيذ الإجراءات المحددة في القاعدة"""
        
        for action_config in actions_config:
            action_type = action_config.get("action_type")
            params = action_config.get("parameters", {})
            
            # هنا يتم تنفيذ الإجراءات الفعلية
            # في التطبيق الحقيقي، سيتم استدعاء خدمات خارجية
            print(f"Executing action {action_type} for rule {result.rule_name}")
            print(f"Parameters: {params}")
            
            # مثال: إنشاء تنبيه
            if action_type == RuleActionType.ALERT.value:
                self._execute_alert_action(result, event, params)
            
            # مثال: حظر IP
            elif action_type == RuleActionType.BLOCK.value:
                self._execute_block_action(result, event, params)
            
            # مثال: إنشاء حادث
            elif action_type == RuleActionType.CREATE_INCIDENT.value:
                self._execute_create_incident_action(result, event, params)
    
    def _execute_alert_action(self, result: RuleMatchResult, event: dict, params: dict):
        """تنفيذ إجراء التنبيه"""
        # سيتم تكامل مع نظام الإشعارات
        pass
    
    def _execute_block_action(self, result: RuleMatchResult, event: dict, params: dict):
        """تنفيذ إجراء الحظر"""
        # سيتم تكامل مع الجدار الناري أو WAF
        pass
    
    def _execute_create_incident_action(self, result: RuleMatchResult, event: dict, params: dict):
        """تنفيذ إجراء إنشاء حادث"""
        # سيتم تكامل مع نظام إدارة الحوادث
        pass
    
    def get_rule_statistics(self) -> dict:
        """الحصول على إحصائيات القواعد"""
        
        total_rules = self.db.query(SecurityRule).count()
        enabled_rules = self.db.query(SecurityRule).filter(SecurityRule.enabled == True).count()
        
        top_triggered = self.db.query(SecurityRule).order_by(
            SecurityRule.trigger_count.desc()
        ).limit(10).all()
        
        return {
            "total_rules": total_rules,
            "enabled_rules": enabled_rules,
            "disabled_rules": total_rules - enabled_rules,
            "top_triggered_rules": [
                {"name": r.name, "trigger_count": r.trigger_count, "last_triggered": r.last_triggered_at}
                for r in top_triggered
            ]
        }

# استيراد مساعد
import uuid
