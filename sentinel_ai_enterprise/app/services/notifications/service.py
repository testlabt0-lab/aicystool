"""
Sentinel AI Enterprise - Advanced Notification System
نظام الإشعارات المتقدم متعدد القنوات
"""

from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from enum import Enum
import json
import smtplib
import asyncio
import aiohttp
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pydantic import BaseModel, Field
from sqlalchemy import Column, String, Integer, DateTime, Text, Boolean, ForeignKey
from sqlalchemy.orm import relationship, Session
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class NotificationChannel(str, Enum):
    EMAIL = "email"
    SMS = "sms"
    SLACK = "slack"
    TEAMS = "teams"
    WEBHOOK = "webhook"
    PUSH = "push"
    SYSLOG = "syslog"

class NotificationPriority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class NotificationStatus(str, Enum):
    PENDING = "pending"
    SENT = "sent"
    FAILED = "failed"
    RETRYING = "retrying"

class Notification(Base):
    """نموذج قاعدة البيانات للإشعارات"""
    __tablename__ = "notifications"
    
    id = Column(String, primary_key=True)
    title = Column(String(500), nullable=False)
    message = Column(Text, nullable=False)
    channel = Column(String(50), nullable=False)
    priority = Column(String(50), default=NotificationPriority.MEDIUM.value)
    status = Column(String(50), default=NotificationStatus.PENDING.value)
    
    # المستلمون
    recipients = Column(Text)  # JSON list
    recipient_groups = Column(Text)  # JSON list of group names
    
    # المحتوى الإضافي
    subject = Column(String(1000))  # للعنوان في الإيميل
    html_content = Column(Text)  # محتوى HTML للإيميل
    attachments = Column(Text)  # JSON list of attachment paths
    
    # السياق
    incident_id = Column(String)  # مرتبط بحادث أمني
    rule_id = Column(String)  # مرتبط بقاعدة أمنية
    event_data = Column(Text)  # JSON data للحدث المسبب
    
    # التوقيت والمحاولة
    created_at = Column(DateTime, default=datetime.utcnow)
    scheduled_at = Column(DateTime)  # مجدول للإرسال في وقت لاحق
    sent_at = Column(DateTime)
    delivered_at = Column(DateTime)
    failed_at = Column(DateTime)
    failure_reason = Column(Text)
    
    retry_count = Column(Integer, default=0)
    max_retries = Column(Integer, default=3)
    next_retry_at = Column(DateTime)
    
    # الاستجابة
    response_code = Column(String(100))
    response_data = Column(Text)  # JSON

class NotificationTemplate(Base):
    """قوالب الإشعارات"""
    __tablename__ = "notification_templates"
    
    id = Column(String, primary_key=True)
    name = Column(String(500), nullable=False, unique=True)
    description = Column(Text)
    channel = Column(String(50), nullable=False)
    
    # محتوى القالب
    subject_template = Column(String(1000))  # للعناوين
    body_template = Column(Text, nullable=False)
    html_template = Column(Text)  # قالب HTML اختياري
    
    # متغيرات القالب
    variables = Column(Text)  # JSON list of variable names
    
    # الإعدادات
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class NotificationRecipient(Base):
    """مستلمو الإشعارات"""
    __tablename__ = "notification_recipients"
    
    id = Column(String, primary_key=True)
    name = Column(String(500), nullable=False)
    email = Column(String(500))
    phone = Column(String(50))  # لـ SMS
    slack_webhook = Column(String(1000))
    teams_webhook = Column(String(1000))
    
    # المجموعات
    groups = Column(Text)  # JSON list of group names
    
    # التفضيلات
    channels = Column(Text)  # JSON list of preferred channels
    priority_filter = Column(Text)  # JSON list of priorities to receive
    time_restrictions = Column(Text)  # JSON: {"start_hour": 9, "end_hour": 17}
    
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

# Pydantic Models
class NotificationCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=500)
    message: str = Field(..., min_length=1)
    channel: NotificationChannel
    priority: NotificationPriority = NotificationPriority.MEDIUM
    recipients: Optional[List[str]] = None
    recipient_groups: Optional[List[str]] = None
    subject: Optional[str] = None
    html_content: Optional[str] = None
    incident_id: Optional[str] = None
    rule_id: Optional[str] = None
    event_data: Optional[Dict[str, Any]] = None
    scheduled_at: Optional[datetime] = None

class NotificationUpdate(BaseModel):
    status: Optional[NotificationStatus] = None
    failure_reason: Optional[str] = None
    response_code: Optional[str] = None
    response_data: Optional[Dict[str, Any]] = None

class NotificationStats(BaseModel):
    total_sent: int
    total_failed: int
    by_channel: Dict[str, int]
    by_priority: Dict[str, int]
    avg_delivery_time_seconds: float

class NotificationService:
    """خدمة الإشعارات المتقدمة متعددة القنوات"""
    
    def __init__(self, db_session: Session, config: dict):
        self.db = db_session
        self.config = config
        self._templates: Dict[str, dict] = {}
        self._load_templates()
    
    def _load_templates(self):
        """تحميل قوالب الإشعارات"""
        templates = self.db.query(NotificationTemplate).filter(
            NotificationTemplate.enabled == True
        ).all()
        
        for template in templates:
            self._templates[template.name] = {
                "template": template,
                "variables": json.loads(template.variables) if template.variables else []
            }
    
    async def send_notification(self, notification_data: NotificationCreate) -> Notification:
        """إرسال إشعار جديد"""
        
        # إنشاء سجل الإشعار
        notification = Notification(
            id=self._generate_id(),
            title=notification_data.title,
            message=notification_data.message,
            channel=notification_data.channel.value,
            priority=notification_data.priority.value,
            recipients=json.dumps(notification_data.recipients) if notification_data.recipients else None,
            recipient_groups=json.dumps(notification_data.recipient_groups) if notification_data.recipient_groups else None,
            subject=notification_data.subject,
            html_content=notification_data.html_content,
            incident_id=notification_data.incident_id,
            rule_id=notification_data.rule_id,
            event_data=json.dumps(notification_data.event_data) if notification_data.event_data else None,
            scheduled_at=notification_data.scheduled_at
        )
        
        self.db.add(notification)
        self.db.commit()
        self.db.refresh(notification)
        
        # إذا كان مجدولاً، لا ترسل الآن
        if notification.scheduled_at and notification.scheduled_at > datetime.utcnow():
            return notification
        
        # إرسال الإشعار
        await self._process_notification(notification)
        
        return notification
    
    async def _process_notification(self, notification: Notification):
        """معالجة وإرسال الإشعار"""
        
        try:
            notification.status = NotificationStatus.SENT.value
            
            if notification.channel == NotificationChannel.EMAIL.value:
                await self._send_email(notification)
            elif notification.channel == NotificationChannel.SMS.value:
                await self._send_sms(notification)
            elif notification.channel == NotificationChannel.SLACK.value:
                await self._send_slack(notification)
            elif notification.channel == NotificationChannel.TEAMS.value:
                await self._send_teams(notification)
            elif notification.channel == NotificationChannel.WEBHOOK.value:
                await self._send_webhook(notification)
            elif notification.channel == NotificationChannel.SYSLOG.value:
                await self._send_syslog(notification)
            
            notification.sent_at = datetime.utcnow()
            notification.status = NotificationStatus.SENT.value
            
        except Exception as e:
            notification.status = NotificationStatus.FAILED.value
            notification.failed_at = datetime.utcnow()
            notification.failure_reason = str(e)
            
            # التحقق من إمكانية إعادة المحاولة
            if notification.retry_count < notification.max_retries:
                notification.status = NotificationStatus.RETRYING.value
                notification.retry_count += 1
                notification.next_retry_at = datetime.utcnow() + timedelta(minutes=5 * notification.retry_count)
        
        self.db.commit()
    
    async def _send_email(self, notification: Notification):
        """إرسال إشعار عبر البريد الإلكتروني"""
        
        smtp_config = self.config.get("smtp", {})
        if not smtp_config:
            raise ValueError("SMTP configuration not found")
        
        recipients = json.loads(notification.recipients) if notification.recipients else []
        if not recipients:
            # الحصول على المستلمين من المجموعات
            recipients = self._get_recipients_from_groups(
                json.loads(notification.recipient_groups) if notification.recipient_groups else [],
                NotificationChannel.EMAIL
            )
        
        if not recipients:
            raise ValueError("No email recipients specified")
        
        msg = MIMEMultipart('alternative')
        msg['Subject'] = notification.subject or notification.title
        msg['From'] = smtp_config.get("from_email", "sentinel@example.com")
        msg['To'] = ', '.join(recipients)
        
        # نص عادي
        text_part = MIMEText(notification.message, 'plain')
        msg.attach(text_part)
        
        # HTML إذا وجد
        if notification.html_content:
            html_part = MIMEText(notification.html_content, 'html')
            msg.attach(html_part)
        
        # إرسال عبر SMTP
        with smtplib.SMTP(smtp_config.get("host"), smtp_config.get("port", 587)) as server:
            if smtp_config.get("use_tls", True):
                server.starttls()
            
            if smtp_config.get("username") and smtp_config.get("password"):
                server.login(smtp_config["username"], smtp_config["password"])
            
            server.sendmail(msg['From'], recipients, msg.as_string())
        
        notification.response_code = "250"
        notification.response_data = json.dumps({"recipients_count": len(recipients)})
    
    async def _send_slack(self, notification: Notification):
        """إرسال إشعار إلى Slack"""
        
        webhook_urls = []
        
        if notification.recipients:
            webhook_urls = json.loads(notification.recipients)
        elif notification.recipient_groups:
            webhook_urls = self._get_recipients_from_groups(
                json.loads(notification.recipient_groups),
                NotificationChannel.SLACK
            )
        
        if not webhook_urls:
            # استخدام الويب هوك الافتراضي من الإعدادات
            default_webhook = self.config.get("slack", {}).get("default_webhook")
            if default_webhook:
                webhook_urls = [default_webhook]
            else:
                raise ValueError("No Slack webhook configured")
        
        # تنسيق الرسالة لـ Slack
        color_map = {
            NotificationPriority.CRITICAL.value: "#dc3545",
            NotificationPriority.HIGH.value: "#fd7e14",
            NotificationPriority.MEDIUM.value: "#ffc107",
            NotificationPriority.LOW.value: "#28a745"
        }
        
        payload = {
            "attachments": [
                {
                    "color": color_map.get(notification.priority, "#6c757d"),
                    "title": notification.title,
                    "text": notification.message,
                    "fields": [
                        {"title": "Priority", "value": notification.priority.upper(), "short": True},
                        {"title": "Channel", "value": notification.channel, "short": True}
                    ],
                    "footer": "Sentinel AI Enterprise",
                    "ts": int(datetime.utcnow().timestamp())
                }
            ]
        }
        
        # إضافة معلومات الحادث إذا وجد
        if notification.incident_id:
            payload["attachments"][0]["fields"].append({
                "title": "Incident ID",
                "value": notification.incident_id,
                "short": False
            })
        
        async with aiohttp.ClientSession() as session:
            for webhook_url in webhook_urls:
                async with session.post(webhook_url, json=payload) as response:
                    if response.status != 200:
                        raise Exception(f"Slack API returned status {response.status}")
        
        notification.response_code = "200"
    
    async def _send_teams(self, notification: Notification):
        """إرسال إشعار إلى Microsoft Teams"""
        
        webhook_urls = []
        
        if notification.recipients:
            webhook_urls = json.loads(notification.recipients)
        elif notification.recipient_groups:
            webhook_urls = self._get_recipients_from_groups(
                json.loads(notification.recipient_groups),
                NotificationChannel.TEAMS
            )
        
        if not webhook_urls:
            default_webhook = self.config.get("teams", {}).get("default_webhook")
            if default_webhook:
                webhook_urls = [default_webhook]
            else:
                raise ValueError("No Teams webhook configured")
        
        # تنسيق الرسالة لـ Teams
        theme_color_map = {
            NotificationPriority.CRITICAL.value: "8B0000",
            NotificationPriority.HIGH.value: "FF8C00",
            NotificationPriority.MEDIUM.value: "FFD700",
            NotificationPriority.LOW.value: "008000"
        }
        
        payload = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": theme_color_map.get(notification.priority, "808080"),
            "summary": notification.title,
            "sections": [
                {
                    "activityTitle": notification.title,
                    "activitySubtitle": f"Priority: {notification.priority.upper()} | Channel: {notification.channel}",
                    "activityText": notification.message,
                    "facts": [
                        {"name": "Priority", "value": notification.priority.upper()},
                        {"name": "Channel", "value": notification.channel}
                    ]
                }
            ],
            "potentialAction": []
        }
        
        # إضافة رابط للحادث إذا وجد
        if notification.incident_id:
            base_url = self.config.get("base_url", "http://localhost:8000")
            payload["potentialAction"].append({
                "@type": "OpenUri",
                "name": "View Incident",
                "targets": [{
                    "os": "default",
                    "uri": f"{base_url}/incidents/{notification.incident_id}"
                }]
            })
        
        async with aiohttp.ClientSession() as session:
            for webhook_url in webhook_urls:
                headers = {"Content-Type": "application/json"}
                async with session.post(webhook_url, json=payload, headers=headers) as response:
                    if response.status != 200:
                        raise Exception(f"Teams API returned status {response.status}")
        
        notification.response_code = "200"
    
    async def _send_webhook(self, notification: Notification):
        """إرسال إشعار عبر Webhook عام"""
        
        webhook_urls = json.loads(notification.recipients) if notification.recipients else []
        
        if not webhook_urls and notification.recipient_groups:
            webhook_urls = self._get_recipients_from_groups(
                json.loads(notification.recipient_groups),
                NotificationChannel.WEBHOOK
            )
        
        if not webhook_urls:
            raise ValueError("No webhook URLs specified")
        
        payload = {
            "title": notification.title,
            "message": notification.message,
            "priority": notification.priority,
            "channel": notification.channel,
            "timestamp": datetime.utcnow().isoformat(),
            "incident_id": notification.incident_id,
            "rule_id": notification.rule_id,
            "event_data": json.loads(notification.event_data) if notification.event_data else None
        }
        
        async with aiohttp.ClientSession() as session:
            for webhook_url in webhook_urls:
                async with session.post(webhook_url, json=payload) as response:
                    if response.status not in [200, 201, 202, 204]:
                        raise Exception(f"Webhook returned status {response.status}")
        
        notification.response_code = "200"
    
    async def _send_sms(self, notification: Notification):
        """إرسال إشعار SMS (يتطلب تكامل مع مزود خدمة)"""
        # تطبيق افتراضي - يحتاج لتكامل مع Twilio أو غيره
        print(f"[SMS] Would send to: {notification.recipients}")
        print(f"[SMS] Message: {notification.message}")
        notification.response_code = "SIMULATED"
    
    async def _send_syslog(self, notification: Notification):
        """إرسال إشعار إلى Syslog"""
        # تطبيق افتراضي - يحتاج لتكامل مع syslog server
        syslog_config = self.config.get("syslog", {})
        print(f"[SYSLOG] {notification.priority.upper()}: {notification.title} - {notification.message}")
        notification.response_code = "SIMULATED"
    
    def _get_recipients_from_groups(self, groups: List[str], channel: NotificationChannel) -> List[str]:
        """الحصول على المستلمين من المجموعات"""
        
        recipients = []
        recipients_query = self.db.query(NotificationRecipient).filter(
            NotificationRecipient.enabled == True,
            NotificationRecipient.groups != None
        )
        
        for recipient in recipients_query.all():
            recipient_groups = json.loads(recipient.groups) if recipient.groups else []
            if any(group in recipient_groups for group in groups):
                # التحقق من تفضيلات القناة
                channels = json.loads(recipient.channels) if recipient.channels else []
                if not channels or channel.value in channels:
                    if channel == NotificationChannel.EMAIL and recipient.email:
                        recipients.append(recipient.email)
                    elif channel == NotificationChannel.SLACK and recipient.slack_webhook:
                        recipients.append(recipient.slack_webhook)
                    elif channel == NotificationChannel.TEAMS and recipient.teams_webhook:
                        recipients.append(recipient.teams_webhook)
        
        return recipients
    
    def _generate_id(self) -> str:
        """توليد معرف فريد"""
        import uuid
        return str(uuid.uuid4())
    
    def get_notification_stats(self) -> NotificationStats:
        """الحصول على إحصائيات الإشعارات"""
        
        from sqlalchemy import func
        
        total_sent = self.db.query(Notification).filter(
            Notification.status == NotificationStatus.SENT.value
        ).count()
        
        total_failed = self.db.query(Notification).filter(
            Notification.status == NotificationStatus.FAILED.value
        ).count()
        
        by_channel_query = self.db.query(
            Notification.channel, func.count(Notification.id)
        ).group_by(Notification.channel).all()
        
        by_priority_query = self.db.query(
            Notification.priority, func.count(Notification.id)
        ).group_by(Notification.priority).all()
        
        avg_delivery = self.db.query(
            func.avg(Notification.sent_at - Notification.created_at)
        ).filter(
            Notification.sent_at != None
        ).scalar()
        
        return NotificationStats(
            total_sent=total_sent,
            total_failed=total_failed,
            by_channel={ch: cnt for ch, cnt in by_channel_query},
            by_priority={pr: cnt for pr, cnt in by_priority_query},
            avg_delivery_time_seconds=avg_delivery.total_seconds() if avg_delivery else 0.0
        )
