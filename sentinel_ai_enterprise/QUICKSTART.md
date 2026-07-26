# 🚀 دليل التشغيل السريع - Sentinel AI Enterprise

## المتطلبات الأساسية

### الحد الأدنى:
- CPU: 4 cores
- RAM: 8 GB
- Storage: 20 GB
- OS: Linux/macOS/Windows with WSL2

### الموصى به:
- CPU: 8+ cores
- RAM: 16+ GB
- Storage: 50+ GB SSD
- GPU: NVIDIA (اختياري لتسريع ML)

---

## طريقة 1: Docker (الأسهل)

```bash
# 1. استنساخ المشروع
cd /workspace/sentinel_ai_enterprise

# 2. نسخ ملف البيئة
cp .env.example .env

# 3. تشغيل النظام كاملاً
docker-compose up -d

# 4. التحقق من الحالة
docker-compose ps

# 5. عرض السجلات
docker-compose logs -f api

# 6. إيقاف النظام
docker-compose down
```

**المنافذ المفتوحة:**
- API: http://localhost:8000
- PostgreSQL: localhost:5432
- Redis: localhost:6379
- Prometheus: localhost:9090
- Grafana: localhost:3000

---

## طريقة 2: التشغيل المحلي (للتطوير)

### الخطوة 1: تثبيت Python والمكتبات

```bash
# تأكد من وجود Python 3.9+
python3 --version

# إنشاء بيئة افتراضية
python3 -m venv venv
source venv/bin/activate  # على Windows: venv\Scripts\activate

# تثبيت المكتبات
pip install -r requirements.txt
```

### الخطوة 2: إعداد قاعدة البيانات

```bash
# تثبيت PostgreSQL
# Ubuntu/Debian:
sudo apt-get install postgresql postgresql-contrib

# macOS:
brew install postgresql

# بدء الخدمة
sudo service postgresql start

# إنشاء قاعدة البيانات
sudo -u postgres psql
CREATE DATABASE sentinel_db;
CREATE USER sentinel_user WITH PASSWORD 'sentinel_pass';
GRANT ALL PRIVILEGES ON DATABASE sentinel_db TO sentinel_user;
\q
```

### الخطوة 3: إعداد Redis

```bash
# Ubuntu/Debian:
sudo apt-get install redis-server
sudo service redis-server start

# macOS:
brew install redis
brew services start redis
```

### الخطوة 4: تشغيل التطبيق

```bash
# تحميل المتغيرات البيئية
export $(cat .env | xargs)

# تشغيل الخادم
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

---

## اختبار النظام

### 1. فحص الصحة

```bash
curl http://localhost:8000/health
```

**الاستجابة المتوقعة:**
```json
{
  "status": "healthy",
  "version": "2.0.0",
  "engines": {...},
  "services": {...}
}
```

### 2. الحصول على Token

```bash
curl -X POST "http://localhost:8000/api/v1/auth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=admin123"
```

### 3. تجربة كشف DDoS

```bash
curl -X POST "http://localhost:8000/api/v1/ddos/detect" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "source_ip": "192.168.1.100",
    "destination_ip": "10.0.0.1",
    "packets_per_second": 50000,
    "bytes_per_second": 500000000,
    "protocol": "TCP"
  }'
```

### 4. تجربة كشف SQL Injection

```bash
curl -X POST "http://localhost:8000/api/v1/sqli/detect" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "SELECT * FROM users WHERE id=1 OR 1=1--",
    "source": "web_form"
  }'
```

---

## المستخدمون الافتراضيون

| Username | Password | Role |
|----------|----------|------|
| admin | admin123 | Admin |
| analyst | analyst123 | Analyst |
| operator | operator123 | Operator |

**⚠️ مهم:** غيّر كلمات المرور قبل الاستخدام الإنتاجي!

---

## الوصول للوثائق

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc
- **OpenAPI JSON**: http://localhost:8000/openapi.json

---

## حل المشاكل الشائعة

### المشكلة: Port 8000 مشغول

```bash
# ابحث عن العملية
lsof -i :8000

# أوقف العملية
kill -9 <PID>

# أو غيّر المنفذ
uvicorn app.main:app --port 8001
```

### المشكلة: خطأ في قاعدة البيانات

```bash
# تحقق من اتصال قاعدة البيانات
psql -h localhost -U sentinel_user -d sentinel_db

# أعد تعيين قاعدة البيانات
docker-compose down -v
docker-compose up -d db
```

### المشكلة: ذاكرة غير كافية

```bash
# قلل عدد workers
gunicorn app.main:app -w 2 -k uvicorn.workers.UvicornWorker

# أو زد مساحة swap
sudo fallocate -l 4G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

---

## الخطوات التالية

1. ✅ غيّر كلمات المرور الافتراضية
2. ✅ عدّل ملف `.env` حسب بيئتك
3. ✅ اضبط قواعد الجدار الناري
4. ✅ فعّل HTTPS للإنتاج
5. ✅ اضبط النسخ الاحتياطية التلقائية
6. ✅ راقب أداء النظام

---

## للحصول على المساعدة

- 📚 التوثيق الكامل: README.md
- 🐛 الإبلاغ عن مشاكل: GitHub Issues
- 💬 الدعم: support@sentinel.ai

**🎯 استمتع بحماية متقدمة بذكاء اصطناعي!**
