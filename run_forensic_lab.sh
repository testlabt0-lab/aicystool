#!/bin/bash
# ============================================
# سكريبت تشغيل المختبر الجنائي الرقمي
# Digital Forensics Cyber Lab Launcher
# ============================================

echo ""
echo "=============================================="
echo "     🔬 المختبر الجنائي الرقمي المتقدم 🔬"
echo "     Digital Forensics Cyber Lab v3.0"
echo "=============================================="
echo ""

# التحقق من تثبيت Python
if ! command -v python &> /dev/null; then
    echo "❌ خطأ: Python غير مثبت!"
    exit 1
fi

echo "✅ Python version: $(python --version)"
echo ""

# التحقق من تثبيت المتطلبات
echo "📦 جاري التحقق من المكتبات المطلوبة..."
python -c "import streamlit, PIL, exifread, pandas, plotly" 2>/dev/null

if [ $? -ne 0 ]; then
    echo "⚠️ بعض المكتبات غير مثبتة، جاري التثبيت..."
    pip install -q streamlit Pillow exifread pandas plotly
    echo "✅ تم تثبيت المكتبات بنجاح!"
else
    echo "✅ جميع المكتبات مثبتة!"
fi

echo ""
echo "=============================================="
echo "🚀 جاري تشغيل واجهة الويب..."
echo "=============================================="
echo ""
echo "📍 افتح المتصفح على: http://localhost:8501"
echo ""
echo "⌨️  لإيقاف التطبيق اضغط: Ctrl+C"
echo ""
echo "=============================================="
echo ""

# تشغيل Streamlit
streamlit run forensic_lab_interface.py --server.headless true --server.port 8501
