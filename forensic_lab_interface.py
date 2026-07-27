# اسم الملف: forensic_lab_interface.py
import streamlit as st
import os
import hashlib
import csv
import json
import time
from datetime import datetime
from PIL import Image
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

# --- استيراد مكتبات التحليل ---
try:
    import exifread
    EXIF_AVAILABLE = True
except ImportError:
    EXIF_AVAILABLE = False

try:
    import numpy as np
    import tensorflow as tf
    from tensorflow.keras.applications.mobilenet_v2 import MobileNetV2, preprocess_input, decode_predictions
    from tensorflow.keras.preprocessing import image
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False

# ==========================================
# إعدادات الصفحة والتصميم المرعب الاحترافي
# ==========================================
st.set_page_config(
    page_title="المختبر الجنائي الرقمي - Cyber Forensics Lab",
    page_icon="🔬",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ==========================================
# CSS مخصص لتصميم واجهة الاختراق المرعبة
# ==========================================
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap');
    
    /* الخلفية الرئيسية */
    .stApp {
        background: linear-gradient(135deg, #0a0a0a 0%, #1a0505 50%, #0f0f0f 100%);
        font-family: 'Share Tech Mono', monospace;
    }
    
    /* العنوان الرئيسي */
    h1, h2, h3 {
        color: #ff0000;
        text-shadow: 0 0 10px #ff0000, 0 0 20px #ff0000;
        animation: glow 2s ease-in-out infinite alternate;
    }
    
    @keyframes glow {
        from { text-shadow: 0 0 5px #ff0000, 0 0 10px #ff0000; }
        to { text-shadow: 0 0 20px #ff0000, 0 0 30px #ff0000, 0 0 40px #ff0000; }
    }
    
    /* الشريط الجانبي */
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #000000 0%, #1a0000 100%);
        border-right: 2px solid #ff0000;
    }
    
    /* الأزرار */
    .stButton > button {
        background: linear-gradient(45deg, #330000, #660000);
        color: #ff0000;
        border: 2px solid #ff0000;
        border-radius: 5px;
        font-weight: bold;
        box-shadow: 0 0 10px #ff0000;
        transition: all 0.3s;
    }
    
    .stButton > button:hover {
        background: linear-gradient(45deg, #660000, #990000);
        box-shadow: 0 0 20px #ff0000, 0 0 30px #ff0000;
        transform: scale(1.05);
    }
    
    /* صناديق المعلومات */
    .info-box {
        background: rgba(255, 0, 0, 0.1);
        border: 1px solid #ff0000;
        border-radius: 10px;
        padding: 20px;
        margin: 10px 0;
        box-shadow: 0 0 15px rgba(255, 0, 0, 0.3);
    }
    
    /* تأثيرات الترميز */
    .code-block {
        background: #000000;
        border: 1px solid #330000;
        border-radius: 5px;
        padding: 15px;
        font-family: 'Courier New', monospace;
        color: #00ff00;
        overflow-x: auto;
    }
    
    /* شريط التقدم المرعب */
    .stProgress > div > div {
        background: linear-gradient(90deg, #ff0000, #990000);
        box-shadow: 0 0 10px #ff0000;
    }
    
    /* الجداول */
    table {
        background: rgba(0, 0, 0, 0.8);
        border: 1px solid #ff0000;
        color: #ffcccc;
    }
    
    th {
        background: #330000;
        color: #ff0000;
        border: 1px solid #ff0000;
    }
    
    td {
        border: 1px solid #660000;
    }
    
    /* تحذيرات */
    .warning {
        background: rgba(255, 69, 0, 0.2);
        border-left: 4px solid #ff4500;
        padding: 15px;
        margin: 10px 0;
        animation: pulse 1.5s infinite;
    }
    
    @keyframes pulse {
        0% { opacity: 1; }
        50% { opacity: 0.7; }
        100% { opacity: 1; }
    }
    
    /* تأثيرات المسح الضوئي */
    .scanner {
        height: 2px;
        background: #ff0000;
        width: 100%;
        position: relative;
        animation: scan 2s linear infinite;
        box-shadow: 0 0 10px #ff0000;
    }
    
    @keyframes scan {
        0% { top: 0%; opacity: 0; }
        50% { opacity: 1; }
        100% { top: 100%; opacity: 0; }
    }
</style>
""", unsafe_allow_html=True)

# ==========================================
# دوال المساعدة للواجهة
# ==========================================
def create_scanner_effect():
    """إنشاء تأثير المسح الضوئي"""
    st.markdown('<div class="scanner"></div>', unsafe_allow_html=True)

def display_header():
    """عرض رأس الصفحة بتصميم مرعب"""
    col1, col2, col3 = st.columns([1, 3, 1])
    with col2:
        st.title("🔬 المختبر الجنائي الرقمي المتقدم")
        st.subheader("Digital Forensics Cyber Lab v3.0")
        st.markdown("---")
    
    # شريط حالة النظام
    status_col1, status_col2, status_col3, status_col4 = st.columns(4)
    with status_col1:
        st.metric("حالة النظام", "🟢 نشط", delta=None)
    with status_col2:
        st.metric("نمط التشغيل", "🔴 متقدم", delta=None)
    with status_col3:
        st.metric("مستوى الوصول", "🔓 ROOT", delta=None)
    with status_col4:
        st.metric("التشفير", "🔐 SHA-512", delta=None)

def display_warning_box(message, level="high"):
    """عرض صندوق تحذير بتصميم مرعب"""
    if level == "high":
        icon = "🚨"
        color = "#ff0000"
    elif level == "medium":
        icon = "⚠️"
        color = "#ff8800"
    else:
        icon = "ℹ️"
        color = "#00ff00"
    
    st.markdown(f"""
    <div class="warning" style="border-left-color: {color};">
        <strong>{icon}</strong> {message}
    </div>
    """, unsafe_allow_html=True)

def create_progress_bar_with_effects(progress, message):
    """إنشاء شريط تقدم مع تأثيرات بصرية"""
    progress_bar = st.progress(0)
    progress_text = st.empty()
    
    for i in range(progress):
        time.sleep(0.05)
        progress_bar.progress((i + 1) * (100 // progress))
        progress_text.text(f"{message}... {((i + 1) * (100 // progress))}%")
    
    time.sleep(0.3)
    progress_bar.empty()
    progress_text.empty()

# ==========================================
# الوظائف الأساسية للتحقيق الجنائي
# ==========================================

def calculate_all_hashes(file_path):
    """حساب جميع أنواع البصمات الرقمية للملف"""
    hashes = {
        'MD5': hashlib.md5(),
        'SHA1': hashlib.sha1(),
        'SHA256': hashlib.sha256(),
        'SHA512': hashlib.sha512()
    }
    
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                for hash_obj in hashes.values():
                    hash_obj.update(byte_block)
        
        return {name: hash_obj.hexdigest() for name, hash_obj in hashes.items()}
    except Exception as e:
        return {'Error': str(e)}

def run_hash_analysis(directory_path):
    """تحليل شامل للبصمات الرقمية"""
    results = []
    
    if not os.path.exists(directory_path):
        return None, "المسار غير موجود"
    
    total_files = sum(len(files) for _, _, files in os.walk(directory_path))
    processed = 0
    
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            file_size = os.path.getsize(file_path)
            file_type = file.split('.')[-1].upper() if '.' in file else 'UNKNOWN'
            modified_time = datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%Y-%m-%d %H:%M:%S')
            
            hashes = calculate_all_hashes(file_path)
            
            results.append({
                'File Name': file,
                'Path': file_path,
                'Size (Bytes)': file_size,
                'Type': file_type,
                'Modified': modified_time,
                **hashes
            })
            
            processed += 1
            progress = min(100, int((processed / total_files) * 100))
            progress_bar.progress(progress)
            status_text.text(f"جاري تحليل: {file} ({processed}/{total_files})")
    
    progress_bar.empty()
    status_text.empty()
    
    return results, None

def extract_exif_data(image_path):
    """استخراج بيانات EXIF من الصور"""
    if not EXIF_AVAILABLE:
        return {'Error': 'مكتبة exifread غير متوفرة'}
    
    try:
        with open(image_path, 'rb') as f:
            tags = exifread.process_file(f, details=False)
        
        exif_data = {}
        for tag in tags.keys():
            exif_data[str(tag)] = str(tags[tag])
        
        return exif_data
    except Exception as e:
        return {'Error': str(e)}

def analyze_image_ai(image_path, model):
    """تحليل الصورة بالذكاء الاصطناعي"""
    if not AI_AVAILABLE or model is None:
        return {'Error': 'الذكاء الاصطناعي غير متوفر'}
    
    try:
        img = image.load_img(image_path, target_size=(224, 224))
        img_array = image.img_to_array(img)
        img_array = np.expand_dims(img_array, axis=0)
        img_array = preprocess_input(img_array)
        
        predictions = model.predict(img_array, verbose=0)
        decoded = decode_predictions(predictions, top=5)[0]
        
        results = []
        for _, label, prob in decoded:
            results.append({
                'Label': label,
                'Probability': f"{prob*100:.2f}%",
                'Forensic_Relevance': 'HIGH' if any(kw in label.lower() for kw in ['screen', 'document', 'person', 'keyboard']) else 'LOW'
            })
        
        return results
    except Exception as e:
        return {'Error': str(e)}

def search_sensitive_data(directory_path, patterns=None):
    """البحث عن بيانات حساسة في الملفات"""
    if patterns is None:
        patterns = {
            'Email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'Phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
            'Credit_Card': r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',
            'IP_Address': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
            'Password_Pattern': r'(?:password|passwd|pwd)\s*[=:]\s*\S+'
        }
    
    import re
    results = []
    
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            if file.endswith(('.txt', '.log', '.csv', '.json', '.xml', '.ini', '.conf')):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    for pattern_name, pattern in patterns.items():
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        if matches:
                            results.append({
                                'File': file_path,
                                'Pattern_Type': pattern_name,
                                'Matches_Count': len(matches),
                                'Sample': matches[0][:50] + '...' if len(matches[0]) > 50 else matches[0]
                            })
                except Exception:
                    continue
    
    return results

# ==========================================
# واجهات الوحدات المختلفة
# ==========================================

def hash_integrity_module():
    """وحدة تحليل البصمات الرقمية"""
    st.header("🔐 وحدة البصمات الرقمية وسلسلة الحضانة")
    st.markdown('<div class="info-box">', unsafe_allow_html=True)
    st.write("""
    **الوظيفة:** حساب بصمات رقمية متعددة (MD5, SHA1, SHA256, SHA512) لجميع الملفات
    لضمان سلامة الأدلة وكشف أي تلاعب.
    
    **المخرجات:** تقرير CSV شامل مع طابع زمني وجميع أنواع الهاش.
    """)
    st.markdown('</div>', unsafe_allow_html=True)
    
    target_path = st.text_input("أدخل مسار المجلد المستهدف:", placeholder="C:\\Evidence\\Case_001")
    
    if st.button("🚀 بدء تحليل البصمات", use_container_width=True):
        if not target_path or not os.path.exists(target_path):
            display_warning_box("المسار المدخل غير صحيح أو غير موجود!", "high")
            return
        
        create_scanner_effect()
        create_progress_bar_with_effects(10, "جاري مسح الملفات وحساب البصمات")
        
        results, error = run_hash_analysis(target_path)
        
        if error:
            display_warning_box(error, "high")
            return
        
        if results:
            st.success(f"✅ تم تحليل {len(results)} ملف بنجاح!")
            
            # عرض النتائج كجدول
            df = pd.DataFrame(results)
            st.dataframe(df, use_container_width=True)
            
            # إحصائيات
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("إجمالي الملفات", len(results))
            with col2:
                total_size = sum(r['Size (Bytes)'] for r in results) / (1024*1024)
                st.metric("الحجم الإجمالي (MB)", f"{total_size:.2f}")
            with col3:
                unique_types = len(set(r['Type'] for r in results))
                st.metric("أنواع الملفات", unique_types)
            
            # تصدير التقرير
            csv_data = df.to_csv(index=False)
            st.download_button(
                label="📥 تحميل تقرير CSV",
                data=csv_data,
                file_name=f"Forensic_Hash_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                use_container_width=True
            )

def image_forensics_module():
    """وحدة تحليل الصور الجنائي"""
    st.header("🖼️ وحدة التحليل الجنائي للصور")
    st.markdown('<div class="info-box">', unsafe_allow_html=True)
    st.write("""
    **الوظيفة:** استخراج بيانات EXIF، تحليل المحتوى بالذكاء الاصطناعي، 
    وكشف مؤشرات التلاعب بالصور.
    
    **المميزات:** 
    - تحديد موقع GPS وتاريخ الالتقاط
    - كشف الأجهزة المستخدمة
    - تحليل محتوى الصورة وتحديد العناصر المشبوهة
    """)
    st.markdown('</div>', unsafe_allow_html=True)
    
    # تحميل نموذج الذكاء الاصطناعي
    model = None
    if AI_AVAILABLE:
        with st.spinner("🤖 جاري تحميل نموذج الذكاء الاصطناعي..."):
            try:
                model = MobileNetV2(weights='imagenet')
                st.success("✅ نموذج الذكاء الاصطناعي جاهز!")
            except Exception as e:
                st.error(f"فشل تحميل النموذج: {e}")
    
    upload_option = st.radio("اختر طريقة الإدخال:", ["رفع صورة", "مسار مجلد"])
    
    if upload_option == "رفع صورة":
        uploaded_file = st.file_uploader("اختر صورة للتحليل", type=['jpg', 'jpeg', 'png'])
        
        if uploaded_file and st.button("🔍 تحليل الصورة"):
            # حفظ الصورة المؤقتة
            temp_path = f"temp_{uploaded_file.name}"
            with open(temp_path, "wb") as f:
                f.write(uploaded_file.getbuffer())
            
            create_progress_bar_with_effects(5, "جاري تحليل الصورة")
            
            # تحليل EXIF
            st.subheader("📊 البيانات الوصفية (EXIF)")
            exif_data = extract_exif_data(temp_path)
            
            if 'Error' not in exif_data:
                col1, col2 = st.columns(2)
                with col1:
                    st.json(exif_data)
                with col2:
                    # عرض الصورة
                    image = Image.open(uploaded_file)
                    st.image(image, caption="الصورة المحللة", use_container_width=True)
            else:
                display_warning_box("لا توجد بيانات EXIF أو حدث خطأ", "medium")
            
            # تحليل الذكاء الاصطناعي
            if model:
                st.subheader("🤖 تحليل الذكاء الاصطناعي")
                ai_results = analyze_image_ai(temp_path, model)
                
                if 'Error' not in ai_results:
                    ai_df = pd.DataFrame(ai_results)
                    st.dataframe(ai_df, use_container_width=True)
                    
                    # تقييم مستوى الشك
                    high_relevance = sum(1 for r in ai_results if r.get('Forensic_Relevance') == 'HIGH')
                    if high_relevance >= 2:
                        display_warning_box(f"🚨 مؤشر شك عالي: تم رصد {high_relevance} عناصر مشبوهة!", "high")
                    elif high_relevance == 1:
                        display_warning_box("⚠️ مؤشر شك متوسط: عنصر مشبوه واحد تم رصده", "medium")
                    else:
                        st.success("✅ لا توجد مؤشرات شك عالية")
            
            # تنظيف
            os.remove(temp_path)
    
    else:
        folder_path = st.text_input("مسار مجلد الصور:", placeholder="C:\\Evidence\\Images")
        
        if st.button("🔍 فحص المجلد"):
            if not folder_path or not os.path.exists(folder_path):
                display_warning_box("المسار غير صحيح!", "high")
                return
            
            image_files = [f for f in os.listdir(folder_path) if f.lower().endswith(('.jpg', '.jpeg', '.png'))]
            
            if not image_files:
                display_warning_box("لم يتم العثور على صور في المجلد!", "medium")
                return
            
            create_progress_bar_with_effects(len(image_files), "جاري فحص الصور")
            
            results_summary = []
            
            for idx, img_file in enumerate(image_files):
                img_path = os.path.join(folder_path, img_file)
                
                exif_data = extract_exif_data(img_path)
                suspicion_score = 0
                
                # حساب مؤشر الشك
                if 'GPS' in str(exif_data):
                    suspicion_score += 2
                if 'DateTime' not in str(exif_data):
                    suspicion_score += 3
                
                ai_results = analyze_image_ai(img_path, model) if model else {}
                if isinstance(ai_results, list):
                    high_count = sum(1 for r in ai_results if r.get('Forensic_Relevance') == 'HIGH')
                    suspicion_score += high_count * 2
                
                results_summary.append({
                    'Image': img_file,
                    'Suspicion_Score': suspicion_score,
                    'Has_GPS': 'GPS' in str(exif_data),
                    'Has_Date': 'DateTime' in str(exif_data)
                })
            
            summary_df = pd.DataFrame(results_summary)
            st.dataframe(summary_df, use_container_width=True)
            
            # رسم بياني
            fig = px.bar(summary_df, x='Image', y='Suspicion_Score', 
                        title="مؤشر الشك لكل صورة",
                        color='Suspicion_Score',
                        color_continuous_scale='Reds')
            st.plotly_chart(fig, use_container_width=True)

def sensitive_data_module():
    """وحدة البحث عن البيانات الحساسة"""
    st.header("🔎 وحدة التنقيب عن البيانات الحساسة")
    st.markdown('<div class="info-box">', unsafe_allow_html=True)
    st.write("""
    **الوظيفة:** البحث عن أنماط حساسة مثل:
    - عناوين البريد الإلكتروني
    - أرقام الهواتف وبطاقات الائتمان
    - عناوين IP
    - كلمات المرور المخزنة
    
    **التقنية:** استخدام تعبيرات نمطية (Regex) متقدمة
    """)
    st.markdown('</div>', unsafe_allow_html=True)
    
    target_path = st.text_input("مسار المجلد للفحص:", placeholder="C:\\Evidence\\Documents")
    
    pattern_options = st.multiselect(
        "اختر الأنماط المطلوب البحث عنها:",
        ['Email', 'Phone', 'Credit_Card', 'IP_Address', 'Password_Pattern'],
        default=['Email', 'Phone']
    )
    
    if st.button("🚀 بدء البحث العميق"):
        if not target_path or not os.path.exists(target_path):
            display_warning_box("المسار غير صحيح!", "high")
            return
        
        create_scanner_effect()
        create_progress_bar_with_effects(15, "جاري فحص الملفات والبحث عن الأنماط")
        
        patterns = {}
        if 'Email' in pattern_options:
            patterns['Email'] = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        if 'Phone' in pattern_options:
            patterns['Phone'] = r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'
        if 'Credit_Card' in pattern_options:
            patterns['Credit_Card'] = r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b'
        if 'IP_Address' in pattern_options:
            patterns['IP_Address'] = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        if 'Password_Pattern' in pattern_options:
            patterns['Password_Pattern'] = r'(?:password|passwd|pwd)\s*[=:]\s*\S+'
        
        results = search_sensitive_data(target_path, patterns)
        
        if results:
            st.success(f"✅ تم العثور على {len(results)} نتيجة مشبوهة!")
            
            df = pd.DataFrame(results)
            st.dataframe(df, use_container_width=True)
            
            # إحصائيات
            pattern_counts = df['Pattern_Type'].value_counts()
            fig = px.pie(values=pattern_counts.values, names=pattern_counts.index,
                        title="توزيع الأنماط المكتشفة")
            st.plotly_chart(fig, use_container_width=True)
            
            # تصدير
            json_data = json.dumps(results, indent=2, ensure_ascii=False)
            st.download_button(
                label="📥 تحميل تقرير JSON",
                data=json_data,
                file_name=f"Sensitive_Data_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json",
                use_container_width=True
            )
        else:
            st.info("ℹ️ لم يتم العثور على بيانات حساسة في المجلد المحدد")

def timeline_analysis_module():
    """وحدة بناء الخط الزمني للأحداث"""
    st.header("⏳ وحدة التحليل الزمني وإعادة البناء")
    st.markdown('<div class="info-box">', unsafe_allow_html=True)
    st.write("""
    **الوظيفة:** بناء خط زمني شامل لأحداث النظام والملفات
    لإعادة بناء سيناريو الحادث وتحديد تسلسل الأحداث.
    
    **المخرجات:** جدول زمني تفاعلي مع رسوم بيانية
    """)
    st.markdown('</div>', unsafe_allow_html=True)
    
    target_path = st.text_input("مسار المجلد للتحليل الزمني:")
    
    if st.button("🕐 بناء الخط الزمني"):
        if not target_path or not os.path.exists(target_path):
            display_warning_box("المسار غير صحيح!", "high")
            return
        
        create_progress_bar_with_effects(10, "جاري جمع البيانات الزمنية")
        
        events = []
        for root, dirs, files in os.walk(target_path):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    stat = os.stat(file_path)
                    events.extend([
                        {'Time': datetime.fromtimestamp(stat.st_ctime).strftime('%Y-%m-%d %H:%M:%S'),
                         'Event': 'تم الإنشاء', 'File': file, 'Type': 'CREATE'},
                        {'Time': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                         'Event': 'تم التعديل', 'File': file, 'Type': 'MODIFY'},
                        {'Time': datetime.fromtimestamp(stat.st_atime).strftime('%Y-%m-%d %H:%M:%S'),
                         'Event': 'تم الوصول', 'File': file, 'Type': 'ACCESS'}
                    ])
                except Exception:
                    continue
        
        if events:
            df = pd.DataFrame(events)
            df = df.sort_values('Time')
            
            st.subheader("📅 الجدول الزمني للأحداث")
            st.dataframe(df, use_container_width=True)
            
            # رسم بياني زمني
            fig = px.scatter(df, x='Time', y='File', color='Type',
                           title="الخط الزمني للتفاعلات مع الملفات",
                           size_max=10)
            st.plotly_chart(fig, use_container_width=True)
            
            # إحصائيات
            col1, col2, col3 = st.columns(3)
            with col1:
                creates = len(df[df['Type'] == 'CREATE'])
                st.metric("ملفات تم إنشاؤها", creates)
            with col2:
                modifies = len(df[df['Type'] == 'MODIFY'])
                st.metric("ملفات تم تعديلها", modifies)
            with col3:
                accesses = len(df[df['Type'] == 'ACCESS'])
                st.metric("عمليات وصول", accesses)

def main():
    """الوظيفة الرئيسية للتطبيق"""
    display_header()
    
    # القائمة الجانبية
    with st.sidebar:
        st.image("https://img.icons8.com/color/96/hacker.png", width=100)
        st.title("لوحة التحكم")
        
        menu_options = [
            "🏠 الرئيسية",
            "🔐 البصمات الرقمية",
            "🖼️ تحليل الصور",
            "🔎 البيانات الحساسة",
            "⏳ الخط الزمني",
            "📊 التقارير الشاملة",
            "⚙️ الإعدادات"
        ]
        
        choice = st.radio("اختر الوحدة:", menu_options)
        
        st.markdown("---")
        st.markdown("**حالة النظام:**")
        st.info(f"""
        - EXIF: {'✅ متاح' if EXIF_AVAILABLE else '❌ غير متاح'}
        - AI: {'✅ متاح' if AI_AVAILABLE else '❌ غير متاح'}
        - الوقت: {datetime.now().strftime('%H:%M:%S')}
        """)
        
        st.markdown("---")
        st.markdown("**معلومات الجلسة:**")
        st.success(f"جلسة آمنة بدأت: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    
    # عرض المحتوى حسب الاختيار
    if choice == "🏠 الرئيسية":
        st.header("مرحباً بك في المختبر الجنائي الرقمي")
        st.markdown("""
        ### 🎯 مهام الأداة:
        1. **حماية الأدلة**: حساب بصمات رقمية متعددة لضمان النزاهة
        2. **تحليل الصور**: استخراج EXIF وتحليل بالذكاء الاصطناعي
        3. **كشف البيانات**: البحث عن معلومات حساسة مخفية
        4. **إعادة البناء**: بناء خطوط زمنية للأحداث
        
        ### 🚀 ابدأ الآن:
        اختر أي وحدة من القائمة الجانبية لبدء التحقيق!
        """)
        
        # عرض إحصائيات سريعة
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("الوحدات المتاحة", "5")
        with col2:
            st.metric("دعم الصيغ", "20+")
        with col3:
            st.metric("خوارزميات", "8")
        with col4:
            st.metric("مستوى الأمان", "MAX")
    
    elif choice == "🔐 البصمات الرقمية":
        hash_integrity_module()
    
    elif choice == "🖼️ تحليل الصور":
        image_forensics_module()
    
    elif choice == "🔎 البيانات الحساسة":
        sensitive_data_module()
    
    elif choice == "⏳ الخط الزمني":
        timeline_analysis_module()
    
    elif choice == "📊 التقارير الشاملة":
        st.header("📈 مركز التقارير الشاملة")
        st.info("هذه الوحدة تقوم بتوليد تقارير PDF شاملة تجمع كل نتائج التحليلات السابقة.")
        st.warning("⚠️ قيد التطوير - ستكون متاحة في الإصدار القادم!")
    
    elif choice == "⚙️ الإعدادات":
        st.header("⚙️ إعدادات النظام")
        st.markdown("""
        ### خيارات التخصيص:
        - تغيير سمة الألوان
        - ضبط مستوى التفصيل في التقارير
        - إدارة نماذج الذكاء الاصطناعي
        - تكوين أنماط البحث المخصصة
        """)
        st.warning("⚠️ معظم الإعدادات تتطلب إعادة تشغيل التطبيق")

if __name__ == "__main__":
    main()