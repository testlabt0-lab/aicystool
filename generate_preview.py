"""
سكريبت لتوليد صورة تجريبية لواجهة أداة التحقيق الجنائي الرقمي.
يقوم هذا السكريبت برسم واجهة تحاكي تصميم Streamlit مع الثيم المرعب (Hacker/Cyber).
"""

from PIL import Image, ImageDraw, ImageFont
import os

def create_mockup():
    # إعدادات الصورة
    width = 1200
    height = 800
    bg_color = (10, 10, 15)  # أسود مزرق داكن جداً
    sidebar_color = (20, 20, 30)
    accent_red = (255, 50, 50)
    text_white = (240, 240, 240)
    text_gray = (150, 150, 160)
    terminal_green = (0, 255, 100)

    # إنشاء الصورة
    img = Image.new('RGB', (width, height), bg_color)
    draw = ImageDraw.Draw(img)

    # محاولة تحميل خط (استخدام خط افتراضي إذا لم يتوفر)
    try:
        # خطوط شائعة في ويندوز/لينكس قد تعمل
        font_title = ImageFont.truetype("arial.ttf", 32)
        font_body = ImageFont.truetype("consola.ttf", 18)
        font_small = ImageFont.truetype("arial.ttf", 14)
    except:
        font_title = ImageFont.load_default()
        font_body = ImageFont.load_default()
        font_small = ImageFont.load_default()

    # 1. رسم الشريط الجانبي (Sidebar)
    draw.rectangle([(0, 0), (250, height)], fill=sidebar_color)
    
    # عنوان القائمة الجانبية
    draw.text((20, 30), "🛡️ FORENSIC LAB", fill=accent_red, font=font_title)
    draw.line([(20, 70), (230, 70)], fill=accent_red, width=2)

    # عناصر القائمة
    menu_items = [
        "🏠 الرئيسية",
        "🔐 بصمات الملفات",
        "🖼️ تحليل الصور EXIF+AI",
        "🔎 بحث عن بيانات حساسة",
        "⏳ الخط الزمني للأحداث",
        "💾 تصدير التقارير",
        "⚙️ الإعدادات"
    ]
    
    y_offset = 100
    for item in menu_items:
        # تأثير الزر النشط
        if item == "🏠 الرئيسية":
            draw.rectangle([(10, y_offset-10), (240, y_offset+25)], fill=(40, 20, 20))
            draw.text((20, y_offset), item, fill=accent_red, font=font_body)
        else:
            draw.text((20, y_offset), item, fill=text_gray, font=font_body)
        y_offset += 50

    # حالة النظام في الأسفل
    draw.text((20, height - 100), "System Status:", fill=text_white, font=font_small)
    draw.text((20, height - 80), "● ONLINE", fill=terminal_green, font=font_body)
    draw.text((20, height - 60), "CPU: 12% | RAM: 4.2GB", fill=text_gray, font=font_small)

    # 2. المنطقة الرئيسية (Main Content)
    # العنوان الرئيسي
    main_title = "مختبر التحقيق الجنائي الرقمي"
    draw.text((280, 40), main_title, fill=text_white, font=font_title)
    
    sub_title = "Digital Forensics & Incident Response Toolkit"
    draw.text((280, 80), sub_title, fill=accent_red, font=font_small)

    # مربع التحذير (Alert Box)
    alert_x, alert_y = 280, 130
    alert_w, alert_h = 880, 60
    draw.rectangle([(alert_x, alert_y), (alert_x + alert_w, alert_y + alert_h)], outline=accent_red, width=2)
    draw.text((alert_x + 20, alert_y + 15), "⚠️ WARNING: UNAUTHORIZED ACCESS DETECTED IN SECTOR 7", fill=accent_red, font=font_body)

    # محاكاة منطقة رفع الملفات (Drop Zone)
    drop_x, drop_y = 280, 220
    drop_w, drop_h = 400, 200
    draw.rectangle([(drop_x, drop_y), (drop_x + drop_w, drop_y + drop_h)], outline=text_gray, width=2)
    draw.text((drop_x + 130, drop_y + 90), "اسحب الملفات هنا للفحص\nأو انقر للاختيار", fill=text_gray, font=font_body)

    # محاكاة شاشة终端 (Terminal Output)
    term_x, term_y = 700, 220
    term_w, term_h = 460, 200
    draw.rectangle([(term_x, term_y), (term_x + term_w, term_y + term_h)], fill=(0, 0, 0))
    draw.rectangle([(term_x, term_y), (term_x + term_w, term_y + term_h)], outline=terminal_green, width=1)
    
    terminal_lines = [
        "> Initializing core modules...",
        "> Loading AI models (MobileNetV2)... [OK]",
        "> Scanning directory C:\\Evidence\\Case_001",
        "> Found suspicious file: hidden_data.jpg",
        "> Calculating SHA256 Hash...",
        "> Match found in database! (Risk: HIGH)"
    ]
    
    for i, line in enumerate(terminal_lines):
        color = terminal_green if "HIGH" in line or "suspicious" in line else text_gray
        draw.text((term_x + 10, term_y + 10 + (i * 25)), line, fill=color, font=font_small)

    # رسوم بيانية وهمية (Charts Mockup)
    chart_x, chart_y = 280, 450
    chart_w, chart_h = 880, 250
    draw.rectangle([(chart_x, chart_y), (chart_x + chart_w, chart_y + chart_h)], fill=(15, 15, 20))
    draw.text((chart_x + 20, chart_y + 20), "تحليل توزيع أنواع الملفات المكتشفة", fill=text_white, font=font_body)
    
    # رسم أعمدة بسيطة
    bar_colors = [accent_red, (50, 100, 255), (50, 200, 50), (200, 200, 50)]
    bar_labels = ["Images", "Documents", "Logs", "Archives"]
    for i in range(4):
        bx = chart_x + 50 + (i * 200)
        by = chart_y + 180
        bh = 50 + (i * 30) # ارتفاع عشوائي
        draw.rectangle([(bx, by - bh), (bx + 150, by)], fill=bar_colors[i])
        draw.text((bx, by + 10), bar_labels[i], fill=text_white, font=font_small)

    # تأثيرات ضوئية (Glow Effect Simulation)
    # دائرة حمراء متوهجة في الزاوية
    draw.ellipse([(width-100, height-100), (width-20, height-20)], outline=accent_red, width=3)
    
    # حفظ الصورة
    filename = "forensic_lab_preview.png"
    img.save(filename)
    print(f"[+] تم توليد صورة المعاينة بنجاح: {filename}")
    print(f"[*] الموقع: {os.path.abspath(filename)}")

if __name__ == "__main__":
    create_mockup()