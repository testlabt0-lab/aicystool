# اسم الملف: integrated_forensic_toolkit.py
# أداة التحقيق الجنائي الرقمي المتقدمة - الإصدار 2.0
# Developed for Advanced Digital Forensics Investigations

import os
import sys
import hashlib
import csv
import json
import re
import struct
from datetime import datetime
from pathlib import Path
from collections import defaultdict

# --- التحقق من المكتبات الثانوية ---
try:
    import exifread
    EXIF_AVAILABLE = True
except ImportError:
    EXIF_AVAILABLE = False
    print("[!] تحذير: مكتبة exifread غير مثبتة.")

try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    print("[!] تحذير: مكتبة Pillow غير مثبتة.")

try:
    import numpy as np
    import tensorflow as tf
    from tensorflow.keras.applications.mobilenet_v2 import MobileNetV2, preprocess_input, decode_predictions
    from tensorflow.keras.preprocessing import image
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False
    print("[!] تحذير: مكتبات TensorFlow/Numpy غير مثبتة.")

try:
    import chardet
    CHARDET_AVAILABLE = True
except ImportError:
    CHARDET_AVAILABLE = False
    print("[!] تحذير: مكتبة chardet غير مثبتة.")


# ==========================================
# ثوابت وأعراف التحقيق الجنائي
# ==========================================
FORENSIC_SIGNATURES = {
    b'\xFF\xD8\xFF': 'JPEG',
    b'\x89PNG\r\n\x1a\n': 'PNG',
    b'GIF87a': 'GIF',
    b'GIF89a': 'GIF',
    b'%PDF': 'PDF',
    b'PK\x03\x04': 'ZIP/DOCX/XLSX',
    b'\xD0\xCF\x11\xE0': 'MSI/DOC/XLS',
    b'\x50\x4B\x05\x06': 'ZIP_EMPTY',
    b'\x7F\x45\x4C\x46': 'ELF_EXECUTABLE',
    b'MZ': 'WINDOWS_EXECUTABLE',
    b'\x00\x00\x00\x18\x66\x74\x79\x70': 'MP4',
    b'\x00\x00\x00\x1c\x66\x74\x79\x70': 'MP4_ALT',
    b'RIFF': 'AVI/WAV',
    b'\x1A\x45\xDF\xA3': 'MKV',
    b'ID3': 'MP3_ID3',
    b'\xFF\xFB': 'MP3',
    b'\x00\x00\x00\x20\x66\x74\x79\x70': 'M4A',
    b'SQLite format 3': 'SQLITE_DB',
    b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00': 'POSSIBLE_DELETED_DATA'
}

SENSITIVE_PATTERNS = [
    (r'\b\d{16}\b', 'Credit Card Number'),
    (r'\b\d{3}-\d{2}-\d{4}\b', 'SSN'),
    (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 'Email Address'),
    (r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', 'IP Address'),
    (r'\b(?:http|https|ftp)://[^\s]+', 'URL'),
    (r'\b[A-Za-z0-9]{32}\b', 'Possible Hash (MD5)'),
    (r'\b[A-Za-z0-9]{40}\b', 'Possible Hash (SHA1)'),
    (r'\b[A-Za-z0-9]{64}\b', 'Possible Hash (SHA256)'),
    (r'password\s*[:=]\s*\S+', 'Password in Clear Text'),
    (r'-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----', 'Private Key'),
]

TIMELINE_EVENTS = []


# ==========================================
# الوحدة 1: حساب البصمات الرقمية وسلسلة الحضانة
# ==========================================
def calculate_sha256(file_path):
    """حساب الـ Hash لكل ملف لضمان سلامة الأدلة"""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(8192), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        return f"Error: {e}"

def calculate_multiple_hashes(file_path):
    """حساب عدة خوارزميات تجزئة للمقارنة"""
    hashes = {}
    algorithms = {
        'MD5': hashlib.md5(),
        'SHA1': hashlib.sha1(),
        'SHA256': hashlib.sha256(),
        'SHA512': hashlib.sha512()
    }
    
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                for algo in algorithms.values():
                    algo.update(chunk)
        
        for name, algo in algorithms.items():
            hashes[name] = algo.hexdigest()
        
        return hashes
    except Exception as e:
        return {'Error': str(e)}

def get_file_metadata(file_path):
    """استخراج البيانات الوصفية الكاملة للملف"""
    try:
        stat_info = os.stat(file_path)
        metadata = {
            'file_name': os.path.basename(file_path),
            'file_path': file_path,
            'file_size': stat_info.st_size,
            'created_time': datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
            'modified_time': datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
            'accessed_time': datetime.fromtimestamp(stat_info.st_atime).isoformat(),
            'inode': stat_info.st_ino,
            'device': stat_info.st_dev,
            'permissions': oct(stat_info.st_mode)[-3:]
        }
        return metadata
    except Exception as e:
        return {'Error': str(e)}

def run_hash_integrity_checker(directory_path, output_csv="Forensic_Hash_Report.csv"):
    """مسح المجلد وتوليد تقرير CSV بحالة الملفات وبصماتها"""
    print(f"\n[*] بدء حساب البصمات الرقمية للمجلد: {directory_path}")
    
    if not os.path.exists(directory_path):
        print("[-] خطأ: المسار المرفق غير موجود.")
        return []

    results = []
    with open(output_csv, mode='w', newline='', encoding='utf-8') as csv_file:
        fieldnames = ['Timestamp', 'File Name', 'File Path', 'File Size', 
                     'MD5', 'SHA1', 'SHA256', 'SHA512', 'Created', 'Modified', 'Accessed']
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        
        file_count = 0
        error_count = 0
        
        for root, dirs, files in os.walk(directory_path):
            # استبعاد المجلدات النظامية
            dirs[:] = [d for d in dirs if d not in ['.git', '__pycache__', '$RECYCLE.BIN']]
            
            for file in files:
                file_path = os.path.join(root, file)
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                
                try:
                    hashes = calculate_multiple_hashes(file_path)
                    metadata = get_file_metadata(file_path)
                    
                    if 'Error' not in hashes and 'Error' not in metadata:
                        row = {
                            'Timestamp': timestamp,
                            'File Name': file,
                            'File Path': file_path,
                            'File Size': metadata['file_size'],
                            'MD5': hashes.get('MD5', 'N/A'),
                            'SHA1': hashes.get('SHA1', 'N/A'),
                            'SHA256': hashes.get('SHA256', 'N/A'),
                            'SHA512': hashes.get('SHA512', 'N/A'),
                            'Created': metadata['created_time'],
                            'Modified': metadata['modified_time'],
                            'Accessed': metadata['accessed_time']
                        }
                        writer.writerow(row)
                        results.append(row)
                        file_count += 1
                        print(f"[+] تم الفحص: {file} ({metadata['file_size']} bytes)")
                    else:
                        error_count += 1
                        print(f"[!] خطأ في معالجة: {file}")
                        
                except Exception as e:
                    error_count += 1
                    print(f"[!] استثناء في {file}: {str(e)}")
                
    print(f"\n[*] اكتملت العملية. تم فحص {file_count} ملفاً بنجاح، {error_count} أخطاء.")
    print(f"[*] تم حفظ التقرير في: {os.path.abspath(output_csv)}")
    return results


# ==========================================
# الوحدة 2: استخراج الملفات المحذوفة (File Carving)
# ==========================================
def carve_files_from_disk(image_path, output_dir="carved_files", min_size=512):
    """استخراج الملفات من صورة قرص أو ملف ثنائي بناءً على الترويسات"""
    print(f"\n[*] بدء عملية الاستخراج (Carving) من: {image_path}")
    
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    carved_count = 0
    
    try:
        with open(image_path, 'rb') as f:
            file_data = f.read()
        
        file_size = len(file_data)
        print(f"[*] حجم البيانات: {file_size} بايت")
        
        offset = 0
        while offset < file_size - 8:
            # البحث عن الترويسات المعروفة
            for signature, file_type in FORENSIC_SIGNATURES.items():
                sig_len = len(signature)
                if offset + sig_len <= file_size:
                    if file_data[offset:offset+sig_len] == signature:
                        # تحديد حجم الملف التقريبي
                        end_offset = find_file_end(file_data, offset, file_type)
                        if end_offset and (end_offset - offset) >= min_size:
                            carved_file_name = f"carved_{carved_count}_{file_type}_{offset}.bin"
                            carved_file_path = os.path.join(output_dir, carved_file_name)
                            
                            with open(carved_file_path, 'wb') as out_f:
                                out_f.write(file_data[offset:end_offset])
                            
                            print(f"[+] تم استخراج: {file_type} عند الإزاحة {offset} (الحجم: {end_offset-offset})")
                            carved_count += 1
                        
                        offset = end_offset if end_offset else offset + 1
                        break
            else:
                offset += 1
                
    except Exception as e:
        print(f"[!] خطأ في عملية الاستخراج: {e}")
    
    print(f"[*] تم استخراج {carved_count} ملفاً إلى المجلد: {output_dir}")
    return carved_count

def find_file_end(data, start_offset, file_type):
    """محاولة العثور على نهاية الملف بناءً على النوع"""
    # هذه دالة مبسطة - في الأدوات الاحترافية تستخدم خوارزميات أكثر تعقيداً
    max_search = min(len(data) - start_offset, 10 * 1024 * 1024)  # حد أقصى 10MB
    
    if file_type in ['JPEG']:
        # البحث عن علامة نهاية JPEG
        end_marker = b'\xFF\xD9'
        pos = data.find(end_marker, start_offset, start_offset + max_search)
        if pos != -1:
            return pos + 2
    
    elif file_type in ['PNG']:
        # البحث عن نهاية PNG
        end_marker = b'IEND\xae\x42\x60\x82'
        pos = data.find(end_marker, start_offset, start_offset + max_search)
        if pos != -1:
            return pos + 8
    
    elif file_type in ['PDF']:
        # البحث عن نهاية PDF
        end_marker = b'%%EOF'
        pos = data.find(end_marker, start_offset, start_offset + max_search)
        if pos != -1:
            return pos + 5
    
    # إذا لم يتم العثور على نهاية محددة، نعود بحجم افتراضي
    return start_offset + min(max_search, 1024 * 1024)  # 1MB كحد أقصى افتراضي


# ==========================================
# الوحدة 3: تحليل السجلات والأنظمة (Log Analysis)
# ==========================================
def analyze_log_file(log_path):
    """تحليل ملفات السجل للكشف عن أنشطة مشبوهة"""
    print(f"\n[*] جاري تحليل ملف السجل: {log_path}")
    
    suspicious_patterns = [
        (r'failed|failure|error|denied|unauthorized', 'Security Event'),
        (r'login|authentication|password', 'Authentication Event'),
        (r'delete|remove|erase|format', 'Data Destruction Event'),
        (r'admin|root|sudo|privilege', 'Privilege Escalation'),
        (r'firewall|blocked|intrusion|attack', 'Network Security Event'),
        (r'shutdown|reboot|restart', 'System State Change'),
    ]
    
    events = []
    timeline = []
    
    try:
        # محاولة كشف الترميز
        if CHARDET_AVAILABLE:
            with open(log_path, 'rb') as f:
                detected = chardet.detect(f.read(10000))
                encoding = detected['encoding'] or 'utf-8'
        else:
            encoding = 'utf-8'
        
        with open(log_path, 'r', encoding=encoding, errors='ignore') as f:
            lines = f.readlines()
        
        print(f"[*] عدد الأسطر التي تم تحليلها: {len(lines)}")
        
        for line_num, line in enumerate(lines, 1):
            line_lower = line.lower()
            
            for pattern, event_type in suspicious_patterns:
                if re.search(pattern, line_lower):
                    event = {
                        'line_number': line_num,
                        'event_type': event_type,
                        'content': line.strip()[:200],  # اقتطاع للأسطر الطويلة
                        'timestamp': extract_timestamp_from_line(line)
                    }
                    events.append(event)
                    
                    # إضافة للخط الزمني
                    if event['timestamp']:
                        timeline.append({
                            'timestamp': event['timestamp'],
                            'event': f"{event_type}: {event['content'][:100]}"
                        })
        
        # فرز الخط الزمني
        timeline.sort(key=lambda x: x['timestamp'] if x['timestamp'] else '')
        
        print(f"[+] تم رصد {len(events)} حدثاً مشبوهاً")
        if timeline:
            print(f"[+] تم بناء خط زمني بـ {len(timeline)} حدثاً مؤرخاً")
        
        return {'events': events, 'timeline': timeline}
        
    except Exception as e:
        print(f"[!] خطأ في تحليل السجل: {e}")
        return {'events': [], 'timeline': []}

def extract_timestamp_from_line(line):
    """محاولة استخراج طابع زمني من سجل النص"""
    # أنماط شائعة للطوابع الزمنية
    patterns = [
        r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}',
        r'\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}',
        r'\w{3} \d{1,2} \d{2}:\d{2}:\d{2}',
        r'\d{1,2}-\w{3}-\d{4} \d{2}:\d{2}:\d{2}'
    ]
    
    for pattern in patterns:
        match = re.search(pattern, line)
        if match:
            return match.group(0)
    
    return None


# ==========================================
# الوحدة 4: البحث المتقدم عن الأنماط الحساسة
# ==========================================
def search_sensitive_patterns(directory_path, output_file="sensitive_data_report.json"):
    """البحث عن بيانات حساسة في الملفات النصية"""
    print(f"\n[*] بدء البحث عن بيانات حساسة في: {directory_path}")
    
    if not os.path.exists(directory_path):
        print("[-] خطأ: المسار غير موجود.")
        return []
    
    results = []
    files_scanned = 0
    matches_found = 0
    
    text_extensions = ['.txt', '.log', '.csv', '.xml', '.json', '.html', '.htm', 
                      '.md', '.rtf', '.doc', '.docx', '.pdf', '.eml', '.msg']
    
    for root, dirs, files in os.walk(directory_path):
        # تخطي المجلدات المؤقتة
        dirs[:] = [d for d in dirs if d not in ['.git', '__pycache__', 'node_modules']]
        
        for file in files:
            file_path = os.path.join(root, file)
            file_ext = os.path.splitext(file)[1].lower()
            
            # فحص الملفات النصية وملفات معينة
            if file_ext in text_extensions or file_ext == '':
                try:
                    files_scanned += 1
                    
                    # قراءة المحتوى
                    if CHARDET_AVAILABLE:
                        with open(file_path, 'rb') as f:
                            detected = chardet.detect(f.read(10000))
                            encoding = detected['encoding'] or 'utf-8'
                    else:
                        encoding = 'utf-8'
                    
                    with open(file_path, 'r', encoding=encoding, errors='ignore') as f:
                        content = f.read()
                    
                    file_matches = []
                    
                    # البحث عن الأنماط
                    for pattern, pattern_name in SENSITIVE_PATTERNS:
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        if matches:
                            for match in matches[:10]:  # حد أقصى 10 مطابقات لكل نمط
                                file_matches.append({
                                    'type': pattern_name,
                                    'value': match,
                                    'context': content[max(0, content.find(match)-50):content.find(match)+50]
                                })
                                matches_found += 1
                    
                    if file_matches:
                        results.append({
                            'file_path': file_path,
                            'file_name': file,
                            'matches': file_matches
                        })
                        print(f"[+] تم العثور على {len(file_matches)} بيانات حساسة في: {file}")
                
                except Exception as e:
                    print(f"[!] خطأ في فحص {file}: {e}")
    
    # حفظ التقرير
    report = {
        'scan_timestamp': datetime.now().isoformat(),
        'directory_scanned': directory_path,
        'files_scanned': files_scanned,
        'total_matches': matches_found,
        'findings': results
    }
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    
    print(f"\n[*] اكتمل المسح. تم فحص {files_scanned} ملفاً، والعثور على {matches_found} بيانات حساسة.")
    print(f"[*] تم حفظ التقرير في: {output_file}")
    
    return report


# ==========================================
# الوحدة 5: كشف التلاعب والتعديلات (Tampering Detection)
# ==========================================
def detect_tampering_indicators(file_path):
    """الكشف عن مؤشرات التلاعب بالملفات"""
    print(f"\n[*] جاري فحص مؤشرات التلاعب: {os.path.basename(file_path)}")
    
    indicators = []
    suspicion_score = 0
    
    try:
        # 1. فحص تناقض التواريخ
        metadata = get_file_metadata(file_path)
        if 'Error' not in metadata:
            created = datetime.fromisoformat(metadata['created_time'])
            modified = datetime.fromisoformat(metadata['modified_time'])
            accessed = datetime.fromisoformat(metadata['accessed_time'])
            
            if modified < created:
                indicators.append({
                    'type': 'TIMESTAMP_ANOMALY',
                    'description': 'تاريخ التعديل أقدم من تاريخ الإنشاء',
                    'severity': 'HIGH'
                })
                suspicion_score += 3
            
            if accessed < created:
                indicators.append({
                    'type': 'TIMESTAMP_ANOMALY',
                    'description': 'تاريخ الوصول أقدم من تاريخ الإنشاء',
                    'severity': 'MEDIUM'
                })
                suspicion_score += 2
        
        # 2. فحص تناقض الترويسة مع الامتداد
        with open(file_path, 'rb') as f:
            header = f.read(16)
        
        file_ext = os.path.splitext(file_path)[1].lower()
        detected_type = None
        
        for signature, file_type in FORENSIC_SIGNATURES.items():
            if header.startswith(signature):
                detected_type = file_type
                break
        
        extension_mapping = {
            '.jpg': ['JPEG'],
            '.jpeg': ['JPEG'],
            '.png': ['PNG'],
            '.gif': ['GIF'],
            '.pdf': ['PDF'],
            '.zip': ['ZIP/DOCX/XLSX', 'ZIP_EMPTY'],
            '.docx': ['ZIP/DOCX/XLSX'],
            '.xlsx': ['ZIP/DOCX/XLSX'],
            '.doc': ['MSI/DOC/XLS'],
            '.xls': ['MSI/DOC/XLS'],
            '.exe': ['WINDOWS_EXECUTABLE'],
            '.elf': ['ELF_EXECUTABLE'],
            '.mp4': ['MP4', 'MP4_ALT'],
            '.avi': ['AVI/WAV'],
            '.mp3': ['MP3_ID3', 'MP3'],
        }
        
        expected_types = extension_mapping.get(file_ext, [])
        if expected_types and detected_type and detected_type not in expected_types:
            indicators.append({
                'type': 'HEADER_MISMATCH',
                'description': f'الترويسة تشير إلى {detected_type} لكن الامتداد هو {file_ext}',
                'severity': 'CRITICAL'
            })
            suspicion_score += 4
        
        # 3. فحص وجود بيانات مخفية بعد نهاية الملف
        file_size = os.path.getsize(file_path)
        with open(file_path, 'rb') as f:
            f.seek(0, 2)  # الذهاب لنهاية الملف
            f.seek(max(0, f.tell() - 1024))  # العودة 1024 بايت
            tail_data = f.read()
        
        # البحث عن ترويسات ملفات في نهاية الملف الحالي
        for signature, file_type in FORENSIC_SIGNATURES.items():
            if signature in tail_data and len(signature) > 3:
                indicators.append({
                    'type': 'APPENDED_DATA',
                    'description': f'تم العثور على ترويسة {file_type} في نهاية الملف',
                    'severity': 'MEDIUM'
                })
                suspicion_score += 2
                break
        
        # 4. فحص الأحجام غير الطبيعية
        if file_size == 0:
            indicators.append({
                'type': 'EMPTY_FILE',
                'description': 'الملف فارغ تماماً',
                'severity': 'LOW'
            })
            suspicion_score += 1
        elif file_size > 10 * 1024 * 1024 * 1024:  # أكبر من 10GB
            indicators.append({
                'type': 'UNUSUAL_SIZE',
                'description': 'حجم الملف كبير جداً (>10GB)',
                'severity': 'LOW'
            })
            suspicion_score += 1
        
    except Exception as e:
        indicators.append({
            'type': 'ANALYSIS_ERROR',
            'description': f'خطأ في التحليل: {str(e)}',
            'severity': 'UNKNOWN'
        })
    
    result = {
        'file_path': file_path,
        'indicators': indicators,
        'suspicion_score': suspicion_score,
        'verdict': 'SUSPICIOUS' if suspicion_score >= 5 else 'NORMAL'
    }
    
    print(f"🚨 مؤشر الشك: {suspicion_score}/10 - الحكم: {result['verdict']}")
    for indicator in indicators:
        print(f"   - [{indicator['severity']}] {indicator['description']}")
    
    return result


# ==========================================
# الوحدة 6: تحليل الصور المتقدم (EXIF + AI + Steganography)
# ==========================================
def load_ai_model():
    """تحميل نموذج الذكاء الاصطناعي"""
    if AI_AVAILABLE:
        print("[*] جاري تحميل نموذج MobileNetV2...")
        return MobileNetV2(weights='imagenet')
    return None

def analyze_image_content(img_path, model):
    """تحليل محتوى الصورة بالذكاء الاصطناعي"""
    if not AI_AVAILABLE or not model:
        return ["الذكاء الاصطناعي غير متاح"]
    
    try:
        img = image.load_img(img_path, target_size=(224, 224))
        img_array = image.img_to_array(img)
        img_array = np.expand_dims(img_array, axis=0)
        img_array = preprocess_input(img_array)

        predictions = model.predict(img_array, verbose=0)
        decoded = decode_predictions(predictions, top=5)[0]
        
        forensic_keywords = ['monitor', 'laptop', 'screen', 'document', 'book', 
                           'keyboard', 'person', 'cellular', 'telephone', 'computer']
        flags = []
        
        for _, label, prob in decoded:
            confidence = prob * 100
            flag_entry = f"{label} ({confidence:.1f}%)"
            
            if any(keyword in label.lower() for keyword in forensic_keywords):
                flag_entry += " ⚠️ ذو أهمية جنائية"
            
            flags.append(flag_entry)
        
        return flags
    except Exception as e:
        return [f"فشل التحليل: {e}"]

def detect_steganography_indicators(image_path):
    """كشف مؤشرات إخفاء البيانات في الصور"""
    indicators = []
    
    if not PIL_AVAILABLE:
        return [{"type": "LIBRARY_MISSING", "description": "مكتبة Pillow غير متوفرة"}]
    
    try:
        with Image.open(image_path) as img:
            width, height = img.size
            file_size = os.path.getsize(image_path)
            
            # 1. فحص نسبة الضغط
            expected_size = width * height * 3  # RGB تقريبي
            compression_ratio = file_size / expected_size if expected_size > 0 else 0
            
            if compression_ratio > 0.95:  # ضغط منخفض جداً
                indicators.append({
                    'type': 'LOW_COMPRESSION',
                    'description': 'نسبة الضغط منخفضة جداً (قد تشير لبيانات مخفية)',
                    'severity': 'MEDIUM'
                })
            
            # 2. فحص الأبعاد غير القياسية
            if width % 8 != 0 or height % 8 != 0:
                indicators.append({
                    'type': 'NON_STANDARD_DIMENSIONS',
                    'description': 'أبعاد الصورة ليست من مضاعفات 8 (غير قياسي)',
                    'severity': 'LOW'
                })
            
            # 3. فحص وجود قنوات ألفا غير ضرورية
            if img.mode in ['RGBA', 'LA'] and file_size > expected_size * 1.1:
                indicators.append({
                    'type': 'UNNECESSARY_ALPHA_CHANNEL',
                    'description': 'وجود قناة شفافية مع حجم ملف كبير',
                    'severity': 'MEDIUM'
                })
            
            # 4. تحليل الضوضاء في البتات الأقل أهمية (LSB) - مبسط
            if img.mode == 'RGB':
                pixels = list(img.getdata())
                if len(pixels) > 1000:
                    # عينة عشوائية
                    sample_pixels = pixels[::len(pixels)//100]
                    lsb_sum = sum(sum(pixel) % 2 for pixel in sample_pixels)
                    expected_lsb = len(sample_pixels) * 1.5  # متوسط متوقع
                    
                    if abs(lsb_sum - expected_lsb) > expected_lsb * 0.3:
                        indicators.append({
                            'type': 'LSB_ANOMALY',
                            'description': 'توزيع غير طبيعي في البتات الأقل أهمية',
                            'severity': 'HIGH'
                        })
    
    except Exception as e:
        indicators.append({
            'type': 'ANALYSIS_ERROR',
            'description': f'خطأ: {str(e)}',
            'severity': 'UNKNOWN'
        })
    
    return indicators

def extract_exif_and_analyze(image_path, model=None):
    """تحليل شامل للصور"""
    print(f"\n{'='*60}")
    print(f"📷 التحليل الجنائي للصورة: {os.path.basename(image_path)}")
    print(f"{'='*60}")
    
    suspicion_score = 0
    analysis_result = {
        'file_path': image_path,
        'exif_data': {},
        'ai_analysis': [],
        'steganography_indicators': [],
        'tampering_indicators': [],
        'overall_score': 0
    }
    
    # 1. تحليل EXIF
    if EXIF_AVAILABLE:
        try:
            with open(image_path, 'rb') as f:
                tags = exifread.process_file(f, details=False)
            
            exif_data = {}
            important_tags = ['EXIF DateTimeOriginal', 'Image Model', 'Image Make', 
                             'GPS GPSLatitude', 'GPS GPSLongitude', 'EXIF Software',
                             'Image DateTime', 'EXIF UserComment']
            
            for tag in important_tags:
                value = str(tags.get(tag, 'غير متوفر'))
                if value != 'غير متوفر':
                    exif_data[tag] = value
                    print(f"✓ {tag}: {value}")
            
            analysis_result['exif_data'] = exif_data
            
            # تقييم الشك بناءً على EXIF
            if 'GPS GPSLatitude' not in exif_data or 'GPS GPSLongitude' not in exif_data:
                print("⚠️ لا توجد إحداثيات GPS")
                suspicion_score += 1
            
            if 'EXIF DateTimeOriginal' not in exif_data:
                print("⚠️ لا يوجد تاريخ التقاط أصلي")
                suspicion_score += 2
            
            if 'EXIF Software' in exif_data:
                software = exif_data['EXIF Software'].lower()
                if any(edit in software for edit in ['photoshop', 'gimp', 'paint']):
                    print(f"⚠️ تم التعديل بواسطة: {exif_data['EXIF Software']}")
                    suspicion_score += 3
            
        except Exception as e:
            print(f"[!] خطأ في EXIF: {e}")
            suspicion_score += 2
    else:
        print("[!] EXIF غير متاح")
    
    # 2. تحليل الذكاء الاصطناعي
    print("\n🤖 تحليل المحتوى:")
    ai_results = analyze_image_content(image_path, model)
    analysis_result['ai_analysis'] = ai_results
    for result in ai_results:
        print(f"   - {result}")
        if '⚠️' in result:
            suspicion_score += 1
    
    # 3. كشف الستيجانوجرافي
    print("\n🔍 فحص إخفاء البيانات:")
    steg_indicators = detect_steganography_indicators(image_path)
    analysis_result['steganography_indicators'] = steg_indicators
    for indicator in steg_indicators:
        severity = indicator.get('severity', 'UNKNOWN')
        desc = indicator.get('description', 'غير معروف')
        print(f"   - [{severity}] {desc}")
        if severity == 'HIGH':
            suspicion_score += 3
        elif severity == 'MEDIUM':
            suspicion_score += 2
        elif severity == 'LOW':
            suspicion_score += 1
    
    # 4. فحص التلاعب
    tampering_result = detect_tampering_indicators(image_path)
    analysis_result['tampering_indicators'] = tampering_result['indicators']
    suspicion_score += tampering_result['suspicion_score']
    
    # النتيجة النهائية
    analysis_result['overall_score'] = suspicion_score
    max_score = 15  # الحد الأقصى المتوقع
    
    print(f"\n{'='*60}")
    print(f"🚨 مؤشر الشك الجنائي الشامل: {suspicion_score}/{max_score}")
    
    if suspicion_score >= 8:
        print("🔴 التوصية: أولوية قصوى - تتطلب تحليلاً عميقاً فورياً")
    elif suspicion_score >= 5:
        print("🟠 التوصية: أولوية عالية - تحتاج مراجعة مفصلة")
    elif suspicion_score >= 3:
        print("🟡 التوصية: أولوية متوسطة - فحص إضافي مستحسن")
    else:
        print("🟢 التوصية: أولوية منخفضة - أرشفة روتينية")
    
    print(f"{'='*60}\n")
    
    return analysis_result


# ==========================================
# الوحدة 7: بناء الخط الزمني للأحداث (Timeline Reconstruction)
# ==========================================
def build_timeline(directory_path, output_file="forensic_timeline.json"):
    """إعادة بناء الخط الزمني للأحداث من الملفات"""
    print(f"\n[*] جاري بناء الخط الزمني للمجلد: {directory_path}")
    
    if not os.path.exists(directory_path):
        print("[-] المسار غير موجود.")
        return []
    
    timeline_events = []
    
    for root, dirs, files in os.walk(directory_path):
        dirs[:] = [d for d in dirs if d not in ['.git', '__pycache__']]
        
        for file in files:
            file_path = os.path.join(root, file)
            
            try:
                stat_info = os.stat(file_path)
                
                # حدث الإنشاء
                timeline_events.append({
                    'timestamp': datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
                    'event_type': 'FILE_CREATED',
                    'file_path': file_path,
                    'file_name': file,
                    'details': f'تم إنشاء الملف'
                })
                
                # حدث التعديل
                timeline_events.append({
                    'timestamp': datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
                    'event_type': 'FILE_MODIFIED',
                    'file_path': file_path,
                    'file_name': file,
                    'details': f'تم تعديل الملف'
                })
                
                # حدث الوصول
                timeline_events.append({
                    'timestamp': datetime.fromtimestamp(stat_info.st_atime).isoformat(),
                    'event_type': 'FILE_ACCESSED',
                    'file_path': file_path,
                    'file_name': file,
                    'details': f'تم الوصول للملف'
                })
                
            except Exception as e:
                print(f"[!] خطأ في {file}: {e}")
    
    # الفرز حسب الزمن
    timeline_events.sort(key=lambda x: x['timestamp'])
    
    # حفظ التقرير
    report = {
        'generated_at': datetime.now().isoformat(),
        'source_directory': directory_path,
        'total_events': len(timeline_events),
        'events': timeline_events
    }
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    
    print(f"[+] تم بناء الخط الزمني: {len(timeline_events)} حدثاً")
    print(f"[*] تم الحفظ في: {output_file}")
    
    # عرض ملخص
    print("\n📅 آخر 10 أحداث:")
    for event in timeline_events[-10:]:
        print(f"   {event['timestamp']} - {event['event_type']}: {event['file_name']}")
    
    return report


# ==========================================
# الوحدة 8: توليد التقرير الجنائي الشامل
# ==========================================
def generate_comprehensive_report(case_name, evidence_path, output_dir="forensic_reports"):
    """توليد تقرير جنائي شامل"""
    print(f"\n{'='*70}")
    print(f"📋 جاري توليد التقرير الجنائي الشامل للقضية: {case_name}")
    print(f"{'='*70}")
    
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = os.path.join(output_dir, f"Report_{case_name}_{timestamp}.json")
    
    report = {
        'case_metadata': {
            'case_name': case_name,
            'examiner': 'Digital Forensics Toolkit v2.0',
            'examination_date': datetime.now().isoformat(),
            'evidence_path': evidence_path,
            'tool_version': '2.0',
            'hash_algorithm': 'SHA-256'
        },
        'executive_summary': {},
        'hash_analysis': [],
        'image_analysis': [],
        'tampering_detection': [],
        'sensitive_data_findings': [],
        'timeline_reconstruction': [],
        'carved_files': [],
        'recommendations': []
    }
    
    # 1. تحليل البصمات
    print("\n[1/6] جاري تحليل البصمات الرقمية...")
    hash_results = run_hash_integrity_checker(evidence_path, 
                                              os.path.join(output_dir, "hash_report.csv"))
    report['hash_analysis'] = hash_results[:100]  # حد أقصى 100 ملف
    
    # 2. تحليل الصور
    print("\n[2/6] جاري تحليل الصور...")
    if os.path.isdir(evidence_path):
        for filename in os.listdir(evidence_path):
            if filename.lower().endswith(('.jpg', '.jpeg', '.png')):
                file_path = os.path.join(evidence_path, filename)
                img_analysis = extract_exif_and_analyze(file_path)
                report['image_analysis'].append(img_analysis)
    
    # 3. كشف التلاعب
    print("\n[3/6] جاري فحص مؤشرات التلاعب...")
    if os.path.isfile(evidence_path):
        tampering = detect_tampering_indicators(evidence_path)
        report['tampering_detection'].append(tampering)
    elif os.path.isdir(evidence_path):
        for root, dirs, files in os.walk(evidence_path):
            for file in files[:50]:  # حد أقصى 50 ملف
                file_path = os.path.join(root, file)
                tampering = detect_tampering_indicators(file_path)
                if tampering['suspicion_score'] > 0:
                    report['tampering_detection'].append(tampering)
    
    # 4. البحث عن بيانات حساسة
    print("\n[4/6] جاري البحث عن بيانات حساسة...")
    sensitive_report = search_sensitive_patterns(
        evidence_path, 
        os.path.join(output_dir, "sensitive_data.json")
    )
    report['sensitive_data_findings'] = sensitive_report.get('findings', [])
    
    # 5. بناء الخط الزمني
    print("\n[5/6] جاري بناء الخط الزمني...")
    timeline = build_timeline(
        evidence_path,
        os.path.join(output_dir, "timeline.json")
    )
    report['timeline_reconstruction'] = timeline.get('events', [])[:200]  # حد أقصى
    
    # 6. استخراج الملفات (إذا كان مسار صورة قرص)
    print("\n[6/6] جاري فحص إمكانية استخراج الملفات...")
    if os.path.isfile(evidence_path):
        carved_count = carve_files_from_disk(
            evidence_path,
            os.path.join(output_dir, "carved_files")
        )
        report['carved_files'] = {'count': carved_count, 'output_dir': 'carved_files'}
    
    # الملخص التنفيذي
    total_suspicious = len([x for x in report['tampering_detection'] if x.get('suspicion_score', 0) > 3])
    total_sensitive = len(report['sensitive_data_findings'])
    total_images = len(report['image_analysis'])
    high_risk_images = len([x for x in report['image_analysis'] if x.get('overall_score', 0) >= 8])
    
    report['executive_summary'] = {
        'total_files_hashed': len(report['hash_analysis']),
        'total_images_analyzed': total_images,
        'high_risk_images': high_risk_images,
        'tampering_indicators_found': total_suspicious,
        'sensitive_data_instances': total_sensitive,
        'timeline_events_count': len(report['timeline_reconstruction']),
        'overall_risk_level': 'CRITICAL' if total_suspicious > 5 or high_risk_images > 3 else 
                             'HIGH' if total_suspicious > 2 or high_risk_images > 0 else
                             'MEDIUM' if total_sensitive > 0 else 'LOW'
    }
    
    # التوصيات
    recommendations = []
    if high_risk_images > 0:
        recommendations.append("إجراء تحليل عميق للصور عالية الخطورة باستخدام أدوات متخصصة")
    if total_suspicious > 0:
        recommendations.append("التحقق من مصدر الملفات ذات مؤشرات التلاعب ومقارنتها بالنسخ الأصلية")
    if total_sensitive > 0:
        recommendations.append("توثيق جميع حالات البيانات الحساسة وإبلاغ الجهة المختصة")
    if len(report['hash_analysis']) > 0:
        recommendations.append("حفظ بصمات SHA-256 كأدلة مرجعية لسلسلة الحضانة")
    
    report['recommendations'] = recommendations
    
    # حفظ التقرير النهائي
    with open(report_file, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    
    print(f"\n{'='*70}")
    print("✅ تم توليد التقرير الجنائي الشامل بنجاح!")
    print(f"{'='*70}")
    print(f"📄 موقع التقرير: {os.path.abspath(report_file)}")
    print(f"\n📊 الملخص التنفيذي:")
    print(f"   - مستوى الخطورة العام: {report['executive_summary']['overall_risk_level']}")
    print(f"   - الملفات المفحوصة: {report['executive_summary']['total_files_hashed']}")
    print(f"   - الصور المحللة: {total_images} ({high_risk_images} عالية الخطورة)")
    print(f"   - مؤشرات التلاعب: {total_suspicious}")
    print(f"   - بيانات حساسة: {total_sensitive}")
    print(f"\n💡 التوصيات الرئيسية:")
    for i, rec in enumerate(recommendations, 1):
        print(f"   {i}. {rec}")
    print(f"{'='*70}\n")
    
    return report


# ==========================================
# القائمة الرئيسية التفاعلية
# ==========================================
def display_banner():
    """عرض شعار الأداة"""
    banner = """
╔═══════════════════════════════════════════════════════════════╗
║         🛡️  أداة التحقيق الجنائي الرقمي المتقدمة v2.0  🛡️       ║
║          Advanced Digital Forensics Investigation Toolkit      ║
╠═══════════════════════════════════════════════════════════════╣
║  المطور: فريق الأمن السيبراني والتحقيق الجنائي الرقمي          ║
║  الإصدار: 2.0 - ديسمبر 2024                                    ║
╚═══════════════════════════════════════════════════════════════╝
    """
    print(banner)

def main():
    """الوظيفة الرئيسية"""
    display_banner()
    
    # تحميل نموذج الذكاء الاصطناعي إذا كان متاحاً
    ai_model = load_ai_model() if AI_AVAILABLE else None
    
    while True:
        print("\n" + "="*70)
        print("                     📋 القائمة الرئيسية")
        print("="*70)
        print("  1. 🔐 حساب البصمات الرقمية وسلسلة الحضانة (Hash & Integrity)")
        print("  2. 📷 تحليل الصور المتقدم (EXIF + AI + Steganography)")
        print("  3. 🔍 كشف التلاعب والتعديلات (Tampering Detection)")
        print("  4. 🗂️  استخراج الملفات المحذوفة (File Carving)")
        print("  5. 📊 تحليل السجلات والأنظمة (Log Analysis)")
        print("  6. 🔎 البحث عن بيانات حساسة (Sensitive Data Search)")
        print("  7. 📅 بناء الخط الزمني للأحداث (Timeline Reconstruction)")
        print("  8. 📋 توليد تقرير جنائي شامل (Comprehensive Report)")
        print("  9. 🚀 الفحص الشامل السريع (Quick Full Scan)")
        print("  10. ❌ الخروج")
        print("="*70)
        
        choice = input("\n➡️  اختر رقم الخدمة المطلوبة (1-10): ").strip()
        
        if choice == '1':
            path = input("\n📁 أدخل مسار المجلد أو الملف: ").strip('"\'')
            run_hash_integrity_checker(path)
            
        elif choice == '2':
            path = input("\n📷 أدخل مسار الصورة أو مجلد الصور: ").strip('"\'')
            if os.path.isfile(path):
                extract_exif_and_analyze(path, ai_model)
            elif os.path.isdir(path):
                for filename in os.listdir(path):
                    if filename.lower().endswith(('.jpg', '.jpeg', '.png')):
                        file_path = os.path.join(path, filename)
                        extract_exif_and_analyze(file_path, ai_model)
            else:
                print("[-] المسار غير صحيح أو لا يحتوي على صور")
            
        elif choice == '3':
            path = input("\n🔍 أدخل مسار الملف أو المجلد: ").strip('"\'')
            if os.path.isfile(path):
                detect_tampering_indicators(path)
            elif os.path.isdir(path):
                count = 0
                for root, dirs, files in os.walk(path):
                    for file in files[:20]:  # حد أقصى 20 ملف
                        file_path = os.path.join(root, file)
                        detect_tampering_indicators(file_path)
                        count += 1
                print(f"\n[*] تم فحص {count} ملفاً")
            
        elif choice == '4':
            path = input("\n💾 أدخل مسار صورة القرص أو الملف الثنائي: ").strip('"\'')
            output_dir = input("أدخل مجلد الإخراج (اضغط Enter للافتراضي): ").strip() or "carved_files"
            carve_files_from_disk(path, output_dir)
            
        elif choice == '5':
            path = input("\n📜 أدخل مسار ملف السجل: ").strip('"\'')
            analyze_log_file(path)
            
        elif choice == '6':
            path = input("\n🔎 أدخل مسار المجلد للبحث: ").strip('"\'')
            search_sensitive_patterns(path)
            
        elif choice == '7':
            path = input("\n📅 أدخل مسار المجلد لبناء الخط الزمني: ").strip('"\'')
            build_timeline(path)
            
        elif choice == '8':
            case_name = input("\n📋 أدخل اسم القضية: ").strip()
            path = input("أدخل مسار الأدلة: ").strip('"\'')
            generate_comprehensive_report(case_name, path)
            
        elif choice == '9':
            print("\n⚡ بدء الفحص الشامل السريع...")
            case_name = "QuickScan_" + datetime.now().strftime("%Y%m%d_%H%M%S")
            path = input("أدخل مسار الأدلة: ").strip('"\'')
            generate_comprehensive_report(case_name, path, "quick_reports")
            
        elif choice == '10':
            print("\n✅ تم إغلاق البرنامج بنجاح.")
            print("🙏 شكراً لاستخدام أداة التحقيق الجنائي الرقمي المتقدمة")
            print("🔒 بالتوفيق في تحقيقاتكم!\n")
            sys.exit(0)
            
        else:
            print("\n[-] خيار غير صحيح، يرجى اختيار رقم من 1 إلى 10.")
        
        # سؤال عن متابعة العمل
        continue_choice = input("\n↩️  هل تريد إجراء عملية أخرى؟ (y/n): ").strip().lower()
        if continue_choice not in ['y', 'yes', 'نعم', '']:
            print("\n✅ انتهت جلسة العمل. بالتوفيق!")
            break

if __name__ == "__main__":
    main()
