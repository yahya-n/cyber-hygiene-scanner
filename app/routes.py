from flask import Blueprint, render_template, request, jsonify, send_file
from werkzeug.utils import secure_filename
from .scanner import run_scan
import os
import uuid

main = Blueprint('main', __name__)

# File upload configuration
UPLOAD_FOLDER = 'app/uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'exe', 'dll', 'zip', 'doc', 'docx', 'xls', 'xlsx', 'apk', 'jar'}
MAX_FILE_SIZE = 32 * 1024 * 1024  # 32MB (VirusTotal limit)

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@main.route('/')
def index():
    return render_template('index.html')

@main.route('/scan', methods=['POST'])
def scan():
    try:
        data = request.get_json()
        target = data.get('target')
        scan_types = data.get('scan_types', [])
        
        if not target:
            return jsonify({'error': 'Target is required'}), 400
        
        # Generate unique scan ID
        scan_id = str(uuid.uuid4())
        
        # Run scan (this could be made async with Celery)
        result = run_scan(target, scan_types)
        
        return jsonify({
            'scan_id': scan_id,
            'status': 'completed',
            'findings': result['findings'],
            'score': result['score'],
            'pdf_path': result.get('pdf_path')
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@main.route('/scan-file', methods=['POST'])
def scan_file():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'error': 'File type not allowed'}), 400
        
        # Save file securely
        filename = secure_filename(file.filename)
        unique_filename = f"{uuid.uuid4()}_{filename}"
        filepath = os.path.join(UPLOAD_FOLDER, unique_filename)
        file.save(filepath)
        
        # Check file size
        if os.path.getsize(filepath) > MAX_FILE_SIZE:
            os.remove(filepath)
            return jsonify({'error': 'File too large (max 32MB)'}), 400
        
        # Run VirusTotal scan
        result = run_scan(filename, ['virustotal_file'], file_path=filepath)
        
        # Clean up file after scan
        try:
            os.remove(filepath)
        except:
            pass
        
        return jsonify({
            'status': 'completed',
            'findings': result['findings'],
            'score': result['score'],
            'pdf_path': result.get('pdf_path')
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@main.route('/download/<filename>')
def download(filename):
    try:
        filepath = os.path.join('app/static/reports', filename)
        return send_file(filepath, as_attachment=True)
    except Exception as e:
        return jsonify({'error': str(e)}), 404