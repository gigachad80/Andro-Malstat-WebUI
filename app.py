
#!/usr/bin/env python3
"""
Refactored Flask Backend for Ultimate APK Analyzer
Architecture: Async Polling (Non-blocking)
"""

from flask import Flask, request, jsonify, send_from_directory
from werkzeug.utils import secure_filename
import os
import tempfile
import threading
import uuid
import time
import shutil
import logging
from pathlib import Path

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Import the analyzer safely
try:
    from andromalstat import UltimateAnalyzer
except ImportError as e:
    logger.error(f"Critical Import Error: {e}")
    # We don't exit here to allow the server to start and report the error via API
    UltimateAnalyzer = None

app = Flask(__name__, static_folder='.')
app.config['MAX_CONTENT_LENGTH'] = 200 * 1024 * 1024  # Increased to 200MB
app.config['UPLOAD_FOLDER'] = tempfile.gettempdir()
app.config['JOBS'] = {}  # In-memory job store (Use Redis/DB in prod)

ALLOWED_EXTENSIONS = {'apk'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def background_worker(job_id, apk_path, output_dir):
    """
    Worker thread that performs analysis and updates the global job store.
    Self-contained: Handles its own file cleanup to prevent race conditions.
    """
    logger.info(f"[{job_id}] Worker started for {apk_path}")
    app.config['JOBS'][job_id]['status'] = 'processing'
    
    try:
        if not UltimateAnalyzer:
            raise ImportError("Analyzer module failed to load. Check server logs.")

        # Initialize and Run
        analyzer = UltimateAnalyzer(apk_path, output_dir)
        app.config['JOBS'][job_id]['message'] = 'Decompiling resources...'
        
        # We assume analyzer.run() is blocking but thread-safe
        analyzer.run()
        
        # Verify Report
        report_path = Path(output_dir) / "analysis_report.json"
        if not report_path.exists():
            raise FileNotFoundError("Analysis finished but no report generated.")
            
        with open(report_path, 'r') as f:
            report_data = json.load(f)

        # Update Job
        app.config['JOBS'][job_id]['status'] = 'completed'
        app.config['JOBS'][job_id]['result'] = report_data
        logger.info(f"[{job_id}] Analysis successful")

    except Exception as e:
        logger.error(f"[{job_id}] Analysis failed: {e}")
        app.config['JOBS'][job_id]['status'] = 'failed'
        app.config['JOBS'][job_id]['error'] = str(e)
    
    finally:
        # CLEANUP: The thread that uses the file must be the one to delete it
        if os.path.exists(apk_path):
            try:
                os.remove(apk_path)
                logger.info(f"[{job_id}] Cleaned up APK")
            except Exception as e:
                logger.warning(f"[{job_id}] Failed to delete APK: {e}")
        
        # Cleanup output dir if needed (or keep for caching)
        # shutil.rmtree(output_dir, ignore_errors=True) 

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/scan', methods=['POST'])
def scan_apk():
    """
    Non-blocking endpoint. Returns a Job ID immediately.
    """
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'Empty filename'}), 400
        
    if not allowed_file(file.filename):
        return jsonify({'success': False, 'error': 'Only .apk files allowed'}), 400

    # generate unique job ID
    job_id = str(uuid.uuid4())
    
    # Save file
    filename = secure_filename(file.filename)
    unique_filename = f"{job_id}_{filename}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
    file.save(filepath)
    
    # Create Output Dir
    output_dir = os.path.join(app.config['UPLOAD_FOLDER'], f"out_{job_id}")
    os.makedirs(output_dir, exist_ok=True)

    # Initialize Job
    app.config['JOBS'][job_id] = {
        'id': job_id,
        'status': 'queued',
        'submitted_at': time.time(),
        'filename': filename
    }

    # Spawn Thread
    thread = threading.Thread(
        target=background_worker,
        args=(job_id, filepath, output_dir),
        daemon=True # Daemon threads die if the main server dies, which is fine here
    )
    thread.start()

    return jsonify({
        'success': True,
        'job_id': job_id,
        'message': 'Analysis started in background'
    })

@app.route('/status/<job_id>', methods=['GET'])
def get_status(job_id):
    """
    Client polls this endpoint to check progress.
    """
    job = app.config['JOBS'].get(job_id)
    
    if not job:
        return jsonify({'success': False, 'error': 'Job not found'}), 404
    
    if job['status'] == 'completed':
        # Return the full report
        return jsonify({
            'success': True,
            'status': 'completed',
            'report': job['result']
        })
    elif job['status'] == 'failed':
        return jsonify({
            'success': False,
            'status': 'failed',
            'error': job.get('error', 'Unknown error')
        })
    else:
        return jsonify({
            'success': True,
            'status': job['status'],
            'message': job.get('message', 'Processing...')
        })

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy', 'jobs_active': len(app.config['JOBS'])})

import json # needed for the worker

if __name__ == '__main__':
    print(f"[*] Server running on http://0.0.0.0:5000")
    # threaded=True is default in recent Flask versions, but good to be explicit
    app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)
