#!/usr/bin/env python3
"""
Refactored Flask Backend for Ultimate APK Analyzer
Architecture: Async Polling (Non-blocking) + SQLAlchemy Persistence
"""

from flask import Flask, request, jsonify, send_from_directory, Response
from werkzeug.utils import secure_filename
import os
import tempfile
import threading
import uuid
import time
import json
import logging
from pathlib import Path

from config import Config
from models import db, ScanResult

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Import the analyzer safely
try:
    from andromalstat import UltimateAnalyzer
except ImportError as e:
    logger.error(f"Critical Import Error: {e}")
    UltimateAnalyzer = None

app = Flask(__name__)
app.config.from_object(Config)

# Initialize SQLAlchemy
db.init_app(app)

with app.app_context():
    db.create_all()
    logger.info("Database tables created / verified.")

ALLOWED_EXTENSIONS = {'apk'}


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def background_worker(job_id, apk_path, output_dir):
    """
    Worker thread that performs analysis and updates the global job store.
    On completion, persists the result to the SQLAlchemy database.
    """
    logger.info(f"[{job_id}] Worker started for {apk_path}")
    app.config['JOBS'][job_id]['status'] = 'processing'

    try:
        if not UltimateAnalyzer:
            raise ImportError("Analyzer module failed to load. Check server logs.")

        # Initialize and Run
        analyzer = UltimateAnalyzer(apk_path, output_dir)
        app.config['JOBS'][job_id]['message'] = 'Decompiling resources...'

        analyzer.run()

        # Verify Report
        report_path = Path(output_dir) / "analysis_report.json"
        if not report_path.exists():
            raise FileNotFoundError("Analysis finished but no report generated.")

        with open(report_path, 'r') as f:
            report_data = json.load(f)

        # Update in-memory job store
        app.config['JOBS'][job_id]['status'] = 'completed'
        app.config['JOBS'][job_id]['result'] = report_data
        logger.info(f"[{job_id}] Analysis successful")

        # ── Persist to database ──
        with app.app_context():
            scan = ScanResult(
                job_id=job_id,
                filename=app.config['JOBS'][job_id].get('filename', 'unknown'),
                package_name=report_data.get('package_name'),
                risk_score=report_data.get('risk_score', 0),
                risk_level=report_data.get('risk_level'),
                report_json=json.dumps(report_data, default=str),
            )
            db.session.add(scan)
            db.session.commit()
            logger.info(f"[{job_id}] Scan result saved to database (id={scan.id})")

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


# ─────────────────────────────────────────────
#  ROUTES
# ─────────────────────────────────────────────

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

    # Generate unique job ID
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
        daemon=True
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
    Falls back to the database if the job is not found in memory
    (e.g. after a server restart).
    """
    job = app.config['JOBS'].get(job_id)

    if not job:
        # Fallback: check if this scan was already persisted to the DB
        scan = ScanResult.query.filter_by(job_id=job_id).first()
        if scan:
            report_data = json.loads(scan.report_json)
            return jsonify({
                'success': True,
                'status': 'completed',
                'report': report_data
            })
        return jsonify({'success': False, 'error': 'Job not found'}), 404

    if job['status'] == 'completed':
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


# ─────────────────────────────────────────────
#  DATABASE-BACKED ENDPOINTS
# ─────────────────────────────────────────────

@app.route('/scans', methods=['GET'])
def list_scans():
    """Returns a list of all persisted scan results (summary only)."""
    scans = ScanResult.query.order_by(ScanResult.created_at.desc()).all()
    return jsonify({
        'success': True,
        'count': len(scans),
        'scans': [s.to_dict() for s in scans]
    })


@app.route('/export/<int:scan_id>', methods=['GET'])
def export_scan(scan_id):
    """Downloads the full JSON report for a specific scan from the database."""
    scan = ScanResult.query.get(scan_id)
    if not scan:
        return jsonify({'success': False, 'error': 'Scan not found'}), 404

    safe_name = scan.filename.replace(' ', '_').replace('.apk', '')
    return Response(
        scan.report_json,
        mimetype='application/json',
        headers={
            'Content-Disposition': f'attachment; filename=report_{safe_name}.json'
        }
    )


@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'jobs_active': len(app.config['JOBS']),
        'db': 'connected'
    })


if __name__ == '__main__':
    print(f"[*] Server running on http://0.0.0.0:5000")
    # use_reloader=False prevents the watchdog from restarting the server
    # mid-scan, which would kill background threads and wipe the JOBS dict.
    app.run(debug=True, host='0.0.0.0', port=5000, threaded=True, use_reloader=False)
