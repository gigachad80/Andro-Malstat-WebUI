"""
SQLAlchemy Database Models for Andro-Malstat
"""
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()


class ScanResult(db.Model):
    """Persists completed APK analysis results."""
    __tablename__ = 'scan_results'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    job_id = db.Column(db.String(36), unique=True, nullable=False, index=True)
    filename = db.Column(db.String(255), nullable=False)
    package_name = db.Column(db.String(255), nullable=True)
    risk_score = db.Column(db.Integer, default=0)
    risk_level = db.Column(db.String(20), nullable=True)
    report_json = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        """Summary dict for the /scans listing endpoint."""
        return {
            'id': self.id,
            'job_id': self.job_id,
            'filename': self.filename,
            'package_name': self.package_name,
            'risk_score': self.risk_score,
            'risk_level': self.risk_level,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self):
        return f'<ScanResult {self.id} – {self.filename}>'
