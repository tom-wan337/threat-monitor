# models.py
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import json

db = SQLAlchemy()

class MonitoringTarget(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    keywords = db.Column(db.Text, nullable=False)  # JSON string
    target_type = db.Column(db.String(50), nullable=False)
    active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    alerts = db.relationship('Alert', backref='target', lazy=True, cascade='all, delete-orphan')
    
    def get_keywords(self):
        try:
            return json.loads(self.keywords)
        except:
            return []
    
    def set_keywords(self, keywords_list):
        self.keywords = json.dumps(keywords_list)

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target_id = db.Column(db.Integer, db.ForeignKey('monitoring_target.id'), nullable=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    source_url = db.Column(db.String(500))
    source_type = db.Column(db.String(50))
    risk_level = db.Column(db.String(20), default='medium')
    status = db.Column(db.String(20), default='new')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    content_hash = db.Column(db.String(64), unique=True)
    location = db.Column(db.String(100))
    query_type = db.Column(db.String(50), default='monitoring')

class SearchQuery(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    topic = db.Column(db.String(200), nullable=False)
    location = db.Column(db.String(100))
    query_text = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    results_count = db.Column(db.Integer, default=0)

class DataSource(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    source_type = db.Column(db.String(50), nullable=False)
    api_endpoint = db.Column(db.String(500))
    active = db.Column(db.Boolean, default=True)
    last_scan = db.Column(db.DateTime)
    scan_count = db.Column(db.Integer, default=0)