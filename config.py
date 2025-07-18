# config.py
import os
from datetime import timedelta

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///threat_monitor.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # API Keys (get these from respective services)
    NEWS_API_KEY = os.environ.get('NEWS_API_KEY') or ''
    TWITTER_BEARER_TOKEN = os.environ.get('TWITTER_BEARER_TOKEN') or ''
    
    # Monitoring settings
    SCAN_INTERVAL_MINUTES = int(os.environ.get('SCAN_INTERVAL_MINUTES', 30))
    MAX_ALERTS_PER_PAGE = 20
    
    # Rate limiting
    REQUESTS_PER_MINUTE = 60
    REQUEST_TIMEOUT = 10