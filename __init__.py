# app/__init__.py
from flask import Flask, render_template
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from apscheduler.schedulers.background import BackgroundScheduler
import atexit
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize extensions
db = SQLAlchemy()

def create_app():
    app = Flask(__name__, template_folder='../dashboard')
    
    # Load configuration
    from config import Config
   app.config.from_object(Config)
    
    # Initialize extensions
    db.init_app(app)
    CORS(app)
    
    # Import models
    from models import Alert, MonitoringTarget, SearchQuery
    
    # Import monitoring engine
    from monitoringengine import ThreatMonitor, SearchEngine
    
    # Initialize monitoring engine
    monitor = ThreatMonitor()
    search_engine = SearchEngine()
    
    # Register routes
    from app.routes import register_routes
    register_routes(app, monitor, search_engine)
    
    # Initialize database
    with app.app_context():
        db.create_all()
        logger.info("✅ Database initialized")
    
    # Start background scheduler
    scheduler = BackgroundScheduler()
    scheduler.add_job(
        func=lambda: monitor.monitor_all_targets(),
        trigger="interval",
        minutes=30,
        id='monitoring_scan'
    )
    
    try:
        scheduler.start()
        logger.info("⏰ Background monitoring started (30-minute intervals)")
        atexit.register(lambda: scheduler.shutdown())
    except Exception as e:
        logger.error(f"❌ Failed to start scheduler: {e}")
    
    return app