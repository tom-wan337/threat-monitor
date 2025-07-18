# monitoring/engine.py
import requests
import hashlib
import re
from datetime import datetime, timedelta
from models import db, Alert, MonitoringTarget
from config import Config
import time
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ThreatMonitor:
    def __init__(self):
        self.config = Config()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'ThreatMonitor/1.0 (Security Research)'
        })
        
    def monitor_all_targets(self):
        """Main monitoring function"""
        logger.info("Starting monitoring scan...")
        
        targets = MonitoringTarget.query.filter_by(active=True).all()
        total_alerts = 0
        
        for target in targets:
            try:
                keywords = target.get_keywords()
                alerts_created = self.monitor_target(target, keywords)
                total_alerts += alerts_created
                logger.info(f"Target '{target.name}': {alerts_created} new alerts")
                
                # Rate limiting
                time.sleep(1)
                
            except Exception as e:
                logger.error(f"Error monitoring target {target.name}: {e}")
        
        logger.info(f"Monitoring scan completed. Total new alerts: {total_alerts}")
        return total_alerts
    
    def monitor_target(self, target, keywords):
        """Monitor a specific target across all sources"""
        alerts_created = 0
        
        # Monitor different sources
        sources = [
            self.monitor_reddit,
            self.monitor_github,
            self.monitor_hackernews,
            # Add more sources as needed
        ]
        
        for source_func in sources:
            try:
                alerts_created += source_func(target, keywords)
                time.sleep(0.5)  # Rate limiting between sources
            except Exception as e:
                logger.error(f"Error in {source_func.__name__}: {e}")
        
        return alerts_created
    
    def monitor_reddit(self, target, keywords):
        """Monitor Reddit for mentions"""
        alerts_created = 0
        
        try:
            for keyword in keywords[:3]:  # Limit to 3 keywords to avoid rate limiting
                url = f"https://www.reddit.com/search.json"
                params = {
                    'q': keyword,
                    'sort': 'new',
                    'limit': 10,
                    't': 'day'  # Last 24 hours
                }
                
                response = self.session.get(url, params=params, timeout=self.config.REQUEST_TIMEOUT)
                
                if response.status_code == 200:
                    data = response.json()
                    
                    for post in data.get('data', {}).get('children', []):
                        post_data = post['data']
                        
                        if self.process_potential_threat({
                            'title': post_data.get('title', ''),
                            'content': post_data.get('selftext', ''),
                            'url': f"https://reddit.com{post_data.get('permalink', '')}",
                            'source': 'reddit',
                            'target_id': target.id,
                            'created': datetime.fromtimestamp(post_data.get('created_utc', 0))
                        }):
                            alerts_created += 1
                
                time.sleep(1)  # Rate limiting
                
        except Exception as e:
            logger.error(f"Reddit monitoring error: {e}")
        
        return alerts_created
    
    def monitor_github(self, target, keywords):
        """Monitor GitHub for code mentions"""
        alerts_created = 0
        
        try:
            for keyword in keywords[:2]:  # GitHub has strict rate limits
                url = "https://api.github.com/search/code"
                params = {
                    'q': f'"{keyword}" in:file',
                    'sort': 'indexed',
                    'per_page': 5
                }
                
                response = self.session.get(url, params=params, timeout=self.config.REQUEST_TIMEOUT)
                
                if response.status_code == 200:
                    data = response.json()
                    
                    for item in data.get('items', []):
                        if self.process_potential_threat({
                            'title': f"Code found: {item.get('name', '')}",
                            'content': f"Repository: {item.get('repository', {}).get('full_name', '')}",
                            'url': item.get('html_url', ''),
                            'source': 'github',
                            'target_id': target.id,
                            'created': datetime.utcnow()
                        }):
                            alerts_created += 1
                
                time.sleep(2)  # GitHub rate limiting
                
        except Exception as e:
            logger.error(f"GitHub monitoring error: {e}")
        
        return alerts_created
    
    def monitor_hackernews(self, target, keywords):
        """Monitor Hacker News"""
        alerts_created = 0
        
        try:
            # Get recent stories
            url = "https://hacker-news.firebaseio.com/v0/newstories.json"
            response = self.session.get(url, timeout=self.config.REQUEST_TIMEOUT)
            
            if response.status_code == 200:
                story_ids = response.json()[:50]  # Check last 50 stories
                
                for story_id in story_ids:
                    story_url = f"https://hacker-news.firebaseio.com/v0/item/{story_id}.json"
                    story_response = self.session.get(story_url, timeout=self.config.REQUEST_TIMEOUT)
                    
                    if story_response.status_code == 200:
                        story = story_response.json()
                        title = story.get('title', '').lower()
                        
                        # Check if any keyword matches
                        for keyword in keywords:
                            if keyword.lower() in title:
                                if self.process_potential_threat({
                                    'title': story.get('title', ''),
                                    'content': story.get('text', ''),
                                    'url': story.get('url', f"https://news.ycombinator.com/item?id={story_id}"),
                                    'source': 'hackernews',
                                    'target_id': target.id,
                                    'created': datetime.fromtimestamp(story.get('time', 0))
                                }):
                                    alerts_created += 1
                                break
                    
                    time.sleep(0.1)  # Small delay between requests
                    
        except Exception as e:
            logger.error(f"Hacker News monitoring error: {e}")
        
        return alerts_created
    
    def process_potential_threat(self, data):
        """Process and score potential threats"""
        # Create content hash to avoid duplicates
        content_str = f"{data['title']}{data['content']}{data['url']}"
        content_hash = hashlib.sha256(content_str.encode()).hexdigest()
        
        # Check if already exists
        existing = Alert.query.filter_by(content_hash=content_hash).first()
        if existing:
            return False
        
        # Calculate risk level
        risk_level = self.calculate_risk_level(data)
        
        # Create alert
        alert = Alert(
            target_id=data['target_id'],
            title=data['title'][:200] if data['title'] else 'No title',
            description=data['content'][:1000] if data['content'] else '',
            source_url=data['url'],
            source_type=data['source'],
            risk_level=risk_level,
            content_hash=content_hash
        )
        
        db.session.add(alert)
        db.session.commit()
        
        logger.info(f"New {risk_level} risk alert: {data['title'][:50]}...")
        return True
    
    def calculate_risk_level(self, data):
        """Calculate risk level based on content analysis"""
        content = f"{data['title']} {data['content']}".lower()
        
        # Critical risk keywords
        critical_keywords = [
            'password leak', 'data breach', 'database dump', 'credentials leaked',
            'api key exposed', 'private key', 'security breach', 'hacked database'
        ]
        
        # High risk keywords
        high_risk_keywords = [
            'password', 'leak', 'breach', 'hack', 'exploit', 'vulnerability',
            'database', 'credentials', 'api key', 'token', 'exposed'
        ]
        
        # Medium risk keywords
        medium_risk_keywords = [
            'security', 'threat', 'attack', 'malware', 'phishing',
            'suspicious', 'fraud', 'scam', 'investigation'
        ]
        
        # Check for critical combinations
        for keyword in critical_keywords:
            if keyword in content:
                return 'critical'
        
        # Count individual keywords
        high_risk_count = sum(1 for keyword in high_risk_keywords if keyword in content)
        medium_risk_count = sum(1 for keyword in medium_risk_keywords if keyword in content)
        
        if high_risk_count >= 2:
            return 'high'
        elif high_risk_count >= 1:
            return 'medium'
        elif medium_risk_count >= 2:
            return 'medium'
        else:
            return 'low'