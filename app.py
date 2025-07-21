from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from apscheduler.schedulers.background import BackgroundScheduler
import atexit
import logging
import json
import hashlib
from datetime import datetime, timedelta
import requests
import time
import urllib.parse

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize extensions
db = SQLAlchemy()

# Database Models
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

# Threat Monitoring Engine
class ThreatMonitor:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'ThreatMonitor/1.0 (Security Research Tool)'
        })
        
    def monitor_all_targets(self):
        """Main monitoring function"""
        logger.info("🔍 Starting monitoring scan...")
        
        targets = MonitoringTarget.query.filter_by(active=True).all()
        total_alerts = 0
        
        if not targets:
            logger.info("No active targets found")
            return 0
        
        for target in targets:
            try:
                keywords = target.get_keywords()
                if keywords:
                    alerts_created = self.monitor_target(target, keywords)
                    total_alerts += alerts_created
                    logger.info(f"✅ Target '{target.name}': {alerts_created} new alerts")
                    time.sleep(2)
                
            except Exception as e:
                logger.error(f"❌ Error monitoring target {target.name}: {e}")
        
        logger.info(f"🎯 Monitoring scan completed. Total new alerts: {total_alerts}")
        return total_alerts
    
    def monitor_target(self, target, keywords):
        """Monitor a specific target across all sources"""
        alerts_created = 0
        
        sources = [
            ('Reddit', self.monitor_reddit),
            ('GitHub', self.monitor_github),
            ('Hacker News', self.monitor_hackernews),
        ]
        
        for source_name, source_func in sources:
            try:
                alerts = source_func(target, keywords)
                alerts_created += alerts
                if alerts > 0:
                    logger.info(f"  📊 {source_name}: {alerts} alerts")
                time.sleep(1)
            except Exception as e:
                logger.error(f"❌ Error in {source_name}: {e}")
        
        return alerts_created
    
    def monitor_reddit(self, target, keywords):
        """Monitor Reddit for mentions"""
        alerts_created = 0
        
        try:
            for keyword in keywords[:3]:
                url = "https://www.reddit.com/search.json"
                params = {
                    'q': keyword,
                    'sort': 'new',
                    'limit': 5,
                    't': 'day'
                }
                
                response = self.session.get(url, params=params, timeout=10)
                
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
                
                time.sleep(1)
                
        except Exception as e:
            logger.error(f"Reddit monitoring error: {e}")
        
        return alerts_created
    
    def monitor_github(self, target, keywords):
        """Monitor GitHub for code mentions"""
        alerts_created = 0
        
        try:
            for keyword in keywords[:2]:
                url = "https://api.github.com/search/code"
                params = {
                    'q': f'"{keyword}"',
                    'sort': 'indexed',
                    'per_page': 3
                }
                
                response = self.session.get(url, params=params, timeout=10)
                
                if response.status_code == 200:
                    data = response.json()
                    
                    for item in data.get('items', []):
                        repo_name = item.get('repository', {}).get('full_name', '')
                        if self.process_potential_threat({
                            'title': f"Code found: {item.get('name', '')}",
                            'content': f"Repository: {repo_name}\nPath: {item.get('path', '')}",
                            'url': item.get('html_url', ''),
                            'source': 'github',
                            'target_id': target.id,
                            'created': datetime.utcnow()
                        }):
                            alerts_created += 1
                
                time.sleep(3)
                
        except Exception as e:
            logger.error(f"GitHub monitoring error: {e}")
        
        return alerts_created
    
    def monitor_hackernews(self, target, keywords):
        """Monitor Hacker News"""
        alerts_created = 0
        
        try:
            url = "https://hacker-news.firebaseio.com/v0/newstories.json"
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                story_ids = response.json()[:20]
                
                for story_id in story_ids:
                    story_url = f"https://hacker-news.firebaseio.com/v0/item/{story_id}.json"
                    story_response = self.session.get(story_url, timeout=5)
                    
                    if story_response.status_code == 200:
                        story = story_response.json()
                        title = story.get('title', '').lower()
                        
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
                    
                    time.sleep(0.2)
                    
        except Exception as e:
            logger.error(f"Hacker News monitoring error: {e}")
        
        return alerts_created
    
    def process_potential_threat(self, data):
        """Process and score potential threats"""
        if not data['title']:
            return False
            
        content_str = f"{data['title']}{data['content']}{data['url']}"
        content_hash = hashlib.sha256(content_str.encode()).hexdigest()
        
        existing = Alert.query.filter_by(content_hash=content_hash).first()
        if existing:
            return False
        
        risk_level = self.calculate_risk_level(data)
        
        alert = Alert(
            target_id=data['target_id'],
            title=data['title'][:200],
            description=data['content'][:1000] if data['content'] else '',
            source_url=data['url'],
            source_type=data['source'],
            risk_level=risk_level,
            content_hash=content_hash,
            query_type='monitoring'
        )
        
        db.session.add(alert)
        db.session.commit()
        
        return True
    
    def calculate_risk_level(self, data):
        """Calculate risk level based on content analysis"""
        content = f"{data['title']} {data['content']}".lower()
        
        critical_keywords = [
            'password leak', 'data breach', 'database dump', 'credentials leaked',
            'api key exposed', 'private key leaked', 'security breach'
        ]
        
        high_risk_keywords = [
            'password', 'leak', 'breach', 'hack', 'exploit', 'vulnerability',
            'database', 'credentials', 'api key', 'token', 'exposed', 'dump'
        ]
        
        medium_risk_keywords = [
            'security', 'threat', 'attack', 'malware', 'phishing',
            'suspicious', 'fraud', 'scam', 'investigation', 'alert'
        ]
        
        for keyword in critical_keywords:
            if keyword in content:
                return 'critical'
        
        high_count = sum(1 for keyword in high_risk_keywords if keyword in content)
        medium_count = sum(1 for keyword in medium_risk_keywords if keyword in content)
        
        if high_count >= 2:
            return 'high'
        elif high_count >= 1:
            return 'medium'
        elif medium_count >= 2:
            return 'medium'
        else:
            return 'low'

# Search Engine
class SearchEngine:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
    
    def search_topic_location(self, topic, location=None):
        """Search for a specific topic and location across multiple sources"""
        results = []
        
        # Build search query
        if location:
            search_query = f"{topic} {location}"
            location_query = f"site:reddit.com {topic} {location}"
        else:
            search_query = topic
            location_query = f"site:reddit.com {topic}"
        
        logger.info(f"🔍 Searching for: '{search_query}'")
        
        # Search multiple sources
        try:
            # Reddit search
            reddit_results = self.search_reddit_specific(topic, location)
            results.extend(reddit_results)
            
            # News search (using multiple sources)
            news_results = self.search_news(topic, location)
            results.extend(news_results)
            
            # GitHub search
            github_results = self.search_github_specific(topic, location)
            results.extend(github_results)
            
            # Hacker News search
            hn_results = self.search_hackernews_specific(topic, location)
            results.extend(hn_results)
            
        except Exception as e:
            logger.error(f"Search error: {e}")
        
        # Remove duplicates and sort by relevance
        unique_results = self.deduplicate_results(results)
        scored_results = self.score_results(unique_results, topic, location)
        
        logger.info(f"✅ Found {len(scored_results)} unique results")
        return scored_results
    
    def search_reddit_specific(self, topic, location):
        """Enhanced Reddit search"""
        results = []
        try:
            # Multiple search strategies
            queries = [topic]
            if location:
                queries.extend([
                    f"{topic} {location}",
                    f"{location} {topic}",
                    f'"{topic}" "{location}"'
                ])
            
            for query in queries[:3]:  # Limit queries
                url = "https://www.reddit.com/search.json"
                params = {
                    'q': query,
                    'sort': 'relevance',
                    'limit': 15,
                    't': 'month'
                }
                
                response = self.session.get(url, params=params, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    
                    for post in data.get('data', {}).get('children', []):
                        post_data = post['data']
                        
                        results.append({
                            'title': post_data.get('title', ''),
                            'content': post_data.get('selftext', ''),
                            'url': f"https://reddit.com{post_data.get('permalink', '')}",
                            'source': 'reddit',
                            'created': datetime.fromtimestamp(post_data.get('created_utc', 0)),
                            'score': post_data.get('score', 0),
                            'subreddit': post_data.get('subreddit', ''),
                            'author': post_data.get('author', ''),
                            'location': location
                        })
                
                time.sleep(1)
        except Exception as e:
            logger.error(f"Reddit search error: {e}")
        
        return results
    
    def search_news(self, topic, location):
        """Search news sources"""
        results = []
        try:
            # Use Bing News API alternative (free tier)
            query = f"{topic} {location}" if location else topic
            
            # Alternative: Use RSS feeds from major news sources
            rss_feeds = [
                'https://feeds.bbci.co.uk/news/rss.xml',
                'https://rss.cnn.com/rss/edition.rss',
                'https://feeds.reuters.com/reuters/topNews'
            ]
            
            for feed_url in rss_feeds:
                try:
                    response = self.session.get(feed_url, timeout=10)
                    if response.status_code == 200:
                        # Simple XML parsing for RSS
                        content = response.text.lower()
                        if topic.lower() in content:
                            if location is None or location.lower() in content:
                                results.append({
                                    'title': f"News mention found for {topic}",
                                    'content': f"Found relevant news content for {topic}" + (f" in {location}" if location else ""),
                                    'url': feed_url,
                                    'source': 'news',
                                    'created': datetime.utcnow(),
                                    'location': location
                                })
                    time.sleep(1)
                except:
                    continue
                    
        except Exception as e:
            logger.error(f"News search error: {e}")
        
        return results
    
    def search_github_specific(self, topic, location):
        """Enhanced GitHub search"""
        results = []
        try:
            queries = [topic]
            if location:
                queries.append(f"{topic} {location}")
            
            for query in queries[:2]:
                url = "https://api.github.com/search/repositories"
                params = {
                    'q': query,
                    'sort': 'updated',
                    'per_page': 10
                }
                
                response = self.session.get(url, params=params, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    
                    for repo in data.get('items', []):
                        results.append({
                            'title': f"Repository: {repo.get('name', '')}",
                            'content': f"Description: {repo.get('description', '')}\nLanguage: {repo.get('language', 'N/A')}\nStars: {repo.get('stargazers_count', 0)}",
                            'url': repo.get('html_url', ''),
                            'source': 'github',
                            'created': datetime.fromisoformat(repo.get('updated_at', '').replace('Z', '+00:00')) if repo.get('updated_at') else datetime.utcnow(),
                            'stars': repo.get('stargazers_count', 0),
                            'language': repo.get('language', ''),
                            'location': location
                        })
                
                time.sleep(2)
        except Exception as e:
            logger.error(f"GitHub search error: {e}")
        
        return results
    
    def search_hackernews_specific(self, topic, location):
        """Enhanced Hacker News search"""
        results = []
        try:
            # Use HN Algolia API
            query = f"{topic} {location}" if location else topic
            url = "https://hn.algolia.com/api/v1/search"
            params = {
                'query': query,
                'tags': 'story',
                'hitsPerPage': 20
            }
            
            response = self.session.get(url, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                
                for hit in data.get('hits', []):
                    results.append({
                        'title': hit.get('title', ''),
                        'content': hit.get('story_text', ''),
                        'url': hit.get('url', f"https://news.ycombinator.com/item?id={hit.get('objectID')}"),
                        'source': 'hackernews',
                        'created': datetime.fromisoformat(hit.get('created_at', '').replace('Z', '+00:00')) if hit.get('created_at') else datetime.utcnow(),
                        'points': hit.get('points', 0),
                        'comments': hit.get('num_comments', 0),
                        'location': location
                    })
        except Exception as e:
            logger.error(f"Hacker News search error: {e}")
        
        return results
    
    def deduplicate_results(self, results):
        """Remove duplicate results"""
        seen_urls = set()
        unique_results = []
        
        for result in results:
            url = result.get('url', '')
            title = result.get('title', '')
            
            # Create a simple hash for deduplication
            content_hash = hashlib.md5(f"{url}{title}".encode()).hexdigest()
            
            if content_hash not in seen_urls:
                seen_urls.add(content_hash)
                unique_results.append(result)
        
        return unique_results
    
    def score_results(self, results, topic, location):
        """Score and sort results by relevance"""
        for result in results:
            score = 0
            title = result.get('title', '').lower()
            content = result.get('content', '').lower()
            topic_lower = topic.lower()
            
            # Title relevance
            if topic_lower in title:
                score += 10
            
            # Content relevance
            if topic_lower in content:
                score += 5
            
            # Location relevance
            if location:
                location_lower = location.lower()
                if location_lower in title:
                    score += 8
                if location_lower in content:
                    score += 4
            
            # Source-specific scoring
            if result.get('source') == 'reddit':
                score += result.get('score', 0) * 0.1
            elif result.get('source') == 'github':
                score += result.get('stars', 0) * 0.1
            elif result.get('source') == 'hackernews':
                score += result.get('points', 0) * 0.2
            
            # Recency bonus
            created = result.get('created', datetime.utcnow())
            days_old = (datetime.utcnow() - created).days
            if days_old < 7:
                score += 5
            elif days_old < 30:
                score += 2
            
            result['relevance_score'] = score
        
        # Sort by relevance score
        return sorted(results, key=lambda x: x.get('relevance_score', 0), reverse=True)

def create_app():
    app = Flask(__name__, template_folder='dashboard')
    
    # Configuration
    app.config['SECRET_KEY'] = 'threat-monitor-secret-key-2024'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///threat_monitor.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # Initialize extensions
    db.init_app(app)
    CORS(app)
    
    # Initialize monitoring engine
    monitor = ThreatMonitor()
    search_engine = SearchEngine()
    
    # Routes
    @app.route('/')
    def dashboard():
        return render_template('dashboard.html')

    @app.route('/api/search', methods=['POST'])
    def search_query():
        """Handle search queries"""
        try:
            data = request.json
            topic = data.get('topic', '').strip()
            location = data.get('location', '').strip() or None
            
            if not topic:
                return jsonify({'error': 'Topic is required'}), 400
            
            logger.info(f"🔍 New search query: '{topic}'" + (f" in '{location}'" if location else ""))
            
            # Save search query
            search_query = SearchQuery(
                topic=topic,
                location=location,
                query_text=f"{topic} {location}" if location else topic
            )
            db.session.add(search_query)
            db.session.commit()
            
            # Perform search
            results = search_engine.search_topic_location(topic, location)
            
            # Save results as alerts for easy viewing
            alerts_created = 0
            for result in results[:20]:  # Limit to top 20 results
                content_str = f"{result['title']}{result['content']}{result['url']}"
                content_hash = hashlib.sha256(content_str.encode()).hexdigest()
                
                # Check if already exists
                existing = Alert.query.filter_by(content_hash=content_hash).first()
                if not existing:
                    alert = Alert(
                        title=result['title'][:200],
                        description=result['content'][:1000] if result['content'] else '',
                        source_url=result['url'],
                        source_type=result['source'],
                        risk_level='low',  # Search results are informational
                        status='new',
                        content_hash=content_hash,
                        location=location,
                        query_type='search'
                    )
                    db.session.add(alert)
                    alerts_created += 1
            
            if alerts_created > 0:
                db.session.commit()
            
            # Update search query with results count
            search_query.results_count = len(results)
            db.session.commit()
            
            logger.info(f"✅ Search completed: {len(results)} results found, {alerts_created} new entries saved")
            
            return jsonify({
                'message': f'Search completed! Found {len(results)} results.',
                'results_count': len(results),
                'alerts_created': alerts_created,
                'results': results[:10]  # Return top 10 for immediate display
            })
            
        except Exception as e:
            logger.error(f"❌ Search error: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/search/history')
    def search_history():
        """Get search history"""
        try:
            queries = SearchQuery.query.order_by(SearchQuery.created_at.desc()).limit(20).all()
            return jsonify([{
                'id': q.id,
                'topic': q.topic,
                'location': q.location,
                'query_text': q.query_text,
                'created_at': q.created_at.isoformat(),
                'results_count': q.results_count
            } for q in queries])
        except Exception as e:
            logger.error(f"❌ Error fetching search history: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/targets', methods=['GET', 'POST'])
    def manage_targets():
        if request.method == 'POST':
            try:
                data = request.json
                
                if isinstance(data['keywords'], str):
                    keywords = [k.strip() for k in data['keywords'].split(',') if k.strip()]
                else:
                    keywords = data['keywords']
                
                target = MonitoringTarget(
                    name=data['name'],
                    target_type=data['target_type']
                )
                target.set_keywords(keywords)
                
                db.session.add(target)
                db.session.commit()
                
                logger.info(f"✅ New monitoring target created: {target.name}")
                return jsonify({'id': target.id, 'message': 'Target created successfully'})
            
            except Exception as e:
                logger.error(f"❌ Error creating target: {e}")
                return jsonify({'error': str(e)}), 500
        
        targets = MonitoringTarget.query.filter_by(active=True).all()
        return jsonify([{
            'id': t.id,
            'name': t.name,
            'keywords': t.get_keywords(),
            'target_type': t.target_type,
            'created_at': t.created_at.isoformat(),
            'alert_count': len([a for a in t.alerts if a.status == 'new'])
        } for t in targets])

    @app.route('/api/targets/<int:target_id>', methods=['DELETE'])
    def delete_target(target_id):
        try:
            target = MonitoringTarget.query.get_or_404(target_id)
            target.active = False
            db.session.commit()
            
            logger.info(f"🗑️ Target deactivated: {target.name}")
            return jsonify({'message': 'Target deactivated successfully'})
        
        except Exception as e:
            logger.error(f"❌ Error deactivating target: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/alerts')
    def get_alerts():
        try:
            page = request.args.get('page', 1, type=int)
            risk_level = request.args.get('risk_level')
            status = request.args.get('status')
            query_type = request.args.get('query_type')  # New filter
            
            query = Alert.query
            
            if risk_level:
                query = query.filter_by(risk_level=risk_level)
            if status:
                query = query.filter_by(status=status)
            if query_type:
                query = query.filter_by(query_type=query_type)
            
            alerts = query.order_by(Alert.created_at.desc()).paginate(
                page=page, per_page=20, error_out=False
            )
            
            return jsonify({
                'alerts': [{
                    'id': a.id,
                    'title': a.title,
                    'description': a.description,
                    'source_url': a.source_url,
                    'source_type': a.source_type,
                    'risk_level': a.risk_level,
                    'status': a.status,
                    'created_at': a.created_at.isoformat(),
                    'target_name': a.target.name if a.target else 'Search Result',
                    'location': a.location,
                    'query_type': a.query_type
                } for a in alerts.items],
                'total': alerts.total,
                'pages': alerts.pages,
                'current_page': page
            })
        
        except Exception as e:
            logger.error(f"❌ Error fetching alerts: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/alerts/<int:alert_id>', methods=['PUT'])
    def update_alert(alert_id):
        try:
            alert = Alert.query.get_or_404(alert_id)
            data = request.json
            
            if 'status' in data:
                alert.status = data['status']
                db.session.commit()
                logger.info(f"📝 Alert {alert_id} status updated to {data['status']}")
            
            return jsonify({'message': 'Alert updated successfully'})
        
        except Exception as e:
            logger.error(f"❌ Error updating alert: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/dashboard/stats')
def dashboard_stats():
    try:
        total_alerts = Alert.query.count()
        new_alerts = Alert.query.filter_by(status='new').count()
        critical_alerts = Alert.query.filter_by(risk_level='critical').count()
        active_targets = MonitoringTarget.query.filter_by(active=True).count()
        
        week_ago = datetime.utcnow() - timedelta(days=7)
        recent_alerts = db.session.query(
            Alert.risk_level,
            db.func.count(Alert.id).label('count')
        ).filter(
            Alert.created_at >= week_ago
        ).group_by(Alert.risk_level).all()
        
        return jsonify({
            'total_alerts': total_alerts,
            'new_alerts': new_alerts,
            'critical_alerts': critical_alerts,
            'active_targets': active_targets,
            'recent_alerts_by_risk': {level: count for level, count in recent_alerts}
        })
    
    except Exception as e:
        logger.error(f"❌ Error fetching dashboard stats: {e}")
        return jsonify({'error': str(e)}), 500