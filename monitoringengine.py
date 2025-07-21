# monitoringengine.py
import requests
import hashlib
import re
from datetime import datetime, timedelta
from models import db, Alert, MonitoringTarget
from config import Config
import time
import logging
import urllib.parse

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
        
        if not targets:
            logger.info("No active targets found")
            return 0
        
        for target in targets:
            try:
                keywords = target.get_keywords()
                if keywords:
                    alerts_created = self.monitor_target(target, keywords)
                    total_alerts += alerts_created
                    logger.info(f"Target '{target.name}': {alerts_created} new alerts")
                    time.sleep(2)
                
            except Exception as e:
                logger.error(f"Error monitoring target {target.name}: {e}")
        
        logger.info(f"Monitoring scan completed. Total new alerts: {total_alerts}")
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
                    logger.info(f"  {source_name}: {alerts} alerts")
                time.sleep(1)
            except Exception as e:
                logger.error(f"Error in {source_name}: {e}")
        
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