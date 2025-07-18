# app/routes.py
from flask import request, jsonify, render_template
from models import db, Alert, MonitoringTarget, SearchQuery
import logging
import json
import hashlib
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

def register_routes(app, monitor, search_engine):
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

    @app.route('/api/scan/manual', methods=['POST'])
    def manual_scan():
        """Trigger manual monitoring scan"""
        try:
            logger.info("🚀 Manual scan triggered")
            with app.app_context():
                alerts_created = monitor.monitor_all_targets(app)
            return jsonify({
                'message': f'Manual scan completed. {alerts_created} new alerts created.',
                'alerts_created': alerts_created
            })
        except Exception as e:
            logger.error(f"❌ Manual scan error: {e}")
            return jsonify({'error': str(e)}), 500