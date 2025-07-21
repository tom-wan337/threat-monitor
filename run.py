# run.py
from app import create_app

if __name__ == "__main__":
    app = create_app()
    
    print("\n" + "="*60)
    print("🛡️  THREAT MONITOR DASHBOARD")
    print("="*60)
    print("🌐 Dashboard: http://localhost:5000")
    print("📊 API Docs: http://localhost:5000/api/dashboard/stats")
    print("🔍 Background monitoring: Every 30 minutes")
    print("="*60 + "\n")
    
    app.run(debug=True, host='0.0.0.0', port=5000)