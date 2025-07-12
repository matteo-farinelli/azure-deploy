# startup.py - Entry point per Azure App Service
"""
Questo file serve come punto di ingresso per Azure App Service.
Azure cerca automaticamente questo file per avviare l'applicazione Flask.
"""

import os
import sys
import traceback

# Debug per Azure
print("=== AZURE STARTUP DEBUG ===")
print(f"Python version: {sys.version}")
print(f"Current directory: {os.getcwd()}")
print(f"Files in directory: {os.listdir('.')}")
print(f"PORT environment: {os.environ.get('PORT', 'NOT SET')}")

try:
    # Import app con gestione errori
    print("Importing app...")
    from app import app
    print("App imported successfully!")
    
    # Test dell'app
    print("Testing app...")
    with app.test_client() as client:
        response = client.get('/health')
        print(f"Health check status: {response.status_code}")
    
    print("App test successful!")
    
except Exception as e:
    print(f"=== STARTUP ERROR ===")
    print(f"Error: {e}")
    print(f"Traceback:")
    traceback.print_exc()
    
    # Non interrompere, lascia che Azure provi comunque
    print("Continuing despite error...")

# Per quando viene eseguito direttamente
if __name__ == "__main__":
    port = int(os.environ.get('PORT', 8000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    
    print(f"Starting Flask app on port {port}")
    print(f"Debug mode: {debug}")
    
    try:
        app.run(
            host='0.0.0.0',
            port=port,
            debug=debug,
            use_reloader=False  # Importante per Azure
        )
    except Exception as e:
        print(f"Failed to start app: {e}")
        traceback.print_exc()

# Per WSGI (Gunicorn) - questo è il punto importante per Azure
print("Startup.py loaded - app object available for WSGI")
