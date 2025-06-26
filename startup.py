import os
import json
from datetime import datetime

def create_initial_progress_file():
    """Crea il file di progresso iniziale se non esiste"""
    progress_file = 'user_progress.json'
    
    if not os.path.exists(progress_file):
        initial_data = {
            "users": {},
            "test_results": [],
            "last_updated": datetime.now().isoformat()
        }
        
        try:
            with open(progress_file, 'w', encoding='utf-8') as f:
                json.dump(initial_data, f, indent=2, ensure_ascii=False)
            print(f"✓ File progressi creato: {progress_file}")
        except Exception as e:
            print(f"✗ Errore creazione file progressi: {e}")
    else:
        print(f"✓ File progressi già esistente: {progress_file}")

def azure_startup():
    """Inizializzazione per Azure"""
    try:
        print("=== Azure Startup con GitHub Storage ===")
        
        # Verifica file essenziali
        required_files = ['app.py', 'requirements.txt']
        for file in required_files:
            if os.path.exists(file):
                print(f"✓ {file} trovato")
            else:
                print(f"✗ {file} mancante!")
        
        # Crea directory
        os.makedirs('templates', exist_ok=True)
        os.makedirs('static/images', exist_ok=True)
        os.makedirs('repository_test', exist_ok=True)
        os.makedirs('data', exist_ok=True)
        print("✓ Directory create")
        
        # Crea file progressi
        create_initial_progress_file()
        
        # Verifica variabili d'ambiente GitHub
        github_token = os.environ.get('GITHUB_TOKEN')
        github_repo = os.environ.get('GITHUB_REPO')
        
        if github_token and github_repo:
            print(f"✓ GitHub configurato: {github_repo}")
        else:
            print("⚠ GitHub non configurato - i progressi saranno salvati solo localmente")
        
        print("=== Startup completato ===")
        return True
        
    except Exception as e:
        print(f"✗ Errore startup: {e}")
        return False

if __name__ == "__main__":
    azure_startup()
