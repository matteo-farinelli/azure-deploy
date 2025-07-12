# app.py - Versione ottimizzata per Azure con miglioramenti
from flask import Flask, render_template, request, session, jsonify, send_file, redirect, url_for
import pandas as pd
from datetime import datetime, timedelta
import base64
import os
from openpyxl import load_workbook
from openpyxl.worksheet.protection import SheetProtection
import re
from io import BytesIO
import uuid
import secrets
from functools import wraps
import json
import requests
from werkzeug.security import generate_password_hash, check_password_hash
import logging
from threading import Thread
import time

# Configurazione logging per Azure
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Configurazione sicura per Azure
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('HTTPS_ONLY', 'False').lower() == 'true'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = int(os.environ.get('SESSION_TIMEOUT', '3600'))
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Configurazione GitHub
GITHUB_TOKEN = os.environ.get('GITHUB_TOKEN')
GITHUB_REPO = os.environ.get('GITHUB_REPO')
GITHUB_BRANCH = os.environ.get('GITHUB_BRANCH', 'main')
PROGRESS_FILE = 'data/user_progress.json'
LOCAL_PROGRESS_FILE = 'user_progress.json'

# Cache in memoria per ridurre chiamate a GitHub
_data_cache = None
_cache_timestamp = None
CACHE_DURATION = 300  # 5 minuti

def get_cached_data():
    """Restituisce dati dalla cache se validi"""
    global _data_cache, _cache_timestamp
    
    if _data_cache and _cache_timestamp:
        if (datetime.now() - _cache_timestamp).total_seconds() < CACHE_DURATION:
            return _data_cache
    
    return None

def set_cached_data(data):
    """Imposta i dati in cache"""
    global _data_cache, _cache_timestamp
    _data_cache = data
    _cache_timestamp = datetime.now()

def safe_load_from_github():
    """Carica i dati da GitHub con gestione errori sicura e timeout ottimizzato"""
    try:
        # Controlla cache prima
        cached = get_cached_data()
        if cached:
            logger.info("Usando dati dalla cache")
            return cached
        
        if not GITHUB_TOKEN or not GITHUB_REPO:
            logger.warning("Configurazione GitHub mancante")
            return None
        
        url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{PROGRESS_FILE}"
        headers = {
            'Authorization': f'token {GITHUB_TOKEN}',
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'Azure-Flask-App/1.0'
        }
        
        # Timeout ridotto per Azure
        response = requests.get(url, headers=headers, timeout=5)
        
        if response.status_code == 200:
            content = response.json()['content']
            decoded_content = base64.b64decode(content).decode('utf-8')
            data = json.loads(decoded_content)
            
            # Salva in cache
            set_cached_data(data)
            
            logger.info(f"✓ Dati GitHub caricati: {len(data.get('users', {}))} utenti")
            return data
        elif response.status_code == 404:
            logger.warning("File non trovato su GitHub, creazione nuovo file")
            return None
        else:
            logger.warning(f"GitHub API response: {response.status_code}")
            return None
            
    except requests.exceptions.Timeout:
        logger.warning("Timeout connessione GitHub")
        return None
    except requests.exceptions.RequestException as e:
        logger.warning(f"Errore connessione GitHub: {e}")
        return None
    except Exception as e:
        logger.error(f"Errore GitHub (non critico): {e}")
        return None

def initialize_storage():
    """Inizializza storage in modo sicuro con fallback multipli"""
    try:
        logger.info("=== Inizializzazione Storage ===")
        
        # Prova a caricare da GitHub
        github_data = safe_load_from_github()
        
        if github_data:
            # Salva localmente come backup
            try:
                with open(LOCAL_PROGRESS_FILE, 'w', encoding='utf-8') as f:
                    json.dump(github_data, f, indent=2, ensure_ascii=False)
                logger.info("✓ Dati sincronizzati da GitHub")
            except Exception as e:
                logger.warning(f"Impossibile salvare backup locale: {e}")
            return github_data
        
        # Se GitHub non disponibile, usa file locale
        if os.path.exists(LOCAL_PROGRESS_FILE):
            try:
                with open(LOCAL_PROGRESS_FILE, 'r', encoding='utf-8') as f:
                    local_data = json.load(f)
                logger.info("✓ Usando dati locali")
                return local_data
            except Exception as e:
                logger.error(f"Errore lettura file locale: {e}")
        
        # Crea file nuovo
        new_data = {
            "users": {},
            "test_results": [],
            "last_updated": datetime.now().isoformat(),
            "version": "1.0",
            "created_on_azure": True
        }
        
        try:
            with open(LOCAL_PROGRESS_FILE, 'w', encoding='utf-8') as f:
                json.dump(new_data, f, indent=2, ensure_ascii=False)
            logger.info("✓ Creato nuovo file progressi")
        except Exception as e:
            logger.warning(f"Impossibile creare file locale: {e}")
        
        return new_data
        
    except Exception as e:
        logger.error(f"Errore inizializzazione storage: {e}")
        # Return minimal data per evitare crash
        return {
            "users": {},
            "test_results": [],
            "last_updated": datetime.now().isoformat(),
            "error_recovery": True
        }

def load_progress_data():
    """Carica progressi con cache e fallback sicuro"""
    try:
        # Prima controlla la cache
        cached = get_cached_data()
        if cached:
            return cached
        
        # Poi controlla file locale
        if os.path.exists(LOCAL_PROGRESS_FILE):
            with open(LOCAL_PROGRESS_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
                set_cached_data(data)  # Aggiorna cache
                return data
    except Exception as e:
        logger.error(f"Errore caricamento file locale: {e}")
    
    # Fallback: dati vuoti
    fallback_data = {
        "users": {},
        "test_results": [],
        "last_updated": datetime.now().isoformat(),
        "fallback_mode": True
    }
    return fallback_data

def is_admin_user(email):
    """Verifica se l'utente è admin"""
    admin_emails = [
        'admin@auxiell.com',
        'admin@euxilia.com', 
        'admin@xva-services.com'
    ]
    return email.lower() in [e.lower() for e in admin_emails]

def save_progress_data(data):
    """Salva progressi con gestione errori migliorata"""
    try:
        data["last_updated"] = datetime.now().isoformat()
        
        # Aggiorna cache immediatamente
        set_cached_data(data)
        
        # Salva sempre localmente (sincrono)
        try:
            with open(LOCAL_PROGRESS_FILE, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            logger.info("✓ Dati salvati localmente")
        except Exception as e:
            logger.error(f"Errore salvataggio locale: {e}")
            return False
        
        # Salva su GitHub in background (asincrono)
        if GITHUB_TOKEN and GITHUB_REPO:
            Thread(target=save_to_github_async, args=(data.copy(),), daemon=True).start()
        
        return True
        
    except Exception as e:
        logger.error(f"Errore salvataggio: {e}")
        return False

def save_to_github_async(data):
    """Salva su GitHub in modo asincrono con retry"""
    max_retries = 2
    retry_delay = 1
    
    for attempt in range(max_retries):
        try:
            content = json.dumps(data, indent=2, ensure_ascii=False)
            encoded_content = base64.b64encode(content.encode('utf-8')).decode('utf-8')
            
            url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{PROGRESS_FILE}"
            headers = {
                'Authorization': f'token {GITHUB_TOKEN}',
                'Accept': 'application/vnd.github.v3+json',
                'User-Agent': 'Azure-Flask-App/1.0'
            }
            
            # Get SHA if file exists
            try:
                response = requests.get(url, headers=headers, timeout=3)
                sha = response.json()['sha'] if response.status_code == 200 else None
            except:
                sha = None
            
            payload = {
                'message': f'Auto-update progress {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}',
                'content': encoded_content,
                'branch': GITHUB_BRANCH
            }
            
            if sha:
                payload['sha'] = sha
            
            response = requests.put(url, headers=headers, json=payload, timeout=8)
            
            if response.status_code in [200, 201]:
                logger.info("✓ GitHub aggiornato")
                return True
            else:
                logger.warning(f"GitHub error: {response.status_code}")
                
        except requests.exceptions.Timeout:
            logger.warning(f"GitHub timeout (tentativo {attempt + 1})")
        except Exception as e:
            logger.warning(f"GitHub async save error (tentativo {attempt + 1}): {e}")
        
        if attempt < max_retries - 1:
            time.sleep(retry_delay)
    
    logger.error("Fallimento salvataggio GitHub dopo tutti i tentativi")
    return False

# Funzioni helper (invariate ma con logging migliorato)
def get_user_data(email):
    data = load_progress_data()
    return data["users"].get(email, {})

def save_user_data(email, user_info):
    data = load_progress_data()
    data["users"][email] = user_info
    success = save_progress_data(data)
    if not success:
        logger.error(f"Fallimento salvataggio dati utente: {email}")

def get_user_test_results(email):
    data = load_progress_data()
    user_results = []
    for result in data["test_results"]:
        if result.get("user_email") == email:
            user_results.append(result)
    return sorted(user_results, key=lambda x: x.get("completed_at", ""), reverse=True)

def save_test_result(result):
    data = load_progress_data()
    result["id"] = len(data["test_results"]) + 1
    result["completed_at"] = datetime.now().isoformat()
    data["test_results"].append(result)
    success = save_progress_data(data)
    if success:
        logger.info(f"Test result saved for {result.get('user_email')}")
    else:
        logger.error(f"Failed to save test result for {result.get('user_email')}")

def validate_email(email):
    """Valida email aziendale inclusi admin"""
    normal_pattern = r'^[a-zA-Z]+\.[a-zA-Z]+@(auxiell|euxilia|xva-services)\.com$'
    admin_pattern = r'^admin@(auxiell|euxilia|xva-services)\.com$'
    
    return re.match(normal_pattern, email) or re.match(admin_pattern, email)

def extract_company_from_email(email):
    if '@auxiell.com' in email:
        return 'auxiell'
    elif '@euxilia.com' in email:
        return 'euxilia'  
    elif '@xva-services.com' in email:
        return 'xva'
    return None

def extract_name_from_email(email):
    """Estrae nome e cognome dall'email"""
    if email.startswith('admin@'):
        return "Admin", "Sistema"
    
    local_part = email.split('@')[0]
    parts = local_part.split('.')
    if len(parts) >= 2:
        nome = parts[0].title()
        cognome = parts[1].title()
        return nome, cognome
    return "User", "Unknown"

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            logger.warning(f"Unauthorized access attempt to {f.__name__}")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def get_logo_info(azienda_scelta=None):
    if azienda_scelta is None:
        logo_path = "static/images/auxiell_group_logobase.png"
    else:
        nome_logo = re.sub(r'\W+', '_', azienda_scelta.lower()) + "_logobase.png"
        logo_path = os.path.join("static/images", nome_logo)
    
    if os.path.exists(logo_path):
        return logo_path, True
    return logo_path, False

def get_company_color(azienda):
    colori = {
        "auxiell": "#6C757D",
        "euxilia": "#4A90C2", 
        "xva": "#D4AF37"
    }
    return colori.get(azienda.lower() if azienda else "", "#F63366")

def hash_password(password):
    """Cripta la password"""
    return generate_password_hash(password, method='pbkdf2:sha256')

def verify_password(stored_password, provided_password):
    """Verifica la password"""
    return check_password_hash(stored_password, provided_password)

def get_admin_password():
    """Password fissa per admin"""
    return os.environ.get('ADMIN_PASSWORD', 'assessment25')

def validate_password(password):
    """Valida la password con regole più stringenti"""
    if len(password) < 8:
        return False, "La password deve essere di almeno 8 caratteri"
    if not re.search(r'[A-Za-z]', password):
        return False, "La password deve contenere almeno una lettera"
    if not re.search(r'\d', password):
        return False, "La password deve contenere almeno un numero"
    return True, ""

def user_exists(email):
    """Verifica se l'utente esiste già"""
    data = load_progress_data()
    return email in data.get("users", {})

def create_user(email, password, nome, cognome, azienda, is_admin=False):
    """Crea un nuovo utente"""
    data = load_progress_data()
    
    # Per admin, usa password fissa, per utenti normali cripta la password
    if is_admin:
        password_hash = hash_password(get_admin_password())
    else:
        password_hash = hash_password(password)
    
    user_data = {
        'email': email,
        'password_hash': password_hash,
        'nome': nome,
        'cognome': cognome,
        'azienda': azienda,
        'is_admin': is_admin,
        'created_at': datetime.now().isoformat(),
        'last_login': None,
        'login_attempts': 0,
        'locked_until': None
    }
    
    data["users"][email] = user_data
    return save_progress_data(data)

def authenticate_user(email, password):
    """Autentica un utente con protezione brute force"""
    data = load_progress_data()
    user_data = data.get("users", {}).get(email)
    
    if not user_data:
        return False, "Utente non trovato"
    
    # Controlla se l'account è bloccato
    locked_until = user_data.get('locked_until')
    if locked_until:
        try:
            unlock_time = datetime.fromisoformat(locked_until)
            if datetime.now() < unlock_time:
                remaining = (unlock_time - datetime.now()).total_seconds() / 60
                return False, f"Account bloccato. Riprova tra {int(remaining)} minuti"
        except:
            pass
    
    # Verifica password
    password_correct = False
    if is_admin_user(email):
        password_correct = password == get_admin_password()
    else:
        password_correct = verify_password(user_data.get('password_hash', ''), password)
    
    if password_correct:
        # Reset login attempts on successful login
        user_data['login_attempts'] = 0
        user_data['locked_until'] = None
        save_user_data(email, user_data)
        return True, user_data
    else:
        # Increment login attempts
        attempts = user_data.get('login_attempts', 0) + 1
        user_data['login_attempts'] = attempts
        
        # Lock account after 5 failed attempts
        if attempts >= 5:
            user_data['locked_until'] = (datetime.now() + timedelta(minutes=30)).isoformat()
            save_user_data(email, user_data)
            return False, "Account bloccato per troppi tentativi falliti. Riprova tra 30 minuti"
        
        save_user_data(email, user_data)
        return False, f"Password errata. Tentativi rimasti: {5 - attempts}"

# Error handlers per Azure
@app.errorhandler(404)
def not_found_error(error):
    logger.warning(f"404 error: {request.url}")
    return render_template('error.html', error='Pagina non trovata'), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"500 error: {error}")
    return render_template('error.html', error='Errore interno del server'), 500

@app.errorhandler(413)
def too_large(error):
    return render_template('error.html', error='File troppo grande. Dimensione massima: 16MB'), 413

# Routes (continua con le routes esistenti...)

# Health check migliorato per Azure
@app.route('/health')
def health_check():
    try:
        data = load_progress_data()
        github_status = "connected" if GITHUB_TOKEN and GITHUB_REPO else "not_configured"
        
        # Test connessione GitHub
        if github_status == "connected":
            try:
                url = f"https://api.github.com/repos/{GITHUB_REPO}"
                response = requests.get(url, timeout=3)
                github_status = "healthy" if response.status_code == 200 else "unhealthy"
            except:
                github_status = "unreachable"
        
        return jsonify({
            'status': 'healthy',
            'users_count': len(data.get('users', {})),
            'results_count': len(data.get('test_results', [])),
            'github_status': github_status,
            'local_file_exists': os.path.exists(LOCAL_PROGRESS_FILE),
            'cache_active': _data_cache is not None,
            'timestamp': datetime.now().isoformat(),
            'azure_environment': os.environ.get('WEBSITE_SITE_NAME', 'local')
        })
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({
            'status': 'error',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500

# Endpoint per Azure monitoring
@app.route('/status')
def status():
    """Endpoint semplificato per Azure health probe"""
    return "OK", 200

# Routes principali (usa le routes esistenti dal tuo codice...)
# [Inserisci qui tutte le altre routes del tuo codice originale]

# Inizializzazione sicura all'avvio
def startup_initialization():
    """Inizializzazione sicura con retry"""
    max_attempts = 3
    for attempt in range(max_attempts):
        try:
            logger.info(f"=== Tentativo inizializzazione {attempt + 1}/{max_attempts} ===")
            initialize_storage()
            logger.info("=== App Pronta ===")
            return True
        except Exception as e:
            logger.error(f"Tentativo {attempt + 1} fallito: {e}")
            if attempt < max_attempts - 1:
                time.sleep(2)
    
    logger.warning("Inizializzazione completata con errori - App in modalità degradata")
    return False

if __name__ == '__main__':
    startup_initialization()
    port = int(os.environ.get('PORT', 8000))
    debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=debug)
else:
    # IMPORTANTE: Per Azure/Gunicorn WSGI
    startup_initialization()
