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
import logging
from threading import Thread
import time
import hashlib
from azure.data.tables import TableServiceClient, TableEntity
from azure.core.exceptions import ResourceNotFoundError
from azure_storage import *
import time
import hashlib
from typing import Dict, Any, Optional

class AppCache:
    """Sistema di caching ottimizzato per l'app Assessment"""
    
    def __init__(self, default_ttl: int = 30):
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.default_ttl = default_ttl
        self.stats = {
            'hits': 0,
            'misses': 0,
            'saves': 0,
            'queries_avoided': 0
        }
    
    def _generate_key(self, user_email: str, operation: str, extra: str = "") -> str:
        """Genera chiave cache univoca"""
        key_data = f"{user_email}_{operation}_{extra}"
        return hashlib.md5(key_data.encode()).hexdigest()[:16]
    
    def get(self, user_email: str, operation: str, extra: str = "") -> Optional[Any]:
        """Recupera dati dal cache"""
        key = self._generate_key(user_email, operation, extra)
        
        if key in self.cache:
            entry = self.cache[key]
            if time.time() < entry['expires_at']:
                self.stats['hits'] += 1
                self.stats['queries_avoided'] += 1
                logger.info(f"📋 Cache HIT: {operation} for {user_email}")
                return entry['data']
            else:
                del self.cache[key]
        
        self.stats['misses'] += 1
        logger.info(f"❌ Cache MISS: {operation} for {user_email}")
        return None
    
    def set(self, user_email: str, operation: str, data: Any, extra: str = "", ttl: int = None) -> None:
        """Salva dati nel cache"""
        key = self._generate_key(user_email, operation, extra)
        expires_at = time.time() + (ttl or self.default_ttl)
        
        self.cache[key] = {
            'data': data,
            'expires_at': expires_at,
            'created_at': time.time()
        }
        
        self.stats['saves'] += 1
        logger.info(f"💾 Cache SET: {operation} for {user_email} (TTL: {ttl or self.default_ttl}s)")
    
    def invalidate(self, user_email: str, operation: str = None, extra: str = "") -> None:
        """Invalida cache per utente/operazione"""
        if operation:
            key = self._generate_key(user_email, operation, extra)
            if key in self.cache:
                del self.cache[key]
                logger.info(f"🗑️ Cache INVALIDATED: {operation} for {user_email}")
        else:
            # Invalida tutto per l'utente
            keys_to_delete = []
            for key, entry in self.cache.items():
                if user_email in str(entry.get('data', '')):  # Semplice check
                    keys_to_delete.append(key)
            
            for key in keys_to_delete:
                del self.cache[key]
            
            logger.info(f"🗑️ Cache CLEARED for user: {user_email}")
    
    def get_stats(self) -> dict:
        """Statistiche cache"""
        total_requests = self.stats['hits'] + self.stats['misses']
        hit_rate = (self.stats['hits'] / max(1, total_requests)) * 100
        
        return {
            'cache_hits': self.stats['hits'],
            'cache_misses': self.stats['misses'],
            'total_requests': total_requests,
            'hit_rate_percent': round(hit_rate, 1),
            'queries_avoided': self.stats['queries_avoided'],
            'cache_entries': len(self.cache),
            'memory_usage_kb': round(len(str(self.cache)) / 1024, 2)
        }

# Istanza globale del cache
app_cache = AppCache(default_ttl=30)

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
AZURE_STORAGE_CONNECTION_STRING = os.environ.get('AZURE_STORAGE_CONNECTION_STRING')
TABLE_NAME_USERS = 'users'
TABLE_NAME_RESULTS = 'testresults'

def load_progress_data():
    """Carica tutti i dati da Azure Tables"""
    try:
        users = get_all_users_azure_only()
        test_results = get_all_test_results_azure_only()

        return {
            "users": users,
            "test_results": test_results,
            "last_updated": datetime.now().isoformat(),
            "source": "azure_tables"
        }
    except Exception as e:
        logger.error(f"❌ ERRORE CRITICO load_progress_data: {e}")
        raise Exception(f"Impossibile caricare dati: {e}")

def is_admin_user(email):
    """Verifica se l'utente è admin"""
    admin_emails = [
        'admin@auxiell.com',
        'admin@euxilia.com', 
        'admin@xva-services.com'
    ]
    return email.lower() in [e.lower() for e in admin_emails]
# ==== FUNZIONI WRAPPER CACHED ====

def get_user_test_results_cached(user_email):
    """Versione cached di get_user_test_results_latest_only"""
    
    # Controlla cache
    cached_results = app_cache.get(user_email, "test_results_latest")
    if cached_results is not None:
        return cached_results
    
    # Esegui query reale
    logger.info(f"🔍 QUERY REALE: test results per {user_email}")
    results = get_user_test_results_latest_only(user_email)
    
    # Salva nel cache (30 secondi)
    app_cache.set(user_email, "test_results_latest", results, ttl=30)
    
    return results

def get_user_test_results_all_attempts_cached(user_email):
    """Versione cached di get_user_test_results_all_attempts_azure_only"""
    
    cached_results = app_cache.get(user_email, "test_results_all")
    if cached_results is not None:
        return cached_results
    
    logger.info(f"🔍 QUERY REALE: tutti i tentativi per {user_email}")
    results = get_user_test_results_all_attempts_azure_only(user_email)
    
    # Cache per 45 secondi (dati meno frequenti)
    app_cache.set(user_email, "test_results_all", results, ttl=45)
    
    return results

def check_if_test_allows_retry_cached(user_email, test_name):
    """Versione cached di check_if_test_allows_retry"""
    
    cached_result = app_cache.get(user_email, "retry_check", test_name)
    if cached_result is not None:
        return cached_result
    
    logger.info(f"🔍 QUERY REALE: retry check per {user_email}/{test_name}")
    
    try:
        from azure_storage import check_if_test_allows_retry as azure_check
        result = azure_check(user_email, test_name)
    except Exception as e:
        logger.error(f"Error checking retry permission: {e}")
        result = False
    
    # Cache per meno tempo (15 secondi) - può cambiare rapidamente
    app_cache.set(user_email, "retry_check", result, test_name, ttl=15)
    
    return result

def get_dashboard_data_cached(user_email, azienda_scelta):
    """Dashboard completa con caching ottimizzato"""
    
    # Controlla cache dashboard completa
    cached_dashboard = app_cache.get(user_email, "dashboard_complete", azienda_scelta)
    if cached_dashboard is not None:
        return cached_dashboard
    
    logger.info(f"🔍 BUILDING DASHBOARD: {user_email} ({azienda_scelta})")
    
    # Recupera dati (usando versioni cached)
    completed_tests = get_user_test_results_cached(user_email)
    completed_test_names = [test['test_name'] for test in completed_tests]
    
    available_tests = []
    
    try:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        tipologie_file = os.path.join(base_dir, "repository_test", "Tipologia Test.xlsx")

        if os.path.exists(tipologie_file):
            df_tipologie = pd.read_excel(tipologie_file)

            if "Nome test" in df_tipologie.columns:
                def azienda_match(azienda_cell, azienda_utente):
                    if pd.isna(azienda_cell) or not azienda_cell:
                        return False
                    aziende_test = [a.strip().lower() for a in str(azienda_cell).split(";")]
                    return azienda_utente.lower() in aziende_test

                for _, row in df_tipologie.iterrows():
                    test_name = row["Nome test"]

                    test_available = True
                    if "Azienda" in df_tipologie.columns and pd.notna(row["Azienda"]):
                        test_available = azienda_match(row["Azienda"], azienda_scelta)

                    if test_available:
                        is_completed = test_name in completed_test_names
                        
                        # USA LA VERSIONE CACHED
                        can_retry = check_if_test_allows_retry_cached(user_email, test_name)
                        
                        available_tests.append({
                            'name': test_name,
                            'completed': is_completed,
                            'can_attempt': not is_completed or can_retry,
                            'attempts_count': count_user_test_attempts(user_email, test_name)
                        })
                        
    except Exception as e:
        logger.error(f"Error loading tests: {e}")
    
    # Prepara risultato dashboard
    dashboard_data = {
        'completed_tests': completed_tests,
        'available_tests': available_tests,
        'cache_info': {
            'generated_at': datetime.now().isoformat(),
            'user_email': user_email,
            'azienda': azienda_scelta
        }
    }
    
    # Cache dashboard per 60 secondi
    app_cache.set(user_email, "dashboard_complete", dashboard_data, azienda_scelta, ttl=60)
    
    return dashboard_data
# Funzioni helper
def get_user_data(email):
    """Recupera dati utente SOLO da Azure Table Storage"""
    return get_user_data_azure_only(email)

def save_user_data(email, user_info):
    """Salva dati utente SOLO su Azure Table Storage"""
    return save_user_data_azure_only(email, user_info)

def get_user_test_results(email):
    """Recupera risultati test SOLO da Azure Table Storage"""
    return get_user_test_results_azure_only(email)

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
def save_test_result(result):
    """Salva risultato test con gestione tentativi multipli"""
    try:
        user_email = result.get('user_email')
        test_name = result.get('test_name')
        
        if not user_email or not test_name:
            logger.error("Missing user_email or test_name in result")
            return False
        
        # Recupera risultati esistenti per questo utente e test
        existing_results = get_user_test_results_all_attempts(user_email, test_name)
        
        # Calcola il numero del tentativo
        attempt_number = len(existing_results) + 1
        
        # Aggiungi metadati al risultato
        result.update({
            'attempt_number': attempt_number,
            'is_latest': True,
            'created_at': datetime.now().isoformat(),
            'completed_at': result.get('completed_at', datetime.now().isoformat())
        })
        
        # Marca i risultati precedenti come non più "latest"
        if existing_results:
            for old_result in existing_results:
                update_result_latest_status(user_email, test_name, old_result.get('created_at'), False)
        
        # Salva il nuovo risultato
        return save_test_result_azure_only(result)
        
    except Exception as e:
        logger.error(f"Error saving test result: {e}")
        return False

def get_user_test_results_all_attempts(user_email, test_name=None):
    """Recupera TUTTI i tentativi di test per un utente"""
    try:
        from azure_storage import get_table_service_with_retry, TABLE_NAME_RESULTS
        
        service = get_table_service_with_retry()
        if not service:
            return []
        
        # CORREZIONE: Usa table_client invece di service direttamente
        table_client = service.get_table_client(TABLE_NAME_RESULTS)
        
        # Query per tutti i risultati dell'utente
        if test_name:
            filter_query = f"PartitionKey eq '{user_email}' and test_name eq '{test_name}'"
        else:
            filter_query = f"PartitionKey eq '{user_email}'"
        
        # CORREZIONE: Usa table_client.query_entities invece di service.query_entities
        entities = list(table_client.query_entities(query_filter=filter_query))
        
        results = []
        for entity in entities:
            result = {
                'user_email': entity.get('PartitionKey', ''),
                'test_name': entity.get('test_name', ''),
                'azienda': entity.get('azienda', ''),
                'score': entity.get('score', 0),
                'correct_answers': entity.get('correct_answers', 0),
                'total_questions': entity.get('total_questions', 0),
                'answers_json': entity.get('answers_json', ''),
                'completed_at': entity.get('completed_at', ''),
                'created_at': entity.get('created_at', ''),
                'attempt_number': entity.get('attempt_number', 1),
                'is_latest': entity.get('is_latest', True)
            }
            results.append(result)
        
        # Ordina per data di creazione
        results.sort(key=lambda x: x.get('created_at', ''), reverse=True)
        return results
        
    except Exception as e:
        logger.error(f"Error getting all test attempts: {e}")
        return []
        
def get_user_test_results_latest_only(user_email):
    """Recupera solo gli ultimi tentativi per ogni test"""
    try:
        all_results = get_user_test_results_all_attempts(user_email)
        
        # Filtra solo i risultati "latest"
        latest_results = [r for r in all_results if r.get('is_latest', True)]
        return latest_results
        
    except Exception as e:
        logger.error(f"Error getting latest test results: {e}")
        return []

def update_result_latest_status(user_email, test_name, created_at, is_latest):
    """Aggiorna lo status is_latest di un risultato specifico"""
    try:
        from azure_storage import get_table_service_with_retry, TABLE_NAME_RESULTS
        
        service = get_table_service_with_retry()
        if not service:
            return False
        
        # CORREZIONE: Usa table_client
        table_client = service.get_table_client(TABLE_NAME_RESULTS)
        
        # Trova l'entità specifica usando created_at come RowKey
        row_key = created_at.replace(':', '-').replace('.', '-')
        
        try:
            entity = table_client.get_entity(
                partition_key=user_email,
                row_key=row_key
            )
            
            # Aggiorna solo il campo is_latest
            entity['is_latest'] = is_latest
            
            table_client.update_entity(
                entity=entity,
                mode='replace'
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Entity not found or update failed: {e}")
            return False
            
    except Exception as e:
        logger.error(f"Error updating latest status: {e}")
        return False

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
def optimize_session_data():
    """Ottimizza i dati della sessione per evitare cookie troppo grandi"""
    try:
        # Rimuovi dati pesanti dalla sessione
        if "domande_selezionate" in session and len(str(session["domande_selezionate"])) > 2000:
            # Salva solo gli ID delle domande invece dell'intero contenuto
            domande = session["domande_selezionate"]
            session["domande_count"] = len(domande) if domande else 0
            # Non salvare il contenuto completo nella sessione
            del session["domande_selezionate"]
        
        if "risposte" in session and len(str(session["risposte"])) > 1000:
            # Rimuovi le risposte dalla sessione dopo il salvataggio
            del session["risposte"]
        
        session.modified = True
        logger.info("Session data optimized")
    except Exception as e:
        logger.warning(f"Session optimization failed: {e}")
def hash_password(password):
    """Cripta la password usando SHA-256"""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()
def get_user_test_results_all_attempts_azure_only(user_email):
    """Recupera TUTTI i tentativi di test da Azure per un utente specifico"""
    try:
        from azure_storage import get_table_service_with_retry, TABLE_NAME_RESULTS
        
        service = get_table_service_with_retry()
        if not service:
            logger.error("Azure Table service not available")
            return []
        
        # CORREZIONE: Usa table_client invece di service direttamente
        table_client = service.get_table_client(TABLE_NAME_RESULTS)
        
        # Query per tutti i risultati dell'utente
        filter_query = f"PartitionKey eq '{user_email}'"
        
        # CORREZIONE: query_entities sul table_client, non sul service
        entities = table_client.query_entities(query_filter=filter_query)
        
        results = []
        for entity in entities:
            result = {
                'user_email': entity.get('PartitionKey', ''),
                'test_name': entity.get('test_name', ''),
                'azienda': entity.get('azienda', ''),
                'score': entity.get('score', 0),
                'correct_answers': entity.get('correct_answers', 0),
                'total_questions': entity.get('total_questions', 0),
                'answers_json': entity.get('answers_json', ''),
                'completed_at': entity.get('completed_at', ''),
                'created_at': entity.get('created_at', ''),
                'attempt_number': entity.get('attempt_number', 1),
                'is_latest': entity.get('is_latest', True)
            }
            results.append(result)
        
        # Ordina per data di creazione (più recenti prima)
        results.sort(key=lambda x: x.get('created_at', ''), reverse=True)
        
        logger.info(f"Retrieved {len(results)} test results for user {user_email}")
        return results
        
    except Exception as e:
        logger.error(f"Error getting all attempts for {user_email}: {e}")
        return []
def verify_password(stored_password, provided_password):
    """Verifica la password"""
    return stored_password == hash_password(provided_password)

def validate_password(password):
    if len(password) < 6:
        return False, "La password deve essere di almeno 6 caratteri"
    return True, ""

def create_user(email, password, nome, cognome, azienda, is_admin=False):
    """Crea un nuovo utente"""
    try:

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

        # USA AZURE
        return save_user_data_azure_only(email, user_data)

    except Exception as e:
        logger.error(f"❌ Errore create_user: {e}")
        return False

def authenticate_user(email, password):
    """Autentica un utente - TUTTI usano hash, nessuna eccezione"""
    try:
        # USA AZURE per recuperare utente
        user_data = get_user_data_azure_only(email)

        if not user_data:
            return False, "Utente non trovato"

        # TUTTI gli utenti (admin compresi) usano SOLO hash - nessuna eccezione
        password_correct = verify_password(user_data.get('password_hash', ''), password)

        if password_correct:
            return True, user_data
        else:
            return False, "Password errata"

    except Exception as e:
        logger.error(f"❌ Errore authenticate_user: {e}")
        return False, f"Errore autenticazione: {e}"

# Error handlers per Azure
@app.errorhandler(404)
def not_found_error(error):
    logger.warning(f"404 error: {request.url}")
    return render_template('error.html', error='Pagina non trovata'), 404

@app.route('/hash-generator', methods=['GET', 'POST'])
def hash_generator():
    """Generatore hash password con form"""
    if request.method == 'POST':
        password = request.form.get('password', '').strip()
        
        if not password:
            return render_template_string(HASH_FORM_TEMPLATE, 
                                        error="Inserisci una password")
        
        try:
            password_hash = hash_password(password)
            return render_template_string(HASH_FORM_TEMPLATE, 
                                        password=password, 
                                        hash_result=password_hash)
        except Exception as e:
            return render_template_string(HASH_FORM_TEMPLATE, 
                                        error=f"Errore: {e}")
    
    # GET request - mostra form
    return render_template_string(HASH_FORM_TEMPLATE)

# Template HTML per il form
HASH_FORM_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Password Hash Generator</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header bg-primary text-white">
                        <h4 class="mb-0">Password Hash Generator</h4>
                    </div>
                    <div class="card-body">
                        {% if error %}
                        <div class="alert alert-danger">{{ error }}</div>
                        {% endif %}
                        
                        <form method="POST">
                            <div class="mb-3">
                                <label class="form-label">Password da convertire:</label>
                                <input type="password" class="form-control" name="password" 
                                       placeholder="Inserisci la password" required>
                            </div>
                            <button type="submit" class="btn btn-primary">Genera Hash</button>
                        </form>
                        
                        {% if hash_result %}
                        <hr>
                        <h5>Risultato:</h5>
                        <div class="mb-3">
                            <label class="form-label">Password inserita:</label>
                            <div class="bg-light p-2 border rounded">{{ password }}</div>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Hash SHA-256:</label>
                            <div class="bg-light p-2 border rounded" style="word-break: break-all; font-family: monospace;">
                                {{ hash_result }}
                            </div>
                        </div>
                        <button class="btn btn-success" onclick="copyHash()">Copia Hash</button>
                        
                        <hr>
                        <div class="alert alert-info">
                            <strong>Istruzioni Azure:</strong><br>
                            1. Vai su Azure Portal → Storage Account → Tables<br>
                            2. Apri la tabella "users"<br>
                            3. Trova l'account admin<br>
                            4. Modifica il campo "password_hash"<br>
                            5. Incolla l'hash copiato
                        </div>
                        {% endif %}
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <script>
    function copyHash() {
        const hashText = document.querySelector('div[style*="word-break"] ').textContent.trim();
        navigator.clipboard.writeText(hashText).then(function() {
            alert('Hash copiato negli appunti!');
        });
    }
    </script>
</body>
</html>
'''
@app.errorhandler(500)
def internal_error(error):
    logger.error(f"500 error: {error}")
    return render_template('error.html', error='Errore interno del server'), 500

@app.errorhandler(413)
def too_large(error):
    return render_template('error.html', error='File troppo grande. Dimensione massima: 16MB'), 413

# ===== ROUTES PRINCIPALI =====

@app.route('/')
def index():
    if session.get('logged_in'):
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '').strip()

        if not validate_email(email):
            return render_template('login.html', 
                                 error='Email non valida. Usa il formato nome.cognome@azienda.com o admin@azienda.com',
                                 azienda='auxiell',
                                 company_color='#6C757D')

        if not password:
            return render_template('login.html', 
                                 error='Inserisci la password',
                                 azienda='auxiell',
                                 company_color='#6C757D')

        try:
            # Autentica l'utente (USA SOLO AZURE)
            user_data = get_user_data(email)

            if not user_data:
                return render_template('login.html', 
                                     error='Utente non trovato',
                                     azienda='auxiell',
                                     company_color='#6C757D')

            # Verifica password
            password_correct = verify_password(user_data.get('password_hash', ''), password)
            if not password_correct:
                return render_template('login.html', 
                                     error='Password errata',
                                     azienda='auxiell',
                                     company_color='#6C757D')

            # Aggiorna ultimo login (SU AZURE)
            user_data['last_login'] = datetime.now().isoformat()
            save_user_data(email, user_data)

            # Imposta la sessione
            session['logged_in'] = True
            session['user_email'] = email
            session['utente'] = f"{user_data['nome']} {user_data['cognome']}"
            session['azienda_scelta'] = user_data['azienda']
            session['is_admin'] = user_data['is_admin']
            session.permanent = True

            logger.info(f"✅ Login successful: {email} (Admin: {user_data['is_admin']})")

            # Redirect
            if user_data['is_admin']:
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('dashboard'))

        except Exception as e:
            logger.error(f"❌ Errore login: {e}")
            return render_template('login.html', 
                                 error='Errore server. Verifica la connessione.',
                                 azienda='auxiell',
                                 company_color='#6C757D')

    # GET request
    return render_template('login.html',
                          azienda='auxiell',
                          company_color='#6C757D')

@app.route('/debug/test-retry-check/<user_email>/<test_name>')
@login_required
def debug_test_retry_check(user_email, test_name):
    """Debug: testa la funzione check_if_test_allows_retry"""
    if not is_admin_user(session.get('user_email')):
        return "Accesso negato", 403
    
    try:
        from azure_storage import get_table_service_with_retry
        
        service = get_table_service_with_retry()
        table_client = service.get_table_client('testresets')
        
        # Test la query esatta che usa la funzione
        filter_query = f"PartitionKey eq '{user_email}' and test_name eq '{test_name}' and is_active eq true"
        entities = list(table_client.query_entities(query_filter=filter_query))
        
        # Mostra anche tutti i test_name disponibili
        all_flags_query = f"PartitionKey eq '{user_email}'"
        all_entities = list(table_client.query_entities(query_filter=all_flags_query))
        
        available_tests = [e.get('test_name') for e in all_entities]
        
        return jsonify({
            'user_email': user_email,
            'test_name_searched': test_name,
            'query_used': filter_query,
            'matching_entities': len(entities),
            'entities_found': [{'test_name': e.get('test_name'), 'is_active': e.get('is_active')} for e in entities],
            'all_available_test_names': available_tests,
            'can_retry_result': len(entities) > 0
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/debug/check-flags/<user_email>')
@login_required
def debug_check_flags(user_email):
    """Debug: controlla i flag di reset per un utente"""
    if not is_admin_user(session.get('user_email')):
        return "Accesso negato", 403
    
    try:
        from azure_storage import get_table_service_with_retry
        
        service = get_table_service_with_retry()
        table_client = service.get_table_client('testresets')
        
        # Cerca tutti i flag per questo utente
        filter_query = f"PartitionKey eq '{user_email}'"
        entities = list(table_client.query_entities(query_filter=filter_query))
        
        flags_info = []
        for entity in entities:
            flags_info.append({
                'test_name': entity.get('test_name'),
                'is_active': entity.get('is_active'),
                'created_at': entity.get('created_at'),
                'used_at': entity.get('used_at'),
                'admin_email': entity.get('admin_email')
            })
        
        return jsonify({
            'user_email': user_email,
            'flags_count': len(flags_info),
            'flags': flags_info
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
@app.route('/debug/test-register')
def debug_test_register():
    """Test registrazione step by step"""
    try:
        # Test 1: Azure connection
        logger.info("=== DEBUG REGISTRAZIONE ===")

        # Test connessione Azure
        from azure_storage import get_table_service_with_retry, save_user_data_azure_only

        service = get_table_service_with_retry()
        logger.info("✅ Connessione Azure OK")

        # Test 2: Creazione utente di test
        email_test = "test.debug@auxiell.com"
        user_data_test = {
            'email': email_test,
            'password_hash': 'test_hash',
            'nome': 'Test',
            'cognome': 'Debug',
            'azienda': 'auxiell',
            'is_admin': False,
            'created_at': datetime.now().isoformat(),
            'last_login': None
        }

        logger.info("📝 Tentativo salvataggio utente test...")
        success = save_user_data_azure_only(email_test, user_data_test)

        if success:
            logger.info("✅ Utente test salvato!")

            # Test 3: Recupero utente
            from azure_storage import get_user_data_azure_only
            recovered = get_user_data_azure_only(email_test)

            if recovered:
                logger.info("✅ Utente test recuperato!")
                return jsonify({
                    "status": "success",
                    "message": "Test registrazione completato",
                    "user_saved": True,
                    "user_recovered": True,
                    "user_data": recovered
                })
            else:
                return jsonify({
                    "status": "error",
                    "message": "Utente salvato ma non recuperato",
                    "user_saved": True,
                    "user_recovered": False
                })
        else:
            return jsonify({
                "status": "error",
                "message": "Impossibile salvare utente test",
                "user_saved": False
            })

    except Exception as e:
        logger.error(f"❌ Debug registrazione fallito: {e}")
        return jsonify({
            "status": "error", 
            "error": str(e),
            "message": "Errore durante test registrazione"
        }), 500
@app.route('/test-error')  
def test_error():
    """Forza un errore per vedere error handler"""
    raise Exception("Test errore intenzionale")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '').strip()
        password_confirm = request.form.get('password_confirm', '').strip()

        logger.info(f"📝 Tentativo registrazione: {email}")

        # Validazione email
        if not validate_email(email):
            logger.warning(f"❌ Email non valida: {email}")
            return render_template('register.html', 
                                 error='Email non valida. Usa il formato nome.cognome@azienda.com',
                                 azienda='auxiell',
                                 company_color='#6C757D')

        # Non permettere admin
        if email.startswith('admin@'):
            logger.warning(f"❌ Tentativo registrazione admin: {email}")
            return render_template('register.html', 
                                 error='Non puoi registrare un account admin',
                                 azienda='auxiell',
                                 company_color='#6C757D')

        try:
            logger.info(f"🔍 Verifica utente esistente: {email}")
            # Verifica se l'utente esiste già (SU AZURE)
            existing_user = get_user_data(email)
            if existing_user:
                logger.warning(f"❌ Utente già esistente: {email}")
                return render_template('register.html', 
                                     error='Email già registrata. Usa il login.',
                                     azienda='auxiell',
                                     company_color='#6C757D')

            logger.info(f"✅ Utente non esistente, procedo con registrazione: {email}")

        except Exception as e:
            logger.error(f"❌ Errore verifica utente esistente {email}: {e}")
            return render_template('register.html', 
                                 error=f'Errore verifica utente: {str(e)}',  # ← MOSTRA ERRORE SPECIFICO
                                 azienda='auxiell',
                                 company_color='#6C757D')

        # Validazione password
        if not password:
            return render_template('register.html', 
                                 error='La password è obbligatoria',
                                 azienda='auxiell',
                                 company_color='#6C757D')

        if password != password_confirm:
            return render_template('register.html', 
                                 error='Le password non coincidono',
                                 azienda='auxiell',
                                 company_color='#6C757D')

        is_valid, error_msg = validate_password(password)
        if not is_valid:
            return render_template('register.html', 
                                 error=error_msg,
                                 azienda='auxiell',
                                 company_color='#6C757D')

        try:
            logger.info(f"📝 Creazione dati utente: {email}")
            # Crea nuovo utente (SU AZURE)
            nome, cognome = extract_name_from_email(email)
            azienda = extract_company_from_email(email)

            user_data = {
                'email': email,
                'password_hash': hash_password(password),
                'nome': nome,
                'cognome': cognome,
                'azienda': azienda,
                'is_admin': False,
                'created_at': datetime.now().isoformat(),
                'last_login': None
            }

            logger.info(f"💾 Salvataggio su Azure: {email}")
            success = save_user_data(email, user_data)

            if success:
                logger.info(f"✅ Nuovo utente registrato su Azure: {email}")
                return render_template('login.html', 
                                     success='Registrazione completata! Ora puoi accedere.',
                                     azienda='auxiell',
                                     company_color='#6C757D')
            else:
                logger.error(f"❌ Salvataggio fallito per: {email}")
                return render_template('register.html', 
                                     error='Errore salvataggio su database.',
                                     azienda='auxiell',
                                     company_color='#6C757D')

        except Exception as e:
            logger.error(f"❌ Errore registrazione completo {email}: {e}")
            return render_template('register.html', 
                                 error=f'Errore registrazione: {str(e)}',  # ← MOSTRA ERRORE SPECIFICO  
                                 azienda='auxiell',
                                 company_color='#6C757D')

    # GET request
    return render_template('register.html',
                          azienda='auxiell',
                          company_color='#6C757D')


@app.route('/admin/reset_user_test/<user_email>/<test_name>', methods=['POST'])
@login_required
def admin_reset_user_test(user_email, test_name):
    """Riabilita un test permettendo un nuovo tentativo"""
    admin_email = session.get('user_email')
    
    if not is_admin_user(admin_email):
        return jsonify({'success': False, 'error': 'Accesso negato'}), 403
    
    try:
        # Verifica che l'utente abbia effettivamente completato questo test
        existing_results = get_user_test_results_all_attempts_azure_only(user_email)
        test_results = [r for r in existing_results if r.get('test_name') == test_name]
        
        if not test_results:
            return jsonify({
                'success': False, 
                'error': 'Test non trovato per questo utente'
            }), 404
        
        # NUOVO: Crea il flag di reset
        from azure_storage import set_test_reset_flag
        
        flag_created = set_test_reset_flag(user_email, test_name, admin_email)
        
        if not flag_created:
            return jsonify({
                'success': False,
                'error': 'Errore nella creazione del flag di reset'
            }), 500
        
        # Informazioni sui tentativi esistenti
        total_attempts = len(test_results)
        latest_attempt = max(test_results, key=lambda x: x.get('attempt_number', 1))
        latest_score = latest_attempt.get('score', 0)
        
        # Log dell'azione admin
        logger.info(f"Admin {admin_email} enabled retry for test '{test_name}' for user {user_email}")
        
        return jsonify({
            'success': True, 
            'message': f'Test "{test_name}" riabilitato per {user_email}. L\'utente potrà eseguire il tentativo #{total_attempts + 1}.',
            'details': {
                'attempts_count': total_attempts,
                'latest_score': latest_score,
                'next_attempt': total_attempts + 1
            }
        })
        
    except Exception as e:
        logger.error(f"Error resetting test {test_name} for {user_email}: {e}")
        return jsonify({
            'success': False, 
            'error': f'Errore durante la riabilitazione: {str(e)}'
        }), 500


@app.route('/dashboard')
@login_required 
def dashboard():
    try:
        user_email = session.get('user_email')
        azienda = session.get('azienda_scelta')

        # Recupera solo gli ultimi tentativi per ogni test
        completed_tests = get_user_test_results_latest_only(user_email)
        
        available_tests = []
        completed_test_names = [test['test_name'] for test in completed_tests]

        # AGGIUNGI DEBUG LOG
        logger.info(f"🔍 Dashboard debug for {user_email}:")
        logger.info(f"   Completed tests: {completed_test_names}")

        try:
            # Path assoluto per Azure
            base_dir = os.path.dirname(os.path.abspath(__file__))
            tipologie_file = os.path.join(base_dir, "repository_test", "Tipologia Test.xlsx")

            if os.path.exists(tipologie_file):
                df_tipologie = pd.read_excel(tipologie_file)

                if "Nome test" in df_tipologie.columns:
                    
                    def azienda_match(azienda_cell, azienda_utente):
                        """Controlla se l'azienda dell'utente è presente nella cella"""
                        if pd.isna(azienda_cell) or not azienda_cell:
                            return False
                        
                        aziende_test = [a.strip().lower() for a in str(azienda_cell).split(";")]
                        return azienda_utente.lower() in aziende_test

                    for _, row in df_tipologie.iterrows():
                        test_name = row["Nome test"]

                        test_available = True
                        if "Azienda" in df_tipologie.columns and pd.notna(row["Azienda"]):
                            test_available = azienda_match(row["Azienda"], azienda)

                        if test_available:
                            # MODIFICA: Controlla se ci sono tentativi multipli consentiti
                            is_completed = test_name in completed_test_names
                            
                            # Verifica se sono consentiti tentativi multipli (nuova logica)
                            can_retry = check_if_test_allows_retry(user_email, test_name)
                            
                            # AGGIUNGI DEBUG LOG DETTAGLIATO
                            logger.info(f"   Test: {test_name}")
                            logger.info(f"     - is_completed: {is_completed}")
                            logger.info(f"     - can_retry: {can_retry}")
                            logger.info(f"     - can_attempt: {not is_completed or can_retry}")
                            
                            available_tests.append({
                                'name': test_name,
                                'completed': is_completed,
                                'can_attempt': not is_completed or can_retry,
                                'attempts_count': count_user_test_attempts(user_email, test_name)
                            })
                            
        except Exception as e:
            logger.error(f"Error loading tests: {e}")

        # AGGIUNGI DEBUG LOG FINALE
        logger.info(f"   Final available_tests:")
        for test in available_tests:
            logger.info(f"     - {test['name']}: completed={test['completed']}, can_attempt={test['can_attempt']}")

        logo_path, logo_exists = get_logo_info(azienda)
        company_color = get_company_color(azienda)

        return render_template('dashboard.html',
                             completed_tests=completed_tests,
                             available_tests=available_tests,
                             utente=session.get('utente'),
                             azienda=azienda,
                             logo_path=logo_path if logo_exists else None,
                             company_color=company_color)

    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        return render_template('error.html', error=f'Errore dashboard: {e}')

def check_if_test_allows_retry(user_email, test_name):
    """Controlla se un test consente nuovi tentativi SOLO se riabilitato dall'admin"""
    try:
        # CORREZIONE: Importa la funzione corretta
        from azure_storage import check_if_test_allows_retry as azure_check
        return azure_check(user_email, test_name)
        
    except Exception as e:
        logger.error(f"Error checking retry permission: {e}")
        return False
        
def count_user_test_attempts(user_email, test_name):
    """Conta il numero di tentativi per un test specifico"""
    try:
        attempts = get_user_test_results_all_attempts(user_email, test_name)
        return len(attempts)
    except:
        return 0

@app.route('/start_test/<test_name>')
@login_required
def start_test(test_name):
    user_email = session.get('user_email')

    # Verifica se può tentare
    latest_results = get_user_test_results_latest_only(user_email)
    completed_test_names = [test['test_name'] for test in latest_results]
    
    if test_name in completed_test_names:
        # Controlla se può ritentare (solo se admin ha riabilitato)
        can_retry = check_if_test_allows_retry(user_email, test_name)
        if not can_retry:
            attempts_count = count_user_test_attempts(user_email, test_name)
            return render_template('error.html', 
                                 error=f'Hai già completato il test "{test_name}" ({attempts_count} tentativi). Contatta l\'amministratore per riabilitarlo.',
                                 show_dashboard_button=True)
        else:
            # CONSUMA il flag quando l'utente inizia il test
            from azure_storage import consume_test_reset_flag
            consume_test_reset_flag(user_email, test_name)

    # Se può procedere, continua normalmente
    session["test_scelto"] = test_name
    session["proseguito"] = False
    session["submitted"] = False
    session["domande_selezionate"] = None

    try:
        # Resto della logica esistente...
        base_dir = os.path.dirname(os.path.abspath(__file__))
        tipologie_file = os.path.join(base_dir, "repository_test", "Tipologia Test.xlsx")

        df_tipologie = pd.read_excel(tipologie_file)
        file_row = df_tipologie[df_tipologie["Nome test"] == test_name]

        if len(file_row) > 0:
            if "Tutte" in file_row.columns:
                tutte_value = str(file_row["Tutte"].values[0]).strip().lower()
                session["tutte_domande"] = tutte_value == "si"
            else:
                session["tutte_domande"] = False

            if "Percorso file" in file_row.columns:
                file_path = file_row["Percorso file"].values[0]
                session["file_path"] = os.path.join(base_dir, file_path)
            else:
                session["file_path"] = os.path.join(base_dir, "repository_test", f"{test_name}.xlsx")

        session.modified = True
        return redirect(url_for('quiz'))

    except Exception as e:
        logger.error(f"Error starting test: {e}")
        return render_template('error.html', error=f'Errore caricamento test: {e}')
        
@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    user_email = session.get('user_email')

    if not is_admin_user(user_email):
        return render_template('error.html', error='Accesso negato. Solo per amministratori.')

    try:
        # Carica TUTTI i dati (inclusi tentativi multipli)
        data = load_progress_data_with_attempts()

        total_users = len(data.get('users', {}))
        
        # Per le statistiche generali, usa solo gli ultimi tentativi
        latest_results = get_latest_attempts_only(data.get('test_results', []))
        total_tests_latest = len(latest_results)

        # Calcola punteggio medio generale (solo ultimi tentativi)
        if latest_results:
            scores = [result.get('score', 0) for result in latest_results if result.get('score') is not None]
            if scores:
                average_score = sum(scores) / len(scores)
                success_rate = (len([s for s in scores if s >= 60]) / len(scores)) * 100
            else:
                average_score = 0
                success_rate = 0
        else:
            average_score = 0
            success_rate = 0

        # Statistiche per azienda (solo ultimi tentativi)
        stats_per_azienda = {}

        # Conta utenti per azienda
        for email, user_data in data.get('users', {}).items():
            azienda = user_data.get('azienda', 'Unknown')
            if azienda not in stats_per_azienda:
                stats_per_azienda[azienda] = {
                    'users': 0, 
                    'tests': 0, 
                    'scores': []
                }
            stats_per_azienda[azienda]['users'] += 1

        # Conta test per azienda (solo ultimi tentativi)
        for result in latest_results:
            azienda = result.get('azienda', 'Unknown')
            score = result.get('score')

            if azienda in stats_per_azienda:
                stats_per_azienda[azienda]['tests'] += 1
                if score is not None:
                    stats_per_azienda[azienda]['scores'].append(score)

        # Calcola medie per azienda
        for azienda in stats_per_azienda:
            scores = stats_per_azienda[azienda]['scores']
            if scores:
                stats_per_azienda[azienda]['average_score'] = sum(scores) / len(scores)
                stats_per_azienda[azienda]['success_rate'] = (len([s for s in scores if s >= 60]) / len(scores)) * 100
            else:
                stats_per_azienda[azienda]['average_score'] = 0
                stats_per_azienda[azienda]['success_rate'] = 0

        # Test recenti - INCLUDE TUTTI i tentativi con info sui tentativi
        all_test_results = data.get('test_results', [])
        recent_tests = []
        sorted_tests = sorted(all_test_results, key=lambda x: x.get('completed_at', ''), reverse=True)

        for test in sorted_tests[:20]:  # Ultimi 20 invece di 10 per vedere più tentativi
            email = test.get('user_email', '')
            if email:
                nome, cognome = extract_name_from_email(email)
                test['user_name'] = f"{nome} {cognome}"
            else:
                test['user_name'] = 'Unknown'
            recent_tests.append(test)

        return render_template('admin_dashboard.html',
                             total_users=total_users,
                             total_tests=total_tests_latest,  # Usa solo ultimi tentativi per stats generali
                             average_score=average_score,
                             success_rate=success_rate,
                             stats_per_azienda=stats_per_azienda,
                             recent_tests=recent_tests,  # Include tutti i tentativi
                             utente=session.get('utente', 'Admin'),
                             azienda_scelta=session.get('azienda_scelta', 'auxiell'),
                             company_color=get_company_color(session.get('azienda_scelta', 'auxiell')))

    except Exception as e:
        logger.error(f"Admin dashboard error: {e}")
        return render_template('error.html', error=f'Errore dashboard admin: {str(e)}')

def load_progress_data_with_attempts():
    """Carica tutti i dati inclusi tentativi multipli da Azure Tables"""
    try:
        users = get_all_users_azure_only()
        test_results = get_all_test_results_azure_only()  # Include tutti i tentativi

        return {
            "users": users,
            "test_results": test_results,
            "last_updated": datetime.now().isoformat(),
            "source": "azure_tables_with_attempts"
        }
    except Exception as e:
        logger.error(f"❌ ERRORE CRITICO load_progress_data_with_attempts: {e}")
        raise Exception(f"Impossibile caricare dati: {e}")

def get_latest_attempts_only(test_results):
    """Filtra solo gli ultimi tentativi da una lista di risultati"""
    latest_results = {}
    
    for result in test_results:
        user_email = result.get('user_email', '')
        test_name = result.get('test_name', '')
        attempt_number = result.get('attempt_number', 1)
        
        key = f"{user_email}_{test_name}"
        
        if key not in latest_results or attempt_number > latest_results[key].get('attempt_number', 1):
            latest_results[key] = result
    
    return list(latest_results.values())
# Aggiungi questa route nel tuo app.py per testare Azure

@app.route('/test-azure-connection')
def test_azure_connection():
    """Test completo della connessione Azure"""
    try:
        from azure_storage import get_table_service_with_retry, TABLE_NAME_USERS, TABLE_NAME_RESULTS
        
        results = {
            "timestamp": datetime.now().isoformat(),
            "tests": []
        }
        
        # Test 1: Connessione base
        try:
            service = get_table_service_with_retry()
            results["tests"].append({
                "name": "Connection",
                "status": "✅ SUCCESS",
                "details": "Azure Tables service connected"
            })
        except Exception as e:
            results["tests"].append({
                "name": "Connection", 
                "status": "❌ FAILED",
                "error": str(e)
            })
            return jsonify(results), 500
        
        # Test 2: Lista tabelle
        try:
            tables = list(service.list_tables())
            table_names = [t.name for t in tables]
            results["tests"].append({
                "name": "List Tables",
                "status": "✅ SUCCESS",
                "details": f"Found tables: {table_names}"
            })
        except Exception as e:
            results["tests"].append({
                "name": "List Tables",
                "status": "❌ FAILED", 
                "error": str(e)
            })
        
        # Test 3: Query tabella users
        try:
            table_client = service.get_table_client(TABLE_NAME_USERS)
            users = list(table_client.list_entities())
            results["tests"].append({
                "name": "Query Users Table",
                "status": "✅ SUCCESS",
                "details": f"Found {len(users)} users"
            })
        except Exception as e:
            results["tests"].append({
                "name": "Query Users Table",
                "status": "❌ FAILED",
                "error": str(e)
            })
        
        # Test 4: Query tabella results  
        try:
            table_client = service.get_table_client(TABLE_NAME_RESULTS)
            test_results = list(table_client.list_entities())
            results["tests"].append({
                "name": "Query Results Table", 
                "status": "✅ SUCCESS",
                "details": f"Found {len(test_results)} test results"
            })
        except Exception as e:
            results["tests"].append({
                "name": "Query Results Table",
                "status": "❌ FAILED",
                "error": str(e)
            })
        
        # Test 5: Test scrittura (utente fittizio)
        try:
            table_client = service.get_table_client(TABLE_NAME_USERS)
            test_entity = {
                'PartitionKey': 'test',
                'RowKey': f'test_{int(datetime.now().timestamp())}',
                'email': 'test@test.com',
                'nome': 'Test',
                'cognome': 'User',
                'azienda': 'test',
                'is_admin': False,
                'created_at': datetime.now().isoformat(),
                'test_entity': True
            }
            
            table_client.upsert_entity(test_entity)
            results["tests"].append({
                "name": "Write Test",
                "status": "✅ SUCCESS", 
                "details": "Test entity written successfully"
            })
            
            # Rimuovi l'entità di test
            table_client.delete_entity(
                partition_key=test_entity['PartitionKey'],
                row_key=test_entity['RowKey']
            )
            
        except Exception as e:
            results["tests"].append({
                "name": "Write Test",
                "status": "❌ FAILED",
                "error": str(e)
            })
        
        return jsonify(results)
        
    except Exception as e:
        return jsonify({
            "status": "CRITICAL ERROR",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }), 500
        
@app.route('/admin/user/<user_email>')
@login_required
def admin_user_details(user_email):
    """Dettagli di un utente specifico per admin - INCLUDE TUTTI I TENTATIVI"""
    admin_email = session.get('user_email')
    
    if not is_admin_user(admin_email):
        return render_template('error.html', error='Accesso negato. Solo per amministratori.')
    
    try:
        # Recupera dati utente
        user_data = get_user_data(user_email)
        if not user_data:
            return render_template('error.html', error=f'Utente {user_email} non trovato.')
        
        # Recupera TUTTI i test dell'utente (inclusi tentativi multipli)
        user_test_results = get_user_test_results_all_attempts_azure_only(user_email)
        
        # Formatta i dati per il template
        formatted_tests = []
        for result in user_test_results:
            completed_at = result.get('completed_at', '')
            if completed_at:
                try:
                    dt = datetime.fromisoformat(completed_at.replace('Z', '+00:00'))
                    data_formattata = dt.strftime('%d/%m/%Y %H:%M')
                except:
                    data_formattata = completed_at
            else:
                data_formattata = "N/A"
            
            formatted_tests.append({
                'test_name': result.get('test_name', 'N/A'),
                'completed_at': data_formattata,
                'score': result.get('score', 0),
                'correct_answers': result.get('correct_answers', 0),
                'total_questions': result.get('total_questions', 0),
                'azienda': result.get('azienda', 'N/A'),
                'attempt_number': result.get('attempt_number', 1),
                'is_latest': result.get('is_latest', True),
                'raw_result': result  # Per il download
            })
        
        # Ordina per test_name e poi per attempt_number
        formatted_tests.sort(key=lambda x: (x['test_name'], x['attempt_number']), reverse=True)
        
        # Calcola statistiche solo sugli ultimi tentativi
        latest_tests = [t for t in formatted_tests if t['is_latest']]
        
        # Estrai nome e cognome dall'email
        nome, cognome = extract_name_from_email(user_email)
        
        return render_template('admin_user_details.html',
                             user_email=user_email,
                             user_name=f"{nome} {cognome}",
                             user_data=user_data,
                             test_results=formatted_tests,  # Tutti i tentativi
                             latest_test_results=latest_tests,  # Solo ultimi tentativi
                             total_tests=len(latest_tests),  # Conta solo ultimi tentativi
                             total_attempts=len(formatted_tests),  # Conta tutti i tentativi
                             admin_name=session.get('utente', 'Admin'),
                             azienda_scelta=session.get('azienda_scelta', 'auxiell'),
                             company_color=get_company_color(session.get('azienda_scelta', 'auxiell')))
                             
    except Exception as e:
        logger.error(f"Admin user details error for {user_email}: {e}")
        return render_template('error.html', error=f'Errore caricamento dettagli utente: {str(e)}')
        
@app.route('/admin/download_user_test/<user_email>/<test_name>')
@login_required
def admin_download_user_test(user_email, test_name):
    """Download di un test specifico di un utente per admin"""
    admin_email = session.get('user_email')
    
    if not is_admin_user(admin_email):
        return "Accesso negato. Solo per amministratori.", 403
    
    try:
        # Recupera risultati dell'utente
        user_results = get_user_test_results(user_email)
        
        # Trova il test specifico
        found_result = None
        for result in user_results:
            if result.get('test_name') == test_name:
                found_result = result
                break
        
        if not found_result:
            return f"Test '{test_name}' non trovato per l'utente {user_email}.", 404
        
        try:
            risposte = json.loads(found_result.get('answers_json', '[]'))
            if not risposte:
                return "Dati del test non disponibili.", 404
        except Exception as e:
            logger.error(f"Errore parsing JSON: {e}")
            return "Errore nel recupero dei dati del test.", 500
        
        # Estrai nome utente dall'email
        nome, cognome = extract_name_from_email(user_email)
        utente_nome = f"{nome} {cognome}"
        azienda = found_result.get('azienda', 'N/A')
        
        # Crea DataFrame
        df_r = pd.DataFrame(risposte)
        
        # Calcola punteggio
        chiuse = df_r[df_r["Tipo"] == "chiusa"]
        n_tot = len(chiuse)
        n_cor = int(chiuse["Esatta"].sum()) if n_tot else 0
        perc = int(n_cor / n_tot * 100) if n_tot else 0
        
        # Data completamento
        completed_at = found_result.get('completed_at', '')
        if completed_at:
            try:
                dt = datetime.fromisoformat(completed_at.replace('Z', '+00:00'))
                data_test = dt.strftime("%d/%m/%Y %H:%M")
            except:
                data_test = completed_at
        else:
            data_test = "N/A"
        
        # Crea info sheet
        data_download = datetime.now().strftime("%d/%m/%Y %H:%M")
        admin_name = session.get('utente', 'Admin')
        
        info = pd.DataFrame([{
            "Scaricato da Admin": admin_name,
            "Data Download": data_download,
            "Nome Utente": utente_nome,
            "Email Utente": user_email,
            "Data Completamento Test": data_test,
            "Test": test_name,
            "Azienda": azienda,
            "Punteggio": f"{perc}%",
            "Risposte Corrette": f"{n_cor}/{n_tot}",
            "Totale Domande": n_tot
        }])
        
        # Crea file Excel
        buf = BytesIO()
        
        with pd.ExcelWriter(buf, engine="openpyxl") as writer:
            info.to_excel(writer, index=False, sheet_name="Info Download", startrow=0)
            
            # Riordina colonne per leggibilità
            column_order = ["Tipo", "Azienda", "Utente", "Test", "Argomento", "Domanda", "Risposta", "Corretta", "Esatta"]
            existing_columns = [col for col in column_order if col in df_r.columns]
            other_columns = [col for col in df_r.columns if col not in column_order]
            final_columns = existing_columns + other_columns
            
            df_export = df_r[final_columns]
            df_export.to_excel(writer, index=False, sheet_name="Dettaglio Risposte", startrow=0)
        
        buf.seek(0)
        
        # Nome file
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        nome_sicuro = re.sub(r'[^\w\s-]', '', utente_nome).strip()
        nome_sicuro = re.sub(r'[-\s]+', '_', nome_sicuro)
        test_sicuro = re.sub(r'[^\w\s-]', '', test_name).strip()
        test_sicuro = re.sub(r'[-\s]+', '_', test_sicuro)
        
        filename = f"admin_download_{nome_sicuro}_{test_sicuro}_{timestamp}.xlsx"
        
        logger.info(f"Admin {admin_email} downloaded test {test_name} for user {user_email}")
        
        return send_file(
            buf,
            as_attachment=True,
            download_name=filename,
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )
        
    except Exception as e:
        logger.error(f"Admin download error: {e}")
        return f"Errore durante il download: {e}", 500
@app.route('/admin/users')
@login_required
def admin_all_users():
    """Lista completa di tutti gli utenti per admin"""
    admin_email = session.get('user_email')
    
    if not is_admin_user(admin_email):
        return render_template('error.html', error='Accesso negato. Solo per amministratori.')
    
    try:
        # Carica tutti i dati
        data = load_progress_data()
        users = data.get('users', {})
        test_results = data.get('test_results', [])
        
        # Prepara lista utenti con statistiche
        users_list = []
        
        for email, user_data in users.items():
            # Conta test per questo utente
            user_tests = [t for t in test_results if t.get('user_email') == email]
            
            # Calcola statistiche
            if user_tests:
                scores = [t.get('score', 0) for t in user_tests]
                avg_score = sum(scores) / len(scores) if scores else 0
                passed_tests = len([s for s in scores if s >= 60])
                last_test_date = max([t.get('completed_at', '') for t in user_tests])
            else:
                avg_score = 0
                passed_tests = 0
                last_test_date = None
            
            # Formatta data ultimo test
            if last_test_date:
                try:
                    dt = datetime.fromisoformat(last_test_date.replace('Z', '+00:00'))
                    last_test_formatted = dt.strftime('%d/%m/%Y')
                except:
                    last_test_formatted = "N/A"
            else:
                last_test_formatted = "Mai"
            
            # Formatta data registrazione
            created_at = user_data.get('created_at', '')
            if created_at:
                try:
                    dt = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                    created_formatted = dt.strftime('%d/%m/%Y')
                except:
                    created_formatted = created_at[:10] if len(created_at) >= 10 else "N/A"
            else:
                created_formatted = "N/A"
            
            # Estrai nome
            nome, cognome = extract_name_from_email(email)
            
            users_list.append({
                'email': email,
                'nome': nome,
                'cognome': cognome,
                'nome_completo': f"{nome} {cognome}",
                'azienda': user_data.get('azienda', 'N/A'),
                'is_admin': user_data.get('is_admin', False),
                'created_at': created_formatted,
                'last_test': last_test_formatted,
                'total_tests': len(user_tests),
                'avg_score': round(avg_score, 1),
                'passed_tests': passed_tests,
                'user_data': user_data
            })
        
        # Ordina per data ultimo test (più recenti prima)
        users_list.sort(key=lambda x: x['last_test'], reverse=True)
        
        return render_template('admin_users_list.html',
                             users=users_list,
                             total_users=len(users_list),
                             admin_name=session.get('utente', 'Admin'),
                             azienda_scelta=session.get('azienda_scelta', 'auxiell'),
                             company_color=get_company_color(session.get('azienda_scelta', 'auxiell')))
                             
    except Exception as e:
        logger.error(f"Admin users list error: {e}")
        return render_template('error.html', error=f'Errore caricamento lista utenti: {str(e)}')
@app.route('/admin/download_all_user_tests/<user_email>')
@login_required
def admin_download_all_user_tests(user_email):
    """Download di tutti i test di un utente per admin"""
    admin_email = session.get('user_email')
    
    if not is_admin_user(admin_email):
        return "Accesso negato. Solo per amministratori.", 403
    
    try:
        # Recupera tutti i risultati dell'utente
        user_results = get_user_test_results(user_email)
        
        if not user_results:
            return f"Nessun test trovato per l'utente {user_email}.", 404
        
        # Estrai nome utente
        nome, cognome = extract_name_from_email(user_email)
        utente_nome = f"{nome} {cognome}"
        
        # Crea file Excel con tutti i test
        buf = BytesIO()
        
        with pd.ExcelWriter(buf, engine="openpyxl") as writer:
            # Sheet di riepilogo
            summary_data = []
            for result in user_results:
                completed_at = result.get('completed_at', '')
                if completed_at:
                    try:
                        dt = datetime.fromisoformat(completed_at.replace('Z', '+00:00'))
                        data_formattata = dt.strftime('%d/%m/%Y %H:%M')
                    except:
                        data_formattata = completed_at
                else:
                    data_formattata = "N/A"
                
                summary_data.append({
                    'Test': result.get('test_name', 'N/A'),
                    'Data Completamento': data_formattata,
                    'Punteggio (%)': result.get('score', 0),
                    'Risposte Corrette': result.get('correct_answers', 0),
                    'Totale Domande': result.get('total_questions', 0),
                    'Azienda': result.get('azienda', 'N/A')
                })
            
            # Info generale
            admin_name = session.get('utente', 'Admin')
            data_download = datetime.now().strftime("%d/%m/%Y %H:%M")
            
            info_generale = pd.DataFrame([{
                'Scaricato da Admin': admin_name,
                'Data Download': data_download,
                'Nome Utente': utente_nome,
                'Email Utente': user_email,
                'Totale Test Completati': len(user_results)
            }])
            
            # Scrivi sheets
            info_generale.to_excel(writer, index=False, sheet_name="Info Download", startrow=0)
            
            summary_df = pd.DataFrame(summary_data)
            summary_df.to_excel(writer, index=False, sheet_name="Riepilogo Test", startrow=0)
            
            # Sheet per ogni test (se non troppi)
            if len(user_results) <= 10:  # Limita per evitare file troppo grandi
                for i, result in enumerate(user_results):
                    try:
                        risposte = json.loads(result.get('answers_json', '[]'))
                        if risposte:
                            df_test = pd.DataFrame(risposte)
                            test_name = result.get('test_name', f'Test_{i+1}')
                            sheet_name = re.sub(r'[^\w\s-]', '', test_name)[:31]  # Max 31 caratteri per Excel
                            df_test.to_excel(writer, index=False, sheet_name=sheet_name, startrow=0)
                    except:
                        continue
        
        buf.seek(0)
        
        # Nome file
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        nome_sicuro = re.sub(r'[^\w\s-]', '', utente_nome).strip()
        nome_sicuro = re.sub(r'[-\s]+', '_', nome_sicuro)
        
        filename = f"admin_tutti_test_{nome_sicuro}_{timestamp}.xlsx"
        
        logger.info(f"Admin {admin_email} downloaded all tests for user {user_email}")
        
        return send_file(
            buf,
            as_attachment=True,
            download_name=filename,
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )
        
    except Exception as e:
        logger.error(f"Admin download all tests error: {e}")
        return f"Errore durante il download: {e}", 500
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/forgot-password')
def forgot_password():
    return render_template('forgot_password.html')

@app.route('/health')
def health_check():
    try:
        # Health check completo per Azure
        azure_health = azure_tables_health_check()

        return jsonify({
            'status': azure_health['status'],
            'azure_tables': azure_health,
            'users_count': azure_health['record_counts']['users'],
            'results_count': azure_health['record_counts']['results'],
            'github_status': 'disabled',  # Non più usato per storage
            'timestamp': datetime.now().isoformat(),
            'azure_environment': os.environ.get('WEBSITE_SITE_NAME', 'local'),
            'storage_mode': 'azure_tables_only'
        })

    except Exception as e:
        logger.error(f"❌ Health check failed: {e}")
        return jsonify({
            'status': 'error',
            'error': str(e),
            'timestamp': datetime.now().isoformat(),
            'storage_mode': 'azure_tables_only'
        }), 500

@app.route('/admin/azure-status')
@login_required
def admin_azure_status():
    """Status dettagliato Azure Tables per admin"""
    user_email = session.get('user_email')

    if not is_admin_user(user_email):
        return "Accesso negato", 403

    try:
        health = azure_tables_health_check()
        return jsonify(health)
    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500

@app.route('/test-simple-login')
def test_simple_login():
    """Test login con HTML semplice"""
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Login Test</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body class="bg-light">
        <div class="container mt-5">
            <div class="row justify-content-center">
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-body">
                            <h2>Login Test - Funziona!</h2>
                            <form method="POST" action="/login">
                                <div class="mb-3">
                                    <label class="form-label">Email</label>
                                    <input type="email" class="form-control" name="email" required>
                                </div>
                                <div class="mb-3">
                                    <label class="form-label">Password</label>
                                    <input type="password" class="form-control" name="password" required>
                                </div>
                                <button type="submit" class="btn btn-primary">Login</button>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </body>
    </html>
    """
    return html
# Endpoint per Azure monitoring
@app.route('/status')
def status():
    """Endpoint semplificato per Azure health probe"""
    return "OK", 200


@app.route('/quiz')
@login_required
def quiz():
    if not session.get("test_scelto"):
        return redirect(url_for('dashboard'))

    if not session["proseguito"]:
        session["proseguito"] = True
        session.modified = True

    return show_quiz()
def apply_deduplication_filter(df):
    """
    Filtra le domande per evitare duplicati con le stesse opzioni di risposta.
    Mantiene solo la prima occorrenza di ogni set unico di opzioni.
    IGNORA le domande Vero/Falso che possono essere duplicate.
    """
    if df.empty:
        return df
    
    try:
        # Trova tutte le colonne opzione
        option_cols = [col for col in df.columns if col.lower().strip().startswith("opzione")]
        
        if not option_cols:
            logger.info("Nessuna colonna opzione trovata, filtro anti-duplicati saltato")
            return df
        
        # Crea una signature per ogni domanda basata sulle opzioni
        def create_options_signature(row):
            """Crea un hash unico basato sulle opzioni della domanda, ignora Vero/Falso"""
            options = []
            
            for col in option_cols:
                option_value = row.get(col)
                if pd.notna(option_value) and option_value is not None:
                    # Normalizza il testo per confronto robusto
                    normalized = str(option_value).strip().lower()
                    if normalized:  # Solo se non vuoto
                        options.append(normalized)
            
            if not options:
                # Domanda aperta o senza opzioni - usa la domanda stessa come signature
                return f"open_question_{str(row.get('Domanda', '')).strip().lower()}"
            
            # NUOVO: Controlla se è una domanda Vero/Falso
            if is_true_false_question(options):
                # Per domande Vero/Falso, usa la domanda stessa come signature
                # così ogni domanda Vero/Falso è considerata unica
                return f"true_false_{str(row.get('Domanda', '')).strip().lower()}"
            
            # Ordina le opzioni per rendere l'hash consistente
            options.sort()
            
            # Crea hash delle opzioni
            import hashlib
            signature = hashlib.md5("|".join(options).encode()).hexdigest()
            return signature
        
        # Aggiungi colonna temporanea con signature
        df_with_signature = df.copy()
        df_with_signature['_options_signature'] = df_with_signature.apply(create_options_signature, axis=1)
        
        # Log per debug
        total_before = len(df_with_signature)
        unique_signatures = df_with_signature['_options_signature'].nunique()
        duplicates_count = total_before - unique_signatures
        
        # Conta domande Vero/Falso per info
        true_false_count = sum(1 for sig in df_with_signature['_options_signature'] if sig.startswith('true_false_'))
        
        if duplicates_count > 0:
            logger.info(f"Filtro anti-duplicati: trovate {duplicates_count} domande con opzioni duplicate")
            logger.info(f"Domande Vero/Falso preservate: {true_false_count}")
            
            # Mostra alcuni esempi di duplicati per debug (escluse vero/falso)
            duplicate_signatures = df_with_signature[
                df_with_signature.duplicated('_options_signature', keep=False) & 
                ~df_with_signature['_options_signature'].str.startswith('true_false_')
            ]['_options_signature'].unique()
            
            for sig in duplicate_signatures[:3]:  # Mostra solo i primi 3 per non spammare i log
                duplicate_rows = df_with_signature[df_with_signature['_options_signature'] == sig]
                logger.debug(f"Signature {sig}: {len(duplicate_rows)} domande duplicate")
                for _, row in duplicate_rows.head(2).iterrows():  # Mostra solo le prime 2
                    logger.debug(f"  - Domanda: {row.get('Domanda', 'N/A')[:50]}...")
        else:
            logger.info(f"Nessun duplicato trovato. Domande Vero/Falso preservate: {true_false_count}")
        
        # Rimuovi duplicati mantenendo la prima occorrenza
        df_deduped = df_with_signature.drop_duplicates(subset=['_options_signature'], keep='first')
        
        # Rimuovi la colonna temporanea
        df_deduped = df_deduped.drop('_options_signature', axis=1)
        
        logger.info(f"Filtro anti-duplicati completato: {total_before} → {len(df_deduped)} domande")
        
        return df_deduped.reset_index(drop=True)
        
    except Exception as e:
        logger.error(f"Errore nel filtro anti-duplicati: {e}")
        # In caso di errore, ritorna il dataframe originale
        return df


def get_options_hash(row, option_cols):
    """Helper function per creare hash delle opzioni (versione alternativa più semplice)"""
    options = []
    
    for col in option_cols:
        if col in row and pd.notna(row[col]) and str(row[col]).strip():
            options.append(str(row[col]).strip().lower())
    
    if not options:
        return None
    
    # Ordina e crea hash
    options.sort()
    return "|".join(options)
def show_quiz():
    try:
        file_path = session.get("file_path", "")
        logger.info(f"Caricamento quiz: {file_path}")

        if not os.path.exists(file_path):
            return render_template('error.html', error=f"File non trovato: {file_path}")

        df = pd.read_excel(file_path)
        logger.info(f"Excel caricato: {len(df)} righe")

        # Verifica colonne necessarie
        required_cols = ["Azienda", "principio", "Domanda", "Corretta", "opzione 1"]
        missing = [col for col in required_cols if col not in required_cols]
        if missing:
            return render_template('error.html', error=f"Colonne mancanti: {', '.join(missing)}")

        azienda_scelta = session["azienda_scelta"]
        df_filtrato = df[df["Azienda"] == azienda_scelta]

        if df_filtrato.empty:
            return render_template('error.html', error=f"Nessuna domanda per {azienda_scelta}")

        if session["domande_selezionate"] is None:
            if session["tutte_domande"]:
                domande_selezionate = df_filtrato.reset_index(drop=True)
            else:
                target_questions = 30  # Numero desiderato di domande
                
                # NUOVO: Applica filtro anti-duplicati PRIMA della selezione
                df_filtered = apply_deduplication_filter(df_filtrato)
                logger.info(f"Domande dopo filtro anti-duplicati: {len(df_filtered)} (erano {len(df_filtrato)})")
                
                principi = df_filtered["principio"].unique()
                num_principi = len(principi)
                
                if num_principi > 0:
                    # Calcola quante domande per principio
                    domande_per_principio = max(1, target_questions // num_principi)
                    
                    domande_selezionate = (
                        df_filtered.groupby("principio", group_keys=False)
                                   .apply(lambda x: x.sample(n=min(domande_per_principio, len(x)), random_state=42))
                                   .reset_index(drop=True)
                    )
                    
                    # Se non abbiamo abbastanza domande, aggiungi altre random (sempre dal df_filtered)
                    if len(domande_selezionate) < target_questions:
                        remaining = target_questions - len(domande_selezionate)
                        unused = df_filtered[~df_filtered.index.isin(domande_selezionate.index)]
                        if len(unused) > 0:
                            extra = unused.sample(n=min(remaining, len(unused)), random_state=42)
                            domande_selezionate = pd.concat([domande_selezionate, extra]).reset_index(drop=True)
                else:
                    domande_selezionate = df_filtered.reset_index(drop=True)
            
            session["domande_selezionate"] = domande_selezionate.to_dict('records')

        # Resto della funzione rimane uguale...
        domande = session["domande_selezionate"]
        domande_formatted = []
        option_cols = [c for c in df.columns if c.lower().strip().startswith("opzione")]

        for idx, row in enumerate(domande):
            corretta_originale = row.get('Corretta', '')

            domanda_data = {
                'id': idx,
                'domanda': row['Domanda'],
                'principio': row['principio'],
                'tipo': 'aperta' if pd.isna(row.get("opzione 1")) or row.get("opzione 1") is None else 'chiusa',
                'opzioni': [],
                'corretta': corretta_originale,
                'multiple': False
            }

            if domanda_data['tipo'] == 'chiusa':
                opzioni = []
                for col in option_cols:
                    if col in row and row[col] is not None and pd.notna(row[col]) and str(row[col]).strip():
                        opzioni.append(str(row[col]))
                domanda_data['opzioni'] = opzioni

                if corretta_originale and not pd.isna(corretta_originale) and str(corretta_originale).strip():
                    corrette = [c.strip() for c in str(corretta_originale).split(";") if c.strip()]
                    domanda_data['multiple'] = len(corrette) > 1

            domande_formatted.append(domanda_data)

        logo_path, logo_exists = get_logo_info(session["azienda_scelta"])
        company_color = get_company_color(session["azienda_scelta"])

        return render_template('quiz.html',
                             domande=domande_formatted,
                             azienda=session["azienda_scelta"],
                             test_name=session["test_scelto"],
                             proseguito=session["proseguito"],
                             submitted=session["submitted"],
                             utente=session.get("utente", ""),
                             logo_path=logo_path if logo_exists else None,
                             company_color=company_color)

    except Exception as e:
        logger.error(f"Errore show_quiz: {e}")
        return render_template('error.html', error=f"Errore quiz: {e}")

def clean_text(text):
    """Pulizia robusta del testo"""
    if text is None:
        return ""

    text = str(text)
    import unicodedata

    # Normalizza Unicode
    text = unicodedata.normalize('NFKD', text)

    # Rimuovi caratteri di controllo
    text = ''.join(char for char in text if not unicodedata.category(char).startswith('C'))

    # Rimuovi spazi e converti a minuscolo
    text = text.strip().lower()

    # Sostituisci spazi multipli
    import re
    text = re.sub(r'\s+', ' ', text)

    return text

def answers_match(user_answer, correct_answer):
    """Confronto robuste delle risposte"""
    user_clean = clean_text(user_answer)
    correct_clean = clean_text(correct_answer)

    # Confronto diretto
    if user_clean == correct_clean:
        return True

    # Confronto per varianti booleane
    true_variants = ['vero', 'true', 'si', 'sì', 'yes', '1', 'corretto', 'giusto']
    false_variants = ['falso', 'false', 'no', '0', 'sbagliato', 'errato']

    if user_clean in true_variants and correct_clean in true_variants:
        return True
    if user_clean in false_variants and correct_clean in false_variants:
        return True

    # Confronto senza spazi e punteggiatura
    import re
    user_minimal = re.sub(r'[^\w]', '', user_clean)
    correct_minimal = re.sub(r'[^\w]', '', correct_clean)

    return user_minimal == correct_minimal
@app.route('/gdpr-requests')
@login_required
def gdpr_requests():
    """Pagina principale richieste GDPR"""
    try:
        logo_path, logo_exists = get_logo_info(session.get('azienda_scelta'))
        company_color = get_company_color(session.get('azienda_scelta'))
        
        return render_template('gdpr_requests.html',
                             utente=session.get('utente'),
                             azienda=session.get('azienda_scelta'),
                             logo_path=logo_path if logo_exists else None,
                             company_color=company_color)
    except Exception as e:
        logger.error(f"GDPR requests error: {e}")
        return render_template('error.html', error='Errore caricamento pagina GDPR')

@app.route('/delete-account')
@login_required
def delete_account():
    """Pagina informazioni cancellazione account"""
    try:
        logo_path, logo_exists = get_logo_info(session.get('azienda_scelta'))
        company_color = get_company_color(session.get('azienda_scelta'))
        
        return render_template('delete_account.html',
                             utente=session.get('utente'),
                             azienda=session.get('azienda_scelta'),
                             logo_path=logo_path if logo_exists else None,
                             company_color=company_color)
    except Exception as e:
        logger.error(f"Delete account page error: {e}")
        return render_template('error.html', error='Errore caricamento pagina cancellazione account')

@app.route('/data-export')
@login_required
def data_export():
    """Esporta tutti i dati dell'utente (GDPR compliance)"""
    try:
        user_email = session.get('user_email')
        if not user_email:
            return render_template('error.html', error='Sessione scaduta')
        
        # Recupera dati utente
        user_data = get_user_data(user_email)
        if not user_data:
            return render_template('error.html', error='Dati utente non trovati')
        
        # Recupera risultati test
        test_results = get_user_test_results(user_email)
        
        # Prepara dati per export
        export_data = {
            'informazioni_account': {
                'email': user_data.get('email', ''),
                'nome': user_data.get('nome', ''),
                'cognome': user_data.get('cognome', ''),
                'azienda': user_data.get('azienda', ''),
                'data_creazione': user_data.get('created_at', ''),
                'ultimo_accesso': user_data.get('last_login', ''),
                'tipo_account': 'Admin' if user_data.get('is_admin') else 'Utente Standard'
            },
            'risultati_test': [],
            'statistiche_generali': {
                'numero_test_completati': len(test_results),
                'data_primo_test': None,
                'data_ultimo_test': None
            }
        }
        
        # Processa risultati test
        for result in test_results:
            test_data = {
                'nome_test': result.get('test_name', ''),
                'data_completamento': result.get('completed_at', ''),
                'punteggio_percentuale': result.get('score', 0),
                'risposte_corrette': result.get('correct_answers', 0),
                'totale_domande': result.get('total_questions', 0),
                'azienda': result.get('azienda', '')
            }
            
            # Aggiungi dettagli risposte se disponibili
            if result.get('answers_json'):
                try:
                    answers_detail = json.loads(result.get('answers_json', '[]'))
                    test_data['dettaglio_risposte'] = answers_detail
                except:
                    test_data['dettaglio_risposte'] = []
            
            export_data['risultati_test'].append(test_data)
        
        # Calcola statistiche
        if test_results:
            dates = [r.get('completed_at') for r in test_results if r.get('completed_at')]
            dates = [d for d in dates if d]  # Rimuovi valori None/vuoti
            
            if dates:
                export_data['statistiche_generali']['data_primo_test'] = min(dates)
                export_data['statistiche_generali']['data_ultimo_test'] = max(dates)
        
        # Crea file Excel
        buf = BytesIO()
        
        with pd.ExcelWriter(buf, engine="openpyxl") as writer:
            # Sheet 1: Informazioni Account
            account_df = pd.DataFrame([export_data['informazioni_account']])
            account_df.to_excel(writer, index=False, sheet_name="Informazioni Account")
            
            # Sheet 2: Statistiche
            stats_df = pd.DataFrame([export_data['statistiche_generali']])
            stats_df.to_excel(writer, index=False, sheet_name="Statistiche")
            
            # Sheet 3: Risultati Test (senza dettagli risposte)
            if export_data['risultati_test']:
                test_summary = []
                for test in export_data['risultati_test']:
                    summary = {k: v for k, v in test.items() if k != 'dettaglio_risposte'}
                    test_summary.append(summary)
                
                test_df = pd.DataFrame(test_summary)
                test_df.to_excel(writer, index=False, sheet_name="Risultati Test")
            
            # Sheet 4: Dettagli Completi (se ci sono test)
            if export_data['risultati_test']:
                all_answers = []
                for test in export_data['risultati_test']:
                    test_name = test.get('nome_test', '')
                    test_date = test.get('data_completamento', '')
                    
                    for answer in test.get('dettaglio_risposte', []):
                        answer_row = answer.copy()
                        answer_row['Nome_Test_Origine'] = test_name
                        answer_row['Data_Test'] = test_date
                        all_answers.append(answer_row)
                
                if all_answers:
                    details_df = pd.DataFrame(all_answers)
                    details_df.to_excel(writer, index=False, sheet_name="Dettagli Completi")
        
        buf.seek(0)
        
        # Nome file
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        nome_sicuro = re.sub(r'[^\w\s-]', '', session.get('utente', 'utente')).strip()
        nome_sicuro = re.sub(r'[-\s]+', '_', nome_sicuro)
        
        filename = f"dati_personali_{nome_sicuro}_{timestamp}.xlsx"
        
        logger.info(f"Data export requested by: {user_email}")
        
        return send_file(
            buf,
            as_attachment=True,
            download_name=filename,
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )
        
    except Exception as e:
        logger.error(f"Data export error: {e}")
        return render_template('error.html', error=f'Errore esportazione dati: {e}')

@app.route('/privacy-policy')
def privacy_policy():
    """Pagina informativa privacy policy"""
    try:
        # Determina azienda per styling
        azienda = 'auxiell'  # default
        company_color = get_company_color(azienda)
        
        if session.get('logged_in'):
            azienda = session.get('azienda_scelta', 'auxiell')
            company_color = get_company_color(azienda)
        
        logo_path, logo_exists = get_logo_info(azienda)
        
        return render_template('privacy_policy.html',
                             azienda=azienda,
                             company_color=company_color,
                             logo_path=logo_path if logo_exists else None)
    except Exception as e:
        logger.error(f"Privacy policy error: {e}")
        return render_template('error.html', error='Errore caricamento privacy policy')

# Route per admin - gestione richieste GDPR
@app.route('/admin/gdpr-requests')
@login_required
def admin_gdpr_requests():
    """Dashboard admin per richieste GDPR"""
    user_email = session.get('user_email')
    
    if not is_admin_user(user_email):
        return render_template('error.html', error='Accesso negato. Solo per amministratori.')
    
    try:
        # Questa è una pagina informativa per ora
        # In futuro potresti aggiungere un sistema di tracking delle richieste GDPR
        
        return render_template('admin_gdpr.html',
                             utente=session.get('utente', 'Admin'),
                             azienda_scelta=session.get('azienda_scelta', 'auxiell'),
                             company_color=get_company_color(session.get('azienda_scelta', 'auxiell')))
        
    except Exception as e:
        logger.error(f"Admin GDPR requests error: {e}")
        return render_template('error.html', error='Errore caricamento dashboard GDPR admin')

@app.route('/submit_answers', methods=['POST'])
@login_required
def submit_answers():
    try:
        data = request.json
        answers = data.get('answers', {})
        quiz_data = data.get('quiz_data', {})

        utente = session.get('utente', '')
        user_email = session.get('user_email', '')
        azienda_scelta = session.get('azienda_scelta', '')
        test_scelto = session.get('test_scelto', '')
        domande = quiz_data.get('domande', [])

        if not domande or not user_email:
            return jsonify({'success': False, 'error': 'Dati mancanti', 'reload': True})

        risposte = []

        for idx, row in enumerate(domande):
            answer_key = f'question_{idx}'
            user_answer = answers.get(answer_key, '')

            opzioni = row.get("opzioni", [])
            tipo_domanda = row.get("tipo", "")

            if tipo_domanda == 'aperta' or not opzioni:
                # Domanda aperta
                risposte.append({
                    "Tipo": "aperta",
                    "Azienda": azienda_scelta,
                    "Utente": utente,
                    "Domanda": row.get("domanda", ""),
                    "Argomento": row.get("principio", ""),
                    "Risposta": str(user_answer) if user_answer else "",
                    "Corretta": "N/A - Domanda aperta",
                    "Esatta": None,
                    "Test": test_scelto
                })

            else:
                # Domanda chiusa
                corretta_raw = row.get("corretta", "")

                if not corretta_raw or pd.isna(corretta_raw):
                    corretta_raw = "ERRORE - Risposta corretta mancante"

                # Processa risposte corrette
                if corretta_raw and corretta_raw != "ERRORE - Risposta corretta mancante":
                    corrette_list = [c.strip() for c in str(corretta_raw).split(";") if c.strip()]
                else:
                    corrette_list = []

                # Verifica se è multipla
                is_multiple = row.get("multiple", False) or len(corrette_list) > 1

                if is_multiple:
                    # Risposta multipla
                    user_answers_list = user_answer if isinstance(user_answer, list) else [user_answer] if user_answer else []
                    user_answers_list = [ans for ans in user_answers_list if ans]

                    # Confronto per risposte multiple
                    matches = []
                    for user_ans in user_answers_list:
                        for correct_ans in corrette_list:
                            if answers_match(user_ans, correct_ans):
                                matches.append(user_ans)
                                break

                    is_correct = len(matches) == len(user_answers_list) == len(corrette_list)
                    risposta_str = ";".join(user_answers_list)

                else:
                    # Risposta singola
                    is_correct = False
                    if corrette_list:
                        for correct_option in corrette_list:
                            if answers_match(user_answer, correct_option):
                                is_correct = True
                                break

                    risposta_str = str(user_answer) if user_answer else ""

                risposte.append({
                    "Tipo": "chiusa",
                    "Azienda": azienda_scelta,
                    "Utente": utente,
                    "Domanda": row.get("domanda", ""),
                    "Argomento": row.get("principio", ""),
                    "Risposta": risposta_str,
                    "Corretta": str(corretta_raw),
                    "Esatta": is_correct,
                    "Test": test_scelto
                })

        # Calcola punteggio
        df_r = pd.DataFrame(risposte)
        chiuse = df_r[df_r["Tipo"] == "chiusa"]
        n_tot = len(chiuse)

        if n_tot > 0:
            n_cor = int(chiuse["Esatta"].sum())
            perc = int(n_cor / n_tot * 100)
        else:
            n_cor = perc = 0

        # Prepara risultato per il salvataggio
        result = {
            'user_email': user_email,
            'test_name': test_scelto,
            'azienda': azienda_scelta,
            'score': perc,
            'correct_answers': n_cor,
            'total_questions': n_tot,
            'answers_json': json.dumps(risposte, ensure_ascii=False),
            'completed_at': datetime.now().isoformat(),
            'created_at': datetime.now().isoformat()
        }

        # Salva risultato
        save_success = save_test_result(result)

        if save_success:
            session["submitted"] = True
            
            # Ottimizza la sessione per evitare cookie troppo grandi
            try:
                # Rimuovi dati pesanti dalla sessione
                if "domande_selezionate" in session:
                    session["domande_count"] = len(session.get("domande_selezionate", []))
                    del session["domande_selezionate"]
                
                # Non salvare le risposte nella sessione (troppo pesante)
                session.modified = True
                logger.info("Session data optimized")
            except Exception as e:
                logger.warning(f"Session optimization failed: {e}")

            logger.info(f"Test completed: {perc}% ({n_cor}/{n_tot}) - {user_email}")

            return jsonify({
                'success': True,
                'score': perc,
                'correct': n_cor,
                'total': n_tot
            })
        else:
            logger.error(f"Failed to save test result for {user_email}")
            return jsonify({
                'success': False,
                'error': 'Errore nel salvataggio dei risultati. Riprova.'
            })

    except Exception as e:
        logger.error(f"Submit answers error: {e}")
        return jsonify({
            'success': False, 
            'error': f'Errore durante il salvataggio: {str(e)}'
        })
@app.route('/download_results')
@app.route('/download_results/<test_name>')
@login_required
def download_results(test_name=None):
    try:
        user_email = session.get('user_email')

        if not user_email:
            return "Utente non identificato.", 404

        # Se non specificato un test, prendi l'ultimo
        if not test_name:
            if session.get("submitted") and "risposte" in session:
                risposte = session["risposte"]
                test_name = session.get("test_scelto", "Test")
            else:
                user_results = get_user_test_results(user_email)
                if not user_results:
                    return "Nessun test completato trovato.", 404

                latest_result = user_results[0]
                test_name = latest_result.get('test_name', 'Test')

                try:
                    risposte = json.loads(latest_result.get('answers_json', '[]'))
                    if not risposte:
                        return "Dati del test non disponibili.", 404
                except Exception as e:
                    logger.error(f"Errore parsing JSON: {e}")
                    return "Errore nel recupero dei dati del test.", 500
        else:
            # Test specifico richiesto
            user_results = get_user_test_results(user_email)
            found_result = None

            for result in user_results:
                if result.get('test_name') == test_name:
                    found_result = result
                    break

            if not found_result:
                return f"Test '{test_name}' non trovato.", 404

            try:
                risposte = json.loads(found_result.get('answers_json', '[]'))
                if not risposte:
                    return "Dati del test non disponibili.", 404
            except Exception as e:
                logger.error(f"Errore parsing JSON: {e}")
                return "Errore nel recupero dei dati del test.", 500

        utente = session.get("utente", "Utente")
        azienda = session.get("azienda_scelta", "")

        # Crea DataFrame
        df_r = pd.DataFrame(risposte)

        # Calcola punteggio
        chiuse = df_r[df_r["Tipo"] == "chiusa"]
        n_tot = len(chiuse)
        n_cor = int(chiuse["Esatta"].sum()) if n_tot else 0
        perc = int(n_cor / n_tot * 100) if n_tot else 0

        # Crea info sheet
        data_test = datetime.now().strftime("%d/%m/%Y %H:%M")
        info = pd.DataFrame([{
            "Nome": utente,
            "Email": user_email,
            "Data Download": data_test,
            "Test": test_name,
            "Azienda": azienda,
            "Punteggio": f"{perc}%",
            "Risposte Corrette": f"{n_cor}/{n_tot}",
            "Totale Domande": n_tot
        }])

        # Crea file Excel
        buf = BytesIO()

        with pd.ExcelWriter(buf, engine="openpyxl") as writer:
            info.to_excel(writer, index=False, sheet_name="Riassunto", startrow=0)

            # Riordina colonne per leggibilità
            column_order = ["Tipo", "Azienda", "Utente", "Test", "Argomento", "Domanda", "Risposta", "Corretta", "Esatta"]
            existing_columns = [col for col in column_order if col in df_r.columns]
            other_columns = [col for col in df_r.columns if col not in column_order]
            final_columns = existing_columns + other_columns

            df_export = df_r[final_columns]
            df_export.to_excel(writer, index=False, sheet_name="Dettaglio Risposte", startrow=0)

        buf.seek(0)

        # Nome file
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        nome_sicuro = re.sub(r'[^\w\s-]', '', utente).strip()
        nome_sicuro = re.sub(r'[-\s]+', '_', nome_sicuro)
        test_sicuro = re.sub(r'[^\w\s-]', '', test_name).strip()
        test_sicuro = re.sub(r'[-\s]+', '_', test_sicuro)

        filename = f"risultati_{nome_sicuro}_{test_sicuro}_{timestamp}.xlsx"

        return send_file(
            buf,
            as_attachment=True,
            download_name=filename,
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )

    except Exception as e:
        logger.error(f"Download error: {e}")
        return f"Errore durante il download: {e}", 500

@app.route('/download_latest')
@login_required
def download_latest():
    """Download dell'ultimo test completato"""
    return download_results()

@app.route('/admin/download_report')
@login_required
def admin_download_report():
    """Scarica report completo di tutti i test"""
    user_email = session.get('user_email')

    if not is_admin_user(user_email):
        return "Accesso negato. Solo per amministratori.", 403

    try:
        data = load_progress_data()
        test_results = data.get('test_results', [])

        if not test_results:
            return "Nessun test completato trovato.", 404

        # Prepara dati per Excel
        report_data = []

        for result in test_results:
            email = result.get('user_email', '')

            if email:
                nome, cognome = extract_name_from_email(email)
                nome_completo = f"{nome} {cognome}"
            else:
                nome_completo = "Unknown"

            # Formatta data
            completed_at = result.get('completed_at', '')
            if completed_at:
                try:
                    dt = datetime.fromisoformat(completed_at.replace('Z', '+00:00'))
                    data_formattata = dt.strftime('%d/%m/%Y %H:%M')
                except:
                    data_formattata = completed_at
            else:
                data_formattata = "N/A"

            report_data.append({
                'Nome Utente': nome_completo,
                'Email': email,
                'Azienda': result.get('azienda', 'N/A'),
                'Test Svolto': result.get('test_name', 'N/A'),
                'Data Completamento': data_formattata,
                'Punteggio (%)': result.get('score', 0),
                'Risposte Corrette': result.get('correct_answers', 0),
                'Totale Domande': result.get('total_questions', 0)
            })

        # Ordina per data
        report_data.sort(key=lambda x: x['Data Completamento'], reverse=True)

        # Crea DataFrame
        df_report = pd.DataFrame(report_data)

        # Info generale
        data_report = datetime.now().strftime("%d/%m/%Y %H:%M")
        admin_name = session.get('utente', 'Admin')

        info_generale = pd.DataFrame([{
            'Report Generato Da': admin_name,
            'Data Generazione': data_report,
            'Totale Test': len(df_report),
            'Utenti Totali': df_report['Nome Utente'].nunique()
        }])

        # Crea file Excel
        buf = BytesIO()

        with pd.ExcelWriter(buf, engine="openpyxl") as writer:
            info_generale.to_excel(writer, index=False, sheet_name="Info Report", startrow=0)
            df_report.to_excel(writer, index=False, sheet_name="Report Completo", startrow=0)

        buf.seek(0)

        # Nome file
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"report_completo_test_{timestamp}.xlsx"

        return send_file(
            buf,
            as_attachment=True,
            download_name=filename,
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )

    except Exception as e:
        logger.error(f"Admin download error: {e}")
        return f"Errore durante la generazione del report: {e}", 500

@app.route('/sync')
def manual_sync():
    try:
        data = initialize_storage()
        return jsonify({
            'success': True,
            'users_count': len(data.get('users', {})),
            'results_count': len(data.get('test_results', []))
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# Inizializzazione sicura all'avvio
# SOSTITUISCI la funzione startup_initialization nel tuo app.py con questa:

def startup_initialization():
    """Inizializzazione OBBLIGATORIA con Azure Tables"""
    try:
        logger.info("🚀 === AVVIO INIZIALIZZAZIONE AZURE === 🚀")

        # STEP 1: Verifica configurazione
        if not AZURE_STORAGE_CONNECTION_STRING:
            error_msg = "❌ ERRORE CRITICO: AZURE_STORAGE_CONNECTION_STRING non configurata!"
            logger.error(error_msg)
            raise Exception(error_msg)

        logger.info("✅ Configurazione Azure trovata")

        # STEP 2: Inizializza Azure Tables (OBBLIGATORIO) - QUESTA RIGA MANCAVA!
        from azure_storage import initialize_azure_tables_mandatory, migrate_from_files_to_azure, azure_tables_health_check
        initialize_azure_tables_mandatory()

        # STEP 3: Migrazione da file se necessario (OPZIONALE)
        try:
            migrate_from_files_to_azure()
        except Exception as e:
            logger.warning(f"⚠️  Migrazione fallita (non critico): {e}")

        # STEP 4: Test finale
        health = azure_tables_health_check()
        if health['status'] != 'healthy':
            raise Exception(f"Health check fallito: {health}")

        logger.info("🎉 === INIZIALIZZAZIONE COMPLETATA === 🎉")
        logger.info(f"👥 Utenti: {health['record_counts']['users']}")
        logger.info(f"📝 Test Results: {health['record_counts']['results']}")

        return True

    except Exception as e:
        logger.error(f"💥 ERRORE CRITICO INIZIALIZZAZIONE: {e}")
        logger.error("❌ APP NON PUÒ AVVIARSI SENZA AZURE TABLES")
        raise Exception(f"Inizializzazione fallita: {e}")

# AGGIUNGI anche questa route per forzare la creazione delle tabelle manualmente:
@app.route('/admin/force-create-tables')
def force_create_tables():
    """Crea manualmente le tabelle Azure (emergenza)"""
    try:
        logger.info("🔧 Creazione forzata tabelle Azure...")

        from azure_storage import initialize_azure_tables_mandatory
        initialize_azure_tables_mandatory()

        return jsonify({
            "status": "success",
            "message": "Tabelle create con successo",
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"❌ Errore creazione tabelle: {e}")
        return jsonify({
            "status": "error",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }), 500

def safe_startup():
    """Inizializzazione sicura che non blocca l'avvio"""
    try:
        startup_initialization()
    except Exception as e:
        logger.error(f"Startup error (non-blocking): {e}")

@app.route('/debug/info')
def debug_info():
    """Debug info per Azure"""
    try:
        import sys
        import os
        return jsonify({
            'python_version': sys.version,
            'working_directory': os.getcwd(),
            'files_in_directory': os.listdir('.'),
            'templates_exist': os.path.exists('templates'),
            'static_exists': os.path.exists('static'),
            'repository_test_exists': os.path.exists('repository_test'),
            'environment_vars': {
                'WEBSITE_SITE_NAME': os.environ.get('WEBSITE_SITE_NAME'),
                'GITHUB_CONFIGURED': bool(os.environ.get('GITHUB_TOKEN'))
            }
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/minimal')
def minimal_page():
    """Pagina minima per testare che Flask funzioni"""
    html = """
    <!DOCTYPE html>
    <html>
    <head><title>Assessment App - Azure Test</title></head>
    <body>
        <h1>✅ Flask App Running on Azure!</h1>
        <p>Timestamp: {{ timestamp }}</p>
        <ul>
            <li><a href="/health">Health Check</a></li>
            <li><a href="/debug/info">Debug Info</a></li>
            <li><a href="/status">Status</a></li>
        </ul>
    </body>
    </html>
    """
    from flask import render_template_string
    return render_template_string(html, timestamp=datetime.now().isoformat())

if __name__ == '__main__':
    safe_startup()
    port = int(os.environ.get('PORT', 8000))
    debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=debug)
else:
    logger.info("App started in WSGI mode")
