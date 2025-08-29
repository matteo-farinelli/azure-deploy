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

def save_test_result(result):
    """Salva risultato test SOLO su Azure Table Storage"""
    # Aggiungi timestamp se mancante
    if not result.get('completed_at'):
        result['completed_at'] = datetime.now().isoformat()

    return save_test_result_azure_only(result)

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
    """Cripta la password usando SHA-256"""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

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

@app.route('/dashboard')
@login_required 
def dashboard():
    try:
        user_email = session.get('user_email')
        azienda = session.get('azienda_scelta')

        completed_tests = get_user_test_results(user_email)

        available_tests = []
        completed_test_names = [test['test_name'] for test in completed_tests]

        try:
            # Path assoluto per Azure
            base_dir = os.path.dirname(os.path.abspath(__file__))
            tipologie_file = os.path.join(base_dir, "repository_test", "Tipologia Test.xlsx")

            if os.path.exists(tipologie_file):
                df_tipologie = pd.read_excel(tipologie_file)

                if "Nome test" in df_tipologie.columns:
                    for _, row in df_tipologie.iterrows():
                        test_name = row["Nome test"]

                        test_available = True
                        if "Azienda" in df_tipologie.columns and pd.notna(row["Azienda"]):
                            aziende_test = [a.strip() for a in str(row["Azienda"]).split(";")]
                            test_available = azienda in aziende_test

                        if test_available:
                            is_completed = test_name in completed_test_names
                            available_tests.append({
                                'name': test_name,
                                'completed': is_completed,
                                'can_attempt': not is_completed
                            })
        except Exception as e:
            logger.error(f"Error loading tests: {e}")

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

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    user_email = session.get('user_email')

    if not is_admin_user(user_email):
        return render_template('error.html', error='Accesso negato. Solo per amministratori.')

    try:
        data = load_progress_data()

        total_users = len(data.get('users', {}))
        total_tests = len(data.get('test_results', []))

        # Calcola punteggio medio generale
        test_results = data.get('test_results', [])
        if test_results:
            scores = [result.get('score', 0) for result in test_results if result.get('score') is not None]
            if scores:
                average_score = sum(scores) / len(scores)
                success_rate = (len([s for s in scores if s >= 60]) / len(scores)) * 100
            else:
                average_score = 0
                success_rate = 0
        else:
            average_score = 0
            success_rate = 0

        # Statistiche per azienda
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

        # Conta test per azienda
        for result in data.get('test_results', []):
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

        # Test recenti
        recent_tests = []
        sorted_tests = sorted(test_results, key=lambda x: x.get('completed_at', ''), reverse=True)

        for test in sorted_tests[:10]:
            email = test.get('user_email', '')
            if email:
                nome, cognome = extract_name_from_email(email)
                test['user_name'] = f"{nome} {cognome}"
            else:
                test['user_name'] = 'Unknown'
            recent_tests.append(test)

        return render_template('admin_dashboard.html',
                             total_users=total_users,
                             total_tests=total_tests,
                             average_score=average_score,
                             success_rate=success_rate,
                             stats_per_azienda=stats_per_azienda,
                             recent_tests=recent_tests,
                             utente=session.get('utente', 'Admin'),
                             azienda_scelta=session.get('azienda_scelta', 'auxiell'),
                             company_color=get_company_color(session.get('azienda_scelta', 'auxiell')))

    except Exception as e:
        logger.error(f"Admin dashboard error: {e}")
        return render_template('error.html', error=f'Errore dashboard admin: {str(e)}')

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

@app.route('/start_test/<test_name>')
@login_required
def start_test(test_name):
    user_email = session.get('user_email')

    # Verifica se l'utente ha già completato questo test
    completed_tests = get_user_test_results(user_email)
    completed_test_names = [test['test_name'] for test in completed_tests]

    if test_name in completed_test_names:
        return render_template('error.html', 
                             error=f'Hai già completato il test "{test_name}". Ogni test può essere svolto una sola volta.',
                             show_dashboard_button=True)

    # Se non completato, procedi normalmente
    session["test_scelto"] = test_name
    session["proseguito"] = False
    session["submitted"] = False
    session["domande_selezionate"] = None

    try:
        # Path assoluto per Azure
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
                # Converti path relativo in assoluto
                session["file_path"] = os.path.join(base_dir, file_path)
            else:
                session["file_path"] = os.path.join(base_dir, "repository_test", f"{test_name}.xlsx")

        session.modified = True
        return redirect(url_for('quiz'))

    except Exception as e:
        logger.error(f"Error starting test: {e}")
        return render_template('error.html', error=f'Errore caricamento test: {e}')

@app.route('/quiz')
@login_required
def quiz():
    if not session.get("test_scelto"):
        return redirect(url_for('dashboard'))

    if not session["proseguito"]:
        session["proseguito"] = True
        session.modified = True

    return show_quiz()

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
        missing = [col for col in required_cols if col not in df.columns]
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
                domande_selezionate = (
                    df_filtrato.groupby("principio", group_keys=False)
                               .apply(lambda x: x.sample(n=min(2, len(x)), random_state=42))
                               .reset_index(drop=True)
                )
            session["domande_selezionate"] = domande_selezionate.to_dict('records')

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

# Aggiungi anche supporto per le richieste GDPR nella dashboard principale
# Modifica la tua dashboard route per includere un link alle richieste GDPR
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

        # Salva risultato
        result = {
            'user_email': user_email,
            'test_name': test_scelto,
            'azienda': azienda_scelta,
            'score': perc,
            'correct_answers': n_cor,
            'total_questions': n_tot,
            'answers_json': json.dumps(risposte, ensure_ascii=False)
        }

        save_test_result(result)

        session["submitted"] = True
        session["risposte"] = risposte
        session.modified = True

        logger.info(f"Test completed: {perc}% ({n_cor}/{n_tot}) - {user_email}")

        return jsonify({
            'success': True,
            'score': perc,
            'correct': n_cor,
            'total': n_tot
        })

    except Exception as e:
        logger.error(f"Submit answers error: {e}")
        return jsonify({'success': False, 'error': str(e)})

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
