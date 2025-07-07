# app.py - Versione corretta per Azure (senza errori di avvio)
from flask import Flask, render_template, request, session, jsonify, send_file, redirect, url_for
import pandas as pd
from datetime import datetime
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

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 3600

# Configurazione GitHub
GITHUB_TOKEN = os.environ.get('GITHUB_TOKEN')
GITHUB_REPO = os.environ.get('GITHUB_REPO')
GITHUB_BRANCH = 'main'
PROGRESS_FILE = 'data/user_progress.json'
LOCAL_PROGRESS_FILE = 'user_progress.json'

def safe_load_from_github():
    """Carica i dati da GitHub con gestione errori sicura"""
    try:
        if not GITHUB_TOKEN or not GITHUB_REPO:
            return None
        
        url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{PROGRESS_FILE}"
        headers = {
            'Authorization': f'token {GITHUB_TOKEN}',
            'Accept': 'application/vnd.github.v3+json'
        }
        
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            content = response.json()['content']
            decoded_content = base64.b64decode(content).decode('utf-8')
            data = json.loads(decoded_content)
            print(f"✓ Dati GitHub caricati: {len(data.get('users', {}))} utenti")
            return data
        else:
            print(f"⚠ GitHub API response: {response.status_code}")
            return None
            
    except Exception as e:
        print(f"⚠ Errore GitHub (non critico): {e}")
        return None

def initialize_storage():
    """Inizializza storage in modo sicuro"""
    try:
        print("=== Inizializzazione Storage ===")
        
        # Prova a caricare da GitHub
        github_data = safe_load_from_github()
        
        if github_data:
            # Salva localmente
            with open(LOCAL_PROGRESS_FILE, 'w', encoding='utf-8') as f:
                json.dump(github_data, f, indent=2, ensure_ascii=False)
            print("✓ Dati sincronizzati da GitHub")
            return github_data
        
        # Se GitHub non disponibile, usa file locale
        if os.path.exists(LOCAL_PROGRESS_FILE):
            with open(LOCAL_PROGRESS_FILE, 'r', encoding='utf-8') as f:
                local_data = json.load(f)
            print("✓ Usando dati locali")
            return local_data
        
        # Crea file nuovo
        new_data = {
            "users": {},
            "test_results": [],
            "last_updated": datetime.now().isoformat()
        }
        
        with open(LOCAL_PROGRESS_FILE, 'w', encoding='utf-8') as f:
            json.dump(new_data, f, indent=2, ensure_ascii=False)
        
        print("✓ Creato nuovo file progressi")
        return new_data
        
    except Exception as e:
        print(f"⚠ Errore inizializzazione storage: {e}")
        # Return minimal data per evitare crash
        return {
            "users": {},
            "test_results": [],
            "last_updated": datetime.now().isoformat()
        }

def load_progress_data():
    """Carica progressi con fallback sicuro"""
    try:
        if os.path.exists(LOCAL_PROGRESS_FILE):
            with open(LOCAL_PROGRESS_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception as e:
        print(f"Errore caricamento file locale: {e}")
    
    # Fallback: dati vuoti
    return {
        "users": {},
        "test_results": [],
        "last_updated": datetime.now().isoformat()
    }

def save_progress_data(data):
    """Salva progressi con gestione errori"""
    try:
        data["last_updated"] = datetime.now().isoformat()
        
        # Salva sempre localmente
        with open(LOCAL_PROGRESS_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        # Prova a salvare su GitHub (non bloccante)
        try:
            if GITHUB_TOKEN and GITHUB_REPO:
                save_to_github_async(data)
        except Exception as e:
            print(f"⚠ GitHub save error (non-critical): {e}")
        
        return True
        
    except Exception as e:
        print(f"Errore salvataggio: {e}")
        return False

def save_to_github_async(data):
    """Salva su GitHub in modo asincrono (non bloccante)"""
    try:
        content = json.dumps(data, indent=2, ensure_ascii=False)
        encoded_content = base64.b64encode(content.encode('utf-8')).decode('utf-8')
        
        url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{PROGRESS_FILE}"
        headers = {
            'Authorization': f'token {GITHUB_TOKEN}',
            'Accept': 'application/vnd.github.v3+json'
        }
        
        # Get SHA if file exists
        try:
            response = requests.get(url, headers=headers, timeout=5)
            sha = response.json()['sha'] if response.status_code == 200 else None
        except:
            sha = None
        
        payload = {
            'message': f'Auto-update progress {datetime.now().strftime("%H:%M:%S")}',
            'content': encoded_content,
            'branch': GITHUB_BRANCH
        }
        
        if sha:
            payload['sha'] = sha
        
        response = requests.put(url, headers=headers, json=payload, timeout=10)
        
        if response.status_code in [200, 201]:
            print("✓ GitHub aggiornato")
        else:
            print(f"⚠ GitHub error: {response.status_code}")
            
    except Exception as e:
        print(f"⚠ GitHub async save error: {e}")

# Funzioni helper
def get_user_data(email):
    data = load_progress_data()
    return data["users"].get(email, {})

def save_user_data(email, user_info):
    data = load_progress_data()
    data["users"][email] = user_info
    save_progress_data(data)

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
    save_progress_data(data)

def validate_email(email):
    pattern = r'^[a-zA-Z]+\.[a-zA-Z]+@(auxiell|euxilia|xva-services)\.com$'
    return re.match(pattern, email) is not None

def extract_company_from_email(email):
    if '@auxiell.com' in email:
        return 'auxiell'
    elif '@euxilia.com' in email:
        return 'euxilia'  
    elif '@xva-services.com' in email:
        return 'xva'
    return None

def extract_name_from_email(email):
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

# Routes
@app.route('/health')
def health_check():
    try:
        data = load_progress_data()
        return jsonify({
            'status': 'healthy',
            'users_count': len(data.get('users', {})),
            'results_count': len(data.get('test_results', [])),
            'github_configured': bool(GITHUB_TOKEN and GITHUB_REPO),
            'local_file_exists': os.path.exists(LOCAL_PROGRESS_FILE),
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500

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

@app.route('/')
def index():
    if session.get('logged_in'):
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        
        if not validate_email(email):
            return render_template('login.html', error='Email non valida. Usa il formato nome.cognome@azienda.com')
        
        try:
            azienda = extract_company_from_email(email)
            nome, cognome = extract_name_from_email(email)
            
            user_data = get_user_data(email)
            
            if not user_data:
                user_data = {
                    'email': email,
                    'nome': nome,
                    'cognome': cognome,
                    'azienda': azienda,
                    'created_at': datetime.now().isoformat(),
                    'last_login': datetime.now().isoformat()
                }
            else:
                user_data['last_login'] = datetime.now().isoformat()
            
            save_user_data(email, user_data)
            
            session['logged_in'] = True
            session['user_email'] = email
            session['utente'] = f"{nome} {cognome}"
            session['azienda_scelta'] = azienda
            session.permanent = True
            
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            print(f"Login error: {e}")
            return render_template('login.html', error='Errore durante il login. Riprova.')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

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
            tipologie_file = "repository_test/Tipologia Test.xlsx"
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
                            available_tests.append({
                                'name': test_name,
                                'completed': test_name in completed_test_names
                            })
        except Exception as e:
            print(f"Error loading tests: {e}")
        
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
        print(f"Dashboard error: {e}")
        return render_template('error.html', error=f'Errore dashboard: {e}')

@app.route('/start_test/<test_name>')
@login_required
def start_test(test_name):
    session["test_scelto"] = test_name
    session["proseguito"] = False
    session["submitted"] = False
    session["domande_selezionate"] = None
    
    try:
        tipologie_file = "repository_test/Tipologia Test.xlsx"
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
                session["file_path"] = file_path
            else:
                session["file_path"] = f"repository_test/{test_name}.xlsx"
        
        session.modified = True
        return redirect(url_for('quiz'))
        
    except Exception as e:
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
        print(f"\n=== CARICAMENTO QUIZ ===")
        print(f"File path: {file_path}")
        
        df = pd.read_excel(file_path)
        print(f"Excel caricato: {len(df)} righe, colonne: {list(df.columns)}")
        
        # Verifica che la colonna "Corretta" esista e abbia dati
        if 'Corretta' in df.columns:
            corrette_count = df['Corretta'].notna().sum()
            print(f"Colonna 'Corretta' trovata: {corrette_count}/{len(df)} righe hanno dati")
            
            # Mostra alcuni esempi
            sample_corrette = df['Corretta'].dropna().head(5).tolist()
            print(f"Esempi risposte corrette: {sample_corrette}")
        else:
            print("⚠️ ERRORE: Colonna 'Corretta' non trovata!")
            return render_template('error.html', error="Colonna 'Corretta' mancante nel file Excel")
        
        required_cols = ["Azienda", "principio", "Domanda", "Corretta", "opzione 1"]
        missing = [col for col in required_cols if col not in df.columns]
        if missing:
            return render_template('error.html', error=f"Colonne mancanti: {', '.join(missing)}")
        
        azienda_scelta = session["azienda_scelta"]
        df_filtrato = df[df["Azienda"] == azienda_scelta]
        print(f"Dopo filtro azienda '{azienda_scelta}': {len(df_filtrato)} righe")
        
        if df_filtrato.empty:
            return render_template('error.html', error=f"Nessuna domanda per {azienda_scelta}")
        
        # Verifica risposte corrette dopo il filtro
        corrette_filtrate = df_filtrato['Corretta'].notna().sum()
        print(f"Risposte corrette dopo filtro: {corrette_filtrate}/{len(df_filtrato)}")
        
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
            
            print(f"Domande selezionate: {len(domande_selezionate)}")
            
            # Debug: verifica che le risposte corrette siano nelle domande selezionate
            domande_dict = domande_selezionate.to_dict('records')
            for i, domanda in enumerate(domande_dict):
                corretta = domanda.get('Corretta', 'MISSING')
                print(f"Domanda {i}: Corretta = '{corretta}' (type: {type(corretta)})")
        
        domande = session["domande_selezionate"]
        print(f"Domande dalla sessione: {len(domande)}")
        
        domande_formatted = []
        option_cols = [c for c in df.columns if c.lower().strip().startswith("opzione")]
        
        for idx, row in enumerate(domande):
            corretta_originale = row.get('Corretta', '')
            
            # DEBUG CRITICO: Verifica il valore della risposta corretta
            print(f"\n--- DOMANDA {idx} ---")
            print(f"Corretta originale: '{corretta_originale}' (type: {type(corretta_originale)})")
            print(f"È null/nan: {pd.isna(corretta_originale) if pd else 'N/A'}")
            print(f"È stringa vuota: {corretta_originale == ''}")
            
            domanda_data = {
                'id': idx,
                'domanda': row['Domanda'],
                'principio': row['principio'],
                'tipo': 'aperta' if pd.isna(row.get("opzione 1")) or row.get("opzione 1") is None else 'chiusa',
                'opzioni': [],
                'corretta': corretta_originale,  # MANTIENI IL VALORE ORIGINALE
                'multiple': False
            }
            
            if domanda_data['tipo'] == 'chiusa':
                opzioni = []
                for col in option_cols:
                    if col in row and row[col] is not None and pd.notna(row[col]) and str(row[col]).strip():
                        opzioni.append(str(row[col]))
                domanda_data['opzioni'] = opzioni
                
                # Verifica se è multipla SOLO se abbiamo una risposta corretta valida
                if corretta_originale and not pd.isna(corretta_originale) and str(corretta_originale).strip():
                    corrette = [c.strip() for c in str(corretta_originale).split(";") if c.strip()]
                    domanda_data['multiple'] = len(corrette) > 1
                    print(f"Opzioni: {opzioni}")
                    print(f"Corrette split: {corrette}")
                    print(f"Multiple: {domanda_data['multiple']}")
                else:
                    print("⚠️ PROBLEMA: Risposta corretta vuota o invalida!")
                    domanda_data['corretta'] = "ERRORE - Risposta mancante nel file Excel"
            
            domande_formatted.append(domanda_data)
        
        print(f"=== QUIZ PRONTO: {len(domande_formatted)} domande ===")
        
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
        print(f"Errore show_quiz: {e}")
        import traceback
        traceback.print_exc()
        return render_template('error.html', error=f"Errore quiz: {e}")
def clean_text(text):
    """Pulizia ultra-robusta del testo"""
    if text is None:
        return ""
    
    # Converti a stringa
    text = str(text)
    
    # Rimuovi tutti i tipi di spazi
    import unicodedata
    
    # Normalizza Unicode
    text = unicodedata.normalize('NFKD', text)
    
    # Rimuovi caratteri di controllo e spazi speciali
    text = ''.join(char for char in text if not unicodedata.category(char).startswith('C'))
    
    # Rimuovi spazi all'inizio e fine
    text = text.strip()
    
    # Sostituisci spazi multipli con uno singolo
    import re
    text = re.sub(r'\s+', ' ', text)
    
    # Converti a minuscolo
    text = text.lower()
    
    return text

def answers_match(user_answer, correct_answer):
    """Confronto ultra-robusto delle risposte"""
    
    # Pulizia robusta
    user_clean = clean_text(user_answer)
    correct_clean = clean_text(correct_answer)
    
    print(f"  DEBUG MATCH:")
    print(f"    User RAW: '{user_answer}' (len: {len(str(user_answer)) if user_answer else 0})")
    print(f"    User CLEAN: '{user_clean}' (len: {len(user_clean)})")
    print(f"    Correct RAW: '{correct_answer}' (len: {len(str(correct_answer)) if correct_answer else 0})")
    print(f"    Correct CLEAN: '{correct_clean}' (len: {len(correct_clean)})")
    
    # Confronto diretto
    if user_clean == correct_clean:
        print(f"    MATCH: Confronto diretto ✓")
        return True
    
    # Confronto byte-by-byte per debug
    if len(user_clean) == len(correct_clean):
        for i, (u, c) in enumerate(zip(user_clean, correct_clean)):
            if u != c:
                print(f"    DIFF at pos {i}: '{u}' (ord:{ord(u)}) vs '{c}' (ord:{ord(c)})")
                break
    else:
        print(f"    DIFF: Lunghezze diverse {len(user_clean)} vs {len(correct_clean)}")
    
    # Confronto per varianti booleane
    true_variants = ['vero', 'true', 'si', 'sì', 'yes', '1', 'corretto', 'giusto']
    false_variants = ['falso', 'false', 'no', '0', 'sbagliato', 'errato']
    
    if user_clean in true_variants and correct_clean in true_variants:
        print(f"    MATCH: Entrambi TRUE variants ✓")
        return True
    if user_clean in false_variants and correct_clean in false_variants:
        print(f"    MATCH: Entrambi FALSE variants ✓")
        return True
    
    # Confronto senza spazi e punteggiatura
    import re
    user_minimal = re.sub(r'[^\w]', '', user_clean)
    correct_minimal = re.sub(r'[^\w]', '', correct_clean)
    
    if user_minimal == correct_minimal:
        print(f"    MATCH: Minimal comparison ✓")
        return True
    
    print(f"    NO MATCH ✗")
    return False
    
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
            
            print(f"\n=== DOMANDA {idx} ===")
            print(f"Domanda: {row.get('domanda', '')[:100]}...")
            print(f"Risposta utente RAW: '{user_answer}' (type: {type(user_answer)})")
            
            # Verifica se è domanda aperta o chiusa
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
                print("Tipo: APERTA")
                
            else:
                # Domanda chiusa
                corretta_raw = row.get("corretta", "")
                print(f"Risposta corretta RAW: '{corretta_raw}' (type: {type(corretta_raw)})")
                
                if not corretta_raw or pd.isna(corretta_raw):
                    print("⚠️ Risposta corretta mancante!")
                    corretta_raw = "ERRORE - Risposta corretta mancante"
                
                # Processa risposte corrette (potrebbero essere multiple)
                if corretta_raw and corretta_raw != "ERRORE - Risposta corretta mancante":
                    corrette_list = [c.strip() for c in str(corretta_raw).split(";") if c.strip()]
                else:
                    corrette_list = []
                
                print(f"Risposte corrette split: {corrette_list}")
                
                # Verifica se è multipla
                is_multiple = row.get("multiple", False) or len(corrette_list) > 1
                print(f"È multipla: {is_multiple}")
                
                if is_multiple:
                    # Risposta multipla
                    user_answers_list = user_answer if isinstance(user_answer, list) else [user_answer] if user_answer else []
                    user_answers_list = [ans for ans in user_answers_list if ans]
                    
                    print(f"Risposte utente (lista): {user_answers_list}")
                    
                    # Confronto per risposte multiple usando la nuova funzione
                    matches = []
                    for user_ans in user_answers_list:
                        for correct_ans in corrette_list:
                            if answers_match(user_ans, correct_ans):
                                matches.append(user_ans)
                                break
                    
                    # È corretta se tutte le risposte utente matchano e sono nel numero giusto
                    is_correct = len(matches) == len(user_answers_list) == len(corrette_list)
                    risposta_str = ";".join(user_answers_list)
                    
                else:
                    # Risposta singola
                    print(f"Risposta singola - User: '{user_answer}', Correct: {corrette_list}")
                    
                    is_correct = False
                    if corrette_list:
                        for correct_option in corrette_list:
                            print(f"  Confrontando '{user_answer}' con '{correct_option}'")
                            if answers_match(user_answer, correct_option):
                                is_correct = True
                                print(f"  ✓ MATCH trovato!")
                                break
                            else:
                                print(f"  ✗ No match")
                    
                    risposta_str = str(user_answer) if user_answer else ""
                
                print(f"RISULTATO: {'✓ CORRETTO' if is_correct else '✗ SBAGLIATO'}")
                print(f"Risposta finale: '{risposta_str}'")
                
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
        print("\n=== CALCOLO PUNTEGGIO ===")
        df_r = pd.DataFrame(risposte)
        chiuse = df_r[df_r["Tipo"] == "chiusa"]
        n_tot = len(chiuse)
        
        if n_tot > 0:
            n_cor = int(chiuse["Esatta"].sum())
            perc = int(n_cor / n_tot * 100)
            
            print(f"Domande chiuse: {n_tot}")
            print(f"Risposte corrette: {n_cor}")
            print(f"Percentuale: {perc}%")
            
            # Mostra dettaglio risposte sbagliate
            sbagliate = chiuse[chiuse["Esatta"] == False]
            if len(sbagliate) > 0:
                print(f"\nRisposte SBAGLIATE ({len(sbagliate)}):")
                for _, risposta in sbagliate.iterrows():
                    print(f"- Domanda: {risposta['Domanda'][:50]}...")
                    print(f"  User: '{risposta['Risposta']}' | Correct: '{risposta['Corretta']}'")
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
        
        print(f"\n=== SUBMIT SUCCESS: {perc}% ({n_cor}/{n_tot}) ===")
        
        return jsonify({
            'success': True,
            'score': perc,
            'correct': n_cor,
            'total': n_tot
        })
        
    except Exception as e:
        print(f"=== SUBMIT ERROR ===")
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)})

@app.route('/debug/quiz_data')
@login_required
def debug_quiz_data():
    """Debug per verificare i dati del quiz e le risposte corrette"""
    try:
        # Leggi direttamente dal file Excel
        file_path = session.get("file_path", "")
        if not file_path:
            return jsonify({'error': 'Nessun file path in sessione'})
        
        print(f"Leggendo file: {file_path}")
        df = pd.read_excel(file_path)
        
        azienda_scelta = session.get("azienda_scelta")
        df_filtrato = df[df["Azienda"] == azienda_scelta]
        
        debug_info = {
            'file_path': file_path,
            'total_rows': len(df),
            'filtered_rows': len(df_filtrato),
            'columns': list(df.columns),
            'azienda_filter': azienda_scelta,
            'sample_data': []
        }
        
        # Prendi le prime 5 domande per debug
        for idx, row in df_filtrato.head(5).iterrows():
            sample = {
                'index': idx,
                'domanda': row.get('Domanda', 'N/A')[:100],
                'corretta_raw': row.get('Corretta', 'MISSING'),
                'corretta_type': str(type(row.get('Corretta', None))),
                'opzione_1': row.get('opzione 1', 'N/A'),
                'principio': row.get('principio', 'N/A'),
                'all_columns_for_this_row': {}
            }
            
            # Mostra tutti i valori per questa riga
            for col in df.columns:
                sample['all_columns_for_this_row'][col] = str(row.get(col, 'N/A'))
            
            debug_info['sample_data'].append(sample)
        
        return jsonify(debug_info)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500



@app.route('/download_results')
@app.route('/download_results/<test_name>')
@login_required
def download_results(test_name=None):
    try:
        print("=== DOWNLOAD RESULTS START ===")
        user_email = session.get('user_email')
        
        if not user_email:
            return "Utente non identificato.", 404
        
        # Se non specificato un test, prendi l'ultimo
        if not test_name:
            # Prova prima dalla sessione
            if session.get("submitted") and "risposte" in session:
                print("Usando dati dalla sessione")
                risposte = session["risposte"]
                test_name = session.get("test_scelto", "Test")
            else:
                # Prendi l'ultimo test dal database
                print("Recuperando ultimo test dal database")
                user_results = get_user_test_results(user_email)
                if not user_results:
                    return "Nessun test completato trovato. Completa prima un test.", 404
                
                latest_result = user_results[0]
                test_name = latest_result.get('test_name', 'Test')
                
                try:
                    risposte = json.loads(latest_result.get('answers_json', '[]'))
                    if not risposte:
                        return "Dati del test non disponibili.", 404
                except Exception as e:
                    print(f"Errore parsing JSON: {e}")
                    return "Errore nel recupero dei dati del test.", 500
        else:
            # Test specifico richiesto
            print(f"Cercando test specifico: {test_name}")
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
                print(f"Errore parsing JSON: {e}")
                return "Errore nel recupero dei dati del test.", 500
        
        utente = session.get("utente", "Utente")
        azienda = session.get("azienda_scelta", "")
        
        print(f"Generando report per: {utente}, Test: {test_name}, Risposte: {len(risposte)}")
        
        # Crea DataFrame
        df_r = pd.DataFrame(risposte)
        
        # Calcola punteggio
        chiuse = df_r[df_r["Tipo"] == "chiusa"]
        n_tot = len(chiuse)
        n_cor = int(chiuse["Esatta"].sum()) if n_tot else 0
        perc = int(n_cor / n_tot * 100) if n_tot else 0
        
        print(f"Punteggio: {perc}% ({n_cor}/{n_tot})")
        
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
            # Sheet riassunto
            info.to_excel(writer, index=False, sheet_name="Riassunto", startrow=0)
            
            # Sheet dettaglio - pulisci e organizza i dati
            df_export = df_r.copy()
            
            # Riordina colonne per leggibilità
            column_order = ["Tipo", "Azienda", "Utente", "Test", "Argomento", "Domanda", "Risposta", "Corretta", "Esatta"]
            existing_columns = [col for col in column_order if col in df_export.columns]
            other_columns = [col for col in df_export.columns if col not in column_order]
            final_columns = existing_columns + other_columns
            
            df_export = df_export[final_columns]
            df_export.to_excel(writer, index=False, sheet_name="Dettaglio Risposte", startrow=0)
        
        # Proteggi il foglio riassunto
        buf.seek(0)
        wb = load_workbook(buf)
        
        if "Riassunto" in wb.sheetnames:
            ws = wb["Riassunto"]
            ws.protection.sheet = True
            ws.protection.password = "assessment25"
            ws.protection.enable()
        
        buf_protetto = BytesIO()
        wb.save(buf_protetto)
        buf_protetto.seek(0)
        
        # Nome file
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        nome_sicuro = re.sub(r'[^\w\s-]', '', utente).strip()
        nome_sicuro = re.sub(r'[-\s]+', '_', nome_sicuro)
        test_sicuro = re.sub(r'[^\w\s-]', '', test_name).strip()
        test_sicuro = re.sub(r'[-\s]+', '_', test_sicuro)
        
        filename = f"risultati_{nome_sicuro}_{test_sicuro}_{timestamp}.xlsx"
        
        print(f"Download file: {filename}")
        print("=== DOWNLOAD SUCCESS ===")
        
        return send_file(
            buf_protetto,
            as_attachment=True,
            download_name=filename,
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )
        
    except Exception as e:
        print(f"=== DOWNLOAD ERROR ===")
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return f"Errore durante il download: {e}", 500


# Aggiungiamo anche un endpoint per scaricare test specifici dalla dashboard
@app.route('/download_latest')
@login_required
def download_latest():
    """Download dell'ultimo test completato"""
    return download_results()

# Inizializzazione sicura all'avvio
try:
    print("=== Avvio App ===")
    initialize_storage()
    print("=== App Pronta ===")
except Exception as e:
    print(f"⚠ Errore inizializzazione (non critico): {e}")

if __name__ == '__main__':
    app.run(debug=True)

