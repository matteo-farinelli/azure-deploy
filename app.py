from flask import Flask, render_template, request, session, jsonify, send_file, redirect, url_for, flash
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
import json
import requests
from urllib.parse import urlencode

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config['SESSION_COOKIE_SECURE'] = False  # Per sviluppo
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 ora

# Configurazione Azure AD
AZURE_AD_CONFIG = {
    'CLIENT_ID': '12345678-1234-1234-1234-123456789012',  # DA CONFIGURARE
    'CLIENT_SECRET': 'your-client-secret-here',  # DA CONFIGURARE
    'TENANT_ID': 'your-tenant-id-here',  # DA CONFIGURARE
    'AUTHORITY': 'https://login.microsoftonline.com/your-tenant-id-here',
    'REDIRECT_URI': 'https://vericaconoscenze-b8hbaagxakbwdrbr.italynorth-01.azurewebsites.net/auth/callback',
    'SCOPE': ['openid', 'profile', 'email', 'User.Read'],
    'ALLOWED_DOMAINS': ['auxiell.com', 'euxilia.com', 'xva.com']  # Domini aziendali permessi
}

DEFAULT_KEYS = {
    "test_scelto": None,
    "azienda_scelta": None,
    "proseguito": False,
    "submitted": False,
    "invia_a_mentor": None,
    "tutte_domande": None,
    "utente": "",
    "domande_selezionate": None,
    "file_path": None,
    "user_id": None,
    "user_name": None,
    "user_email": None,
    "user_company": None
}

# File per salvare i dati utenti
RESULTS_FILE = "data/user_results.json"

def ensure_data_directory():
    """Crea la directory data se non esiste"""
    if not os.path.exists("data"):
        os.makedirs("data")

def load_user_results():
    """Carica i risultati degli utenti"""
    ensure_data_directory()
    try:
        with open(RESULTS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def save_user_results(results):
    """Salva i risultati degli utenti"""
    ensure_data_directory()
    with open(RESULTS_FILE, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

def get_company_from_email(email):
    """Determina l'azienda dall'email"""
    domain = email.split('@')[-1].lower()
    company_mapping = {
        'auxiell.com': 'auxiell',
        'euxilia.com': 'euxilia', 
        'xva.com': 'xva'
    }
    return company_mapping.get(domain, domain.split('.')[0])

def is_email_allowed(email):
    """Controlla se l'email appartiene a un dominio autorizzato"""
    domain = email.split('@')[-1].lower()
    return domain in AZURE_AD_CONFIG['ALLOWED_DOMAINS']

def get_all_available_tests():
    """Ottieni tutti i test disponibili"""
    try:
        tipologie_file = "repository_test/Tipologia Test.xlsx"
        df_tipologie = pd.read_excel(tipologie_file)
        return df_tipologie["Nome test"].tolist()
    except:
        return []

def get_user_completed_tests(user_id):
    """Ottieni i test completati da un utente"""
    results = load_user_results()
    user_results = results.get(user_id, [])
    completed_tests = set()
    for result in user_results:
        completed_tests.add(result.get('test_name', ''))
    return list(completed_tests)

def initialize_session():
    """Inizializza la sessione"""
    session.permanent = True
    for key, default_value in DEFAULT_KEYS.items():
        if key not in session:
            session[key] = default_value
    session.modified = True

def require_login(f):
    """Decorator per richiedere il login"""
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session['user_id'] is None:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

@app.route('/login')
def login():
    """Pagina di login - reindirizza a Microsoft"""
    # Genera state per sicurezza
    state = secrets.token_urlsafe(32)
    session['auth_state'] = state
    
    # URL di autorizzazione Microsoft
    auth_url = f"{AZURE_AD_CONFIG['AUTHORITY']}/oauth2/v2.0/authorize?" + urlencode({
        'client_id': AZURE_AD_CONFIG['CLIENT_ID'],
        'response_type': 'code',
        'redirect_uri': AZURE_AD_CONFIG['REDIRECT_URI'],
        'response_mode': 'query',
        'scope': ' '.join(AZURE_AD_CONFIG['SCOPE']),
        'state': state,
        'prompt': 'select_account'  # Forza la selezione dell'account
    })
    
    return render_template('login_microsoft.html', auth_url=auth_url)

@app.route('/auth/callback')
def auth_callback():
    """Callback di autenticazione Microsoft"""
    try:
        # Verifica lo state per sicurezza
        if request.args.get('state') != session.get('auth_state'):
            flash('Errore di sicurezza durante l\'autenticazione', 'error')
            return redirect(url_for('login'))
        
        # Ottieni il codice di autorizzazione
        auth_code = request.args.get('code')
        if not auth_code:
            error = request.args.get('error_description', 'Autenticazione fallita')
            flash(f'Errore di autenticazione: {error}', 'error')
            return redirect(url_for('login'))
        
        # Scambia il codice per un token
        token_url = f"{AZURE_AD_CONFIG['AUTHORITY']}/oauth2/v2.0/token"
        token_data = {
            'client_id': AZURE_AD_CONFIG['CLIENT_ID'],
            'client_secret': AZURE_AD_CONFIG['CLIENT_SECRET'],
            'code': auth_code,
            'redirect_uri': AZURE_AD_CONFIG['REDIRECT_URI'],
            'grant_type': 'authorization_code',
            'scope': ' '.join(AZURE_AD_CONFIG['SCOPE'])
        }
        
        token_response = requests.post(token_url, data=token_data)
        token_json = token_response.json()
        
        if 'access_token' not in token_json:
            flash('Errore nell\'ottenimento del token di accesso', 'error')
            return redirect(url_for('login'))
        
        # Ottieni informazioni utente
        access_token = token_json['access_token']
        user_response = requests.get(
            'https://graph.microsoft.com/v1.0/me',
            headers={'Authorization': f'Bearer {access_token}'}
        )
        
        if user_response.status_code != 200:
            flash('Errore nell\'ottenimento delle informazioni utente', 'error')
            return redirect(url_for('login'))
        
        user_data = user_response.json()
        user_email = user_data.get('mail') or user_data.get('userPrincipalName')
        user_name = user_data.get('displayName', '')
        
        # Verifica che l'email sia da un dominio autorizzato
        if not is_email_allowed(user_email):
            flash(f'Accesso negato. Solo gli account aziendali sono autorizzati.', 'error')
            return redirect(url_for('login'))
        
        # Determina l'azienda dall'email
        user_company = get_company_from_email(user_email)
        
        # Imposta la sessione
        session['user_id'] = user_email
        session['user_name'] = user_name
        session['user_email'] = user_email
        session['user_company'] = user_company
        session['access_token'] = access_token
        session.permanent = True
        session.modified = True
        
        # Pulisci lo state
        session.pop('auth_state', None)
        
        flash(f'Benvenuto, {user_name}!', 'success')
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        flash(f'Errore durante l\'autenticazione: {str(e)}', 'error')
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    """Logout - pulisce la sessione e reindirizza a Microsoft logout"""
    # URL di logout Microsoft
    logout_url = f"{AZURE_AD_CONFIG['AUTHORITY']}/oauth2/v2.0/logout?" + urlencode({
        'post_logout_redirect_uri': request.url_root
    })
    
    session.clear()
    return redirect(logout_url)

@app.route('/')
@require_login
def dashboard():
    """Dashboard utente con test completati e da fare"""
    user_id = session['user_id']
    user_name = session['user_name']
    user_company = session['user_company']
    
    # Ottieni tutti i test disponibili per l'azienda
    all_tests = get_all_available_tests()
    completed_tests = get_user_completed_tests(user_id)
    
    # Test ancora da fare
    pending_tests = [test for test in all_tests if test not in completed_tests]
    
    # Ottieni i risultati dettagliati
    results = load_user_results()
    user_results = results.get(user_id, [])
    
    return render_template('dashboard.html',
                         user_name=user_name,
                         user_email=session['user_email'],
                         user_company=user_company,
                         completed_tests=user_results,
                         pending_tests=pending_tests,
                         total_tests=len(all_tests),
                         completed_count=len(completed_tests))

@app.route('/take_test/<test_name>')
@require_login
def take_test(test_name):
    """Inizia un test specifico"""
    # Reset dei dati di sessione per nuovo test
    for key in ["test_scelto", "proseguito", "submitted", "domande_selezionate", "file_path"]:
        session[key] = None
    
    session["test_scelto"] = test_name
    session["azienda_scelta"] = session["user_company"]
    session.modified = True
    
    # Carica il test
    try:
        tipologie_file = "repository_test/Tipologia Test.xlsx"
        df_tipologie = pd.read_excel(tipologie_file)
        file_row = df_tipologie[df_tipologie["Nome test"] == test_name]
        
        if len(file_row) == 0:
            flash(f'Test "{test_name}" non trovato', 'error')
            return redirect(url_for('dashboard'))
        
        # Imposta tutte_domande
        if "Tutte" in file_row.columns:
            tutte_value = str(file_row["Tutte"].values[0]).strip().lower()
            session["tutte_domande"] = tutte_value == "si"
        else:
            session["tutte_domande"] = False
        
        # Imposta file_path
        if "Percorso file" in file_row.columns:
            file_path = file_row["Percorso file"].values[0]
            session["file_path"] = file_path
        else:
            session["file_path"] = f"repository_test/{test_name}.xlsx"
        
        session.modified = True
        return redirect(url_for('quiz'))
        
    except Exception as e:
        flash(f'Errore nel caricamento del test: {e}', 'error')
        return redirect(url_for('dashboard'))

@app.route('/quiz')
@require_login
def quiz():
    """Pagina del quiz"""
    if not session.get("test_scelto"):
        flash('Nessun test selezionato', 'error')
        return redirect(url_for('dashboard'))
    
    return show_quiz()

def show_quiz():
    try:
        # Carica il file delle domande
        file_path = session.get("file_path", "")
        df = pd.read_excel(file_path)
        
        # Verifica colonne necessarie
        required_cols = ["Azienda", "principio", "Domanda", "Corretta", "opzione 1"]
        missing = [col for col in required_cols if col not in df.columns]
        if missing:
            flash(f"Mancano le colonne obbligatorie: {', '.join(missing)}", 'error')
            return redirect(url_for('dashboard'))
        
        option_cols = [c for c in df.columns if c.lower().strip().startswith("opzione")]
        if not option_cols:
            flash("Nessuna colonna di opzione trovata.", 'error')
            return redirect(url_for('dashboard'))
        
        # Filtra domande per azienda
        azienda_scelta = session["user_company"]
        df_filtrato = df[df["Azienda"] == azienda_scelta]
        
        if df_filtrato.empty:
            flash(f"Non ci sono domande disponibili per l'azienda '{azienda_scelta}' in questo test.", 'error')
            return redirect(url_for('dashboard'))
        
        # Seleziona domande se non già fatto
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
            session.modified = True
        
        domande = session["domande_selezionate"]
        
        # Prepara dati per il template
        domande_formatted = []
        
        for idx, row in enumerate(domande):
            domanda_data = {
                'id': idx,
                'domanda': row['Domanda'],
                'principio': row['principio'],
                'tipo': 'aperta' if pd.isna(row.get("opzione 1")) or row.get("opzione 1") is None else 'chiusa',
                'opzioni': [],
                'corretta': row.get('Corretta', ''),
                'multiple': False
            }
            
            if domanda_data['tipo'] == 'chiusa':
                opzioni = []
                for col in option_cols:
                    if col in row and row[col] is not None and pd.notna(row[col]) and str(row[col]).strip():
                        opzioni.append(str(row[col]))
                domanda_data['opzioni'] = opzioni
                
                corretta_raw = row.get("Corretta", "")
                if corretta_raw is None or pd.isna(corretta_raw):
                    corretta_raw = ""
                
                corrette = [c.strip() for c in str(corretta_raw).split(";") if c.strip()]
                domanda_data['multiple'] = len(corrette) > 1
            
            domande_formatted.append(domanda_data)
        
        logo_path, logo_exists = get_logo_info(session["user_company"])
        company_color = get_company_color(session["user_company"])
        
        return render_template('quiz_auth.html', 
                             domande=domande_formatted,
                             azienda=session["user_company"],
                             test_name=session["test_scelto"],
                             proseguito=True,  # Sempre True perché l'utente è già loggato
                             submitted=session.get("submitted", False),
                             user_name=session["user_name"],
                             logo_path=logo_path if logo_exists else None,
                             company_color=company_color)
        
    except Exception as e:
        flash(f'Errore nel caricamento del test: {e}', 'error')
        return redirect(url_for('dashboard'))

@app.route('/submit_answers', methods=['POST'])
@require_login
def submit_answers():
    try:
        data = request.json
        answers = data.get('answers', {})
        
        # Estrai i dati dalla sessione
        user_name = session["user_name"]
        azienda_scelta = session["user_company"]
        test_scelto = session["test_scelto"]
        domande = session["domande_selezionate"]
        
        if not domande:
            return jsonify({
                'success': False, 
                'error': 'Nessuna domanda trovata. Ricarica la pagina.',
                'reload': True
            })
        
        risposte = []
        
        for idx, row in enumerate(domande):
            answer_key = f'question_{idx}'
            user_answer = answers.get(answer_key, '')
            
            # Gestisci valori None
            opzione_1 = row.get("opzione 1")
            if opzione_1 is None or str(opzione_1).lower() in ['nan', 'none', '', 'null']:
                # Domanda aperta
                risposte.append({
                    "Tipo": "aperta",
                    "Azienda": azienda_scelta,
                    "Utente": user_name,
                    "Email": session["user_email"],
                    "Domanda": row.get("Domanda", ""),
                    "Argomento": row.get("principio", ""),
                    "Risposta": user_answer,
                    "Corretta": None,
                    "Esatta": None,
                    "Test": test_scelto
                })
            else:
                # Domanda chiusa
                corretta_raw = row.get("Corretta", "")
                if corretta_raw is None:
                    corretta_raw = ""
                
                corrette = [c.strip() for c in str(corretta_raw).split(";") if c.strip()]
                
                if len(corrette) > 1:
                    # Risposta multipla
                    user_answers = user_answer if isinstance(user_answer, list) else [user_answer] if user_answer else []
                    user_answers = [ans for ans in user_answers if ans]
                    is_correct = set(user_answers) == set(corrette)
                    risposta_str = ";".join(user_answers)
                else:
                    # Risposta singola
                    is_correct = user_answer in corrette if corrette else False
                    risposta_str = user_answer
                
                risposte.append({
                    "Tipo": "chiusa",
                    "Azienda": azienda_scelta,
                    "Utente": user_name,
                    "Email": session["user_email"],
                    "Domanda": row.get("Domanda", ""),
                    "Argomento": row.get("principio", ""),
                    "Risposta": risposta_str,
                    "Corretta": corretta_raw,
                    "Esatta": is_correct,
                    "Test": test_scelto
                })
        
        # Calcola punteggio
        df_r = pd.DataFrame(risposte)
        chiuse = df_r[df_r["Tipo"] == "chiusa"]
        n_tot = len(chiuse)
        n_cor = int(chiuse["Esatta"].sum()) if n_tot > 0 else 0
        perc = int(n_cor / n_tot * 100) if n_tot > 0 else 0
        
        # Salva i risultati nel database utente
        user_id = session["user_id"]
        results = load_user_results()
        
        if user_id not in results:
            results[user_id] = []
        
        test_result = {
            'test_name': test_scelto,
            'company': azienda_scelta,
            'score': perc,
            'correct_answers': n_cor,
            'total_questions': n_tot,
            'completed_at': datetime.now().isoformat(),
            'user_name': user_name,
            'user_email': session["user_email"],
            'answers': risposte
        }
        
        results[user_id].append(test_result)
        save_user_results(results)
        
        # Salva i risultati nella sessione per il download
        session["submitted"] = True
        session["risposte"] = risposte
        session.modified = True
        
        return jsonify({
            'success': True, 
            'score': perc,
            'correct': n_cor,
            'total': n_tot,
            'results_data': {
                'utente': user_name,
                'azienda': azienda_scelta,
                'test': test_scelto,
                'score': perc,
                'correct': n_cor,
                'total': n_tot
            }
        })
        
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"Errore in submit_answers: {error_details}")
        return jsonify({
            'success': False, 
            'error': f'Errore del server: {str(e)}',
            'reload': True
        })

@app.route('/download_results')
@require_login
def download_results():
    try:
        if not session.get("submitted") or "risposte" not in session:
            flash("Nessun risultato disponibile per il download", "error")
            return redirect(url_for('dashboard'))
        
        risposte = session["risposte"]
        utente = session["user_name"]
        
        df_r = pd.DataFrame(risposte)
        chiuse = df_r[df_r["Tipo"] == "chiusa"]
        n_tot = len(chiuse)
        n_cor = int(chiuse["Esatta"].sum()) if n_tot else 0
        perc = int(n_cor / n_tot * 100) if n_tot else 0
        
        data_test = datetime.now().strftime("%d/%m/%Y")
        info = pd.DataFrame([{
            "Nome": utente,
            "Email": session["user_email"],
            "Data": data_test,
            "Punteggio": f"{perc}%",
            "Azienda": session["user_company"],
            "Test": session["test_scelto"]
        }])
        
        buf = BytesIO()
        with pd.ExcelWriter(buf, engine="openpyxl") as writer:
            info.to_excel(writer, index=False, sheet_name="Risultati", startrow=0)
            df_r["Punteggio"] = f"{perc}%"
            df_r.to_excel(writer, index=False, sheet_name="Dettaglio Risposte", startrow=0)
        
        # Proteggi il foglio
        buf.seek(0)
        wb = load_workbook(buf)
        ws = wb["Risultati"]
        ws.protection.sheet = True
        ws.protection.password = "assessment25"
        ws.protection.enable()
        
        buf_protetto = BytesIO()
        wb.save(buf_protetto)
        buf_protetto.seek(0)
        
        filename = f"risultati_{utente.replace(' ', '_')}_{session['test_scelto']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        
        return send_file(
            buf_protetto,
            as_attachment=True,
            download_name=filename,
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )
        
    except Exception as e:
        flash(f"Errore nella generazione del file: {e}", "error")
        return redirect(url_for('dashboard'))

def get_logo_info(azienda_scelta=None):
    """Restituisce informazioni sul logo da utilizzare"""
    if azienda_scelta is None:
        logo_path = "static/images/auxiell_group_logobase.png"
    else:
        nome_logo = re.sub(r'\W+', '_', azienda_scelta.lower()) + "_logobase.png"
        logo_path = os.path.join("static/images", nome_logo)
    
    if os.path.exists(logo_path):
        return logo_path, True
    return logo_path, False

def get_company_color(azienda):
    """Restituisce il colore associato all'azienda"""
    colori = {
        "auxiell": "#C8102E",
        "euxilia": "#0072C6",
        "xva": "#FFD700"
    }
    return colori.get(azienda.lower() if azienda else "", "#F63366")

if __name__ == '__main__':
    app.run(debug=True)
