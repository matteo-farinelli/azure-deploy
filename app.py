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
import sqlite3
from functools import wraps
import json

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 3600

# Database
DATABASE = 'assessment_app.db'

def init_db():
    """Inizializza il database"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Tabella utenti semplificata - solo email
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            nome TEXT NOT NULL,
            cognome TEXT NOT NULL,
            azienda TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
    ''')
    
    # Tabella risultati test
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS test_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_email TEXT NOT NULL,
            test_name TEXT NOT NULL,
            azienda TEXT NOT NULL,
            score INTEGER NOT NULL,
            correct_answers INTEGER NOT NULL,
            total_questions INTEGER NOT NULL,
            completed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            answers_json TEXT
        )
    ''')
    
    conn.commit()
    conn.close()

def get_db_connection():
    """Connessione database"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def validate_email(email):
    """Valida email aziendale"""
    pattern = r'^[a-zA-Z]+\.[a-zA-Z]+@(auxiell|euxilia|xva-services)\.com$'
    return re.match(pattern, email) is not None

def extract_company_from_email(email):
    """Estrae azienda dall'email"""
    if '@auxiell.com' in email:
        return 'auxiell'
    elif '@euxilia.com' in email:
        return 'euxilia'  
    elif '@xva-services.com' in email:
        return 'xva'
    return None

def extract_name_from_email(email):
    """Estrae nome e cognome dall'email"""
    local_part = email.split('@')[0]
    parts = local_part.split('.')
    if len(parts) >= 2:
        nome = parts[0].title()
        cognome = parts[1].title()
        return nome, cognome
    return "User", "Unknown"

def login_required(f):
    """Decorator per richiedere login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def get_logo_info(azienda_scelta=None):
    """Info logo"""
    if azienda_scelta is None:
        logo_path = "static/images/auxiell_group_logobase.png"
    else:
        nome_logo = re.sub(r'\W+', '_', azienda_scelta.lower()) + "_logobase.png"
        logo_path = os.path.join("static/images", nome_logo)
    
    if os.path.exists(logo_path):
        return logo_path, True
    return logo_path, False

def get_company_color(azienda):
    """Colore azienda"""
    colori = {
        "auxiell": "#C8102E",
        "euxilia": "#0072C6", 
        "xva": "#FFD700"
    }
    return colori.get(azienda.lower() if azienda else "", "#F63366")

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
        
        # Estrai info dall'email
        azienda = extract_company_from_email(email)
        nome, cognome = extract_name_from_email(email)
        
        # Crea o aggiorna utente
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        
        if not user:
            # Crea nuovo utente
            conn.execute('''
                INSERT INTO users (email, nome, cognome, azienda, last_login)
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (email, nome, cognome, azienda))
            conn.commit()
        else:
            # Aggiorna ultimo login
            conn.execute('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE email = ?', (email,))
            conn.commit()
        
        conn.close()
        
        # Imposta sessione
        session['logged_in'] = True
        session['user_email'] = email
        session['utente'] = f"{nome} {cognome}"
        session['azienda_scelta'] = azienda
        session.permanent = True
        
        return redirect(url_for('dashboard'))
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required 
def dashboard():
    user_email = session.get('user_email')
    azienda = session.get('azienda_scelta')
    
    # Test completati
    conn = get_db_connection()
    completed_tests = conn.execute('''
        SELECT test_name, score, correct_answers, total_questions, completed_at
        FROM test_results
        WHERE user_email = ?
        ORDER BY completed_at DESC
    ''', (user_email,)).fetchall()
    conn.close()
    
    # Test disponibili
    available_tests = []
    completed_test_names = [test['test_name'] for test in completed_tests]
    
    try:
        tipologie_file = "repository_test/Tipologia Test.xlsx"
        if os.path.exists(tipologie_file):
            df_tipologie = pd.read_excel(tipologie_file)
            
            if "Nome test" in df_tipologie.columns:
                for _, row in df_tipologie.iterrows():
                    test_name = row["Nome test"]
                    
                    # Verifica se disponibile per l'azienda
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
        print(f"Errore caricamento test: {e}")
    
    logo_path, logo_exists = get_logo_info(azienda)
    company_color = get_company_color(azienda)
    
    return render_template('dashboard.html',
                         completed_tests=completed_tests,
                         available_tests=available_tests,
                         utente=session.get('utente'),
                         azienda=azienda,
                         logo_path=logo_path if logo_exists else None,
                         company_color=company_color)

@app.route('/start_test/<test_name>')
@login_required
def start_test(test_name):
    # Reset dati test
    session["test_scelto"] = test_name
    session["proseguito"] = False
    session["submitted"] = False
    session["domande_selezionate"] = None
    
    # Carica configurazione test
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
        return render_template('error.html', error=f'Errore nel caricamento del test: {e}')

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
        df = pd.read_excel(file_path)
        
        # Verifica colonne
        required_cols = ["Azienda", "principio", "Domanda", "Corretta", "opzione 1"]
        missing = [col for col in required_cols if col not in df.columns]
        if missing:
            return render_template('error.html', error=f"Colonne mancanti: {', '.join(missing)}")
        
        # Filtra per azienda
        azienda_scelta = session["azienda_scelta"]
        df_filtrato = df[df["Azienda"] == azienda_scelta]
        
        if df_filtrato.empty:
            return render_template('error.html', error=f"Nessuna domanda per {azienda_scelta}")
        
        # Seleziona domande
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
        
        # Format domande
        domande_formatted = []
        option_cols = [c for c in df.columns if c.lower().strip().startswith("opzione")]
        
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
        return render_template('error.html', error=f"Errore: {e}")

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
            
            opzione_1 = row.get("opzione 1")
            if opzione_1 is None or str(opzione_1).lower() in ['nan', 'none', '']:
                # Domanda aperta
                risposte.append({
                    "Tipo": "aperta",
                    "Azienda": azienda_scelta,
                    "Utente": utente,
                    "Domanda": row.get("domanda", ""),
                    "Argomento": row.get("principio", ""),
                    "Risposta": user_answer,
                    "Corretta": None,
                    "Esatta": None,
                    "Test": test_scelto
                })
            else:
                # Domanda chiusa
                corretta_raw = row.get("corretta", "")
                if corretta_raw is None:
                    corretta_raw = ""
                
                corrette = [c.strip() for c in str(corretta_raw).split(";") if c.strip()]
                
                if len(corrette) > 1:
                    # Multipla
                    user_answers = user_answer if isinstance(user_answer, list) else [user_answer] if user_answer else []
                    user_answers = [ans for ans in user_answers if ans]
                    is_correct = set(user_answers) == set(corrette)
                    risposta_str = ";".join(user_answers)
                else:
                    # Singola
                    is_correct = user_answer in corrette if corrette else False
                    risposta_str = user_answer
                
                risposte.append({
                    "Tipo": "chiusa",
                    "Azienda": azienda_scelta,
                    "Utente": utente,
                    "Domanda": row.get("domanda", ""),
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
        
        # Salva nel database
        conn = get_db_connection()
        conn.execute('''
            INSERT INTO test_results (user_email, test_name, azienda, score, correct_answers, total_questions, answers_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (user_email, test_scelto, azienda_scelta, perc, n_cor, n_tot, json.dumps(risposte)))
        conn.commit()
        conn.close()
        
        # Sessione
        session["submitted"] = True
        session["risposte"] = risposte
        session.modified = True
        
        return jsonify({
            'success': True,
            'score': perc,
            'correct': n_cor,
            'total': n_tot
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': f'Errore: {str(e)}', 'reload': True})

@app.route('/download_results')
@login_required
def download_results():
    try:
        if not session.get("submitted") or "risposte" not in session:
            return "Nessun risultato", 404
        
        risposte = session["risposte"]
        utente = session["utente"]
        
        df_r = pd.DataFrame(risposte)
        chiuse = df_r[df_r["Tipo"] == "chiusa"]
        n_tot = len(chiuse)
        n_cor = int(chiuse["Esatta"].sum()) if n_tot else 0
        perc = int(n_cor / n_tot * 100) if n_tot else 0
        
        data_test = datetime.now().strftime("%d/%m/%Y")
        info = pd.DataFrame([{
            "Nome": utente,
            "Data": data_test,
            "Punteggio": f"{perc}%",
            "Azienda": session["azienda_scelta"],
            "Test": session["test_scelto"]
        }])
        
        buf = BytesIO()
        with pd.ExcelWriter(buf, engine="openpyxl") as writer:
            info.to_excel(writer, index=False, sheet_name="Risposte", startrow=0)
            df_r["Punteggio"] = f"{perc}%"
            df_r.to_excel(writer, index=False, sheet_name="DB Risposte", startrow=0)
        
        buf.seek(0)
        wb = load_workbook(buf)
        ws = wb["Risposte"]
        ws.protection.sheet = True
        ws.protection.password = "assessment25"
        ws.protection.enable()
        
        buf_protetto = BytesIO()
        wb.save(buf_protetto)
        buf_protetto.seek(0)
        
        filename = f"risposte_{utente.replace(' ', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        
        return send_file(buf_protetto, as_attachment=True, download_name=filename,
                        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        
    except Exception as e:
        return f"Errore: {e}", 500

# Inizializza database all'avvio
init_db()

if __name__ == '__main__':
    app.run(debug=True)
