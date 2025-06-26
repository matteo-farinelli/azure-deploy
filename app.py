from flask import Flask, render_template, request, session, jsonify, send_file
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

app = Flask(__name__)
# Genera una chiave segreta più robusta
app.secret_key = secrets.token_hex(32)
app.config['SESSION_COOKIE_SECURE'] = False  # Per sviluppo
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 ora

DEFAULT_KEYS = {
    "test_scelto": None,
    "azienda_scelta": None,
    "proseguito": False,
    "submitted": False,
    "invia_a_mentor": None,
    "tutte_domande": None,
    "utente": "",
    "domande_selezionate": None,
    "file_path": None
}

def initialize_session():
    """Inizializza la sessione con controlli più robusti"""
    session.permanent = True  # Rende la sessione permanente
    for key, default_value in DEFAULT_KEYS.items():
        if key not in session:
            session[key] = default_value
    
    # Forza il salvataggio della sessione
    session.modified = True

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

@app.route('/')
def index():
    initialize_session()
    
    # Reset della sessione se necessario
    if request.args.get('reset') == 'true':
        session.clear()
        initialize_session()
    
    try:
        # Carica tipologie di test
        tipologie_file = "repository_test/Tipologia Test.xlsx"
        df_tipologie = pd.read_excel(tipologie_file)
        
        # Verifica colonne necessarie
        if "Nome test" not in df_tipologie.columns:
            return render_template('error.html', 
                                 error="La colonna 'Nome test' non è presente nel file delle tipologie.")
        
        # Step 1: Selezione dell'azienda
        if session["azienda_scelta"] is None:
            aziende_disponibili = set()
            
            if "Azienda" in df_tipologie.columns:
                for aziende_string in df_tipologie["Azienda"].dropna():
                    aziende_list = [a.strip() for a in str(aziende_string).split(";")]
                    aziende_disponibili.update(aziende_list)
            
            if not aziende_disponibili:
                all_aziende = set()
                for _, row in df_tipologie.iterrows():
                    test_file = row.get("Percorso file", f"repository_test/{row['Nome test']}.xlsx")
                    try:
                        test_df = pd.read_excel(test_file)
                        if "Azienda" in test_df.columns:
                            all_aziende.update(test_df["Azienda"].dropna().unique())
                    except Exception:
                        continue
                aziende_disponibili = all_aziende
            
            aziende_disponibili = sorted([a for a in aziende_disponibili if a and not pd.isna(a)])
            
            if not aziende_disponibili:
                return render_template('error.html', 
                                     error="Nessuna azienda trovata nei file di test.")
            
            logo_path, logo_exists = get_logo_info()
            
            return render_template('select_company.html', 
                                 aziende=aziende_disponibili,
                                 logo_path=logo_path if logo_exists else None)
        
        # Step 2: Selezione del tipo di test
        if session["test_scelto"] is None:
            azienda_scelta = session["azienda_scelta"]
            test_disponibili = []
            
            if "Azienda" in df_tipologie.columns:
                for _, row in df_tipologie.iterrows():
                    if pd.notna(row["Azienda"]):
                        aziende_test = [a.strip() for a in str(row["Azienda"]).split(";")]
                        if azienda_scelta in aziende_test:
                            test_disponibili.append(row["Nome test"])
            
            if not test_disponibili:
                test_disponibili = sorted(df_tipologie["Nome test"].dropna().unique())
            else:
                test_disponibili = sorted(test_disponibili)
            
            logo_path, logo_exists = get_logo_info(azienda_scelta)
            company_color = get_company_color(azienda_scelta)
            
            return render_template('select_test.html', 
                                 tests=test_disponibili,
                                 azienda=azienda_scelta,
                                 logo_path=logo_path if logo_exists else None,
                                 company_color=company_color)
        
        # Step 3: Quiz
        return show_quiz()
        
    except FileNotFoundError:
        return render_template('error.html', 
                             error=f"File delle tipologie non trovato: {tipologie_file}")
    except Exception as e:
        return render_template('error.html', 
                             error=f"Errore nel caricamento delle tipologie di test: {e}")

def show_quiz():
    try:
        # Carica il file delle domande
        file_path = session.get("file_path", "")
        df = pd.read_excel(file_path)
        
        # Verifica colonne necessarie
        required_cols = ["Azienda", "principio", "Domanda", "Corretta", "opzione 1"]
        missing = [col for col in required_cols if col not in df.columns]
        if missing:
            return render_template('error.html', 
                                 error=f"Mancano le colonne obbligatorie: {', '.join(missing)}")
        
        option_cols = [c for c in df.columns if c.lower().strip().startswith("opzione")]
        if not option_cols:
            return render_template('error.html', 
                                 error="Nessuna colonna di opzione trovata.")
        
        # Filtra domande per azienda
        azienda_scelta = session["azienda_scelta"]
        df_filtrato = df[df["Azienda"] == azienda_scelta]
        
        if df_filtrato.empty:
            return render_template('error.html', 
                                 error=f"Non ci sono domande disponibili per l'azienda '{azienda_scelta}' in questo test.")
        
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
        
        domande = session["domande_selezionate"]
        
        # Prepara dati per il template
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
        return render_template('error.html', 
                             error=f"Errore nel caricamento del test: {e}")

@app.route('/select_company', methods=['POST'])
def select_company():
    azienda_scelta = request.form.get('azienda')
    if azienda_scelta:
        session["azienda_scelta"] = azienda_scelta
        session.permanent = True
        session.modified = True
    return jsonify({'success': True})

@app.route('/select_test', methods=['POST'])
def select_test():
    test_scelto = request.form.get('test')
    if test_scelto:
        session["test_scelto"] = test_scelto
        session.permanent = True
        
        # Carica tipologie per ottenere il percorso del file
        try:
            tipologie_file = "repository_test/Tipologia Test.xlsx"
            df_tipologie = pd.read_excel(tipologie_file)
            file_row = df_tipologie[df_tipologie["Nome test"] == test_scelto]
            
            # Imposta tutte_domande
            if "Tutte" in file_row.columns and len(file_row) > 0:
                tutte_value = str(file_row["Tutte"].values[0]).strip().lower()
                session["tutte_domande"] = tutte_value == "si"
            else:
                session["tutte_domande"] = False
            
            # Imposta file_path
            if "Percorso file" in file_row.columns and len(file_row) > 0:
                file_path = file_row["Percorso file"].values[0]
                session["file_path"] = file_path
            else:
                session["file_path"] = f"repository_test/{test_scelto}.xlsx"
                
            session.modified = True
                
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})
    
    return jsonify({'success': True})

@app.route('/set_user', methods=['POST'])
def set_user():
    utente = request.form.get('utente', '').strip()
    if not utente:
        return jsonify({'success': False, 'error': 'Per favore, inserisci il tuo nome'})
    
    session["utente"] = utente
    session["proseguito"] = True
    session.permanent = True
    session.modified = True
    return jsonify({'success': True})

@app.route('/submit_answers', methods=['POST'])
def submit_answers():
    try:
        data = request.json
        answers = data.get('answers', {})
        quiz_data = data.get('quiz_data', {})
        
        # Estrai i dati dal payload invece che dalla sessione
        utente = quiz_data.get('utente', '')
        azienda_scelta = quiz_data.get('azienda_scelta', '')
        test_scelto = quiz_data.get('test_scelto', '')
        domande = quiz_data.get('domande', [])
        
        if not domande:
            return jsonify({
                'success': False, 
                'error': 'Nessuna domanda trovata. Ricarica la pagina.',
                'reload': True
            })
        
        if not utente or not azienda_scelta:
            return jsonify({
                'success': False, 
                'error': 'Dati utente mancanti. Ricarica la pagina e riprova.',
                'reload': True
            })
        
        risposte = []
        
        for idx, row in enumerate(domande):
            answer_key = f'question_{idx}'
            user_answer = answers.get(answer_key, '')
            
            # Gestisci valori None - ora row è un dizionario
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
                    # Risposta multipla
                    user_answers = user_answer if isinstance(user_answer, list) else [user_answer] if user_answer else []
                    # Filtra risposte vuote
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
                    "Utente": utente,
                    "Domanda": row.get("domanda", ""),
                    "Argomento": row.get("principio", ""),
                    "Risposta": risposta_str,
                    "Corretta": corretta_raw,
                    "Esatta": is_correct,
                    "Test": test_scelto
                })
        
        # Salva i risultati nella sessione per il download
        session["submitted"] = True
        session["risposte"] = risposte
        session["utente"] = utente
        session["azienda_scelta"] = azienda_scelta
        session["test_scelto"] = test_scelto
        session.modified = True
        
        # Calcola punteggio
        df_r = pd.DataFrame(risposte)
        chiuse = df_r[df_r["Tipo"] == "chiusa"]
        n_tot = len(chiuse)
        n_cor = int(chiuse["Esatta"].sum()) if n_tot > 0 else 0
        perc = int(n_cor / n_tot * 100) if n_tot > 0 else 0
        
        return jsonify({
            'success': True, 
            'score': perc,
            'correct': n_cor,
            'total': n_tot,
            'results_data': {
                'utente': utente,
                'azienda': azienda_scelta,
                'test': test_scelto,
                'score': perc,
                'correct': n_cor,
                'total': n_tot
            }
        })
        
    except Exception as e:
        # Log dell'errore più dettagliato
        import traceback
        error_details = traceback.format_exc()
        print(f"Errore in submit_answers: {error_details}")
        return jsonify({
            'success': False, 
            'error': f'Errore del server: {str(e)}',
            'reload': True
        })


@app.route('/download_results')
def download_results():
    try:
        if not session.get("submitted") or "risposte" not in session:
            return "Nessun risultato disponibile", 404
        
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
        
        # Proteggi il foglio
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
        
        return send_file(
            buf_protetto,
            as_attachment=True,
            download_name=filename,
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )
        
    except Exception as e:
        return f"Errore nella generazione del file: {e}", 500

@app.route('/reset')
def reset():
    session.clear()
    return jsonify({'success': True})

@app.route('/debug')
def debug():
    """Route per debug della sessione - RIMUOVI IN PRODUZIONE"""
    return jsonify({
        'session_data': dict(session),
        'session_id': request.cookies.get('session', 'No session cookie')
    })

if __name__ == '__main__':
    app.run(debug=True)
