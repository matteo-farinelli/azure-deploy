from flask import Flask, render_template_string

app = Flask(__name__)
app.secret_key = 'test-key-123'

# Template inline per evitare problemi di file
LOGIN_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Test Login</title>
    <style>
        body { font-family: Arial; margin: 50px; background: #f0f0f0; }
        .container { background: white; padding: 30px; border-radius: 10px; max-width: 400px; margin: 0 auto; }
        input, select, button { width: 100%; padding: 10px; margin: 10px 0; }
        button { background: #007bff; color: white; border: none; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🎯 Test Assessment</h1>
        <form method="POST">
            <input type="text" name="name" placeholder="Nome e Cognome" required>
            <select name="company" required>
                <option value="">Seleziona Azienda</option>
                <option value="auxiell">Auxiell</option>
                <option value="euxilia">Euxilia</option>
                <option value="xva">XVA</option>
            </select>
            <button type="submit">Accedi</button>
        </form>
    </div>
</body>
</html>
'''

DASHBOARD_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Dashboard</title>
    <style>
        body { font-family: Arial; margin: 50px; background: #f0f0f0; }
        .container { background: white; padding: 30px; border-radius: 10px; }
        .success { background: #d4edda; padding: 15px; border-radius: 5px; margin: 10px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>✅ Test Riuscito!</h1>
        <div class="success">
            <strong>Benvenuto: {{ user_name }}</strong><br>
            <strong>Azienda: {{ company }}</strong>
        </div>
        <p>L'applicazione Flask funziona correttamente!</p>
        <a href="/logout">Logout</a>
    </div>
</body>
</html>
'''

@app.route('/')
def home():
    return render_template_string(LOGIN_TEMPLATE)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        company = request.form.get('company', '').strip()
        
        if name and company:
            return render_template_string(DASHBOARD_TEMPLATE, 
                                        user_name=name, 
                                        company=company.upper())
        else:
            return "Errore: Nome e azienda richiesti", 400
    
    return render_template_string(LOGIN_TEMPLATE)

@app.route('/logout')
def logout():
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True)
