# Azure Assessment Platform

Una piattaforma web per la gestione e somministrazione di test di valutazione aziendali, sviluppata in Flask e deployata su Azure App Service con Azure Table Storage.

## 🚀 Panoramica del Progetto

La piattaforma permette alle aziende del gruppo (Auxiell, Euxilia, XVA Services) di:

* Gestire utenti con autenticazione sicura basata su email aziendale
* Somministrare test dinamici caricati da file Excel
* Monitorare performance attraverso dashboard amministrative
* Generare report dettagliati
* Scalare automaticamente su infrastruttura Azure

## 🏗️ Architettura

```text
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│  GitHub Actions │───▶│   Azure App      │───▶│  Azure Tables   │
│   (CI/CD)       │    │   Service        │    │   Storage       │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │
                                ▼
                       ┌──────────────────┐
                       │  Static Files    │
                       │  (Excel Tests)   │
                       └──────────────────┘
```

## ⚙️ Stack Tecnologico

**Backend**

* Python 3.11
* Flask
* Azure Table Storage (NoSQL)
* Pandas & OpenPyXL (Excel)

**Frontend**

* Bootstrap 5
* Chart.js
* Font Awesome

**Infrastruttura**

* Azure App Service
* Azure Table Storage
* GitHub Actions (CI/CD)

## ✨ Funzionalità Principali

* 🔐 **Autenticazione e Gestione Utenti** (login sicuro, admin, sessioni)
* 📝 **Sistema Test Dinamici** (Excel, open/closed questions, validazione, one-shot)
* 📊 **Dashboard Amministrativa** (overview, analisi per azienda/test, timeline, ranking)
* 📑 **Reporting & Export** (Excel, grafici interattivi)
* 🩺 **Health Check & Monitoraggio** (`/health`, logging strutturato)

## 📂 Struttura del Progetto

```text
azure-deploy/
├── .github/workflows/
│   └── main_assessment.yml     # GitHub Actions workflow
├── static/images/              # Loghi aziendali
├── templates/                  # Template HTML Jinja2
│   ├── base.html
│   ├── admin_dashboard.html
│   ├── dashboard.html
│   ├── quiz.html
│   ├── login.html
│   ├── register.html
│   ├── error.html
│   └── forgot_password.html
├── repository_test/            # File test Excel
│   ├── Tipologia Test.xlsx
│   └── [altri file].xlsx
├── app.py                      # Flask app
├── azure_storage.py            # Gestione Azure Tables
├── requirements.txt            # Dipendenze
└── README.md                   # Documentazione
```

## ⚡ Setup e Installazione

### Prerequisiti

* Python 3.11+
* Account Azure
* Repo GitHub per CI/CD

### Setup Locale

```bash
# 1. Clona repo
git clone https://github.com/matteo-farinelli/azure-deploy.git
cd azure-deploy

# 2. Crea venv
python -m venv venv
source venv/bin/activate   # Linux/Mac
venv\Scripts\activate      # Windows

# 3. Installa dipendenze
pip install -r requirements.txt

# 4. Configura env vars
export SECRET_KEY="your-secret-key"
export AZURE_STORAGE_CONNECTION_STRING="DefaultEndpointsProtocol=https;AccountName=..."
export FLASK_DEBUG="True"

# 5. Avvia app
python app.py
```

## ☁️ Configurazione Azure

### Creazione Storage Account

```bash
az storage account create \
  --name yourstorageaccount \
  --resource-group your-resource-group \
  --location "West Europe" \
  --sku Standard_LRS
```

### Connection String

```bash
az storage account show-connection-string \
  --name yourstorageaccount \
  --resource-group your-resource-group
```

### Creazione App Service

```bash
az webapp create \
  --name your-app-name \
  --resource-group your-resource-group \
  --plan your-app-service-plan \
  --runtime "PYTHON|3.11"
```

## 🔑 Variabili d'Ambiente

| Variabile                         | Descrizione               | Esempio                        |
| --------------------------------- | ------------------------- | ------------------------------ |
| `SECRET_KEY`                      | Chiave Flask sessioni     | `abc123xyz789`                 |
| `AZURE_STORAGE_CONNECTION_STRING` | Connessione Azure Storage | `DefaultEndpointsProtocol=...` |

**Opzionali**

| Variabile         | Default | Descrizione            |
| ----------------- | ------- | ---------------------- |
| `SESSION_TIMEOUT` | `3600`  | Timeout sessione (sec) |
| `HTTPS_ONLY`      | `False` | Forza HTTPS cookie     |
| `FLASK_DEBUG`     | `False` | Modalità debug         |
| `PORT`            | `8000`  | Porta app              |

## 🔗 API Endpoints

**Pubblici**

* `GET /login`, `POST /login`
* `GET /register`, `POST /register`
* `GET /health`, `GET /status`

**Autenticati**

* `GET /dashboard`
* `GET /start_test/<test_name>`
* `POST /submit_answers`
* `GET /download_results`

**Amministratori**

* `GET /admin/dashboard`
* `GET /admin/download_report`
* `GET /admin/azure-status`

**Debug**

* `GET /debug/info`
* `GET /minimal`

## 📊 Struttura Database (Azure Tables)

### Tabella `users`

| Campo          | Tipo     | Descrizione    |
| -------------- | -------- | -------------- |
| PartitionKey   | String   | Azienda        |
| RowKey         | String   | Email utente   |
| nome           | String   | Nome           |
| cognome        | String   | Cognome        |
| password\_hash | String   | Hash SHA-256   |
| is\_admin      | Bool     | Amministratore |
| created\_at    | DateTime | Creazione      |
| last\_login    | DateTime | Ultimo login   |

### Tabella `testresults`

| Campo            | Tipo     | Descrizione        |
| ---------------- | -------- | ------------------ |
| PartitionKey     | String   | Azienda            |
| RowKey           | String   | ID risultato       |
| user\_email      | String   | Email utente       |
| test\_name       | String   | Nome test          |
| score            | Int      | Percentuale        |
| correct\_answers | Int      | Risposte corrette  |
| total\_questions | Int      | Totale domande     |
| answers\_json    | String   | Risposte JSON      |
| completed\_at    | DateTime | Data completamento |

## 📑 Configurazione Test Excel

**Tipologia Test.xlsx**

| Colonna       | Descrizione              |
| ------------- | ------------------------ |
| Nome test     | Identificativo test      |
| Percorso file | Path file Excel          |
| Azienda       | Aziende abilitate        |
| Tutte         | Si/No (tutte le domande) |

**File Test Specifici**

| Colonna      | Descrizione         |
| ------------ | ------------------- |
| Azienda      | Azienda target      |
| principio    | Categoria           |
| Domanda      | Testo               |
| Corretta     | Risposta/e corrette |
| opzione 1..n | Opzioni             |

## 🔐 Sicurezza

* Hashing password con SHA-256 (consigliato upgrade a **bcrypt/argon2**)
* Sessioni sicure (HttpOnly, Secure, SameSite)
* Redirect HTTPS in produzione
* Validazione input & email aziendali
* Limit upload file: max 16MB

## 🛠 Troubleshooting

**Connessione Azure Tables fallita**

```bash
curl https://your-app.azurewebsites.net/admin/azure-status
az webapp log tail --name your-app --resource-group your-rg
```

**Test non caricati**

* Verifica cartella `repository_test/`
* Controlla struttura Excel

**Errori deploy**

```bash
az webapp log deployment show --name your-app --resource-group your-rg
```

## 📈 Monitoraggio & Logging

```python
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
```

* Target: response < 2s
* Availability: 99.9%
* 100+ utenti simultanei
* Auto-scaling Azure

## 👨‍💻 Contribuire

1. Fork del repo
2. Branch feature: `git checkout -b feature/nome-feature`
3. Commit: `git commit -m "feat: descrizione"`
4. Push: `git push origin feature/nome-feature`
5. Pull Request

**Standard di Codice**

* Python → PEP 8
* HTML → semantic markup
* JS → ES6+
* CSS → BEM

## 📜 Licenza

Progetto proprietario - Tutti i diritti riservati

## 📞 Supporto

* Email: [helpdesk@auxiell.com](mailto:helpdesk@auxiell.com)
* Issues: GitHub Issues

---

**Versione:** 1.0.0
**Ultimo aggiornamento:** Agosto 2025
**Autore:** Matteo Farinelli
