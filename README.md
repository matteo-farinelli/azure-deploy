# Azure Assessment Platform

Una piattaforma web per la gestione e somministrazione di test di valutazione aziendali, sviluppata in Flask e deployata su Azure App Service con Azure Table Storage.

## Panoramica del Progetto

La piattaforma permette alle aziende del gruppo (Auxiell, Euxilia, XVA Services) di gestire utenti con autenticazione sicura basata su email aziendale, somministrare test dinamici caricati da file Excel, monitorare performance attraverso dashboard amministrative, generare report dettagliati e scalare automaticamente su infrastruttura Azure.

## Architettura

```
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

### Stack Tecnologico

**Backend:**
- Python 3.11 come runtime principale
- Flask per il framework web
- Azure Table Storage per il database NoSQL
- Pandas & OpenPyXL per l'elaborazione di file Excel

**Frontend:**
- Bootstrap 5 per il framework UI responsive
- Chart.js per grafici e visualizzazioni
- Font Awesome per l'iconografia

**Infrastruttura:**
- Azure App Service per l'hosting dell'applicazione
- Azure Table Storage per la persistenza dei dati
- GitHub Actions per CI/CD automatizzato

## Funzionalità Principali

### Autenticazione e Gestione Utenti
Il sistema include registrazione automatica basata su email aziendale, login sicuro con hash SHA-256, account amministratore per ogni azienda e gestione sessioni con timeout configurabile.

### Sistema di Test Dinamici
I test vengono caricati da file Excel strutturati con supporto per domande aperte e chiuse (singola/multipla scelta), filtri per azienda e tipologia, validazione automatica delle risposte e sistema "one-shot" per garantire che ogni utente possa completare un test una sola volta.

### Dashboard Amministrativa
Include diverse viste:
- **Vista Panoramica**: statistiche generali e test recenti
- **Analisi per Azienda**: performance per organizzazione
- **Analisi per Test**: difficoltà e statistiche per tipologia
- **Timeline**: andamento temporale dei completamenti
- **Performance**: distribuzione punteggi e ranking
- **Dettaglio Utente**: progresso individuale
  
### Sistema di tentativi multipli
- Gli amministratori possono riabilitare test già completati
- Tracking completo di tutti i tentativi con numerazione progressiva
- Visualizzazione separata per ultimi tentativi e storico completo
- Flag di reset gestiti in tabella dedicata testresets

### Reporting e Export
Export risultati individuali in formato Excel, report amministrativo completo, statistiche in tempo reale e grafici interattivi con Chart.js.

### Monitoraggio e Health Check
Endpoint `/health` per il monitoring Azure, controllo stato Azure Table Storage, logging strutturato per troubleshooting e gestione robusta degli errori.

## Struttura del Progetto

```
azure-deploy/
├── .github/workflows/
│   └── main_assessment.yml          # GitHub Actions workflow
├── static/images/                   # Loghi aziendali
│   ├── auxiell_group_logobase.png
│   ├── auxiell_logobase.png
│   ├── euxilia_logobase.png
│   └── xva_logobase.png
├── templates/                       # Template HTML Jinja2
│   ├── base.html                   # Layout base
│   ├── admin_dashboard.html        # Dashboard amministrativa
│   ├── admin_user_details.html     # Dettagli utente con tentativi
│   ├── admin_users_list.html       # Lista tutti gli utenti
│   ├── dashboard.html              # Dashboard utente
│   ├── quiz.html                   # Interfaccia test
│   ├── login.html                  # Pagina login
│   ├── register.html               # Registrazione utenti
│   ├── privacy_policy.html         # Informativa privacy
│   ├── gdpr_requests.html          # Gestione richieste GDPR
│   ├── delete_account.html         # Cancellazione account
│   ├── error.html                  # Pagine errore
│   └── forgot_password.html        # Recupero password
├── repository_test/                 # File test Excel
│   ├── Tipologia Test.xlsx         # Configurazione test
│   └── [altri file test].xlsx      # Test specifici
├── app.py                          # Applicazione Flask principale
├── azure_storage.py                # Gestione Azure Table Storage
├── requirements.txt                # Dipendenze Python
└── README.md                       # Documentazione
```
## Setup e Installazione

### Prerequisiti

- Python 3.11 o superiore
- Account Azure con permessi per creare risorse
- Repository GitHub per CI/CD

### Setup Locale

1. Clona il repository:
```bash
git clone https://github.com/matteo-farinelli/azure-deploy.git
cd azure-deploy
```

2. Crea un ambiente virtuale:
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
```

3. Installa le dipendenze:
```bash
pip install -r requirements.txt
```

4. Configura le variabili d'ambiente:
```bash
export SECRET_KEY="your-secret-key"
export AZURE_STORAGE_CONNECTION_STRING="DefaultEndpointsProtocol=https;AccountName=..."
export FLASK_DEBUG="True"
```

5. Avvia l'applicazione:
```bash
python app.py
```

### Configurazione Azure

#### Creazione Azure Storage Account

```bash
az storage account create \
  --name yourstorageaccount \
  --resource-group your-resource-group \
  --location "West Europe" \
  --sku Standard_LRS
```

#### Ottenere la Connection String

```bash
az storage account show-connection-string \
  --name yourstorageaccount \
  --resource-group your-resource-group
```

#### Creazione Azure App Service

```bash
az webapp create \
  --name your-app-name \
  --resource-group your-resource-group \
  --plan your-app-service-plan \
  --runtime "PYTHON|3.11"
```

## Variabili d'Ambiente

### Obbligatorie

| Variabile | Descrizione | Esempio |
|-----------|-------------|---------|
| `SECRET_KEY` | Chiave segreta Flask per le sessioni | `"abc123xyz789"` |
| `AZURE_STORAGE_CONNECTION_STRING` | Connection string Azure Storage | `"DefaultEndpointsProtocol=https;..."` |

### Opzionali

| Variabile | Valore Default | Descrizione |
|-----------|---------|-------------|
| `SESSION_TIMEOUT` | `3600` | Timeout sessione in secondi |
| `HTTPS_ONLY` | `False` | Forza HTTPS per i cookie |
| `FLASK_DEBUG` | `False` | Modalità debug |
| `PORT` | `8000` | Porta dell'applicazione |

## Deployment su Azure

### GitHub Actions Workflow

Il file `.github/workflows/main_assessment.yml` gestisce il deployment automatizzato. Il processo include build dell'applicazione, installazione dipendenze, creazione del package di deployment e deploy su Azure App Service.

### Configurazione Secrets GitHub

Nel repository GitHub, configura questi secrets:
- `AZUREAPPSERVICE_CLIENTID_*`
- `AZUREAPPSERVICE_TENANTID_*`  
- `AZUREAPPSERVICE_SUBSCRIPTIONID_*`

### Post-Deployment

1. Configura le Application Settings in Azure Portal:
   - `SECRET_KEY`
   - `AZURE_STORAGE_CONNECTION_STRING`
   - `HTTPS_ONLY=True`

2. Verifica l'Health Check:
```bash
curl https://your-app.azurewebsites.net/health
```

## Struttura Database (Azure Tables)

### Tabella `users`

| Campo | Tipo | Descrizione |
|-------|------|-------------|
| `PartitionKey` | String | Azienda dell'utente |
| `RowKey` | String | Email dell'utente |
| `nome` | String | Nome utente |
| `cognome` | String | Cognome utente |
| `password_hash` | String | Hash SHA-256 della password |
| `is_admin` | Boolean | Flag amministratore |
| `created_at` | DateTime | Data di creazione |
| `last_login` | DateTime | Ultimo accesso |

### Tabella `testresults`

| Campo | Tipo | Descrizione |
|-------|------|-------------|
| `PartitionKey` | String | Azienda |
| `RowKey` | String | ID univoco del risultato |
| `user_email` | String | Email dell'utente |
| `test_name` | String | Nome del test |
| `score` | Integer | Punteggio percentuale |
| `correct_answers` | Integer | Risposte corrette |
| `total_questions` | Integer | Domande totali |
| `answers_json` | String | Dettaglio risposte (JSON) |
| `completed_at` | DateTime | Data completamento |

### Tabella `testresats`

| Campo | Tipo | Descrizione |
|-------|------|-------------|
| `PartitionKey` | String | Email utente |
| `RowKey` | String | test_name_timestamp |
| `test_name` | String | Nome del test |
| `admin_email` | String | Admin che ha riabilitato |
| `is active` | Boolean | Flag attivo/consumato |
| `created_at` | DateTime | Data creazione flag |
| `used_at` | DateTime | Data utilizzo flag |


## API Endpoints

### Pubblici
- `GET /` - Redirect al login o dashboard
- `GET /login` - Pagina di login
- `POST /login` - Processo di autenticazione
- `GET /register` - Pagina registrazione utenti
- `POST /register` - Creazione nuovo utente
- `GET /health` - Health check dell'applicazione
- `GET /status` - Status semplice
- `GET /privacy-policy` - Informativa privacy
### Autenticati (Login Required)
- `GET /dashboard` - Dashboard principale dell'utente
- `GET /start_test/<test_name>` - Avvio di un test specifico
- `GET /quiz` - Interfaccia per svolgere il test
- `POST /submit_answers` - Invio delle risposte
- `GET /download_results[/<test_name>]` - Download dei risultati
- `GET /download_latest` - Download ultimo test completato
- `GET /data-export` - Export dati personali GDPR
- `GET /gdpr-requests` - Gestione richieste GDPR
- `GET /delete-account` - Informazioni cancellazione account
- `GET /logout` - Logout dall'applicazione

### Amministratori
- `GET /admin/dashboard` - Dashboard amministrativa
- `GET /admin/users` - Lista completa utenti
- `GET /admin/user/<email>` - Dettagli utente con tutti i tentativi
- `POST /admin/reset_user_test/<email>/<test>` - Riabilita test per nuovo tentativo
- `GET /admin/download_report` - Report completo di tutti i test
- `GET /admin/download_user_test/<email>/<test>` - Download test specifico utente
- `GET /admin/download_all_user_tests/<email>` - Download tutti i test di un utente
- `GET /admin/azure-status` - Status dettagliato di Azure
- `GET /admin/gdpr-requests` - Dashboard richieste GDPR

### Debug & Monitoring
- `GET /debug/info` - Informazioni sull'ambiente
- `GET /debug/check-flags/<email>` - Verifica flag di reset per utente
- `GET /debug/test-retry-check/<email>/<test>` - Test logica retry
- `GET /test-azure-connection` - Test completo connessione Azure
- `GET /debug/test-register` - Test del processo di registrazione
- `GET /minimal` - Pagina di test minimale
- `GET /hash-generator` - Generatore hash password per admin

## Configurazione Test Excel

### File `Tipologia Test.xlsx`

Questo file definisce i test disponibili:

| Colonna | Descrizione |
|---------|-------------|
| `Nome test` | Identificativo univoco del test |
| `Percorso file` | Path del file Excel del test |
| `Azienda` | Aziende abilitate (separate da `;`) |
| `Tutte` | `Si/No` - utilizzare tutte le domande |

### File Test Specifici

Struttura per le domande:

| Colonna | Descrizione |
|---------|-------------|
| `Azienda` | Azienda di destinazione |
| `principio` | Categoria o argomento |
| `Domanda` | Testo della domanda |
| `Corretta` | Risposta/e corrette |
| `opzione 1, 2, 3...` | Opzioni per scelta multipla |

## Gestione Utenti

### Account Amministratore

Gli amministratori hanno accesso completo al sistema:
- **Email**: `admin@auxiell.com`
- **Password**: Configurabile tramite variabili d'ambiente

### Account Utenti

- **Registrazione**: Automatica con email aziendale valida
- **Pattern Email**: `nome.cognome@{auxiell|euxilia|xva-services}.com`
- **Password**: Minimo 6 caratteri, hash SHA-256 per la sicurezza

## Sistema di tentativi multipli

### Workflow
1. Utente completa un test (attempt_number = 1)
2. Admin può riabilitare il test dalla dashboard
3. Sistema crea flag in tabella `testresets`
4. Utente vede pulsante "Nuovo Tentativo" nella dashboard
5. Al click, il flag viene consumato (is_active = false)
6. Nuovo risultato salvato con attempt_number incrementato

### Gestione Flag Reset
```pyton
# Creazione flag da admin
set_test_reset_flag(user_email, test_name, admin_email)

# Verifica se retry è permesso
check_if_test_allows_retry(user_email, test_name)

# Consumo flag quando utente inizia
consume_test_reset_flag(user_email, test_name)
```

## Troubleshooting

### Problemi Comuni

#### Connessione Azure Tables Fallita
```bash
# Verifica la connection string
curl https://your-app.azurewebsites.net/admin/azure-status

# Visualizza log dettagliati
az webapp log tail --name your-app --resource-group your-rg
```

#### Test Non Caricati
Verifica la presenza dei file nella cartella `repository_test/`, controlla che la struttura Excel rispetti il formato richiesto e assicurati che la mappatura in `Tipologia Test.xlsx` sia corretta.

#### Test Non Riabilitabili
- Verifica che l'utente abbia già completato il test
- Controlla che l'admin abbia effettuato il reset
- Verifica esistenza flag in tabella `testresets`

#### Errori di Deployment
```bash
# Controlla i log di deployment
az webapp log deployment show --name your-app --resource-group your-rg

# Verifica i log di GitHub Actions per problemi di build
```

### Health Check Endpoints

```bash
# Health check di base
curl https://your-app.azurewebsites.net/health

# Status specifico di Azure
curl https://your-app.azurewebsites.net/admin/azure-status

# Informazioni sull'applicazione
curl https://your-app.azurewebsites.net/debug/info

# Test connessione Azure completo
curl https://your-app.azurewebsites.net/test-azure-connection
```

## Monitoraggio e Performance

### Metriche Azure

L'applicazione è ottimizzata per Azure Application Insights con target di response time inferiore a 2 secondi per le pagine dashboard, availability del 99.9%, supporto per oltre 100 utenti simultanei e auto-scaling con Azure Tables.

### Logging

Il sistema utilizza logging strutturato con configurazione Python standard:

```python
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
```

### Gestione Errori

Include gestione graceful dei fallimenti con pagine errore personalizzate, logica di retry per le connessioni Azure e gestione delle sessioni con timeout automatico.

## Sicurezza

### Misure Implementate

Il sistema utilizza hashing delle password con SHA-256, sicurezza delle sessioni con cookie HTTPOnly, Secure e SameSite, validazione e sanitizzazione dell'input utente, enforcement HTTPS con redirect automatico in produzione, limiti di dimensione file (16MB massimo), validazione email con pattern matching del dominio aziendale e compliance GDPR con export e cancellazione dati.

### Best Practices

Si raccomanda di utilizzare Azure Key Vault per le variabili sensibili, mantenere aggiornate le dipendenze di sicurezza, monitorare i tentativi di accesso e configurare backup automatici di Azure Tables.

## Contribuire

### Development Workflow

1. Fai un fork del repository
2. Crea un feature branch: `git checkout -b feature/nome-feature`
3. Testa localmente le modifiche
4. Fai commit: `git commit -m "feat: descrizione"`
5. Push: `git push origin feature/nome-feature`
6. Crea una Pull Request con descrizione dettagliata

### Standard di Codice

- Python: compliance PEP 8
- HTML: utilizzo di semantic markup
- JavaScript: funzionalità ES6+
- CSS: metodologia BEM per le classi personalizzate

## Licenza

Progetto proprietario - Tutti i diritti riservati

## Supporto

Per supporto tecnico e domande:
- Email: helpdesk@auxiell.com
- Documentazione: questo README
- Issues: GitHub Issues per segnalazioni di bug

**Versione:** 1.0.0  
**Ultimo aggiornamento:** Agosto 2025  
**Autore:** Matteo Farinelli
