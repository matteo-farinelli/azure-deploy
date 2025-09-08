import logging
import os
import json
from datetime import datetime
from azure.data.tables import TableServiceClient, TableEntity
from azure.core.exceptions import ResourceNotFoundError, HttpResponseError
import time

logger = logging.getLogger(__name__)

# Configurazione Azure Storage
AZURE_STORAGE_CONNECTION_STRING = os.environ.get('AZURE_STORAGE_CONNECTION_STRING')
TABLE_NAME_USERS = 'users'
TABLE_NAME_RESULTS = 'testresults'

# Retry configuration
MAX_RETRIES = 3
RETRY_DELAY = 2
def initialize_reset_flags_table():
    """Crea la tabella per i flag di reset test"""
    try:
        service = get_table_service_with_retry()
        
        try:
            service.create_table('testresets')
            logger.info("✅ Tabella testresets creata")
        except Exception as e:
            if "already exists" in str(e).lower():
                logger.info("✅ Tabella testresets già esistente")
            else:
                raise
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Errore creazione tabella testresets: {e}")
        return False

def set_test_reset_flag(user_email, test_name, admin_email):
    """Imposta un flag che permette di rifare un test"""
    try:
        service = get_table_service_with_retry()
        table_client = service.get_table_client('testresets')
        
        # Crea un nuovo flag
        entity = {
            'PartitionKey': user_email,
            'RowKey': f"{test_name}_{int(datetime.now().timestamp())}",
            'test_name': test_name,
            'user_email': user_email,
            'admin_email': admin_email,
            'is_active': True,
            'created_at': datetime.now().isoformat(),
            'used_at': None
        }
        
        table_client.upsert_entity(entity)
        logger.info(f"✅ Reset flag created: {user_email} - {test_name} by {admin_email}")
        return True
        
    except Exception as e:
        logger.error(f"❌ Error creating reset flag: {e}")
        return False
def :
    """Crea le tabelle OBBLIGATORIAMENTE"""
    try:
        service = get_table_service_with_retry()
        
        # Crea tabella users
        try:
            service.create_table(TABLE_NAME_USERS)
            logger.info(f"✅ Tabella {TABLE_NAME_USERS} creata")
        except Exception as e:
            if "already exists" in str(e).lower() or "tableexists" in str(e).lower():
                logger.info(f"✅ Tabella {TABLE_NAME_USERS} già esistente")
            else:
                logger.error(f"❌ Errore creazione tabella {TABLE_NAME_USERS}: {e}")
                raise
        
        # Crea tabella results
        try:
            service.create_table(TABLE_NAME_RESULTS)
            logger.info(f"✅ Tabella {TABLE_NAME_RESULTS} creata")
        except Exception as e:
            if "already exists" in str(e).lower() or "tableexists" in str(e).lower():
                logger.info(f"✅ Tabella {TABLE_NAME_RESULTS} già esistente")
            else:
                logger.error(f"❌ Errore creazione tabella {TABLE_NAME_RESULTS}: {e}")
                raise
        
        # AGGIUNGI: Crea tabella testresets
        try:
            service.create_table('testresets')
            logger.info("✅ Tabella testresets creata")
        except Exception as e:
            if "already exists" in str(e).lower() or "tableexists" in str(e).lower():
                logger.info("✅ Tabella testresets già esistente")
            else:
                logger.error(f"❌ Errore creazione tabella testresets: {e}")
                raise
        
        logger.info("✅ Azure Tables inizializzate")
        return True
        
    except Exception as e:
        logger.error(f"❌ ERRORE CRITICO inizializzazione tabelle: {e}")
        raise Exception(f"Inizializzazione Azure fallita: {e}")

def check_if_test_allows_retry(user_email, test_name):
    """Controlla se un test consente nuovi tentativi SOLO se riabilitato dall'admin"""
    try:
        service = get_table_service_with_retry()
        if not service:
            return False
        
        # Cerca se esiste un flag di riabilitazione per questo utente/test
        table_client = service.get_table_client('testresets')
        
        try:
            # Cerca un flag attivo per questo utente/test
            filter_query = f"PartitionKey eq '{user_email}' and test_name eq '{test_name}' and is_active eq true"
            entities = list(table_client.query_entities(query_filter=filter_query))
            
            has_active_flag = len(entities) > 0
            logger.info(f"✅ Retry check for {user_email}/{test_name}: {has_active_flag}")
            return has_active_flag
            
        except Exception as e:
            logger.error(f"❌ Error querying reset flags: {e}")
            return False  # Default: non permettere retry
            
    except Exception as e:
        logger.error(f"❌ Error checking retry permission: {e}")
        return False


def consume_test_reset_flag(user_email, test_name):
    """Consuma (disattiva) il flag quando l'utente inizia un nuovo tentativo"""
    try:
        service = get_table_service_with_retry()
        table_client = service.get_table_client('testresets')
        
        # Trova e disattiva tutti i flag attivi per questo utente/test
        filter_query = f"PartitionKey eq '{user_email}' and test_name eq '{test_name}' and is_active eq true"
        entities = list(table_client.query_entities(query_filter=filter_query))
        
        for entity in entities:
            entity['is_active'] = False
            entity['used_at'] = datetime.now().isoformat()
            table_client.update_entity(entity, mode='replace')
        
        logger.info(f"✅ Reset flags consumed: {user_email} - {test_name}")
        return True
        
    except Exception as e:
        logger.error(f"❌ Error consuming reset flags: {e}")
        return False
def get_table_service_with_retry():
    """Ottiene il client Azure Table con retry e validazione"""
    if not AZURE_STORAGE_CONNECTION_STRING:
        logger.error("❌ AZURE_STORAGE_CONNECTION_STRING non configurata!")
        raise Exception("Azure Storage non configurato")
    
    for attempt in range(MAX_RETRIES):
        try:
            service = TableServiceClient.from_connection_string(AZURE_STORAGE_CONNECTION_STRING)
            
            # Test connessione semplice
            tables = list(service.list_tables())
            logger.info(f"✅ Azure connesso (tentativo {attempt + 1})")
            return service
            
        except Exception as e:
            logger.error(f"❌ Tentativo {attempt + 1} fallito: {str(e)}")
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY)
            else:
                raise Exception(f"Connessione Azure fallita dopo {MAX_RETRIES} tentativi: {str(e)}")

def save_user_data_azure_only(email, user_info):
    """Salva dati utente SOLO su Azure - NO fallback"""
    try:
        service = get_table_service_with_retry()
        table_client = service.get_table_client(TABLE_NAME_USERS)
        
        entity = {
            'PartitionKey': user_info.get('azienda', 'default'),
            'RowKey': email,
            'email': email,
            'nome': str(user_info.get('nome', '')),
            'cognome': str(user_info.get('cognome', '')),
            'azienda': str(user_info.get('azienda', '')),
            'is_admin': bool(user_info.get('is_admin', False)),
            'created_at': str(user_info.get('created_at', '')),
            'last_login': str(user_info.get('last_login', '') if user_info.get('last_login') else ''),
            'password_hash': str(user_info.get('password_hash', '')),
            'updated_at': datetime.now().isoformat()
        }
        
        table_client.upsert_entity(entity)
        logger.info(f"✅ Utente {email} salvato su Azure")
        return True
        
    except Exception as e:
        logger.error(f"❌ ERRORE salvataggio utente {email}: {e}")
        return False

def get_user_data_azure_only(email):
    """Recupera dati utente SOLO da Azure - NO fallback"""
    try:
        service = get_table_service_with_retry()
        table_client = service.get_table_client(TABLE_NAME_USERS)
        
        # Cerca in tutte le partizioni
        query = f"RowKey eq '{email}'"
        users = list(table_client.query_entities(query))
        
        if users:
            user = users[0]
            logger.info(f"✅ Utente {email} trovato")
            return {
                'email': user['email'],
                'nome': user.get('nome', ''),
                'cognome': user.get('cognome', ''),
                'azienda': user.get('azienda', ''),
                'is_admin': user.get('is_admin', False),
                'created_at': user.get('created_at', ''),
                'last_login': user.get('last_login', ''),
                'password_hash': user.get('password_hash', '')
            }
        else:
            logger.info(f"❌ Utente {email} non trovato")
            return None
            
    except Exception as e:
        logger.error(f"❌ ERRORE recupero utente {email}: {e}")
        return None

def save_test_result_azure_only(result):
    """Salva risultato test con supporto per tentativi multipli"""
    try:
        service = get_table_service_with_retry()
        if not service:
            logger.error("❌ Impossibile connettersi ad Azure Tables")
            return False

        user_email = result.get('user_email', '')
        created_at = result.get('created_at', datetime.now().isoformat())
        
        # Usa created_at come RowKey per garantire unicità
        row_key = created_at.replace(':', '-').replace('.', '-')
        
        entity = {
            'PartitionKey': user_email,
            'RowKey': row_key,
            'user_email': user_email,
            'test_name': result.get('test_name', ''),
            'azienda': result.get('azienda', ''),
            'score': int(result.get('score', 0)),
            'correct_answers': int(result.get('correct_answers', 0)),
            'total_questions': int(result.get('total_questions', 0)),
            'answers_json': result.get('answers_json', ''),
            'completed_at': result.get('completed_at', ''),
            'created_at': created_at,
            'attempt_number': int(result.get('attempt_number', 1)),
            'is_latest': result.get('is_latest', True)
        }

        # Use upsert_entity instead of create_entity to handle duplicates
        table_client = service.get_table_client(TABLE_NAME_RESULTS)
        table_client.upsert_entity(entity)
        
        logger.info(f"✅ Test result saved to Azure: {user_email} - {result.get('test_name')} (attempt {result.get('attempt_number', 1)})")
        return True

    except Exception as e:
        logger.error(f"❌ Error saving test result to Azure: {e}")
        return False

def get_user_test_results_azure_only(email):
    """Recupera SOLO gli ultimi tentativi per ogni test dell'utente"""
    try:
        service = get_table_service_with_retry()
        table_client = service.get_table_client(TABLE_NAME_RESULTS)
        
        # Usa user_email come PartitionKey
        filter_query = f"PartitionKey eq '{email}'"
        entities = list(table_client.query_entities(query_filter=filter_query))
        
        # Raggruppa per test_name e prendi solo l'ultimo tentativo
        latest_results = {}
        for entity in entities:
            test_name = entity.get('test_name', '')
            attempt_number = entity.get('attempt_number', 1)
            
            if test_name not in latest_results or attempt_number > latest_results[test_name]['attempt_number']:
                latest_results[test_name] = {
                    'user_email': entity.get('PartitionKey', ''),
                    'test_name': test_name,
                    'azienda': entity.get('azienda', ''),
                    'score': entity.get('score', 0),
                    'correct_answers': entity.get('correct_answers', 0),
                    'total_questions': entity.get('total_questions', 0),
                    'answers_json': entity.get('answers_json', ''),
                    'completed_at': entity.get('completed_at', ''),
                    'created_at': entity.get('created_at', ''),
                    'attempt_number': attempt_number,
                    'is_latest': entity.get('is_latest', True)
                }
        
        results = list(latest_results.values())
        results.sort(key=lambda x: x.get('completed_at', ''), reverse=True)
        
        logger.info(f"✅ Retrieved {len(results)} latest test results for {email}")
        return results

    except Exception as e:
        logger.error(f"❌ Error getting user test results: {e}")
        return []

def get_all_users_azure_only():
    """Recupera tutti gli utenti da Azure"""
    try:
        service = get_table_service_with_retry()
        table_client = service.get_table_client(TABLE_NAME_USERS)
        
        users = list(table_client.list_entities())
        
        users_dict = {}
        for user in users:
            email = user['email']
            users_dict[email] = {
                'email': user['email'],
                'nome': user.get('nome', ''),
                'cognome': user.get('cognome', ''),
                'azienda': user.get('azienda', ''),
                'is_admin': user.get('is_admin', False),
                'created_at': user.get('created_at', ''),
                'last_login': user.get('last_login', ''),
                'password_hash': user.get('password_hash', '')
            }
        
        logger.info(f"✅ Recuperati {len(users_dict)} utenti totali")
        return users_dict
        
    except Exception as e:
        logger.error(f"❌ ERRORE recupero utenti: {e}")
        return {}

def get_all_test_results_azure_only():
    """Recupera TUTTI i risultati test da Azure Tables (inclusi tentativi multipli)"""
    try:
        service = get_table_service_with_retry()
        table_client = service.get_table_client(TABLE_NAME_RESULTS)
        
        entities = list(table_client.list_entities())
        
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

        # Ordina per data di completamento
        results.sort(key=lambda x: x.get('completed_at', ''), reverse=True)
        logger.info(f"✅ Retrieved {len(results)} test results from Azure")
        return results

    except Exception as e:
        logger.error(f"❌ Error getting test results from Azure: {e}")
        return []

def get_user_test_results_all_attempts_azure_only(user_email, test_name=None):
    """Recupera TUTTI i tentativi di test per un utente (inclusi tentativi precedenti)"""
    try:
        service = get_table_service_with_retry()
        table_client = service.get_table_client(TABLE_NAME_RESULTS)
        
        # Query per tutti i risultati dell'utente
        if test_name:
            filter_query = f"PartitionKey eq '{user_email}' and test_name eq '{test_name}'"
        else:
            filter_query = f"PartitionKey eq '{user_email}'"
            
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
        
        # Ordina per attempt_number e data
        results.sort(key=lambda x: (x.get('test_name', ''), x.get('attempt_number', 1)))
        
        logger.info(f"✅ Retrieved {len(results)} total attempts for {user_email}")
        return results

    except Exception as e:
        logger.error(f"❌ Error getting all user test attempts: {e}")
        return []

def update_result_latest_status_azure_only(user_email, test_name, created_at, is_latest):
    """Aggiorna lo status is_latest di un risultato specifico"""
    try:
        service = get_table_service_with_retry()
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
            
            logger.info(f"✅ Updated latest status for {user_email} - {test_name}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Entity not found or update failed: {e}")
            return False
            
    except Exception as e:
        logger.error(f"❌ Error updating latest status: {e}")
        return False

def migrate_from_files_to_azure():
    """Migra dati esistenti dai file ad Azure"""
    try:
        logger.info("🔄 Controllo migrazione da file...")
        
        # Controlla se esiste file locale
        local_file = 'user_progress.json'
        if not os.path.exists(local_file):
            logger.info("ℹ️  Nessun file locale da migrare")
            return True
        
        # Carica dati dal file
        with open(local_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        users = data.get('users', {})
        test_results = data.get('test_results', [])
        
        logger.info(f"📁 Migrazione: {len(users)} utenti, {len(test_results)} risultati")
        
        # Migra utenti
        migrated_users = 0
        for email, user_data in users.items():
            try:
                save_user_data_azure_only(email, user_data)
                migrated_users += 1
            except Exception as e:
                logger.warning(f"⚠️ Errore migrazione utente {email}: {e}")
        
        # Migra risultati
        migrated_results = 0
        for result in test_results:
            try:
                if not result.get('completed_at'):
                    result['completed_at'] = datetime.now().isoformat()
                save_test_result_azure_only(result)
                migrated_results += 1
            except Exception as e:
                logger.warning(f"⚠️ Errore migrazione risultato: {e}")
        
        logger.info(f"✅ Migrazione: {migrated_users} utenti, {migrated_results} risultati")
        
        # Backup del file originale
        backup_file = f"{local_file}.backup_{int(datetime.now().timestamp())}"
        os.rename(local_file, backup_file)
        logger.info(f"📦 Backup creato: {backup_file}")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Errore migrazione: {e}")
        return False

def azure_tables_health_check():
    """Verifica stato Azure Tables"""
    try:
        service = get_table_service_with_retry()
        
        # Test lettura tabelle
        tables = list(service.list_tables())
        table_names = [table.name for table in tables]
        
        users_exists = TABLE_NAME_USERS in table_names
        results_exists = TABLE_NAME_RESULTS in table_names
        
        # Conta records
        users_count = 0
        results_count = 0
        
        if users_exists:
            users_client = service.get_table_client(TABLE_NAME_USERS)
            users_count = len(list(users_client.list_entities()))
        
        if results_exists:
            results_client = service.get_table_client(TABLE_NAME_RESULTS)
            results_count = len(list(results_client.list_entities()))
        
        return {
            'status': 'healthy',
            'tables_exist': {
                'users': users_exists,
                'results': results_exists
            },
            'record_counts': {
                'users': users_count,
                'results': results_count
            },
            'connection': 'ok',
            'timestamp': datetime.now().isoformat()
        }
        
    except Exception as e:
        return {
            'status': 'error',
            'error': str(e),
            'connection': 'failed',
            'timestamp': datetime.now().isoformat()
        }
