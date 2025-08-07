import logging
import os
import json
from datetime import datetime
from azure.data.tables import TableServiceClient, TableEntity
from azure.core.exceptions import ResourceNotFoundError, HttpResponseError
import time
import hashlib

logger = logging.getLogger(__name__)

# Configurazione Azure Storage
AZURE_STORAGE_CONNECTION_STRING = os.environ.get('AZURE_STORAGE_CONNECTION_STRING')
TABLE_NAME_USERS = 'users'
TABLE_NAME_RESULTS = 'testresults'

# Retry configuration
MAX_RETRIES = 3
RETRY_DELAY = 2

def get_table_service_with_retry():
    """Ottiene il client Azure Table con retry e validazione"""
    if not AZURE_STORAGE_CONNECTION_STRING:
        logger.error("❌ AZURE_STORAGE_CONNECTION_STRING non configurata!")
        raise Exception("Azure Storage non configurato. Impossibile continuare senza persistenza.")
    
    for attempt in range(MAX_RETRIES):
        try:
            service = TableServiceClient.from_connection_string(AZURE_STORAGE_CONNECTION_STRING)
            
            # Test connessione
            list(service.list_tables())
            logger.info(f"✅ Connessione Azure Table Storage OK (tentativo {attempt + 1})")
            return service
            
        except Exception as e:
            logger.error(f"❌ Tentativo {attempt + 1} connessione Azure fallito: {e}")
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY)
            else:
                raise Exception(f"Impossibile connettersi ad Azure Table Storage dopo {MAX_RETRIES} tentativi: {e}")

def initialize_azure_tables_mandatory():
    """Crea le tabelle OBBLIGATORIAMENTE - fallisce se non riesce"""
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
        
        # Test scrittura/lettura
        test_entity = {
            'PartitionKey': 'test',
            'RowKey': f'test_{datetime.now().timestamp()}',
            'test_field': 'test_value',
            'timestamp': datetime.now().isoformat()
        }
        
        table_client = service.get_table_client(TABLE_NAME_USERS)
        table_client.upsert_entity(test_entity)
        
        # Verifica lettura
        entity = table_client.get_entity('test', test_entity['RowKey'])
        
        # Pulisci test
        table_client.delete_entity('test', test_entity['RowKey'])
        
        logger.info("✅ Azure Tables inizializzate e testate con successo")
        return True
        
    except Exception as e:
        logger.error(f"❌ ERRORE CRITICO: Impossibile inizializzare Azure Tables: {e}")
        raise Exception(f"Azure Tables non disponibili: {e}")

def save_user_data_azure_only(email, user_info):
    """Salva dati utente SOLO su Azure - NO fallback file"""
    try:
        service = get_table_service_with_retry()
        table_client = service.get_table_client(TABLE_NAME_USERS)
        
        entity = {
            'PartitionKey': user_info.get('azienda', 'default'),
            'RowKey': email,
            'email': email,
            'nome': user_info.get('nome', ''),
            'cognome': user_info.get('cognome', ''),
            'azienda': user_info.get('azienda', ''),
            'is_admin': user_info.get('is_admin', False),
            'created_at': user_info.get('created_at', ''),
            'last_login': user_info.get('last_login', ''),
            'password_hash': user_info.get('password_hash', ''),
            'updated_at': datetime.now().isoformat()
        }
        
        table_client.upsert_entity(entity)
        logger.info(f"✅ Utente {email} salvato su Azure Table")
        return True
        
    except Exception as e:
        logger.error(f"❌ ERRORE CRITICO: Impossibile salvare utente {email}: {e}")
        raise Exception(f"Salvataggio utente fallito: {e}")

def get_user_data_azure_only(email):
    """Recupera dati utente SOLO da Azure - NO fallback file"""
    try:
        service = get_table_service_with_retry()
        table_client = service.get_table_client(TABLE_NAME_USERS)
        
        # Cerca in tutte le partizioni
        users = list(table_client.query_entities(f"RowKey eq '{email}'"))
        
        if users:
            user = users[0]
            logger.info(f"✅ Utente {email} trovato su Azure Table")
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
        logger.error(f"❌ ERRORE CRITICO: Impossibile recuperare utente {email}: {e}")
        raise Exception(f"Recupero utente fallito: {e}")

def save_test_result_azure_only(result):
    """Salva risultato test SOLO su Azure - NO fallback file"""
    try:
        service = get_table_service_with_retry()
        table_client = service.get_table_client(TABLE_NAME_RESULTS)
        
        # Genera ID univoco e sicuro
        timestamp = str(int(datetime.now().timestamp() * 1000))
        result_id = f"{result['user_email']}_{timestamp}"
        
        entity = {
            'PartitionKey': result.get('azienda', 'default'),
            'RowKey': result_id,
            'user_email': result['user_email'],
            'test_name': result['test_name'],
            'score': int(result['score']),
            'correct_answers': int(result['correct_answers']),
            'total_questions': int(result['total_questions']),
            'completed_at': result.get('completed_at', datetime.now().isoformat()),
            'answers_json': result['answers_json'],
            'created_at': datetime.now().isoformat()
        }
        
        table_client.upsert_entity(entity)
        logger.info(f"✅ Risultato test salvato su Azure Table per {result['user_email']}")
        return True
        
    except Exception as e:
        logger.error(f"❌ ERRORE CRITICO: Impossibile salvare risultato test: {e}")
        raise Exception(f"Salvataggio risultato fallito: {e}")

def get_user_test_results_azure_only(email):
    """Recupera risultati test SOLO da Azure - NO fallback file"""
    try:
        service = get_table_service_with_retry()
        table_client = service.get_table_client(TABLE_NAME_RESULTS)
        
        results = list(table_client.query_entities(f"user_email eq '{email}'"))
        
        test_results = []
        for result in results:
            test_results.append({
                'user_email': result['user_email'],
                'test_name': result['test_name'],
                'azienda': result.get('PartitionKey', ''),
                'score': result.get('score', 0),
                'correct_answers': result.get('correct_answers', 0),
                'total_questions': result.get('total_questions', 0),
                'completed_at': result.get('completed_at', ''),
                'answers_json': result.get('answers_json', '[]')
            })
        
        # Ordina per data completamento
        test_results.sort(key=lambda x: x.get("completed_at", ""), reverse=True)
        logger.info(f"✅ Recuperati {len(test_results)} risultati per {email}")
        
        return test_results
        
    except Exception as e:
        logger.error(f"❌ ERRORE CRITICO: Impossibile recuperare risultati per {email}: {e}")
        raise Exception(f"Recupero risultati fallito: {e}")

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
        logger.error(f"❌ ERRORE CRITICO: Impossibile recuperare utenti: {e}")
        raise Exception(f"Recupero utenti fallito: {e}")

def get_all_test_results_azure_only():
    """Recupera tutti i risultati test da Azure"""
    try:
        service = get_table_service_with_retry()
        table_client = service.get_table_client(TABLE_NAME_RESULTS)
        
        results = list(table_client.list_entities())
        
        test_results = []
        for result in results:
            test_results.append({
                'user_email': result['user_email'],
                'test_name': result['test_name'],
                'azienda': result.get('PartitionKey', ''),
                'score': result.get('score', 0),
                'correct_answers': result.get('correct_answers', 0),
                'total_questions': result.get('total_questions', 0),
                'completed_at': result.get('completed_at', ''),
                'answers_json': result.get('answers_json', '[]')
            })
        
        # Ordina per data
        test_results.sort(key=lambda x: x.get("completed_at", ""), reverse=True)
        logger.info(f"✅ Recuperati {len(test_results)} risultati totali")
        
        return test_results
        
    except Exception as e:
        logger.error(f"❌ ERRORE CRITICO: Impossibile recuperare risultati: {e}")
        raise Exception(f"Recupero risultati fallito: {e}")

def migrate_from_files_to_azure():
    """Migra dati esistenti dai file ad Azure (run once)"""
    try:
        logger.info("🔄 Avvio migrazione da file a Azure...")
        
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
        
        logger.info(f"📁 Trovati {len(users)} utenti e {len(test_results)} risultati nel file locale")
        
        # Migra utenti
        migrated_users = 0
        for email, user_data in users.items():
            try:
                save_user_data_azure_only(email, user_data)
                migrated_users += 1
            except Exception as e:
                logger.error(f"❌ Errore migrazione utente {email}: {e}")
        
        # Migra risultati
        migrated_results = 0
        for result in test_results:
            try:
                if not result.get('completed_at'):
                    result['completed_at'] = datetime.now().isoformat()
                save_test_result_azure_only(result)
                migrated_results += 1
            except Exception as e:
                logger.error(f"❌ Errore migrazione risultato: {e}")
        
        logger.info(f"✅ Migrazione completata: {migrated_users} utenti, {migrated_results} risultati")
        
        # Backup del file originale
        backup_file = f"{local_file}.backup_{int(datetime.now().timestamp())}"
        os.rename(local_file, backup_file)
        logger.info(f"📦 File originale salvato come backup: {backup_file}")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Errore durante la migrazione: {e}")
        return False

# Funzione di health check specifica per Azure Tables
def azure_tables_health_check():
    """Verifica stato delle Azure Tables"""
    try:
        service = get_table_service_with_retry()
        
        # Test lettura tabelle
        tables = list(service.list_tables())
        table_names = [table.name for table in tables]
        
        users_exists = TABLE_NAME_USERS in table_names
        results_exists = TABLE_NAME_RESULTS in table_names
        
        # Conta records se tabelle esistono
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
