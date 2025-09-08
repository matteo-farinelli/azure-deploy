# Sostituisci queste funzioni nel tuo azure_storage.py

def get_user_data_azure_only(email):
    """Recupera dati utente SOLO da Azure - NO fallback"""
    try:
        service = get_table_service_with_retry()
        table_client = service.get_table_client(TABLE_NAME_USERS)  # Usa table_client
        
        # Cerca in tutte le partizioni
        query = f"RowKey eq '{email}'"
        users = list(table_client.query_entities(query))  # query_entities sul table_client
        
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
        return None  # Cambiato da raise a return None

def get_user_test_results_azure_only(user_email):
    """Recupera SOLO gli ultimi tentativi per ogni test dell'utente"""
    try:
        service = get_table_service_with_retry()
        table_client = service.get_table_client(TABLE_NAME_RESULTS)  # Usa table_client
        
        # Usa user_email come PartitionKey
        filter_query = f"PartitionKey eq '{user_email}'"
        entities = list(table_client.query_entities(query_filter=filter_query))  # table_client.query_entities
        
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
        
        logger.info(f"✅ Retrieved {len(results)} latest test results for {user_email}")
        return results

    except Exception as e:
        logger.error(f"❌ Error getting user test results: {e}")
        return []

def get_all_users_azure_only():
    """Recupera tutti gli utenti da Azure"""
    try:
        service = get_table_service_with_retry()
        table_client = service.get_table_client(TABLE_NAME_USERS)  # Usa table_client
        
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
        return {}  # Cambiato da raise a return {}

def get_all_test_results_azure_only():
    """Recupera TUTTI i risultati test da Azure Tables (inclusi tentativi multipli)"""
    try:
        service = get_table_service_with_retry()
        table_client = service.get_table_client(TABLE_NAME_RESULTS)  # Usa table_client
        
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
        table_client = service.get_table_client(TABLE_NAME_RESULTS)  # Usa table_client
        
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
        table_client = service.get_table_client(TABLE_NAME_RESULTS)  # Usa table_client
        
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
