import os
import configparser
import requests
import logging
from datetime import datetime, timedelta, timezone

# Logging setup
logging.basicConfig(level=logging.DEBUG, format='[%(levelname)s] %(asctime)s - %(message)s')

# Read config
config = configparser.ConfigParser()
config_path = os.path.join(os.getcwd(), 'ttlock_admin_panel', 'config.ini')
logging.debug(f"Reading config from {config_path}")
config.read(config_path)

try:
    client_id = config['ttlock_admin_panel']['client_id']
    client_secret = config['ttlock_admin_panel']['client_secret']
    redirect_uri = config['ttlock_admin_panel']['redirect_uri']
except KeyError as e:
    logging.error(f"Missing config key: {e}")
    raise

# API constants
BASE_URL = "https://api.ttlock.com"
header = {'Content-Type': 'application/x-www-form-urlencoded'}


def get_token(email, password):
    payload = {
        'grant_type': 'password',
        'client_id': client_id,
        'client_secret': client_secret,
        'redirect_uri': redirect_uri,
        'username': email,
        'password': password
    }
    url = f"{BASE_URL}/oauth2/token"
    logging.debug(f"[get_token] Sending payload: {payload}")
    response = requests.post(url, headers=header, data=payload)
    logging.debug(f"[get_token] Response: {response.status_code} {response.text}")
    return response


def refresh_tocken(refresh_token):
    payload = {
        'grant_type': 'refresh_token',
        'client_id': client_id,
        'client_secret': client_secret,
        'redirect_uri': redirect_uri,
        'refresh_token': refresh_token
    }
    url = f"{BASE_URL}/oauth2/token"
    logging.debug("[refresh_token] Refreshing token...")
    response = requests.post(url, headers=header, data=payload)
    logging.debug(f"[refresh_token] Response: {response.status_code} {response.text}")
    return response


def lock_list(accessToken, pageNo):
    payload = {
        'clientId': client_id,
        'accessToken': accessToken,
        'pageNo': pageNo,
        'pageSize': 50,
        'date': int(datetime.now().timestamp() * 1000)
    }
    url = f"{BASE_URL}/v3/lock/list"
    logging.debug(f"[lock_list] Payload: {payload}")
    response = requests.post(url, headers=header, data=payload)
    logging.debug(f"[lock_list] Response: {response.status_code} {response.text}")
    return response


def unlock_records(accessToken, lockId, pageNo):
    now = datetime.now()
    payload = {
        'clientId': client_id,
        'accessToken': accessToken,
        'lockId': lockId,
        'startDate': int((now - timedelta(days=7)).timestamp() * 1000),
        'endDate': int(now.timestamp() * 1000),
        'pageNo': pageNo,
        'pageSize': 100,
        'date': int(now.timestamp() * 1000)
    }
    url = f"{BASE_URL}/v3/lockRecord/list"
    logging.debug(f"[unlock_records] Payload: {payload}")
    response = requests.post(url, headers=header, data=payload)
    logging.debug(f"[unlock_records] Response: {response.status_code} {response.text}")
    return response


def unlock_records_one_day(accessToken, lockId, pageNo):
    now = datetime.now()
    payload = {
        'clientId': client_id,
        'accessToken': accessToken,
        'lockId': lockId,
        'startDate': int((now - timedelta(days=1)).timestamp() * 1000),
        'endDate': int(now.timestamp() * 1000),
        'pageNo': pageNo,
        'pageSize': 100,
        'date': int(now.timestamp() * 1000)
    }
    url = f"{BASE_URL}/v3/lockRecord/list"
    logging.debug(f"[unlock_records_one_day] Payload: {payload}")
    response = requests.post(url, headers=header, data=payload)
    logging.debug(f"[unlock_records_one_day] Response: {response.status_code} {response.text}")
    return response


def list_passwords(accessToken, lockId, pageNo):
    payload = {
        'clientId': client_id,
        'accessToken': accessToken,
        'lockId': lockId,
        'pageNo': pageNo,
        'pageSize': 50,
        'date': int(datetime.now().timestamp() * 1000)
    }
    url = f"{BASE_URL}/v3/lock/listKeyboardPwd"
    logging.debug(f"[list_passwords] Payload: {payload}")
    response = requests.post(url, headers=header, data=payload)
    logging.debug(f"[list_passwords] Response: {response.status_code} {response.text}")
    return response


def get_all_unlock_records(accessToken):
    logging.debug("[get_all_unlock_records] Fetching all locks...")
    response = lock_list(accessToken, 1)
    try:
        locks = response.json().get("list", [])
        lock_ids = [lock['lockId'] for lock in locks]
    except Exception as e:
        logging.error(f"[get_all_unlock_records] Error parsing lock list: {e}")
        return []

    all_unlocks = []
    for lock_id in lock_ids:
        record_response = unlock_records_one_day(accessToken, lock_id, 1)
        try:
            records = record_response.json().get("list", [])
            all_unlocks.extend(records)
        except Exception as e:
            logging.warning(f"[get_all_unlock_records] Skipped lockId {lock_id} due to error: {e}")
    return all_unlocks


def create_password(accessToken, lockId, keyboardPwd, keyboardPwdName, startDate, endDate):
    payload = {
        'clientId': client_id,
        'accessToken': accessToken,
        'lockId': lockId,
        'keyboardPwd': keyboardPwd,
        'keyboardPwdName': keyboardPwdName,
        'startDate': startDate,
        'endDate': endDate,
        'addType': 2,
        'date': int(datetime.now().timestamp() * 1000)
    }
    url = f"{BASE_URL}/v3/keyboardPwd/add"
    logging.debug(f"[create_password] Payload: {payload}")
    response = requests.post(url, headers=header, data=payload)
    logging.debug(f"[create_password] Response: {response.status_code} {response.text}")
    return response
