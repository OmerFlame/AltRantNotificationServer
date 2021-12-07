from os import name, read, stat, system
import threading
import time
from flask import Flask
from flask import request
from flask import Response
import csv
from sys import exit
import requests
import json
import uuid
import signal
import sys
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA512
import json
import os
import base64
from typing import Any, Dict

should_exit = False

task_to_exit = ""

app = Flask(__name__)

flask_process = threading.Thread(target=app.run, args=(False, 8000), daemon=True)

class GracefulKiller:
    kill_now = False

    def __init__(self) -> None:
        signal.signal(signal.SIGINT, self.exit_gracefully)
        signal.signal(signal.SIGTERM, self.exit_gracefully)

    def exit_gracefully(self, *args):
        #print("exit_gracefully running")
        #flask_process.join()
        self.kill_now = True

ignored_notif_lock = threading.Lock()
credential_lock = threading.Lock()
thread_access_lock = threading.Lock()
private_key_lock = threading.Lock()

credential_fields = ['device_uuid', 'device_token', 'user_id', 'token_id', 'token_key', 'expire_time']
ignored_fields = ['user_id', 'created_time', 'type', 'rant_id', 'uid']
private_key_fields = ['device_uuid', 'private_key']

def t1_code(token_collection):
    last_check_time = 0
    apns_id = str(uuid.uuid4())

    while True:
        payload = {
            'last_time': 0,
            'ext_prof': 1,
            'app': 3,
            'user_id': token_collection["user_id"],
            'token_id': token_collection["token_id"],
            'token_key': token_collection["token_key"]
        }

        url = "https://devrant.com/api/users/me/notif-feed"
        request = requests.get(url, params=payload)

        json_data = request.json()

        if json_data["success"] is True:
            last_check_time = json_data["data"]["check_time"]

            is_acquired = False

            while not is_acquired:
                is_acquired = ignored_notif_lock.acquire()

            database = open("ignored_notifications.csv", 'r')
            ignored_csv = csv.DictReader(database, fieldnames=ignored_fields)

            # Delete notifications leading to deleted devRant content
            row_list = list()

            for notif_dict in ignored_csv:
                for notif in json_data["data"]["items"]:
                    if str(notif["created_time"]) == notif_dict["created_time"] and notif["type"] == notif_dict["type"] and str(notif["rant_id"]) == notif_dict["rant_id"] and str(notif["uid"]) == notif_dict["uid"]:
                        row_list.append(notif_dict)
            
            database.close()
            database = open("ignored_notifications.csv", 'w')
            ignored_csv = csv.DictWriter(database, fieldnames=ignored_fields)

            ignored_csv.writeheader()
            ignored_csv.writerows(row_list)
            database.close()

            notif: Dict[str, Any]
            for notif in json_data["data"]["items"]:
                database = open("ignored_notifications.csv", 'r')
                ignored_csv = csv.DictReader(database, fieldnames=ignored_fields)

                notif_dict = {
                    'user_id': str(token_collection["user_id"]),
                    'created_time': str(notif["created_time"]),
                    'type': str(notif["type"]),
                    'rant_id': str(notif["rant_id"]),
                    'uid': str(notif["uid"])
                }

                comment_id = notif.get("comment_id", None)

                if not notif_dict in ignored_csv:
                    if notif["read"] == 0:

                        database.close()
                        database = open("ignored_notifications.csv", 'a')
                        ignored_csv = csv.DictWriter(database, fieldnames=ignored_fields)
                        ignored_csv.writerow(notif_dict)
                        database.close()

                        if comment_id != None:
                            notif_dict["comment_id"] = str(comment_id)

                        notification_username = json_data["data"]["username_map"][str(notif["uid"])]["name"]

                        notification_title = ""

                        if notif["type"] == "rant_sub":
                            notification_title = notification_username + " has posted a new rant!"
                        elif notif["type"] == "comment_vote":
                            notification_title = notification_username + " ++\'d your comment!"
                        elif notif["type"] == "comment_content":
                            notification_title = notification_username + " commented on your rant!"
                        elif notif["type"] == "comment_mention":
                            notification_title = notification_username + " mentioned you in a comment!"
                        elif notif["type"] == "comment_discuss":
                            notification_title = notification_username + " commented on a rant you commented on!"
                        elif notif["type"] == "content_vote":
                            notification_title = notification_username + " ++\'d your rant!"

                        apns_payload = {"app_id": "2a80be30-7399-4a4e-818d-20e53f1eb396",
                                        "include_player_ids": [token_collection["device_token"]],
                                        "contents": {"en": notification_title},
                                        "data": {"rantID": int(notif_dict["rant_id"])}}

                        if notif_dict.get("comment_id", None) != None:
                            apns_payload["data"]["commentID"] = int(notif_dict.get("comment_id"))
                            apns_payload["data"]["username"] = notification_username
                            apns_payload["data"]["createdTime"] = int(notif_dict["created_time"])

                        if len(sys.argv) == 3 and sys.argv[1] == "xcsim":
                            temp_file = open("notification.apns", 'w')
                            temp_file.write(json.dumps(apns_payload))
                            temp_file.close()

                            system(f"xcrun simctl push {sys.argv[2]} com.cracksoftware.AltRant notification.apns")

                            os.remove("notification.apns")
                        else:
                            header = {"Content-Type": "application/json; charset=utf-8"}
 
                            req = requests.post("https://onesignal.com/api/v1/notifications", headers=header, data=json.dumps(apns_payload))
                            print(req.status_code, req.reason)
                
                else:
                    if notif["read"] == 1:
                        database.close()
                        database = open("ignored_notifications.csv", 'r')

                        temp_dictionary = csv.DictReader(database, fieldnames=ignored_fields)
                        #temp_dictionary.__next__()

                        row_list = list()

                        for row in temp_dictionary:
                            if row["user_id"] == notif_dict["user_id"] and row["created_time"] == notif_dict["created_time"] and row["type"] == notif_dict["type"] and row["rant_id"] == notif_dict["rant_id"] and row["uid"] == notif_dict["uid"]:
                                continue

                            row_list.append(row)

                        database.close()
                        database = open("ignored_notifications.csv", 'w')
                        temp_dictionary = csv.DictWriter(database, fieldnames=ignored_fields)
                        #temp_dictionary.writeheader()
                        temp_dictionary.writerows(row_list)
                        database.close()

                        database = open("ignored_notifications.csv", 'r')
                        ignored_csv = csv.DictReader(database, fieldnames=ignored_fields)


                #ignored_csv = csv.
            ignored_notif_lock.release()

        global task_to_exit
        if should_exit or task_to_exit == token_collection["device_uuid"]:
            break
        time.sleep(5)

    exit(0)

@app.route('/register', methods=["POST"])
def register():
    params = request.get_json()
    device_uuid = params["device_uuid"]

    is_acquired = False
    while not is_acquired:
        is_acquired = private_key_lock.acquire()

    private_key_database = open("private_keys.json", 'r+')
    private_keys = json.load(private_key_database)

    for key in private_keys["keys"]:
        if key["device_uuid"] == device_uuid:
            key_priv = RSA.importKey(key["private_key"])
            public_key = key_priv.publickey().exportKey('PEM').decode('utf-8').replace("\n", "")

            private_key_database.close()

            private_key_lock.release()

            return Response("{\"success\": true,\"key\":\"" + public_key + "\"}", status=200, mimetype='application/json')
        
    key = RSA.generate(2048)
    public_key = key.publickey().exportKey('PEM')
    
    new_key = {
        "device_uuid": device_uuid,
        "private_key": key.exportKey('PEM').decode('utf-8')
    }

    private_keys["keys"].append(new_key)

    private_key_database.seek(0)

    json.dump(private_keys, private_key_database, indent=4)

    private_key_database.close()

    private_key_lock.release()

    return Response("{\"success\": true,\"key\":\"" + public_key.decode('utf-8').replace("\n", "") + "\"}", status=200, mimetype='application/json')


@app.route('/test', methods=["POST"])
def test_encryption():
    params = request.get_json()

    b64_cipher_str = str(params["str"])

    b64_cipher_bytes = b64_cipher_str.encode("ascii")

    decoded_cipher_bytes = base64.b64decode(b64_cipher_bytes)

    key_db = open("private_keys.json", 'r')
    key_dict = json.load(key_db)
    key_db.close()

    private_key = RSA.importKey(str(key_dict["keys"][0]["private_key"]))
    decryptor = PKCS1_OAEP.new(private_key, hashAlgo=SHA512)

    decrypted_bytes = decryptor.decrypt(decoded_cipher_bytes)

    decrypted_str = decrypted_bytes.decode("ascii")

    print(f"DECRYPTED: {decrypted_str}")

    return Response("", status=200)


@app.route('/add_token_collection', methods=["POST"])
def add_token_collection():
    params = request.get_json()
    device_uuid = params["device_uuid"]
    device_token = params["device_token"]
    user_id = params["user_id"]
    token_id = params["token_id"]
    token_key = params["token_key"]
    token_expire_time = params["token_expire_time"]

    is_acquired = False

    while not is_acquired:
        is_acquired = private_key_lock.acquire()

    key_db = open("private_keys.json", 'r')
    key_dict = json.load(key_db)
    key_db.close()

    private_key_dict = {}

    for key in key_dict["keys"]:
        if key["device_uuid"] == device_uuid:
            private_key_dict = key
            break

    if private_key_dict == {}:
        return Response("{\"success\":false,\"error\":\"Device UUID not registered!\"}", status=400, mimetype='application/json')

    private_key = RSA.importKey(private_key_dict["private_key"])
    decryptor = PKCS1_OAEP.new(private_key, hashAlgo=SHA512)

    encoded_b64_encrypted_device_token = device_token.encode("ascii")
    encoded_b64_encrypted_user_id = user_id.encode("ascii")
    encoded_b64_encrypted_token_id = token_id.encode("ascii")
    encoded_b64_encrypted_token_key = token_key.encode("ascii")
    encoded_b64_encrypted_expire_time = token_expire_time.encode("ascii")

    decoded_b64_encrypted_device_token = base64.b64decode(encoded_b64_encrypted_device_token)
    decoded_b64_encrypted_user_id = base64.b64decode(encoded_b64_encrypted_user_id)
    decoded_b64_encrypted_token_id = base64.b64decode(encoded_b64_encrypted_token_id)
    decoded_b64_encrypted_token_key = base64.b64decode(encoded_b64_encrypted_token_key)
    decoded_b64_encrypted_expire_time = base64.b64decode(encoded_b64_encrypted_expire_time)

    decrypted_device_token = decryptor.decrypt(decoded_b64_encrypted_device_token).decode("ascii")
    decrypted_user_id = decryptor.decrypt(decoded_b64_encrypted_user_id).decode("ascii")
    decrypted_token_id = decryptor.decrypt(decoded_b64_encrypted_token_id).decode("ascii")
    decrypted_token_key = decryptor.decrypt(decoded_b64_encrypted_token_key).decode("ascii")
    decrypted_expire_time = decryptor.decrypt(decoded_b64_encrypted_expire_time).decode("ascii")

    private_key_lock.release()

    new_dict = {
        'device_uuid': device_uuid,
        'device_token': decrypted_device_token,
        'user_id': decrypted_user_id,
        'token_id': decrypted_token_id,
        'token_key': decrypted_token_key,
        'expire_time': decrypted_expire_time
    }

    is_acquired = False

    while not is_acquired:
        is_acquired = credential_lock.acquire()

    database = open("credential_records.csv", 'r')
    reader = csv.DictReader(database, fieldnames=credential_fields)

    if new_dict in reader:
        database.close()
        credential_lock.release()
        return Response("{\"success\":false,\"error\":\"Collection already exists!\"}", status=400, mimetype='application/json')
    
    database.close()

    database = open("credential_records.csv", 'a')
    writer = csv.DictWriter(database, fieldnames=credential_fields)

    writer.writerow(new_dict)

    database.close()

    credential_lock.release()

    temp_thread = threading.Thread(target=t1_code, args=[new_dict])
    temp_thread.start()

    return Response("{\"success\":true}", status=200, mimetype='application/json')

@app.route('/update_token_collection', methods=["PUT"])
def update_token_collection():
    params = request.get_json()
    device_uuid = params["device_uuid"]
    device_token = params["device_token"]
    user_id = params["user_id"]
    token_id = params["token_id"]
    token_key = params["token_key"]
    token_expire_time = params["token_expire_time"]

    is_acquired = False

    while not is_acquired:
        is_acquired = private_key_lock.acquire()

    key_db = open("private_keys.json", 'r')
    key_dict = json.load(key_db)
    key_db.close()

    private_key_dict = {}

    for key in key_dict["keys"]:
        if key["device_uuid"] == device_uuid:
            private_key_dict = key
            break

    if private_key_dict == {}:
        return Response("{\"success\":false,\"error\":\"Device UUID not registered!\"}", status=400, mimetype='application/json')

    private_key = RSA.importKey(private_key_dict["private_key"])
    decryptor = PKCS1_OAEP.new(private_key, hashAlgo=SHA512)

    encoded_b64_encrypted_device_token = device_token.encode("ascii")
    encoded_b64_encrypted_user_id = user_id.encode("ascii")
    encoded_b64_encrypted_token_id = token_id.encode("ascii")
    encoded_b64_encrypted_token_key = token_key.encode("ascii")
    encoded_b64_encrypted_expire_time = token_expire_time.encode("ascii")

    decoded_b64_encrypted_device_token = base64.b64decode(encoded_b64_encrypted_device_token)
    decoded_b64_encrypted_user_id = base64.b64decode(encoded_b64_encrypted_user_id)
    decoded_b64_encrypted_token_id = base64.b64decode(encoded_b64_encrypted_token_id)
    decoded_b64_encrypted_token_key = base64.b64decode(encoded_b64_encrypted_token_key)
    decoded_b64_encrypted_expire_time = base64.b64decode(encoded_b64_encrypted_expire_time)

    try:
        decrypted_device_token = decryptor.decrypt(decoded_b64_encrypted_device_token).decode("ascii")
        decrypted_user_id = decryptor.decrypt(decoded_b64_encrypted_user_id).decode("ascii")
        decrypted_token_id = decryptor.decrypt(decoded_b64_encrypted_token_id).decode("ascii")
        decrypted_token_key = decryptor.decrypt(decoded_b64_encrypted_token_key).decode("ascii")
        decrypted_expire_time = decryptor.decrypt(decoded_b64_encrypted_expire_time).decode("ascii")
    except:
        private_key_lock.release()
        return Response("{\"success\": false, \"error\": \"Failed to decrypt token collection!\"}", status=500, mimetype='application/json')

    private_key_lock.release()

    new_dict = {
        'device_uuid': device_uuid,
        'device_token': decrypted_device_token,
        'user_id': decrypted_user_id,
        'token_id': decrypted_token_id,
        'token_key': decrypted_token_key,
        'expire_time': decrypted_expire_time
    }

    is_acquired = False

    while not is_acquired:
        is_acquired = credential_lock.acquire()

    database = open("credential_records.csv", 'r')
    reader = csv.DictReader(database, fieldnames=credential_fields)

    row_list = list()

    for row in reader:
        if row["device_uuid"] == device_uuid:
            continue

        row_list.append(row)

    row_list.append(new_dict)

    database.close()
    database = open("credential_records.csv", 'w')
    writer = csv.DictWriter(database, fieldnames=credential_fields)

    writer.writerows(row_list)
    database.close()

    credential_lock.release()

    return Response("{\"success\": true}", status=200, mimetype='application/json')

@app.route('/check_uuid_registration_status', methods=["GET"])
def check_uuid_registration_status():
    device_uuid: str
    device_uuid = request.args["device_uuid"]

    private_key_check: bool
    private_key_check = request.args["private_key_check"]

    credential_check: bool
    credential_check = request.args["credential_check"]

    is_currently_success = True

    if private_key_check:
        while not private_key_lock.acquire():
            pass

        did_find_key = False

        with open("private_keys.json", 'r') as keys_db:
            keys_dict: dict
            keys_dict = json.load(keys_db)

            for i in range(len(keys_dict["keys"]) - 1):
                if keys_dict["keys"][i]["device_uuid"] == device_uuid:
                    keys_db.close()
                    private_key_lock.release()
                    did_find_key = True
                    break

            if not did_find_key:
                keys_db.close()
                private_key_lock.release()

                return Response("{\"success\": false, \"error\": \"Could not find device UUID in the private key database!\"}", status=404, mimetype='application/json')

    if credential_check:
        while not credential_lock.acquire():
            pass

        did_find_credentials = False

        with open("credential_records.csv", 'r') as credentials_db:
            credentials_dict = csv.DictReader(credentials_db, fieldnames=credential_fields)

            for row in credentials_dict:
                if row["device_uuid"] == device_uuid:
                    credentials_db.close()
                    credential_lock.release()
                    did_find_credentials = True
                    break

            if not did_find_credentials:
                credentials_db.close()
                credential_lock.release()

                return Response("{\"success\": false, \"error\": \"Could not find device UUID in the credential records database!\"}", status=404, mimetype='application/json')
            
    return Response("{\"success\": true}", status=200, mimetype='application/json')

@app.route("/")
def test():
    return Response("<h1>If you can see this, then the AltRant notification server is working!</h1>", status=200, mimetype='text/html')


@app.route('/remove_token_collection', methods=["DELETE"])
def remove_token_collection():
    device_uuid = request.args["device_uuid"]

    is_acquired = False

    while not is_acquired:
        is_acquired = credential_lock.acquire()

    credentials_file = open("credential_records.csv", 'r')
    credentials_db = csv.DictReader(credentials_file, fieldnames=credential_fields)

    credentials_list = list()

    for collection in credentials_db:
        if collection["device_uuid"] == device_uuid:
            did_find = True
            continue

        credentials_list.append(collection)

    if did_find:
        credentials_file.close()
        credentials_file = open("credential_records.csv", 'w')
        credentials_db = csv.DictWriter(credentials_file, fieldnames=credential_fields)

        credentials_db.writerows(credentials_list)
        credentials_file.close()

        credential_lock.release()

        is_acquired = False

        while not is_acquired:
            is_acquired = thread_access_lock.acquire()

        current_thread_count = threading.active_count()

        global task_to_exit
        task_to_exit = device_uuid

        while threading.active_count() == current_thread_count:
            time.sleep(0.5)

        task_to_exit = ""
    
        thread_access_lock.release()

        return Response("{\"success\":true}", status=200, mimetype='application/json')
    else:
        credential_lock.release()

        return Response("{\"success\":false,\"error\":\"Collection doesn't exist!\"}", status=410, mimetype='application/json')

@app.route('/unregister', methods=["DELETE"])
def unregister():
    device_uuid = request.args["device_uuid"]

    while credential_lock.acquire() is False:
        pass

    credentials_db = open("credential_records.csv", 'r')
    credentials_dict = csv.DictReader(credentials_db, fieldnames=credential_fields)

    for row in credentials_dict:
        if row["device_uuid"] == device_uuid:
            credentials_db.close()
            credential_lock.release()
            return Response("{\"success\": false,\"error\": \"Remove the token collection associated with the device's UUID first!\"}", status=400, mimetype='application/json')

    credential_lock.release()

    while private_key_lock.acquire() is False:
        pass

    private_keys_db = open("private_keys.json", 'r')
    private_keys_dict = json.load(private_keys_db)

    for i in range(len(private_keys_dict["keys"]) - 1):
        if private_keys_dict["keys"][i]["device_uuid"] == device_uuid:
            private_keys_dict["keys"].pop(i)

            final_json_string = json.dumps(private_keys_dict, indent=4, sort_keys=False)

            private_keys_db.close()
            private_keys_db = open("private_keys.json", 'w')
            private_keys_db.write(final_json_string)
            private_keys_db.close()

            private_key_lock.release()

            return Response("{\"success\": true}", status=200, mimetype='application/json')

    private_key_lock.release()

    return Response("{\"success\": false,\"error\": \"Couldn't find a private key associated with the provided device UUID.\"}", status=400, mimetype='application/json')

if __name__ == '__main__':
    database = open("credential_records.csv", 'r')
    reader = csv.DictReader(database, fieldnames=credential_fields)

    reader.__next__()
    for collection in reader:
        t1 = threading.Thread(target=t1_code, args=[collection])
        t1.name = collection["device_uuid"]
        t1.start()

    database.close()

    flask_process.start()

    killer = GracefulKiller()
    while not killer.kill_now:
        time.sleep(0.1)

    print("Exiting...")

    should_exit = True

    while threading.active_count() > 2:
        pass
    
