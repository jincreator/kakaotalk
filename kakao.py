#!/usr/bin/python
# -*- coding: utf-8 -*-
__author__ = 'carpedm20'

import sys
import struct
import base64
import rsa as RSA
import socket
import bson
import json
import urllib, urllib2
import httplib
from bson import BSON
from bson.py3compat import b
import M2Crypto
from Crypto.Cipher import AES
from pkcs7 import PKCS7Encoder
from config import duuid, sKey, aes_key, user_id

encoder = PKCS7Encoder()

def get_list():
    print "[$] START GET"
    url = 'https://ch-talk.kakao.com/android/chats/list.json'

    headers = { 'GET' : '/android/chats/list.json',
        'HOST' : 'ch-talk.kakao.com',
        'Connection' : 'Close',
        'Accept-Language' : 'ko',
        'Content-Transfer-Encoding' : 'UTF-8',
        'User-Agent' : 'KakaoTalkAndroid/3.8.7 Android/4.1.2',
        'A' : 'android/3.8.7/ko',
        'S' : sKey + '-' + duuid, 
        'Cache-Control' : 'no-cache',
        'Content-Type' : 'application/x-www-form-urlencoded',
        'Content-Length' : '0' }

    request = urllib2.Request(url, None, headers)
    response = urllib2.urlopen(request)

    data = response.read()
    data = json.loads(data ,encoding='utf-8')

    print "[$] END GET"
    return data['chatRooms']

def start(sKey = sKey, duuid = duuid):
    print "[*] START"

    document = checkin() # android
    #document = buy() # windows

    host = document['host']
    port = document['port']

    print "[!] HOST : " + host
    print "[!] PORT : " + str(port)

    h = hand()

    l = login(sKey = sKey, duuid = duuid)
    enc_l = enc_aes(l)
    command = struct.pack('I',len(enc_l)) + enc_l
    #hex_to_dic(encoder.decode(dec_aes(command[4:])[22:]))

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((str(host),port))
    s.settimeout(5)

    s.send(h + command)

    try:
        reply = s.recv(40960)
        hex_secure(reply)
    except:
        print "[x] START ERROR "
        for e in sys.exc_info():
            print e
        sys.exit(1)

    return s

def create(s, host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((str(host),port))

    return s

def hex_secure(data):
    dec_h = dec_aes(data[4:])
    print '  [' + dec_h[6:17] + ']',
    print hex_to_dic(encoder.decode(dec_h[22:]))

def hex_string(data):
    data = data.split('}')[0].replace('\n','').replace(', 0x','\\x').strip().replace('0x','\\x').decode("string-escape")
    dec_h = dec_aes(data[4:])
    #print '  [' + dec_h[6:17] + ']',
    #print hex_to_dic(encoder.decode(dec_h[22:]))

def hex_nosecure(h):
    print '[' + h[6:17] + ']',
    print hex_to_dic(encoder.decode(h[22:]))

def checkin():
    new = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    new.connect(('110.76.141.20', 5228))

    data = '\x12\x27\x00\x00' # Packet ID (4)
    data += '\x00\x00' # Status Code (2)
    data += 'CHECKIN\x00\x00\x00\x00' # Method (11)
    data += '\x00' # Body Type (1)

    body = BSON.encode({u'useSub': True, u'ntype': 3, u'userId': user_id, u'MCCMNC': None, u'appVer': u'3.8.7', u'os': u'android'})

    data += body[:4] # Body Length (4)
    data += body # Body Contents

    new.sendall(data)
    reply = new.recv(20480)

    bs = reply[22:]
    (document, _) = bson._bson_to_dict(bs,dict, True, bson.OLD_UUID_SUBTYPE)

    print "[*] CHECKIN"

    return document

def buy():
    # Alpha: 192.168.77.33:5555
    # Sandbox: 110.76.140.115:9290
    # Beta: 110.76.140.165:9282
    # Real: loco.kakao.com

    # port number when using 3G: 9282, 8080, 5223, 5242, 10009
    # port number when using WIFI: 80, 8080, 5223, 5242, 10009

    new = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    new.connect(('110.76.141.20', 5228))

    data = '\x01\x00\x00\x00' # Packet ID (4)
    data += '\x00\x00' # Status Code (2)
    data += 'BUY\x00\x00\x00\x00\x00\x00\x00\x00' # Method (11)
    data += '\x00' # Body Type (1)

    #body = BSON.encode({u'ntype': 3, u'countryISO': u'KR', u'userId': 7155596L, u'MCCMNC': u'', u'appVer': u'1.5.0', u'os': u'wp', u'voip': False})
    body = BSON.encode({u'ntype': 3, u'countryISO': u'US', u'userId': 7155596L, u'MCCMNC': None, u'appVer': u'3.8.7', u'os': u'android', u'voip': False})

    data += body[:4] # Body Length (4)
    data += body # Body Contents

    new.sendall(data)
    reply = new.recv(4096)

    bs = reply[22:]
    (document, _) = bson._bson_to_dict(bs,dict, True, bson.OLD_UUID_SUBTYPE)

    print "[*] BUY"

    return document

def rsa(secret):
    n = 0xaf0dddb4de63c066808f08b441349ac0d34c57c499b89b2640fd357e5f4783bfa7b808af199d48a37c67155d77f063ddc356ebf15157d97f5eb601edc5a104fffcc8895cf9e46a40304ae1c6e44d0bcc2359221d28f757f859feccf07c13377eec2bf6ac2cdd3d13078ab6da289a236342599f07ffc1d3ef377d3181ce24c719
    e = 3

    pub_key = RSA.PublicKey(n, e)
    enc_key = RSA.encrypt(secret, pub_key)

    #pubkey = M2Crypto.RSA.new_pub_key((M2Crypto.m2.bn_to_mpi(M2Crypto.m2.hex_to_bn(hex(e)[2:])),M2Crypto.m2.bn_to_mpi(M2Crypto.m2.hex_to_bn(hex(n)[2:])),))
    # enc_key = pubkey.public_encrypt(secret, M2Crypto.RSA.pkcs1_oaep_padding)
    # enc_key.encode('base64')

    #print "RSA : " + str(enc_key)

    return enc_key

def hand():
    hand = '\x80\x00\x00\x00'
    hand += '\x01\x00\x00\x00' # RSA = 1, DH = 2
    hand += '\x01\x00\x00\x00' # AES_CBC=1, AES_CFB128=2, AES_OFB128=3, RC4=4
    hand += rsa(aes_key)

    return hand

def send(s, data):
    enc_data = enc_aes(data)
    command = struct.pack('I',len(enc_data)) + enc_data
    s.send(command)

    try:
        reply = s.recv(40960)
        hex_secure(reply)
    except:
        print "[x] ERROR "
        for e in sys.exc_info():
            print e
	return False

    return True

def login(sKey = sKey, duuid = duuid):
    print " [*] LOGIN"

    data = '\x14\x00\x00\x00' # Packet ID
    data += '\x00\x00' # Status Code : when sending command -> 0
    data += 'LOGIN\x00\x00\x00\x00\x00\x00' # Method
    data += '\x00' # Body Type : when sending command -> 0

    body = BSON.encode({u'opt': u'', u'prtVer': u'1.0', u'appVer': u'1.5.0', u'os': u'wp', u'lang': u'ko', u'sKey': sKey, u'duuid': duuid, u'ntype': 3, u'MCCMNC': None})
    body = BSON.encode({u'opt': u'', u'prtVer': u'1.0', u'appVer': u'3.8.7', u'os': u'android', u'lang': u'en', u'sKey': sKey, u'duuid': duuid, u'ntype': 3, u'MCCMNC': None})

    data += body[:4]
    data += body

    return data

def chaton(s, chatId):
    msg = " [*] CHATON : " + str(chatId)
    #print msg

    data = '\x05\x00\x00\x00' # Packet ID
    data += '\x00\x00' # Status Code : when sending command -> 0
    data += 'CHATON\x00\x00\x00\x00\x00' # Method
    data += '\x00' # Body Type : when sending command -> 0

    body = BSON.encode({u'chatId': chatId})

    data += body[:4]
    data += body

    succ = send(s, data)
    return succ

def nchatlist(s):
    print " [*] NCHATLIST"

    data = '\x06\x00\x00\x00' # Packet ID
    data += '\x00\x00' # Status Code : when sending command -> 0
    data += 'NCHATLIST\x00\x00' # Method
    data += '\x00' # Body Type : when sending command -> 0

    body = BSON.encode({u'maxIds': [], u'chatIds': []})

    data += body[:4]
    data += body

    enc_data = enc_aes(data)
    command = struct.pack('I',len(enc_data)) + enc_data
    s.send(command)

    reply = ''

    while True:
        try:
            new = s.recv(1024)
            reply += new
        except socket.timeout:
            break

    while True:
        try:
            dec_h = dec_aes(reply[4:hex_to_num(reply[:4])+4])
            reply = reply[hex_to_num(reply[:4])+4:]

            result = dec_packet(dec_h)
            print "  [-]" + result['command'],
            b = result['body']
            print " from " + b['chatLog']['authorId'] + '('+ b[authorNickname] + ') : ' + b['chatLog']['message']
        except:
	    break

    return True
        
    #succ = send(s, data)
    #return succ

def leave(s, chatId):
    print " [*] LEAVE from " + str(chatId)

    data = '\x06\x00\x00\x00' # Packet ID
    data += '\x00\x00' # Status Code : when sending command -> 0
    data += 'LEAVE\x00\x00\x00\x00\x00\x00' # Method
    data += '\x00' # Body Type : when sending command -> 0

    body = BSON.encode({u'chatId': chatId})

    data += body[:4]
    data += body

    succ = send(s, data)
    return succ

#[CHATON] {u'chatId': } 
def chaton(s, chatId):
    print " [*] CHATON from " + str(chatId)

    data = '\x07\x00\x00\x00' # Packet ID
    data += '\x00\x00' # Status Code : when sending command -> 0
    data += 'CHATON\x00\x00\x00\x00\x00' # Method
    data += '\x00' # Body Type : when sending command -> 0

    body = BSON.encode({u'chatId': chatId})

    data += body[:4]
    data += body

    succ = send(s, data)
    return succ

#[PING]
def ping(s):
    print " [*] PING" 

    data = '\x09\x00\x00\x00' # Packet ID
    data += '\x00\x00' # Status Code : when sending command -> 0
    data += 'PING\x00\x00\x00\x00\x00\x00\x00' # Method
    data += '\x00' # Body Type : when sending command -> 0
    data += '\x00\x00\x00\x00\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a'

    succ = send(s, data)
    return succ

#[UPSEEN] {u'status': 0, u'isOK': True, u'errMsg': None}
def upseen(s, chatId):
    print " [*] UPSEEN from " + str(chatId)

    data = '\x08\x00\x00\x00' # Packet ID
    data += '\x00\x00' # Status Code : when sending command -> 0
    data += 'UPSEEN\x00\x00\x00\x00\x00' # Method
    data += '\x00' # Body Type : when sending command -> 0

    body = BSON.encode({u'max': 0L, u'cnt': 5, u'cur': 0L, u'chatId': chatId})

    data += body[:4]
    data += body

    succ = send(s, data)
    return succ

#[READ] {u'since': 0L, u'chatId': }
def read(s, chatId):
    print " [*] READ from " + str(chatId)

    data = '\x06\x00\x00\x00' # Packet ID
    data += '\x00\x00' # Status Code : when sending command -> 0
    data += 'READ\x00\x00\x00\x00\x00\x00\x00' # Method
    data += '\x00' # Body Type : when sending command -> 0

    body = BSON.encode({u'chatId': chatId, u'since': 462937779245527040L})

    data += body[:4]
    data += body

    succ = send(s, data)
    return succ

def write(s, chatId, msg = u'test'):
    try:
        print " [*] WRITE to " + str(chatId) + " : " + str(msg)
    except:
        print " [*] WRITE to " + str(chatId) + " : ???"

    data = '\x06\x00\x00\x00' # Packet ID
    data += '\x00\x00' # Status Code : when sending command -> 0
    data += 'WRITE\x00\x00\x00\x00\x00\x00' # Method
    data += '\x00' # Body Type : when sending command -> 0

    # print msg

    body = BSON.encode({u'chatId': chatId, u'msg': msg, u'extra': None, u'type': 1})

    data += body[:4]
    data += body

    succ = send(s, data)
    return succ

#http://dn-m.talk.kakao.com/talkm/oWduQM37UX/PLQiP0Jjbt4vSb1dKGdK0K/39qkgm.jpg
#write_pic(s, url=upload_pic())
def write_pic(s, chatId = 42865071710223L, url = "/talkm/oWduQM37UX/PLQiP0Jjbt4vSb1dKGdK0K/39qkgm.jpg", width = 800, height = 600):
    print " [*] WRITE PICTURE to " + str(chatId) + " : " + url

    data = '\x06\x00\x00\x00' # Packet ID
    data += '\x00\x00' # Status Code : when sending command -> 0
    data += 'WRITE\x00\x00\x00\x00\x00\x00' # Method
    data += '\x00' # Body Type : when sending command -> 0

    body = BSON.encode({u'msg': u'', u'extra': u'{\r\n "path": "'+url+'",\r\n "width": '+str(width)+',\r\n  "height": '+str(height)+',\r\n  "name": null,\r\n  "sound": null,\r\n  "msg": null,\r\n  "lat": null,\r\n  "log": null,\r\n  "keyword": null\r\n}', u'type': 2, u'chatId': chatId})

    data += body[:4]
    data += body

    succ = send(s, data)
    return succ

def write_thumb(s, chatId, msg = u'', url = ''):
    print " [*] WRITE THUMBNAIL to " + str(chatId) + " : " + url

    data = '\x06\x00\x00\x00' # Packet ID
    data += '\x00\x00' # Status Code : when sending command -> 0
    data += 'WRITE\x00\x00\x00\x00\x00\x00' # Method
    data += '\x00' # Body Type : when sending command -> 0

    if url.find('gif') is -1:
        t = 12
    else:
        t = 6
    body = BSON.encode({u'msg': msg, u'extra': u'{\r\n "path": "'+url+u'",\r\n "width": 120,\r\n  "height": 120,\r\n  "name": "(Designed by carpedm20)",\r\n  "sound": null,\r\n  "msg": null,\r\n  "lat": null,\r\n  "log": null,\r\n  "keyword": null\r\n}', u'type': t, u'chatId': chatId})

    data += body[:4]
    data += body

    succ = send(s, data)
    return succ

def encode_multipart_formdata(fields, files):
    BOUNDARY = "httphelper--multipartboundary--635103678186870000"
    CRLF = '\r\n'
    L = []
    for (key, value) in fields:
        L.append('--' + BOUNDARY)
        L.append('Content-Disposition: form-data; name="%s"' % key)
        L.append('')
        L.append(value)
    for (key, filename, value) in files:
        L.append('--' + BOUNDARY)
        L.append('Content-Disposition: form-data; name="%s"; filename="%s"' % (key, filename))
        #L.append('Content-Type: image/jpeg')
        L.append('Content-Transfer-Encoding: binary')
        L.append('Content-Length: '+str(len(value)))
        L.append('')
        L.append(value)
    L.append('--' + BOUNDARY + '--')
    L.append('')
    body = CRLF.join(L)
    content_type = 'multipart/form-data; boundary=%s' % BOUNDARY
    return body

#http://dn-m.talk.kakao.com/talkm/oWduQM37UX/PLQiP0Jjbt4vSb1dKGdK0K/39qkgm.jpg
def upload_pic(file_name):
    print "  [!] UPLOAD : " + str(file_name)
    url = 'up-m.talk.kakao.com'

    params = []
    params.append(("user_id", user_id))
    #params.append(("attachment_type", 'image/jpeg'))
    params.append(("attachment_type", 'image'))

    d = ('attachment', file_name, open(file_name,'r').read())

    body = encode_multipart_formdata(params, (d, ))

    conn = httplib.HTTP(url)
    conn.putrequest('POST','/upload')
    conn.putheader("Host", "up-m.talk.kakao.com")
    conn.putheader("Connection", "Keep-Alive")
    conn.putheader("Referer", "file:///Applications/Install/" + duuid + "/Install/")
    conn.putheader("Accept", "*/*")
    conn.putheader("Cache-Control", "no-cache")
    conn.putheader("User-Agent", "NativeHost")
    conn.putheader("Accept-Encoding", "identity")
    conn.putheader("Content-Type", "multipart/form-data; boundary=httphelper--multipartboundary--635103678186870000")
    conn.putheader("Content-Length", str(len(body)))
    conn.endheaders()
    conn.send(body)
    errcode, errmsg, headers = conn.getreply()

    #print headers

    f = conn.getfile()
    file_url = f.read()
    print "  [!] File URL : http://dn-m.talk.kakao.com" + file_url
    return file_url

def update_profile(url):
    print " [#] UPDATE PROFILE : " + str(url)
    url = 'st-talk.kakao.com'

    params = urllib.urlencode({'profileImagePath': url})

    conn = httplib.HTTP(url)
    conn.putrequest('POST','/wp/account/update_settings.json')
    conn.putheader("Host", "st-talk.kakao.com")
    conn.putheader("Connection", "Keep-Alive")
    conn.putheader("Referer", "file:///Applications/Install/" + duuid + "/Install/")
    conn.putheader("Accept", "*/*")
    conn.putheader("Cache-Control", "no-cache")
    conn.putheader("User-Agent", "KakaoTalkWP/1.9.0 WP/Microsoft Windows CE 7.10.8773")
    conn.putheader("Accept-Encoding", "identity")
    conn.putheader("Content-Type", "application/x-www-form-urlencoded")
    conn.putheader("A", "wp/1.9.0/ko")
    conn.putheader("S", sKey + '-' + duuid)
    conn.putheader("Content-Length", str(len(params)))
    conn.endheaders()
    conn.send(params)
    reply, msg, headers = conn.getreply()

    print headers
    print reply
    print msg

    f = conn.getfile()
    file_url = f.read()
    print "  [!] File URL : " + file_url
    return file_url

def upload_profile_pic(file_name):
    print "  [!] UPLOAD PROFILE : " + str(file_name)
    url = 'up-p.talk.kakao.com'

    params = []
    params.append(("user_id", user_id))
    #params.append(("attachment_type", 'image/jpeg'))
    params.append(("attachment_type", 'image'))

    d = ('attachment', file_name, open(file_name,'r').read())

    body = encode_multipart_formdata(params, (d, ))

    conn = httplib.HTTP(url)
    conn.putrequest('POST','/upload')
    conn.putheader("Host", "up-p.talk.kakao.com")
    conn.putheader("Connection", "Keep-Alive")
    conn.putheader("Referer", "file:///Applications/Install/" + duuid + "/Install/")
    conn.putheader("Accept", "*/*")
    conn.putheader("Cache-Control", "no-cache")
    conn.putheader("User-Agent", "NativeHost")
    conn.putheader("Accept-Encoding", "identity")
    conn.putheader("Content-Type", "multipart/form-data; boundary=httphelper--multipartboundary--635103678186870000")
    conn.putheader("Content-Length", str(len(body)))
    conn.endheaders()
    conn.send(body)
    errcode, errmsg, headers = conn.getreply()

    print headers

    f = conn.getfile()
    file_url = f.read()
    print "  [!] File URL : " + file_url
    return file_url

def cwrite(s, memId = [], msg = u'test'):
    print " [*] CWRITE to " + str(memId) + " : " + msg

    data = '\x06\x00\x00\x00' # Packet ID
    data += '\x00\x00' # Status Code : when sending command -> 0
    data += 'CWRITE\x00\x00\x00\x00\x00' # Method
    data += '\x00' # Body Type : when sending command -> 0

    body = BSON.encode({u'memberIds': memId, u'msg': msg, u'extra': None, u'pushAlert': True})

    data += body[:4]
    data += body

    succ = send(s, data)
    return succ

def enc_aes(data):
    iv = 'locoforever\x00\x00\x00\x00\x00'

    aes = AES.new(key=aes_key, mode=AES.MODE_CBC, IV=iv)

    pad_text = encoder.encode(data)

    cipher = aes.encrypt(pad_text)
    #enc_cipher = base64.b64encode(cipher)

    return cipher

def dec_aes(data):
    iv = '\x6c\x6f\x63\x6f\x66\x6f\x72\x65\x76\x65\x72\x00\x00\x00\x00\x00'

    aes = AES.new(key=aes_key, mode=AES.MODE_CBC, IV=iv)

    pad_text = aes.decrypt(data)

    plain_data = encoder.decode(pad_text)

    return pad_text

def dec_packet(data):
    #dec_body = dec_aes(data)
    dec_body=data
    packet = {}
    packet['num'] = hex_to_num(dec_body[:4])
    packet['status'] = dec_body[4:6]
    packet['command'] = dec_body[6:17].replace('\x00','')
    packet['body_type'] = dec_body[17:18]
    packet['body_len'] = hex_to_num(dec_body[18:22])
    packet['body'] = dec_bson(dec_body[22:packet['body_len']+22])
    return packet
 
def hex_to_dic(data):
    return BSON(b(data)).decode()
    
def dec_bson(data):
    (document, _) = bson._bson_to_dict(data, dict, True, bson.OLD_UUID_SUBTYPE)
    return document

def response(data):
    text = dec_aes(data)
    text[22:]

def hex_to_num(data):
    return struct.unpack('I',data)[0]
