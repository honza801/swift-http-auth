#!/usr/bin/env python3

import http.server
import configparser
from datetime import datetime, timedelta
import random
import logging

from rgwadmin import *
from rgwadmin.exceptions import *


#logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger(__name__)

config = configparser.ConfigParser()
config.read('swift-http-auth.ini')

class Token(object):
    
    def __init__(self, user_id):
        self.user_id = user_id
        delta = timedelta(hours=config.getint('token', 'lifetime'))
        self.expire_on = datetime.now() + delta
        self.token = self.generate_token()
    
    def generate_token(self):
        charset = '0123456789abcdef'
        length = config.getint('token', 'length')
        rtoken = ''.join([random.choice(charset) for x in range(length)])
        token = config['token']['prefix'] + rtoken
        return token

    def valid(self):
        return datetime.now() <= self.expire_on

    def __str__(self):
        return self.token

class Tokenizer(object):
    
    def __init__(self):
        self.tokens = dict()

    def get(self, user_id):
        if user_id in self.tokens:
            if not self.tokens[user_id].valid():
                del(self.tokens[user_id])
                self.tokens[user_id] = Token(user_id)
        else:
            self.tokens[user_id] = Token(user_id)
        log.debug('Tokenizer get token for %s' % user_id)
        return self.tokens[user_id]

    def exists(self, token):
        for user_id in self.tokens:
            if str(self.tokens[user_id]) == token:
                log.debug('Token exists %s' % token)
                return self.tokens[user_id]
        log.debug('Token does not exist %s' % token)
        return False

rgw = RGWAdmin(access_key=config['rgw']['key'],
               secret_key=config['rgw']['secret'],
               server=config['rgw']['server'],
               secure=False)
tokenizer = Tokenizer()

class AuthHandler(http.server.BaseHTTPRequestHandler):
    
    def get_storage_url(self):
        return config['auth']['storage_url']

    def get_user_groups(self, user_id):
        groups ="{0}:swift,{0}".format(user_id) 
        log.debug('X-Auth-Groups %s' % groups)
        return groups
    
    def touch_user(self, user_id):
        try:
            rgw.get_user(user_id)
            log.debug('User %s found' % user_id)
        except NoSuchKey:
            log.debug('Creating user %s' % user_id)
            rgw.create_user(uid=user_id, display_name=user_id)
            subuser = "%s:swift" % user_id
            rgw.create_subuser(uid=user_id,
                               subuser=subuser,
                               key_type='swift',
                               access='full')
        
    def forbidden(self):
        self.send_response(403)
        self.end_headers()
    
    def get_remote_user(self):
        remote_user = self.headers.get('REMOTE_USER', '')
        return remote_user.split('@')[0]

    def show_headers(self):
        for k in self.headers:
            log.debug('header %s: %s' % (k, self.headers.get(k)))
    
    def handle_auth(self, return_code=204):
        user_id = self.get_remote_user()
        if not user_id:
            return self.forbidden()
        log.debug('Handle authenticated user %s' % user_id)
        self.touch_user(user_id)
        token = tokenizer.get(user_id)
        self.send_response(return_code)
        self.send_header("X-Storage-Url", self.get_storage_url())
        self.send_header("X-Auth-Token", token)
        self.send_header("X-Storage-Token", token)
        self.end_headers()
        
    def get_token_from_url(self):
        parts = self.path.split('/', 3)
        token = parts[2]
        log.debug('Token from url %s' % token)
        return token

    def validate_token(self, return_code=200):
        token = self.get_token_from_url()
        t = tokenizer.exists(token)
        if t:
            self.send_response(return_code)
            self.send_header("X-Auth-Groups", self.get_user_groups(t.user_id))
            self.end_headers()
        else:
            log.debug('Validate token not found %s' % token)
            self.forbidden()

    def do_GET(self):
        if self.path == '/auth/1.0':
            self.handle_auth()
        elif self.path.startswith('/token'):
            self.validate_token()
        else:
            log.debug('Forbidden %s' % self.path)
            self.forbidden()

httpd_config = (config['httpd']['host'], config.getint('httpd', 'port'))
httpd = http.server.HTTPServer(httpd_config, AuthHandler)
print(__name__, "serving at ", httpd_config)
httpd.serve_forever()

