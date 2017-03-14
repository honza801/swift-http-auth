#!/usr/bin/env python3

import http.server
import configparser
from datetime import datetime, timedelta
import random
import logging

import subprocess
from subprocess import PIPE
import json

class Token(object):
    
    def __init__(self, user_id, prefix, length, lifetime):
        self.user_id = user_id
        delta = timedelta(hours=lifetime)
        self.expire_on = datetime.now() + delta
        self.token = self.generate_token(prefix, length)
    
    def generate_token(self, prefix, length):
        charset = '0123456789abcdef'
        rtoken = ''.join([random.choice(charset) for x in range(length)])
        token = prefix + rtoken
        return token

    def valid(self):
        return datetime.now() <= self.expire_on

    def __str__(self):
        return self.token

class Tokenizer(object):
    
    def __init__(self, config, log=None):
        self.tokens = dict()
        self.config = config
        if log:
            self.log = log
        else:
            self.log = logging.getLogger(__name__)

    def _new(self, user_id):
        self.tokens[user_id] = Token(
            user_id,
            self.config['prefix'],
            self.config.getint('length'),
            self.config.getint('lifetime'))
        return self.tokens[user_id]

    def get_or_create(self, user_id):
        token = self.tokens.get(user_id)
        if token:
            if not token.valid():
                self.log.debug('Token for %s invalid, renewing' % user_id)
                token = self._new(user_id)
        else:
            token = self._new(user_id)
        self.log.debug('Tokenizer get token for %s' % user_id)
        return token

    def exists(self, token):
        for user_id in self.tokens:
            if str(self.tokens[user_id]) == token:
                self.log.debug('Token exists %s' % token)
                return self.tokens[user_id]
        self.log.debug('Token does not exist %s' % token)
        return False

class RadosGWAdminLocal:

    def __init__(self, rgw_binary='/usr/bin/radosgw-admin'):
        self.rgw_binary = rgw_binary

    def _call(self, action, subaction, params):
        cmd = [ self.rgw_binary, "--rgw-cache-enabled=false", action, subaction ]
        for p in params.keys():
            cmd.append('--%s=%s' % (p, params[p]))
        proc = subprocess.Popen(cmd, stdout=PIPE, stderr=PIPE)
        (stdout, stderr) = proc.communicate()
        if proc.returncode == 0:
            return json.loads(str(stdout, 'utf-8'))
        else:
            raise Exception("RadosGWAdminLocal: Err: Cmd '%s' exited with '%s' (%d)"
                % (' '.join(cmd), str(stderr, 'utf-8'), proc.returncode))

    def get_user_info(self, uid, tenant=None):
        params = {
            'uid' : uid,
        }
        if tenant:
            params['uid'] = "%s$%s" % (tenant, uid)
        return self._call('user', 'info', params)

    def create_user(self, uid, display_name, email=None, tenant=None):
        params = {
            'uid': uid,
            'display-name': display_name,
        }
        if email:
            params['email'] = email
        if tenant:
            params['tenant'] = tenant
        return self._call('user', 'create', params)

    def create_subuser(self, uid, subuser, access='full', key_type = None, tenant=None):
        params = {
            'uid' : uid,
            'subuser': subuser,
            'access': access,
        }
        if tenant:
            params['uid'] = "%s$%s" % (tenant, uid)
            params['subuser'] = "%s$%s" % (tenant, subuser)
        if key_type:
            params['key-type'] = key_type
        return self._call('subuser', 'create', params)

class AuthHandler(http.server.BaseHTTPRequestHandler):
    
    def set_tokenizer(tokenizer):
        tokenizer = tokenizer

    def set_rgw(rgw):
        rgw = rgw

    def set_config(config):
        global auth_config
        auth_config = config

    def set_logger(log):
        if log:
            log = log
        else:
            log = logging.getLogger(__main__)

    def get_storage_url(self, user_id=''):
        storage_url = auth_config['storage_url']
        if auth_config.getboolean('account_in_url'):
            if storage_url.endswith('/'):
                storage_url += 'AUTH_%s' % user_id
            else:
                storage_url += '/AUTH_%s' % user_id
        return storage_url

    def get_user_groups(self, user_id, tenant):
        groups ="{0}${1}:swift,{0}${1}".format(tenant, user_id)
        log.debug('X-Auth-Groups %s' % groups)
        return groups
    
    def touch_user(self, user_id):
        try:
            rgw.get_user_info(user_id, user_id)
            log.debug('User %s found' % user_id)
        except Exception:
            log.debug('Creating user %s' % user_id)
            rgw.create_user(uid=user_id, display_name=user_id, tenant=user_id)
            subuser = "%s:swift" % user_id
            rgw.create_subuser(uid=user_id,
                               subuser=subuser,
                               tenant=user_id)
        
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
        token = tokenizer.get_or_create(user_id)
        self.send_response(return_code)
        self.send_header("X-Storage-Url", self.get_storage_url(user_id))
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
            self.send_header("X-Auth-Groups", self.get_user_groups(t.user_id, t.user_id))
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

if __name__ == '__main__':
    #logging.basicConfig(level=logging.DEBUG)
    log = logging.getLogger(__name__)

    config = configparser.ConfigParser()
    config.read('swift-http-auth.ini')

    rgw = RadosGWAdminLocal()
    tokenizer = Tokenizer(config['token'], log)
    httpd_config = (config['httpd']['host'], config.getint('httpd', 'port'))

    httpd = http.server.HTTPServer(httpd_config, AuthHandler)
    httpd.RequestHandlerClass.set_logger(log)
    httpd.RequestHandlerClass.set_config(config['auth'])
    httpd.RequestHandlerClass.set_tokenizer(tokenizer)
    httpd.RequestHandlerClass.set_rgw(rgw)

    print(__name__, "serving at ", httpd_config)
    httpd.serve_forever()

