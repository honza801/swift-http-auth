#!/usr/bin/env python3

import http.server
from socketserver import ThreadingMixIn
import configparser
from datetime import datetime, timedelta
import random
import logging

import subprocess
from subprocess import PIPE
import json

class Token(object):
    
    def __init__(self, user, prefix, length, lifetime, groups=[]):
        self.user = user
        delta = timedelta(hours=lifetime)
        self.expire_on = datetime.now() + delta
        self.token = self.generate_token(prefix, length)
        self.groups = groups
    
    def generate_token(self, prefix, length):
        charset = '0123456789abcdef'
        rtoken = ''.join([random.choice(charset) for x in range(length)])
        token = prefix + rtoken
        return token

    def valid(self):
        return datetime.now() <= self.expire_on

    def get_userid(self):
        user_id = self.user.split('@')[0]
        if '/' in user_id:
            user_id = user_id.split('/')[1]
        user_id = user_id.replace('.', '_')
        return user_id
    
    def get_user_realm(self):
        if '@' in self.user:
            realm = self.user.split('@')[1]
        else:
            realm = ''
        return realm
   
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

    def _new(self, remote_user):
        new_token = Token(
            remote_user,
            self.config['prefix'],
            self.config.getint('length'),
            self.config.getint('lifetime'))
        user_id = new_token.get_userid()
        user_realm = new_token.get_user_realm()
        new_token.groups = self._get_auth_groups(user_id, user_id, user_realm)
        self.tokens[remote_user] = new_token
        self.log.info('New token %s for %s' % (new_token, remote_user))
        return new_token
    
    def _get_auth_groups(self, tenant, user_id, realm):
        groups = []
        for grp in [ "{0}${1}:swift", "{0}${1}" ]:
            groups.append(grp.format(tenant, user_id))
        if realm in self.config['admin_realms'].split(','):
            groups.append('.reseller_admin')
        self.log.debug('Auth groups %s' % groups)
        return groups
    
    def get_valid_token(self, remote_user):
        token = self.tokens.get(remote_user)
        if not (token and token.valid()):
            return False
        return token
    
    def get_or_create(self, remote_user):
        token = self.get_valid_token(remote_user)
        if not token:
            token = self._new(remote_user)
        self.log.debug('Tokenizer get token for %s' % remote_user)
        return token

    def find(self, token_str):
        for remote_user in self.tokens:
            if str(self.tokens[remote_user]) == token_str:
                token = self.tokens[remote_user]
                self.log.debug('Token %s found, issued for %s with groups: %s' % (token, remote_user, token.groups))
                return token
        self.log.info('Token does not exist %s' % token_str)
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
    
    def touch_user(self, user_id):
        try:
            self.get_user_info(user_id, user_id)
            log.debug('User %s found' % user_id)
        except Exception:
            log.info('Creating user %s' % user_id)
            self.create_user(uid=user_id, display_name=user_id, tenant=user_id)
            subuser = "%s:swift" % user_id
            self.create_subuser(uid=user_id,
                               subuser=subuser,
                               tenant=user_id)

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

    def get_storage_url(self, token):
        storage_url = auth_config['storage_url']
        user_id = token.get_userid()
        if auth_config.getboolean('account_in_url'):
            if not storage_url.endswith('/'):
                storage_url += '/'
            storage_url += 'AUTH_%s' % user_id
        log.debug('Storage url for %s is %s' % (user_id, storage_url))
        return storage_url

    def forbidden(self):
        self.send_response(403)
        self.end_headers()
    
    def show_headers(self):
        for k in self.headers:
            log.debug('header %s: %s' % (k, self.headers.get(k)))
    
    def handle_auth(self, return_code=204):
        remote_user = self.headers.get('REMOTE_USER', '')
        if not remote_user:
            return self.forbidden()
        log.debug('Handle authenticated user %s' % remote_user)
        token = tokenizer.get_valid_token(remote_user)
        if not token:
            token = tokenizer.get_or_create(remote_user)
            rgw.touch_user(token.get_userid())
        self.send_response(return_code)
        self.send_header("X-Storage-Url", self.get_storage_url(token))
        self.send_header("X-Auth-Token", token)
        self.send_header("X-Storage-Token", token)
        self.end_headers()
        
    def get_token_from_url(self):
        parts = self.path.split('/', 3)
        token = parts[2]
        log.debug('Token from url %s' % token)
        return token

    def validate_token(self, return_code=200):
        token_req = self.get_token_from_url()
        token = tokenizer.find(token_req)
        if token:
            self.send_response(return_code)
            groups = ','.join(token.groups)
            self.send_header("X-Auth-Groups", groups)
            self.end_headers()
        else:
            log.debug('Valid token not found %s' % token_req)
            self.forbidden()

    def do_GET(self):
        if self.path == '/auth/1.0':
            self.handle_auth()
        elif self.path.startswith('/token'):
            self.validate_token()
        else:
            log.debug('Forbidden %s' % self.path)
            self.forbidden()

class ThreadedHTTPServer(ThreadingMixIn, http.server.HTTPServer):
    pass

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    log = logging.getLogger(__name__)

    config = configparser.ConfigParser()
    config.read('swift-http-auth.ini')

    rgw = RadosGWAdminLocal()
    tokenizer = Tokenizer(config['tokenizer'], log)
    httpd_config = (config['httpd']['host'], config.getint('httpd', 'port'))

    httpd = ThreadedHTTPServer(httpd_config, AuthHandler)
    httpd.RequestHandlerClass.set_logger(log)
    httpd.RequestHandlerClass.set_config(config['auth'])
    httpd.RequestHandlerClass.set_tokenizer(tokenizer)
    httpd.RequestHandlerClass.set_rgw(rgw)

    print(__name__, "serving at ", httpd_config)
    httpd.serve_forever()

