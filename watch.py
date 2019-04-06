import flask
from flask import request, jsonify, send_from_directory, abort
import os
import pymongo
from bson.objectid import ObjectId
import subprocess
import json
import yaml
import ninjadog
import os
import hashlib
import time
import flask_login
import random
import re
from flask_login import UserMixin, LoginManager, login_required

app = flask.Flask(__name__)
login = LoginManager(app)

port_regex = re.compile(r'\*:[0-9]+')

client = pymongo.MongoClient('localhost', 42932)
db = client['dockerserve']
collection = db['repositories']
users = db['users']

SERVER_PORT = 5000

PORT_POOL_START = 20000
PORT_POOL_END = 30000

MAX_PORT_ALLOCATION_TRIES = 300

if 'PORT_POOL_START' in os.environ.keys() and 'PORT_POOL_END' in os.environ.keys():
    PORT_POOL_START = os.environ['PORT_POOL_START']
    PORT_POOL_END = os.environ['PORT_POOL_END']

if 'MAX_PORT_ALLOCATION_TRIES' in os.environ.keys():
    MAX_PORT_ALLOCATION_TRIES = os.environ['MAX_PORT_ALLOCATION_TRIES']

if 'SERVER_PORT' in os.environ.keys():
    SERVER_PORT = int(os.environ['SERVER_PORT'])

DOCKERFILE = {}
ports = {
    'node': '3000',
    'flask': '5000'
}

platform_name = {
    'node': 'Node.js',
    'flask': 'Python Flask'
}

with open('Dockerfiles/Node', 'r') as fr:
    DOCKERFILE['node'] = fr.read()
with open('Dockerfiles/Python', 'r') as fr:
    DOCKERFILE['flask'] = fr.read()

class User:
    def __init__(self, user_id, passwd_hash=None, authenticated=False):
        self.user_id = user_id
        self.passwd_hash = passwd_hash
        self.authenticated = authenticated

    # ==========================================================================
    def __repr__(self):
        r = {
            'user_id': self.user_id,
            'passwd_hash': self.passwd_hash,
            'authenticated': self.authenticated,
        }
        return str(r)

    # ==========================================================================
    def can_login(self, passwd_hash):
        return self.passwd_hash == passwd_hash

    # ==========================================================================
    def is_active(self):
        return True

    # ==========================================================================
    def get_id(self):
        return self.user_id

    # ==========================================================================
    def is_authenticated(self):
        return self.authenticated

    # ==========================================================================
    def is_anonymous(self):
        return False

def run_with_exception(command, cwd=None):
    print('Executing', command.split(' '))
    proc = subprocess.Popen(command.split(' '), cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (out, err) = proc.communicate()
    print(out.decode('utf-8').strip())
    print(err.decode('utf-8').strip())
    print('Process exited with code', proc.returncode)
    if proc.returncode != 0:
        raise Exception(err)
    return out.decode('utf-8')

def int_to_bytes(x):
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')

def gensalt():
    h = hashlib.sha512()
    h.update(int_to_bytes(int(random.random() * (10**15))))
    h.update(int_to_bytes(int(random.random() * (10**15))))
    h.update(int_to_bytes(int(random.random() * (10**15))))
    h.update(int_to_bytes(int(random.random() * (10**15))))
    h.update(int_to_bytes(int(random.random() * (10**15))))
    return h.hexdigest()

app.secret_key = gensalt()

@login.user_loader
def user_loader(username):
    user = users.find_one({'username': username})
    if user == None:
        return
    return User(username, passwd_hash=user['password'])

@login.unauthorized_handler
def unauthorized_handler():
    return ninjadog.render(file='template/unauthorized.pug')

@app.route('/gh-hook', methods=['POST'])
def get_commit():
    repository_path = request.form['repository']['full_name']
    try:
        result = collection.find_one({'repopath', 'https://github.com/' + repository_path})
        if result == None:
            raise Exception('Repository not registered on dockerserve')

        update_server(result)
        return jsonify({
            'success': True
        })
    except Exception as e:
        print(e)
        return jsonify({
            'success': False,
            'reason': str(e)
        })

@app.route('/static/stylesheets/<path:path>')
def send_static_stylesheet(path):
    return send_from_directory('static/stylesheets', path)


@app.route('/static/javascripts/<path:path>')
def send_static_javascript(path):
    return send_from_directory('static/javascripts', path)


@app.route('/static/images/<path:path>')
def send_static_image(path):
    return send_from_directory('static/images', path)


@app.route('/', methods=['GET'])
@flask_login.login_required
def home():
    return ninjadog.render(file='template/home.pug')

@app.route('/watches', methods=['GET'])
@flask_login.login_required
def watches_render():
    servers = get_servers()
    print(servers)
    return ninjadog.render(file='template/watches.pug', context={
        'servers': servers
    })

@app.route('/watches/<id>', methods=['GET'])
@flask_login.login_required
def get_watch_render(id):
    print(id)
    result = collection.find_one({'_id': ObjectId(id), 'user': flask_login.current_user.user_id})
    result['target'] = platform_name[result['target']]
    print(result)
    return ninjadog.render(file='template/watchinfo.pug', context={
        'server': result
    })

@app.route('/login', methods=['GET'])
def login_render():
    return ninjadog.render(file='template/login.pug')

@app.route('/logout')
def logout():
    flask_login.logout_user()
    return flask.redirect('/login')

@app.route('/watches/new', methods=['GET'])
@flask_login.login_required
def watches_new_render():
    return ninjadog.render(file='template/newserver.pug')

@app.route('/api/login', methods=['POST'])
def process_login(): 
    body = request.get_json()
    user_info = users.find_one({ 'username': body['username'] })
    if user_info == None:
        return jsonify({
            'success': False
        })
    hashed = hashlib.sha512((body['password'] + user_info['salt']).encode()).hexdigest()
    if hashed == user_info['password']:
        user = User(user_info['username'], passwd_hash=user_info['password'], authenticated=True)
        flask_login.login_user(user)
        return jsonify({
            'success': True
        })
    else:
        return jsonify({
            'success': False  
        })

@app.route('/api/logout', methods=['POST'])
@flask_login.login_required
def do_logout():
    flask_login.logout_user()
    return jsonify({
        'success': True
    })



@app.route('/api/watches', methods=['GET', 'POST'])
@flask_login.login_required
def watches():
    try:
        if request.method == 'GET':
            return jsonify({
                'success': True,
                'data': get_servers()
            })
        else:
            return create_server()
    except Exception as e:
        print(e)
        return jsonify({
            'success': False,
            'reason': str(e)
        })


@app.route('/api/watches/<id>', methods=['GET', 'PUT', 'DELETE'])
@flask_login.login_required
def watch(id):
    try:
        if request.method == 'GET':
            result = collection.find_one({'_id': ObjectId(id), 'user': flask_login.current_user.user_id})
            if result != None:
                return jsonify({
                    'success': True,
                    'data': result
                })
            else:
                return jsonify({
                    'success': False,
                    'reason': 'No such data'
                })
        if request.method == 'DELETE':
            result = collection.find_one({'_id': ObjectId(id), 'user': flask_login.current_user.user_id})
            if result == None:
                raise Exception('No such item')
            stop_container(result)
            delete_container(result)
            delete_image(result)
            collection.delete_one(result)

            return jsonify({
                'success': True
            })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })      
    return ''


@app.route('/api/watches/<id>/update', methods=['POST'])
@flask_login.login_required
def force_update(id):
    try:
        result = collection.find_one({'_id': ObjectId(id), 'user': flask_login.current_user.user_id})
        if result != None:
            update_server(result)
            return jsonify({
                'success': True
            })
        else:
            raise Exception('No such data')
    except Exception as e:
        print(e)
        return jsonify({
            'success': False,
            'reason': str(e)
        })

@app.route('/api/newuser', methods=['POST'])
def new_user():
    if request.remote_addr != '127.0.0.1':
        abort(403)
    body = request.get_json()
    is_existing = users.find_one({'username': body['username']})
    if is_existing != None:
        return jsonify({
            'success': False,
            'reason': 'Username already registered'
        })
    
    salt = gensalt()
    h = hashlib.sha512((body['password'] + salt).encode('utf-8')).hexdigest()

    users.insert_one({
        'username': body['username'],
        'password': h,
        'salt': salt
    })

    return jsonify({
        'success': True
    })

def list_of_open_ports():
    output = run_with_exception('lsof -iTCP -sTCP:LISTEN')
    opened_ports = []
    for line in output:
        m = port_regex.search(line)
        if m != None:
            port_annotation = m.group()
            opened_ports.append(int(port_annotation[2:]))
    return opened_ports

def allocate_port():
    opened_ports = list_of_open_ports()
    tries = 0
    while True:
        tries += 1
        p = random.randint(PORT_POOL_START, PORT_POOL_END)
        if p not in opened_ports:
            return p
        if tries > MAX_PORT_ALLOCATION_TRIES:
            raise Exception('Port allocation timeout')

def get_servers():
    watches = []
    for doc in collection.find({}):
        doc['_id'] = str(doc['_id'])
        doc['target'] = platform_name[doc['target']]
        watches.append(doc)
    return watches

def create_server():
    try:
        post_body = request.get_json()
        post_body['port'] = allocate_port()

        h = hashlib.sha1()
        h.update(int_to_bytes(int(time.time() * 1000)))

        post_body['_id'] = h.hexdigest()

        repository_path = post_body['repopath']
        repository_name = repository_path.split('/')[-1]


        h = hashlib.sha1()
        h.update(post_body['repopath'].encode('utf-8'))
        h.update(int_to_bytes(int(time.time() * 1000)))
        post_body['image_name'] = repository_name + '-' + h.hexdigest()
            
        print(post_body)
        update_image(post_body)
        start_container(post_body)
        
        data = collection.insert_one({
            'name': post_body['name'],
            'target': post_body['target'],
            'port': post_body['port'],
            'environment': post_body['environment'],
            'repopath': post_body['repopath'],
            'image_name': post_body['image_name'],
            'user': flask_login.current_user.user_id
        })
        return jsonify({
            'success': True,
            'data': str(data.inserted_id)
        })
    except Exception as e:
        print(e)
        return jsonify({
            'success': False,
            'reason': str(e)
        })
    pass


def update_server(server_info):
    stop_container(server_info)
    update_image(server_info)
    start_container(server_info)

def update_image(server_info):
    repository_path = server_info['repopath']
    repository_name = repository_path.split('/')[-1]
    image_name = server_info['image_name']

    output = run_with_exception('rm -rf {}'.format(image_name))
    output = run_with_exception('git clone {} {}'.format(repository_path, image_name))

    Dockerfile = DOCKERFILE[server_info['target']]

    with open('{}/Dockerfile'.format(image_name), 'w') as fw:
        fw.write(Dockerfile)
    
    output = run_with_exception('docker build .', cwd=image_name)
    image_id = output.strip().split('\n')[-1].replace('Successfully built ', '').strip()

    output = run_with_exception('docker tag {} {}'.format(image_id, image_name),  cwd=image_name)
    output = run_with_exception('rm -rf {}'.format(image_name))

def delete_image(server_info):
    repository_path = server_info['repopath']
    image_name = server_info['image_name']
    
    output = run_with_exception('docker image rm {}'.format(image_name))


def stop_container(server_info):
    image_name = server_info['image_name']
    for container_id in parse_container_by_image_name(image_name):
        output = run_with_exception('docker stop {}'.format(container_id))

def start_container(server_info):
    repository_path = server_info['repopath']
    repository_name = repository_path.split('/')[-1]
    container_name = repository_name + str(server_info['_id'])
    image_name = server_info['image_name']
    port = server_info['port']
    target = server_info['target']
    environment = server_info['environment']

    if environment != None and len(environment) > 0:
        cmd = 'docker run -d --name {} -p {}:{} {} {}'.format(container_name, port, ports[target], ' '.join(envvars), image_name)
        envvars = list(map(lambda x: '--env ' + x.strip(), environment.split(';')))
    else:
        cmd = 'docker run -d --name {} -p {}:{} {}'.format(container_name, port, ports[target], image_name)
    output = run_with_exception(cmd)

def delete_container(server_info):
    repository_path = server_info['repopath']
    image_name = server_info['image_name']

    for container_id in parse_container_by_image_name(image_name):
        output = run_with_exception('docker rm {}'.format(container_id))

def parse_container_by_image_name(image_name):
    cmd = 'docker ps -a --format {{.ID}} --filter ancestor=' + image_name
    output = run_with_exception(cmd)
    return output.strip().split('\n')

    output = run_with_exception('docker rm {}'.format(image_name))
if __name__ == "__main__":
    print('Dockerwatcher server is now running on port {}.'.format(SERVER_PORT))
    print('Dockerwatcher user can be created by POSTing to /api/newuser on localhost. POST body should be formed like {"username": "YOURUSER", "password": "YOURPASSWORD"}.')
    app.run('0.0.0.0', port=SERVER_PORT)

