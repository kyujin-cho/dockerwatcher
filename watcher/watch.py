import flask
from flask import request, jsonify
from kubernetes import client, config
import os
import pymysql
import pymysql.cursors
import subprocess
import json
import yaml
app = flask.Flask(__name__)

core = client.CoreV1Api()
apps = client.AppsV1beta1Api()

db = pymysql.connect(host=os.environ['DB_HOST'],
                     user=os.environ['DB_USER'],
                     password=os.environ['DB_PASS'],
                     db='kubeserver',
                     charset='utf8mb4',
                     cursorclass=pymysql.cursors.DictCursor)


DOCKERFILE = {}


with open('Dockerfiles/Node', 'r') as fr:
    DOCKERFILE['node'] = fr.read()
with open('Dockerfiles/Python', 'r') as fr:
    DOCKERFILE['python'] = fr.read()
with open('Kubernetes/patch.json', 'r') as fr:
    KUBEPATCH = json.loads(fr.read())


@app.route('/hook', methods=['POST'])
def get_commit():
    repository_id = request.form['repository']['id']
    repository_path = request.form['repository']['full_name']
    repository_hash = request.form['head']
    try:
        with db.cursor() as cursor:
            sql = 'SELECT * FROM repositories WHERE id=?'
            cursor.execute(sql, (repository_id,))
            result = cursor.fetchone()

        if result == None:
            raise Exception('Repository not registered on kubeserver')

        update_server(repository_id, repository_path, repository_hash, result)
    except Exception as e:
        return jsonify({
            'success': False,
            'reason': e
        })


@app.route('/', methods=['GET'])
def home():
    return ''


@app.route('/api/watches', methods=['GET', 'POST'])
def watches():
    if request.method == 'GET':
        return get_servers()
    else:
        return create_server()


@app.route('/api/watches/<id>', methods=['GET', 'PUT', 'DELETE'])
def watch():
    return ''


@app.route('/api/watches/<id>/update', methods=['POST'])
def force_update():
    return ''


def get_servers():
    pass


def create_server():
    try:
        repository_path = request.form['repopath']
        update_image(request.form)
        repository_name = repository_path.split('/')[-1]

        envvars = list(map(lambda x: client.V1EnvVar(name=x.strip().split('=')[0],
                                                     value=x.strip().split('=')[1]), request.form['environment'].split(';')))

        metadata = client.V1ObjectMeta()
        metadata.labels = {'service': repository_path + '-service'}
        metadata.name = repository_path + '-name'
        metadata.namespace = 'kubeserver'

        spec_template_metadata = client.V1ObjectMeta()
        spec_template_metadata.labels = {'name': repository_path + '-selector'}

        container = client.V1Container()
        container.env = envvars
        container.image = os.environ['REGISTRY'] + '/' + repository_name
        container.name = repository_path + '-container'
        container.ports = [
            client.V1ContainerPort(
                container_port=request.form['port'], name=repository_path + '-port')
        ]

        container_resources = client.V1ResourceRequirements()
        container_resources.limits = {'cpu': '500m', 'memory': '256Mi'}
        container_resources.requests = {'cpu': '250m', 'memory': '128Mi'}
        container.resources = container_resources

        spec_template_spec = client.V1PodSpec()
        spec_template_spec.containers = [container]

        spec_template = client.V1PodTemplateSpec()
        spec_template.metadata = spec_template_metadata
        spec_template.spec = spec_template_spec

        spec = client.AppsV1beta1DeploymentSpec()
        spec.template = spec_template

        deployment = client.AppsV1beta1Deployment()
        deployment.metadata = metadata
        deployment.spec = spec

        api_response = apps.create_namespaced_deployment(
            'kubeserver', deployment, pretty='pretty')

        with db.cursor() as cursor:
            sql = 'INSERT INTO repositories VALUES (?, ?, ?, ?, ?)'
            cursor.execute(sql, ('0', request.form['target'], request.form['port'],
                                 request.form['environment'], request.form['repopath']))
        return jsonify({
            'success': True
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'reason': e
        })
    pass


def update_server(repository_id, repository_path, repository_hash, server_info):
    update_image(server_info)

    envvars = list(
        map(lambda x: {'name': x.strip().split('=')[0], 'value': x.strip().split('=')[1]}, server_info['environment'].split(';')))
    envvars.append('REPO_VER', repository_hash)
    body = [{'op': 'replace', 'value': envvars,
             'path': '/spec/template/spec/conainers/env'}]

    api_response = apps.patch_namespaced_deployment(
        repository_path, 'kubeserver', body, pretty='true')
    return jsonify({
        'success': True
    })


def update_image(server_info):
    repository_path = server_info['repopath']
    repository_name = repository_path.split('/')[-1]
    proc = subprocess.Popen('git clone https://github.com/{} {}'.format(
        repository_path, repository_name), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (out, err) = proc.communicate()
    if len(err) > 0:
        raise Exception(err)

    Dockerfile = DOCKERFILE[server_info['target']].format(server_info['port'])

    with open('{}/Dockerfile', 'w') as fw:
        fw.write(Dockerfile)

    proc = subprocess.Popen('docker build .', cwd=repository_name,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (out, err) = proc.communicate()
    if len(err) > 0:
        raise Exception(err)
    image_id = out.split('\n')[-1].replace('Successfully built ').strip()

    proc = subprocess.Popen('docker tag {} {}/{}'.format(image_id,
                                                         os.environ['REGISTRY'], repository_name), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (out, err) = proc.communicate()
    if len(err) > 0:
        raise Exception(err)

    proc = subprocess.Popen('docker push {}/{}'.format(
        os.environ['REGISTRY'], repository_name), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (out, err) = proc.communicate()
    if len(err) > 0:
        raise Exception(err)
