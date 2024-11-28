from flask import Flask, request, jsonify
from google.cloud import datastore
import requests
import json

app = Flask(__name__)
app.secret_key = 'SECRET_KEY'

client = datastore.Client()

@app.route('/')
def index():
    return "Please navigate to /lodgings to use this API"

@app.route('/test_datastore', methods=['GET'])
def test_datastore():
    # Create a new entity in the datastore
    key = client.key('TestEntity')
    entity = datastore.Entity(key=key)
    entity.update({
        'name': 'Test Name',
        'description': 'This is a test entity'
    })
    client.put(entity)
    return jsonify({"message": "Entity stored successfully"}), 200

@app.route('/view_entities', methods=['GET'])
def view_entities():
    query = client.query(kind='TestEntity')
    results = list(query.fetch())
    entities = []
    for entity in results:
        entities.append({
            'id': entity.key.id,
            'name': entity['name'],
            'description': entity['description']
        })
    return jsonify(entities), 200


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)