#!/usr/bin/env python3
"""
Simple Redis UI using Flask
Run this file to access a web-based Redis interface
"""

from flask import Flask, render_template_string, request, redirect, url_for, jsonify
import redis
import json
from datetime import datetime
import os

app = Flask(__name__)

# Redis connection
redis_client = redis.Redis(
    host=os.getenv('REDIS_HOST', 'localhost'),
    port=int(os.getenv('REDIS_PORT', 6379)),
    db=int(os.getenv('REDIS_DB', 0)),
    decode_responses=True
)

# HTML template
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Redis UI - GymOps</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { background: #2c3e50; color: white; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .key-item { background: #ecf0f1; margin: 10px 0; padding: 15px; border-radius: 5px; border-left: 4px solid #3498db; }
        .key-name { font-weight: bold; color: #2c3e50; font-size: 16px; }
        .key-value { background: #f8f9fa; padding: 10px; border-radius: 3px; margin: 10px 0; font-family: monospace; white-space: pre-wrap; }
        .ttl-info { color: #7f8c8d; font-size: 12px; }
        .delete-btn { background: #e74c3c; color: white; border: none; padding: 5px 10px; border-radius: 3px; cursor: pointer; }
        .refresh-btn { background: #27ae60; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; margin-bottom: 20px; }
        .stats { background: #e8f5e8; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔴 Redis UI - GymOps</h1>
            <p>Manage your Redis database and view JWT tokens</p>
        </div>
        
        <div class="stats">
            <h3>📊 Redis Statistics</h3>
            <p><strong>Total Keys:</strong> {{ total_keys }}</p>
            <p><strong>Database:</strong> {{ db_number }}</p>
            <p><strong>Connected:</strong> {{ connected }}</p>
        </div>
        
        <button class="refresh-btn" onclick="location.reload()">🔄 Refresh Data</button>
        
        <h2>🔑 Redis Keys</h2>
        {% for key in keys %}
        <div class="key-item">
            <div class="key-name">{{ key.name }}</div>
            <div class="ttl-info">TTL: {{ key.ttl }} seconds | Type: {{ key.type }}</div>
            <div class="key-value">{{ key.value }}</div>
            <button class="delete-btn" onclick="deleteKey('{{ key.name }}')">🗑️ Delete</button>
        </div>
        {% endfor %}
        
        {% if not keys %}
        <p>No keys found in Redis database.</p>
        {% endif %}
    </div>
    
    <script>
        function deleteKey(keyName) {
            if (confirm('Are you sure you want to delete key: ' + keyName + '?')) {
                fetch('/delete_key', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({key: keyName})
                }).then(() => location.reload());
            }
        }
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    try:
        # Test connection
        redis_client.ping()
        connected = "✅ Connected"
        
        # Get all keys
        keys = []
        for key_name in redis_client.keys('*'):
            try:
                key_type = redis_client.type(key_name)
                ttl = redis_client.ttl(key_name)
                value = redis_client.get(key_name)
                
                # Try to format JSON if it's a string
                if value and value.startswith('{'):
                    try:
                        parsed = json.loads(value)
                        value = json.dumps(parsed, indent=2)
                    except:
                        pass
                
                keys.append({
                    'name': key_name,
                    'type': key_type,
                    'ttl': ttl,
                    'value': value
                })
            except Exception as e:
                keys.append({
                    'name': key_name,
                    'type': 'error',
                    'ttl': 'N/A',
                    'value': f'Error reading key: {str(e)}'
                })
        
        total_keys = len(keys)
        db_number = redis_client.connection_pool.connection_kwargs.get('db', 0)
        
    except Exception as e:
        connected = f"❌ Error: {str(e)}"
        keys = []
        total_keys = 0
        db_number = 0
    
    return render_template_string(HTML_TEMPLATE, 
                                keys=keys, 
                                total_keys=total_keys, 
                                db_number=db_number, 
                                connected=connected)

@app.route('/delete_key', methods=['POST'])
def delete_key():
    try:
        data = request.get_json()
        key_name = data.get('key')
        if key_name:
            redis_client.delete(key_name)
            return jsonify({'success': True, 'message': f'Key {key_name} deleted'})
        return jsonify({'success': False, 'message': 'No key provided'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

if __name__ == '__main__':
    print("🚀 Starting Redis UI...")
    print("📱 Open your browser and go to: http://localhost:5000")
    print("🔴 Make sure Redis is running on localhost:6379")
    app.run(debug=True, host='0.0.0.0', port=5000) 