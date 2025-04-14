from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os
import json
import logging
from datetime import datetime

# Import tool modules
from tools.network_scanner import scan_network
from tools.vulnerability_scanner import scan_vulnerabilities
from tools.password_cracker import crack_password
from tools.packet_sniffer import sniff_packets

app = Flask(__name__, static_folder='../frontend')
CORS(app)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='activity.log'
)
logger = logging.getLogger(__name__)

# In-memory storage for results (in a production app, use a database)
scan_results = {}

# Serve frontend files
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_frontend(path):
    if path != "" and os.path.exists(os.path.join(app.static_folder, path)):
        return send_from_directory(app.static_folder, path)
    else:
        return send_from_directory(app.static_folder, 'index.html')

@app.route('/api/scan/network', methods=['POST'])
def api_network_scan():
    data = request.json
    target = data.get('target')
    ports = data.get('ports')
    
    if not target:
        return jsonify({"error": "Target IP or range is required"}), 400
    
    try:
        logger.info(f"Starting network scan on {target} with ports {ports}")
        results = scan_network(target, ports)
        scan_id = datetime.now().strftime("%Y%m%d%H%M%S")
        scan_results[scan_id] = {
            "type": "network_scan",
            "timestamp": datetime.now().isoformat(),
            "target": target,
            "results": results
        }
        return jsonify({"scan_id": scan_id, "results": results})
    except Exception as e:
        logger.error(f"Network scan error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/scan/vulnerability', methods=['POST'])
def api_vulnerability_scan():
    data = request.json
    target = data.get('target')
    
    if not target:
        return jsonify({"error": "Target is required"}), 400
    
    try:
        logger.info(f"Starting vulnerability scan on {target}")
        results = scan_vulnerabilities(target)
        scan_id = datetime.now().strftime("%Y%m%d%H%M%S")
        scan_results[scan_id] = {
            "type": "vulnerability_scan",
            "timestamp": datetime.now().isoformat(),
            "target": target,
            "results": results
        }
        return jsonify({"scan_id": scan_id, "results": results})
    except Exception as e:
        logger.error(f"Vulnerability scan error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/crack/password', methods=['POST'])
def api_password_crack():
    data = request.json
    hash_value = data.get('hash')
    hash_type = data.get('type')
    wordlist = data.get('wordlist')
    
    if not hash_value:
        return jsonify({"error": "Hash value is required"}), 400
    
    try:
        logger.info(f"Starting password cracking for hash of type {hash_type}")
        results = crack_password(hash_value, hash_type, wordlist)
        scan_id = datetime.now().strftime("%Y%m%d%H%M%S")
        scan_results[scan_id] = {
            "type": "password_crack",
            "timestamp": datetime.now().isoformat(),
            "hash_type": hash_type,
            "results": results
        }
        return jsonify({"scan_id": scan_id, "results": results})
    except Exception as e:
        logger.error(f"Password cracking error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/sniff/packets', methods=['POST'])
def api_packet_sniff():
    data = request.json
    interface = data.get('interface')
    duration = data.get('duration', 10)  # Default 10 seconds
    filters = data.get('filters', '')
    
    if not interface:
        return jsonify({"error": "Network interface is required"}), 400
    
    try:
        logger.info(f"Starting packet sniffing on {interface} for {duration} seconds")
        results = sniff_packets(interface, duration, filters)
        scan_id = datetime.now().strftime("%Y%m%d%H%M%S")
        scan_results[scan_id] = {
            "type": "packet_sniff",
            "timestamp": datetime.now().isoformat(),
            "interface": interface,
            "results": results
        }
        return jsonify({"scan_id": scan_id, "results": results})
    except Exception as e:
        logger.error(f"Packet sniffing error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/results', methods=['GET'])
def get_results():
    return jsonify(scan_results)

@app.route('/api/results/<scan_id>', methods=['GET'])
def get_result(scan_id):
    if scan_id in scan_results:
        return jsonify(scan_results[scan_id])
    return jsonify({"error": "Scan result not found"}), 404

@app.route('/api/logs', methods=['GET'])
def get_logs():
    try:
        with open('activity.log', 'r') as f:
            logs = f.readlines()
        return jsonify({"logs": logs})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    # Create directory for tools if it doesn't exist
    os.makedirs('tools', exist_ok=True)
    
    # Default port is 5000
    app.run(debug=True, host='0.0.0.0')