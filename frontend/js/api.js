/**
 * Ethical Hacking Toolkit - API Functions
 * Handles communication with the backend API
 */

// Base URL for API endpoints
const API_BASE_URL = 'http://localhost:5000/api';

/**
 * Initialize API-related functionality
 */
function initAPI() {
    // You could set up global fetch handlers or interceptors here
    console.log('API handler initialized');
}

/**
 * Scan a network target for hosts and open ports
 * @param {string} target - IP address, hostname, or network range
 * @param {string} ports - Ports to scan (optional)
 * @returns {Promise} - Resolves with scan results
 */
async function scanNetwork(target, ports = '') {
    try {
        const response = await fetch(`${API_BASE_URL}/scan/network`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ target, ports })
        });
        
        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || 'Network scan failed');
        }
        
        return await response.json();
    } catch (error) {
        console.error('API Error:', error);
        throw error;
    }
}

/**
 * Scan a target for vulnerabilities
 * @param {string} target - IP address or hostname to scan
 * @returns {Promise} - Resolves with vulnerability scan results
 */
async function scanVulnerabilities(target) {
    try {
        const response = await fetch(`${API_BASE_URL}/scan/vulnerability`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ target })
        });
        
        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || 'Vulnerability scan failed');
        }
        
        return await response.json();
    } catch (error) {
        console.error('API Error:', error);
        throw error;
    }
}

/**
 * Attempt to crack a password hash
 * @param {string} hash - The hash to crack
 * @param {string} type - Hash type (md5, sha1, sha256, etc.)
 * @param {string} wordlist - Path to wordlist file (optional)
 * @returns {Promise} - Resolves with password cracking results
 */
async function crackPassword(hash, type = 'sha256', wordlist = '') {
    try {
        const response = await fetch(`${API_BASE_URL}/crack/password`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ 
                hash, 
                type, 
                wordlist: wordlist || undefined 
            })
        });
        
        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || 'Password cracking failed');
        }
        
        return await response.json();
    } catch (error) {
        console.error('API Error:', error);
        throw error;
    }
}

/**
 * Capture and analyze network packets
 * @param {string} interface - Network interface to use
 * @param {number} duration - Duration in seconds to capture
 * @param {string} filters - BPF filter string (optional)
 * @returns {Promise} - Resolves with packet capture results
 */
async function sniffPackets(interface, duration = 10, filters = '') {
    try {
        const response = await fetch(`${API_BASE_URL}/sniff/packets`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ 
                interface, 
                duration: parseInt(duration, 10), 
                filters 
            })
        });
        
        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || 'Packet sniffing failed');
        }
        
        return await response.json();
    } catch (error) {
        console.error('API Error:', error);
        throw error;
    }
}

/**
 * Fetch all stored scan results
 * @returns {Promise} - Resolves with all results
 */
async function fetchResults() {
    try {
        const response = await fetch(`${API_BASE_URL}/results`);
        
        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || 'Failed to fetch results');
        }
        
        return await response.json();
    } catch (error) {
        console.error('API Error:', error);
        throw error;
    }
}

/**
 * Fetch a specific scan result by ID
 * @param {string} scanId - The ID of the scan to fetch
 * @returns {Promise} - Resolves with the specific result
 */
async function fetchResult(scanId) {
    try {
        const response = await fetch(`${API_BASE_URL}/results/${scanId}`);
        
        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || 'Failed to fetch result');
        }
        
        return await response.json();
    } catch (error) {
        console.error('API Error:', error);
        throw error;
    }
}

/**
 * Fetch activity logs
 * @returns {Promise} - Resolves with logs data
 */
async function fetchLogs() {
    try {
        const response = await fetch(`${API_BASE_URL}/logs`);
        
        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || 'Failed to fetch logs');
        }
        
        return await response.json();
    } catch (error) {
        console.error('API Error:', error);
        throw error;
    }
} 