/**
 * Ethical Hacking Toolkit - UI Components and Display Functions
 */

/**
 * Initialize UI components
 */
function initUI() {
    // Initialize modal functionality
    const modal = document.getElementById('alert-modal');
    const closeModal = document.querySelector('.close-modal');
    const modalCloseBtn = document.getElementById('modal-close-btn');
    
    closeModal.addEventListener('click', () => {
        modal.style.display = 'none';
    });
    
    modalCloseBtn.addEventListener('click', () => {
        modal.style.display = 'none';
    });
    
    window.addEventListener('click', (event) => {
        if (event.target === modal) {
            modal.style.display = 'none';
        }
    });
}

/**
 * Show the loading overlay with a custom message
 * @param {string} message - Message to display during loading
 */
function showLoadingOverlay(message = 'Processing...') {
    const overlay = document.getElementById('loading-overlay');
    const loadingMessage = document.getElementById('loading-message');
    
    loadingMessage.textContent = message;
    overlay.style.display = 'flex';
}

/**
 * Hide the loading overlay
 */
function hideLoadingOverlay() {
    document.getElementById('loading-overlay').style.display = 'none';
}

/**
 * Show an alert modal with a title and message
 * @param {string} title - Alert title
 * @param {string} message - Alert message
 */
function showAlert(title, message) {
    const modal = document.getElementById('alert-modal');
    const modalTitle = document.getElementById('modal-title');
    const modalMessage = document.getElementById('modal-message');
    
    modalTitle.textContent = title;
    modalMessage.textContent = message;
    
    modal.style.display = 'flex';
}

/**
 * Display network scan results
 * @param {Object} results - Network scan results from the API
 */
function displayNetworkScanResults(results) {
    const resultsContainer = document.getElementById('network-scan-results');
    
    if (!results || !results.results) {
        resultsContainer.innerHTML = '<p class="no-results">No scan results available</p>';
        return;
    }
    
    const scanResults = results.results;
    const hosts = scanResults.hosts || [];
    
    let html = '<div class="scan-summary">';
    html += `<p>Total Hosts: <strong>${scanResults.total_hosts}</strong></p>`;
    html += `<p>Hosts Up: <strong>${scanResults.up_hosts}</strong></p>`;
    html += `<p>Scan Time: <strong>${scanResults.scan_time} seconds</strong></p>`;
    html += '</div>';
    
    if (hosts.length === 0) {
        html += '<p>No hosts were found in the scan.</p>';
    } else {
        html += '<div class="hosts-container">';
        
        hosts.forEach(host => {
            html += `<div class="host-item">`;
            html += `<h4>${host.ip} ${host.hostname ? `(${host.hostname})` : ''}</h4>`;
            html += `<p>Status: <span class="text-success">${host.status}</span></p>`;
            html += `<p>MAC: ${host.mac_address}</p>`;
            html += `<p>OS: ${host.os}</p>`;
            
            if (host.ports && host.ports.length > 0) {
                html += '<div class="ports-table">';
                html += '<table>';
                html += '<thead><tr><th>Port</th><th>State</th><th>Service</th><th>Version</th></tr></thead>';
                html += '<tbody>';
                
                host.ports.forEach(port => {
                    const stateClass = port.state === 'open' ? 'text-success' : 
                                      (port.state === 'filtered' ? 'text-warning' : 'text-danger');
                    
                    html += `<tr>`;
                    html += `<td>${port.port}</td>`;
                    html += `<td class="${stateClass}">${port.state}</td>`;
                    html += `<td>${port.service}</td>`;
                    html += `<td>${port.version}</td>`;
                    html += `</tr>`;
                });
                
                html += '</tbody></table></div>';
            } else {
                html += '<p>No open ports found</p>';
            }
            
            html += '</div>';
        });
        
        html += '</div>';
    }
    
    resultsContainer.innerHTML = html;
}

/**
 * Display vulnerability scan results
 * @param {Object} results - Vulnerability scan results from the API
 */
function displayVulnerabilityScanResults(results) {
    const resultsContainer = document.getElementById('vulnerability-scan-results');
    
    if (!results || !results.results) {
        resultsContainer.innerHTML = '<p class="no-results">No vulnerability scan results available</p>';
        return;
    }
    
    const scanResults = results.results;
    const vulnerabilities = scanResults.vulnerabilities || [];
    
    let html = '<div class="scan-summary">';
    html += `<p>Target: <strong>${scanResults.target}</strong></p>`;
    html += `<p>Scan Time: <strong>${scanResults.scan_time} seconds</strong></p>`;
    html += `<p>Vulnerabilities Found: <strong>${vulnerabilities.length}</strong></p>`;
    html += '</div>';
    
    if (vulnerabilities.length === 0) {
        html += '<p>No vulnerabilities were found in the scan.</p>';
    } else {
        html += '<div class="vulnerabilities-container">';
        
        // Group vulnerabilities by severity
        const groupedVulns = {
            'Critical': [],
            'High': [],
            'Medium': [],
            'Low': []
        };
        
        vulnerabilities.forEach(vuln => {
            if (groupedVulns[vuln.severity]) {
                groupedVulns[vuln.severity].push(vuln);
            } else {
                groupedVulns['Medium'].push(vuln);
            }
        });
        
        // Display vulnerabilities by severity group
        ['Critical', 'High', 'Medium', 'Low'].forEach(severity => {
            const vulns = groupedVulns[severity];
            if (vulns.length > 0) {
                const severityClass = severity === 'Critical' ? 'text-danger' : 
                                     (severity === 'High' ? 'text-warning' : 
                                     (severity === 'Low' ? 'text-success' : ''));
                
                html += `<div class="vulnerability-group">`;
                html += `<h4 class="${severityClass}">${severity} Severity (${vulns.length})</h4>`;
                
                vulns.forEach(vuln => {
                    html += `<div class="vulnerability-item">`;
                    html += `<h5>${vuln.name}</h5>`;
                    html += `<p>Port: ${vuln.port} (${vuln.service})</p>`;
                    
                    if (vuln.cve_ids && vuln.cve_ids.length > 0) {
                        html += '<p>CVE IDs: ';
                        vuln.cve_ids.forEach((cve, index) => {
                            html += `<a href="https://nvd.nist.gov/vuln/detail/${cve}" target="_blank">${cve}</a>`;
                            if (index < vuln.cve_ids.length - 1) html += ', ';
                        });
                        html += '</p>';
                    }
                    
                    html += `<div class="vuln-description">${vuln.description}</div>`;
                    html += `</div>`;
                });
                
                html += `</div>`;
            }
        });
        
        html += '</div>';
    }
    
    resultsContainer.innerHTML = html;
}

/**
 * Display password cracking results
 * @param {Object} results - Password cracking results from the API
 */
function displayPasswordCrackResults(results) {
    const resultsContainer = document.getElementById('password-crack-results');
    
    if (!results || !results.results) {
        resultsContainer.innerHTML = '<p class="no-results">No password cracking results available</p>';
        return;
    }
    
    const crackResults = results.results;
    
    let html = '<div class="crack-summary">';
    html += `<p>Hash: <strong>${crackResults.hash}</strong></p>`;
    html += `<p>Hash Type: <strong>${crackResults.hash_type}</strong></p>`;
    html += `<p>Attempts: <strong>${crackResults.attempts}</strong></p>`;
    html += `<p>Duration: <strong>${crackResults.duration} seconds</strong></p>`;
    html += `<p>Wordlist: <strong>${crackResults.wordlist || 'Default'}</strong></p>`;
    
    if (crackResults.found) {
        html += `<p class="password-result text-success">Password Found: <strong>${crackResults.password}</strong></p>`;
    } else {
        html += `<p class="password-result text-danger">Password not found in the wordlist</p>`;
    }
    
    html += '</div>';
    
    resultsContainer.innerHTML = html;
}

/**
 * Display packet sniffing results
 * @param {Object} results - Packet sniffing results from the API
 */
function displayPacketSniffResults(results) {
    const resultsContainer = document.getElementById('packet-sniff-results');
    
    if (!results || !results.results) {
        resultsContainer.innerHTML = '<p class="no-results">No packet capture results available</p>';
        return;
    }
    
    const sniffResults = results.results;
    const packets = sniffResults.packets || [];
    
    let html = '<div class="sniff-summary">';
    html += `<p>Interface: <strong>${sniffResults.interface}</strong></p>`;
    html += `<p>Duration: <strong>${sniffResults.duration} seconds</strong></p>`;
    html += `<p>Total Packets: <strong>${sniffResults.total_packets}</strong></p>`;
    
    if (sniffResults.protocol_summary) {
        html += '<p>Protocol Summary:</p>';
        html += '<ul>';
        Object.entries(sniffResults.protocol_summary).forEach(([proto, count]) => {
            html += `<li>${proto.toUpperCase()}: ${count}</li>`;
        });
        html += '</ul>';
    }
    
    if (sniffResults.truncated) {
        html += `<p class="text-warning">Note: Only showing first 1000 of ${sniffResults.total_captured} packets</p>`;
    }
    
    html += '</div>';
    
    if (packets.length === 0) {
        html += '<p>No packets were captured.</p>';
    } else {
        html += '<div class="packets-container">';
        html += '<table class="packets-table">';
        html += '<thead><tr><th>#</th><th>Time</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Length</th><th>Info</th></tr></thead>';
        html += '<tbody>';
        
        packets.forEach((packet, index) => {
            const ipInfo = packet.layers.ip || {};
            const tcpInfo = packet.layers.tcp || {};
            const udpInfo = packet.layers.udp || {};
            
            let protocol = 'Unknown';
            if (packet.layers.tcp) protocol = 'TCP';
            if (packet.layers.udp) protocol = 'UDP';
            if (packet.layers.icmp) protocol = 'ICMP';
            
            html += `<tr class="packet-row" data-index="${index}">`;
            html += `<td>${index + 1}</td>`;
            html += `<td>${new Date(packet.timestamp).toLocaleTimeString()}</td>`;
            html += `<td>${ipInfo.source || 'N/A'}</td>`;
            html += `<td>${ipInfo.destination || 'N/A'}</td>`;
            html += `<td>${protocol}</td>`;
            html += `<td>${ipInfo.length || 'N/A'}</td>`;
            html += `<td>${packet.summary || 'N/A'}</td>`;
            html += `</tr>`;
            
            // Add expandable details row
            html += `<tr class="packet-details" id="packet-details-${index}" style="display: none;">`;
            html += `<td colspan="7">`;
            html += `<div class="packet-details-content">`;
            
            // IP details
            if (packet.layers.ip) {
                html += `<div class="detail-section">`;
                html += `<h5>Internet Protocol (IP)</h5>`;
                html += `<p>Source: ${ipInfo.source}, Destination: ${ipInfo.destination}</p>`;
                html += `<p>TTL: ${ipInfo.ttl}, Length: ${ipInfo.length}</p>`;
                html += `</div>`;
            }
            
            // TCP details
            if (packet.layers.tcp) {
                html += `<div class="detail-section">`;
                html += `<h5>Transmission Control Protocol (TCP)</h5>`;
                html += `<p>Source Port: ${tcpInfo.source_port}, Destination Port: ${tcpInfo.destination_port}</p>`;
                html += `<p>Sequence: ${tcpInfo.seq}, Acknowledgment: ${tcpInfo.ack}</p>`;
                html += `<p>Flags: `;
                
                if (tcpInfo.flags) {
                    Object.entries(tcpInfo.flags).forEach(([flag, value]) => {
                        if (value) html += `${flag} `;
                    });
                }
                
                html += `</p>`;
                html += `</div>`;
            }
            
            // UDP details
            if (packet.layers.udp) {
                html += `<div class="detail-section">`;
                html += `<h5>User Datagram Protocol (UDP)</h5>`;
                html += `<p>Source Port: ${udpInfo.source_port}, Destination Port: ${udpInfo.destination_port}</p>`;
                html += `<p>Length: ${udpInfo.length}</p>`;
                html += `</div>`;
            }
            
            // Payload info
            if (packet.has_payload) {
                html += `<div class="detail-section">`;
                html += `<h5>Payload</h5>`;
                html += `<p>Size: ${packet.payload_size} bytes</p>`;
                html += `<p class="text-muted">Content not displayed for privacy reasons</p>`;
                html += `</div>`;
            }
            
            html += `</div></td></tr>`;
        });
        
        html += '</tbody></table></div>';
    }
    
    resultsContainer.innerHTML = html;
    
    // Add click handler to expand packet details
    const packetRows = resultsContainer.querySelectorAll('.packet-row');
    packetRows.forEach(row => {
        row.addEventListener('click', () => {
            const index = row.getAttribute('data-index');
            const detailsRow = document.getElementById(`packet-details-${index}`);
            
            if (detailsRow.style.display === 'none') {
                detailsRow.style.display = 'table-row';
                row.classList.add('expanded');
            } else {
                detailsRow.style.display = 'none';
                row.classList.remove('expanded');
            }
        });
    });
}

/**
 * Display the list of scan results
 * @param {Object} results - Results from the API
 */
function displayResultsList(results) {
    const resultsListContainer = document.getElementById('results-list-container');
    
    if (!results || Object.keys(results).length === 0) {
        resultsListContainer.innerHTML = '<p class="no-results">No scan history available</p>';
        return;
    }
    
    let html = '<ul class="results-list-items">';
    
    // Sort results by timestamp (newest first)
    const sortedResults = Object.entries(results)
        .sort((a, b) => new Date(b[1].timestamp) - new Date(a[1].timestamp));
    
    sortedResults.forEach(([id, result]) => {
        const timestamp = new Date(result.timestamp).toLocaleString();
        const icon = getActivityIcon(result.type);
        const label = formatActivityType(result.type);
        
        html += `<li class="result-item" data-id="${id}">`;
        html += `<div class="result-icon">${icon}</div>`;
        html += `<div class="result-info">`;
        html += `<span class="result-label">${label}</span>`;
        html += `<span class="result-timestamp">${timestamp}</span>`;
        html += `<span class="result-target">${result.target || result.hash_type || result.interface || ''}</span>`;
        html += `</div>`;
        html += `</li>`;
    });
    
    html += '</ul>';
    resultsListContainer.innerHTML = html;
    
    // Add click handler to view result details
    const resultItems = resultsListContainer.querySelectorAll('.result-item');
    resultItems.forEach(item => {
        item.addEventListener('click', () => {
            const id = item.getAttribute('data-id');
            showResultDetails(id, results[id]);
            
            // Highlight selected item
            resultItems.forEach(i => i.classList.remove('selected'));
            item.classList.add('selected');
        });
    });
}

/**
 * Show detailed view of a specific result
 * @param {string} id - Result ID
 * @param {Object} result - Result data
 */
function showResultDetails(id, result) {
    const detailsContainer = document.getElementById('result-details-container');
    
    if (!result) {
        detailsContainer.innerHTML = '<p class="no-details">Result not found</p>';
        return;
    }
    
    let html = '<div class="result-details-header">';
    html += `<h4>${formatActivityType(result.type)}</h4>`;
    html += `<p>ID: ${id}</p>`;
    html += `<p>Time: ${new Date(result.timestamp).toLocaleString()}</p>`;
    html += '</div>';
    
    // Different display based on result type
    switch (result.type) {
        case 'network_scan':
            html += displayNetworkResultDetails(result);
            break;
        case 'vulnerability_scan':
            html += displayVulnerabilityResultDetails(result);
            break;
        case 'password_crack':
            html += displayPasswordResultDetails(result);
            break;
        case 'packet_sniff':
            html += displayPacketResultDetails(result);
            break;
        default:
            html += `<p>Details not available for this result type.</p>`;
    }
    
    detailsContainer.innerHTML = html;
}

/**
 * Format network scan details for display
 * @param {Object} result - Scan result data
 * @returns {string} - HTML for display
 */
function displayNetworkResultDetails(result) {
    let html = '<div class="details-content">';
    html += `<p>Target: <strong>${result.target}</strong></p>`;
    
    const hosts = result.results?.hosts || [];
    html += `<p>Hosts found: ${hosts.length}</p>`;
    
    if (hosts.length > 0) {
        html += '<div class="details-table-container">';
        html += '<table class="details-table">';
        html += '<thead><tr><th>IP</th><th>Hostname</th><th>Status</th><th>Open Ports</th></tr></thead>';
        html += '<tbody>';
        
        hosts.forEach(host => {
            const openPorts = host.ports
                ? host.ports.filter(p => p.state === 'open').map(p => p.port).join(', ')
                : 'None';
            
            html += `<tr>`;
            html += `<td>${host.ip}</td>`;
            html += `<td>${host.hostname || 'N/A'}</td>`;
            html += `<td>${host.status}</td>`;
            html += `<td>${openPorts}</td>`;
            html += `</tr>`;
        });
        
        html += '</tbody></table></div>';
    }
    
    html += '</div>';
    return html;
}

/**
 * Format vulnerability scan details for display
 * @param {Object} result - Scan result data
 * @returns {string} - HTML for display
 */
function displayVulnerabilityResultDetails(result) {
    let html = '<div class="details-content">';
    html += `<p>Target: <strong>${result.target}</strong></p>`;
    
    const vulns = result.results?.vulnerabilities || [];
    html += `<p>Vulnerabilities found: ${vulns.length}</p>`;
    
    if (vulns.length > 0) {
        html += '<div class="details-table-container">';
        html += '<table class="details-table">';
        html += '<thead><tr><th>Name</th><th>Severity</th><th>Port</th><th>CVEs</th></tr></thead>';
        html += '<tbody>';
        
        vulns.forEach(vuln => {
            const cvesStr = vuln.cve_ids ? vuln.cve_ids.join(', ') : 'None';
            
            html += `<tr>`;
            html += `<td>${vuln.name}</td>`;
            html += `<td>${vuln.severity}</td>`;
            html += `<td>${vuln.port}</td>`;
            html += `<td>${cvesStr}</td>`;
            html += `</tr>`;
        });
        
        html += '</tbody></table></div>';
    }
    
    html += '</div>';
    return html;
}

/**
 * Format password cracking details for display
 * @param {Object} result - Crack result data
 * @returns {string} - HTML for display
 */
function displayPasswordResultDetails(result) {
    let html = '<div class="details-content">';
    html += `<p>Hash: <strong>${result.hash}</strong></p>`;
    html += `<p>Hash Type: <strong>${result.hash_type}</strong></p>`;
    html += `<p>Wordlist: <strong>${result.wordlist || 'Default'}</strong></p>`;
    html += `<p>Attempts: <strong>${result.results.attempts}</strong></p>`;
    html += `<p>Duration: <strong>${result.results.duration} seconds</strong></p>`;
    
    if (result.results.found) {
        html += `<p class="text-success">Password Found: <strong>${result.results.password}</strong></p>`;
    } else {
        html += `<p class="text-danger">Password not found in the wordlist</p>`;
    }
    
    html += '</div>';
    return html;
}

/**
 * Format packet sniffing details for display
 * @param {Object} result - Sniff result data
 * @returns {string} - HTML for display
 */
function displayPacketResultDetails(result) {
    let html = '<div class="details-content">';
    html += `<p>Interface: <strong>${result.interface}</strong></p>`;
    html += `<p>Duration: <strong>${result.results.duration} seconds</strong></p>`;
    html += `<p>Packets Captured: <strong>${result.results.total_packets}</strong></p>`;
    
    if (result.results.protocol_summary) {
        html += '<p>Protocol Summary:</p>';
        html += '<ul>';
        Object.entries(result.results.protocol_summary).forEach(([proto, count]) => {
            html += `<li>${proto.toUpperCase()}: ${count}</li>`;
        });
        html += '</ul>';
    }
    
    html += '</div>';
    return html;
}

/**
 * Display activity logs
 * @param {Object} data - Log data from the API
 */
function displayLogs(data) {
    const logsContainer = document.getElementById('logs-content');
    
    if (!data || !data.logs || data.logs.length === 0) {
        logsContainer.innerHTML = '<p class="no-logs">No activity logs available</p>';
        return;
    }
    
    // Format and display each log entry
    logsContainer.innerHTML = data.logs.join('<br>');
} 