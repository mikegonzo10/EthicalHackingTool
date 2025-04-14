/**
 * Ethical Hacking Toolkit - Main Application Logic
 */

document.addEventListener('DOMContentLoaded', () => {
    // Initialize the application
    initApp();
    
    // Initialize UI components
    initUI();
    
    // Initialize API handlers
    initAPI();
});

/**
 * Initialize the main application
 */
function initApp() {
    // Handle navigation between pages
    const navLinks = document.querySelectorAll('.nav-links li');
    const dashboardCards = document.querySelectorAll('.dashboard-cards .card');
    
    // Navigation sidebar links
    navLinks.forEach(link => {
        link.addEventListener('click', () => {
            const targetPage = link.getAttribute('data-page');
            navigateToPage(targetPage);
            
            // Update active class in navigation
            navLinks.forEach(item => item.classList.remove('active'));
            link.classList.add('active');
        });
    });
    
    // Dashboard cards as shortcuts to tools
    dashboardCards.forEach(card => {
        card.addEventListener('click', () => {
            const targetPage = card.getAttribute('data-page');
            navigateToPage(targetPage);
            
            // Update active class in navigation
            navLinks.forEach(item => {
                if (item.getAttribute('data-page') === targetPage) {
                    item.classList.add('active');
                } else {
                    item.classList.remove('active');
                }
            });
        });
    });
    
    // Dark/Light theme toggle
    const themeToggle = document.querySelector('.theme-toggle');
    themeToggle.addEventListener('click', toggleTheme);
    
    // Stop button functionality
    const stopBtn = document.getElementById('stop-btn');
    stopBtn.addEventListener('click', stopCurrentProcess);
    
    // Initialize tool handlers
    initNetworkScanner();
    initVulnerabilityScanner();
    initPasswordCracker();
    initPacketSniffer();
    initResults();
    initLogs();
    
    // Load any recent activities
    loadRecentActivities();
}

/**
 * Navigate to a specific page
 * @param {string} pageId - The ID of the page to navigate to
 */
function navigateToPage(pageId) {
    const pages = document.querySelectorAll('.page');
    const pageTitle = document.getElementById('page-title');
    
    // Hide all pages
    pages.forEach(page => page.classList.remove('active'));
    
    // Show the selected page
    const targetPage = document.getElementById(pageId);
    if (targetPage) {
        targetPage.classList.add('active');
        
        // Update page title
        const pageName = pageId.split('-').map(word => 
            word.charAt(0).toUpperCase() + word.slice(1)
        ).join(' ');
        pageTitle.textContent = pageName;
    }
}

/**
 * Toggle between dark and light theme
 */
function toggleTheme() {
    // This is a placeholder for theme toggling functionality
    // In a future version, this would toggle between dark/light theme
    showAlert('Theme Toggle', 'Theme switching is not available in this version.');
}

/**
 * Stop the current running process
 */
function stopCurrentProcess() {
    // This function would handle stopping any running scan or process
    showAlert('Process Stopped', 'The current process has been stopped.');
    hideLoadingOverlay();
    document.getElementById('stop-btn').style.display = 'none';
}

/**
 * Load recent activities to display on the dashboard
 */
function loadRecentActivities() {
    const activityList = document.getElementById('recent-activity-list');
    
    // Fetch recent activities from the API
    fetchResults()
        .then(results => {
            if (Object.keys(results).length === 0) {
                return;
            }
            
            // Clear the "no activity" message
            activityList.innerHTML = '';
            
            // Get the 5 most recent scans
            const recentScans = Object.entries(results)
                .sort((a, b) => new Date(b[1].timestamp) - new Date(a[1].timestamp))
                .slice(0, 5);
            
            recentScans.forEach(([id, scan]) => {
                const activityItem = document.createElement('div');
                activityItem.className = 'activity-item';
                
                const timestamp = new Date(scan.timestamp).toLocaleString();
                const icon = getActivityIcon(scan.type);
                
                activityItem.innerHTML = `
                    <div class="activity-icon">${icon}</div>
                    <div class="activity-details">
                        <span class="activity-type">${formatActivityType(scan.type)}</span>
                        <span class="activity-timestamp">${timestamp}</span>
                        <span class="activity-target">${scan.target || scan.hash_type || scan.interface || ''}</span>
                    </div>
                `;
                
                activityList.appendChild(activityItem);
            });
        })
        .catch(error => {
            console.error('Error loading recent activities:', error);
        });
}

/**
 * Get the appropriate icon for an activity type
 * @param {string} type - The type of activity
 * @returns {string} - HTML for the icon
 */
function getActivityIcon(type) {
    switch (type) {
        case 'network_scan':
            return '<i class="fas fa-network-wired"></i>';
        case 'vulnerability_scan':
            return '<i class="fas fa-search"></i>';
        case 'password_crack':
            return '<i class="fas fa-key"></i>';
        case 'packet_sniff':
            return '<i class="fas fa-ethernet"></i>';
        default:
            return '<i class="fas fa-cog"></i>';
    }
}

/**
 * Format an activity type for display
 * @param {string} type - The activity type
 * @returns {string} - Formatted type name
 */
function formatActivityType(type) {
    return type.split('_').map(word => 
        word.charAt(0).toUpperCase() + word.slice(1)
    ).join(' ');
}

// Tool-specific initialization functions
function initNetworkScanner() {
    const scanButton = document.getElementById('scan-network-btn');
    if (!scanButton) return;
    
    scanButton.addEventListener('click', () => {
        const target = document.getElementById('target-input').value.trim();
        const ports = document.getElementById('ports-input').value.trim();
        
        if (!target) {
            showAlert('Input Error', 'Please enter a target IP address or range.');
            return;
        }
        
        showLoadingOverlay('Scanning network...');
        document.getElementById('stop-btn').style.display = 'inline-flex';
        
        // Call the API to perform the scan
        scanNetwork(target, ports)
            .then(results => {
                displayNetworkScanResults(results);
                hideLoadingOverlay();
                document.getElementById('stop-btn').style.display = 'none';
                loadRecentActivities();  // Refresh the recent activities
            })
            .catch(error => {
                console.error('Network scan error:', error);
                showAlert('Scan Error', `Network scan failed: ${error.message || 'Unknown error'}`);
                hideLoadingOverlay();
                document.getElementById('stop-btn').style.display = 'none';
            });
    });
}

function initVulnerabilityScanner() {
    const scanButton = document.getElementById('scan-vulnerabilities-btn');
    if (!scanButton) return;
    
    scanButton.addEventListener('click', () => {
        const target = document.getElementById('vuln-target-input').value.trim();
        
        if (!target) {
            showAlert('Input Error', 'Please enter a target IP address or hostname.');
            return;
        }
        
        showLoadingOverlay('Scanning for vulnerabilities...');
        document.getElementById('stop-btn').style.display = 'inline-flex';
        
        // Call the API to perform the vulnerability scan
        scanVulnerabilities(target)
            .then(results => {
                displayVulnerabilityScanResults(results);
                hideLoadingOverlay();
                document.getElementById('stop-btn').style.display = 'none';
                loadRecentActivities();
            })
            .catch(error => {
                console.error('Vulnerability scan error:', error);
                showAlert('Scan Error', `Vulnerability scan failed: ${error.message || 'Unknown error'}`);
                hideLoadingOverlay();
                document.getElementById('stop-btn').style.display = 'none';
            });
    });
}

function initPasswordCracker() {
    const crackButton = document.getElementById('crack-password-btn');
    if (!crackButton) return;
    
    crackButton.addEventListener('click', () => {
        const hashValue = document.getElementById('hash-input').value.trim();
        const hashType = document.getElementById('hash-type-select').value;
        const wordlist = document.getElementById('wordlist-input').value.trim();
        
        if (!hashValue) {
            showAlert('Input Error', 'Please enter a hash value to crack.');
            return;
        }
        
        showLoadingOverlay('Cracking password...');
        document.getElementById('stop-btn').style.display = 'inline-flex';
        
        // Call the API to perform the password cracking
        crackPassword(hashValue, hashType, wordlist)
            .then(results => {
                displayPasswordCrackResults(results);
                hideLoadingOverlay();
                document.getElementById('stop-btn').style.display = 'none';
                loadRecentActivities();
            })
            .catch(error => {
                console.error('Password cracking error:', error);
                showAlert('Cracking Error', `Password cracking failed: ${error.message || 'Unknown error'}`);
                hideLoadingOverlay();
                document.getElementById('stop-btn').style.display = 'none';
            });
    });
}

function initPacketSniffer() {
    const sniffButton = document.getElementById('start-sniffing-btn');
    if (!sniffButton) return;
    
    // Populate interface select with dummy interfaces
    // In a real app, you would fetch the available interfaces from the API
    const interfaceSelect = document.getElementById('interface-select');
    ['eth0', 'wlan0', 'lo'].forEach(iface => {
        const option = document.createElement('option');
        option.value = iface;
        option.textContent = iface;
        interfaceSelect.appendChild(option);
    });
    
    sniffButton.addEventListener('click', () => {
        const interfaceValue = document.getElementById('interface-select').value;
        const duration = document.getElementById('duration-input').value;
        const filter = document.getElementById('filter-input').value.trim();
        
        if (!interfaceValue) {
            showAlert('Input Error', 'Please select a network interface.');
            return;
        }
        
        showLoadingOverlay(`Capturing packets for ${duration} seconds...`);
        document.getElementById('stop-btn').style.display = 'inline-flex';
        
        // Call the API to perform the packet sniffing
        sniffPackets(interfaceValue, duration, filter)
            .then(results => {
                displayPacketSniffResults(results);
                hideLoadingOverlay();
                document.getElementById('stop-btn').style.display = 'none';
                loadRecentActivities();
            })
            .catch(error => {
                console.error('Packet sniffing error:', error);
                showAlert('Sniffing Error', `Packet sniffing failed: ${error.message || 'Unknown error'}`);
                hideLoadingOverlay();
                document.getElementById('stop-btn').style.display = 'none';
            });
    });
}

function initResults() {
    // Handle the results page functionality
    const refreshResultsList = () => {
        fetchResults()
            .then(results => {
                displayResultsList(results);
            })
            .catch(error => {
                console.error('Error fetching results:', error);
                showAlert('Results Error', 'Failed to load scan results.');
            });
    };
    
    // Refresh when the results page is accessed
    document.querySelector('[data-page="results"]').addEventListener('click', refreshResultsList);
}

function initLogs() {
    // Handle the logs page functionality
    const refreshLogsBtn = document.getElementById('refresh-logs-btn');
    if (!refreshLogsBtn) return;
    
    const refreshLogs = () => {
        showLoadingOverlay('Loading logs...');
        
        fetchLogs()
            .then(logs => {
                displayLogs(logs);
                hideLoadingOverlay();
            })
            .catch(error => {
                console.error('Error fetching logs:', error);
                showAlert('Logs Error', 'Failed to load activity logs.');
                hideLoadingOverlay();
            });
    };
    
    refreshLogsBtn.addEventListener('click', refreshLogs);
    
    // Also refresh when the logs page is accessed
    document.querySelector('[data-page="logs"]').addEventListener('click', refreshLogs);
} 