var latestHealthFactors = [];
var currentModalAlert = null;
// ==========================================
// STATE MANAGEMENT & GLOBALS
// ==========================================
var token = localStorage.getItem("token") || null;
var currentView = "monitoring-view";
var socket = null;
var systemStatusInterval = null;
var deviceProfilesInterval = null;
var analyticsChartsInterval = null;

// Chart instances
var throughputChart = null;
var incidentsChart = null;
var protocolChart = null;
var monitorChart = null;
var dashThroughputChart = null;

// Throughput chart queues
var MAX_CHART_POINTS = 15;
var throughputLabels = [];
var throughputData = [];
var totalBytesLastInterval = 0;

// Pagination state variables (Page-Form Architecture)
var alertsCurrentPage = 1;
var alertsPageSize = 10;
var allFilteredAlerts = [];

var devicesCurrentPage = 1;
var devicesPageSize = 10;
var allFetchedDevices = [];

var logsCurrentPage = 1;
var logsPageSize = 15;
var allFilteredLogs = [];

// API Root URL
var API_URL = window.location.origin;
var WS_URL = (window.location.protocol === 'https:' ? 'wss:' : 'ws:') + '//' + window.location.host;

// ==========================================
// BOOTSTRAP - runs immediately since script is at bottom of body
// ==========================================
(function init() {
    setupLoginButton();
    setupLogoutButton();
    setupViewSwitching();
    setupSystemControl();
    setupDropzone();
    setupModelControls();
    setupReportDownloads();
    setupModalsAndDrawers();
    setupResearchWorkbench();
    setupPaginationControls();
    setupHealthWhyPopover();
    setupSettingsActions();
    setupTheme();

    if (token) {
        initializeDashboard();
    } else {
        showScreen("login-screen");
    }
})();

// ==========================================
// AUTHENTICATION
// ==========================================
function setupLoginButton() {
    var btn = document.getElementById("btn-login");
    var errorMsg = document.getElementById("login-error");

    btn.addEventListener("click", function () {
        // Request desktop notification permission on direct user gesture
        requestNotificationPermission();
        
        var usernameInput = document.getElementById("username").value.trim();
        var passwordInput = document.getElementById("password").value.trim();

        if (!usernameInput || !passwordInput) {
            errorMsg.classList.remove("hide");
            return;
        }

        var params = new URLSearchParams();
        params.append("username", usernameInput);
        params.append("password", passwordInput);

        btn.disabled = true;
        btn.innerHTML = '<i class="fa-solid fa-spinner animate-spin"></i> Authenticating...';

        fetch(API_URL + "/api/auth/token", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: params
        })
        .then(function (response) {
            if (!response.ok) {
                throw new Error("Unauthorized");
            }
            return response.json();
        })
        .then(function (data) {
            token = data.access_token;
            localStorage.setItem("token", token);
            errorMsg.classList.add("hide");
            initializeDashboard();
        })
        .catch(function (err) {
            console.error("Login failed:", err);
            errorMsg.classList.remove("hide");
            btn.disabled = false;
            btn.innerHTML = '<span>Authenticate Console</span><i class="fa-solid fa-arrow-right-to-bracket"></i>';
        });
    });

    document.getElementById("password").addEventListener("keydown", function (e) {
        if (e.key === "Enter") {
            btn.click();
        }
    });

    document.getElementById("username").addEventListener("keydown", function (e) {
        if (e.key === "Enter") {
            document.getElementById("password").focus();
        }
    });
}

function setupLogoutButton() {
    var btn = document.getElementById("btn-logout");
    if (btn) {
        btn.addEventListener("click", function () {
            logout();
        });
    }
}

function logout() {
    localStorage.removeItem("token");
    token = null;
    if (socket) {
        socket.close();
        socket = null;
    }
    if (systemStatusInterval) {
        clearInterval(systemStatusInterval);
        systemStatusInterval = null;
    }
    if (analyticsChartsInterval) {
        clearInterval(analyticsChartsInterval);
        analyticsChartsInterval = null;
    }
    showScreen("login-screen");
}

function showScreen(screenId) {
    var loginScreen = document.getElementById("login-screen");
    var appScreen = document.getElementById("app-screen");
    if (screenId === "login-screen") {
        loginScreen.classList.add("active");
        appScreen.classList.add("hide");
    } else {
        loginScreen.classList.remove("active");
        appScreen.classList.remove("hide");
    }
}

// ==========================================
// AUTHENTICATED FETCH HELPER
// ==========================================
function fnFetch(endpoint, options) {
    options = options || {};
    if (!token) return Promise.resolve(null);

    var headers = options.headers || {};
    headers["Authorization"] = "Bearer " + token;
    options.headers = headers;

    return fetch(API_URL + endpoint, options).then(function (response) {
        if (response.status === 401) {
            logout();
            throw new Error("Session expired. Please re-authenticate.");
        }
        return response;
    });
}

// ==========================================
// VIEW & TAB CONTROLLER (TWO-TIER NAVIGATION)
// ==========================================
function setupViewSwitching() {
    // 1a. Standalone navigation link (Dashboard)
    var standaloneLinks = document.querySelectorAll(".nav-item-standalone");
    standaloneLinks.forEach(function (item) {
        item.addEventListener("click", function (e) {
            e.preventDefault();
            requestNotificationPermission();
            // Close all accordion groups when returning to top dashboard
            document.querySelectorAll(".nav-group").forEach(function (grp) {
                grp.classList.remove("open");
            });
            var targetView = item.getAttribute("data-target") || "dashboard-view";
            var targetTab = item.getAttribute("data-tab");
            switchView(targetView, targetTab);
        });
    });

    // 1b. Accordion Group Headers (Monitor, Security, Learn, Explore, System)
    var groupHeaders = document.querySelectorAll(".nav-group-header");
    groupHeaders.forEach(function (btn) {
        btn.addEventListener("click", function (e) {
            e.preventDefault();
            requestNotificationPermission();
            var group = btn.closest(".nav-group");
            if (!group) return;
            var isCurrentlyOpen = group.classList.contains("open");
            var groupName = group.getAttribute("data-group") || "group";

            // Single-open accordion: close all other groups
            document.querySelectorAll(".nav-group").forEach(function (g) {
                if (g !== group) g.classList.remove("open");
            });

            if (isCurrentlyOpen) {
                // Clicking an open group collapses it
                group.classList.remove("open");
                console.log("[NEXz Telemetry] Accordion collapsed:", groupName);
            } else {
                group.classList.add("open");
                console.log("[NEXz Telemetry] Accordion expanded:", groupName);
                var targetView = btn.getAttribute("data-target");
                var targetTab = btn.getAttribute("data-tab");
                if (targetView) {
                    switchView(targetView, targetTab);
                }
            }
        });
    });

    // 1c. Accordion Sub-items
    var subitems = document.querySelectorAll(".nav-subitem");
    subitems.forEach(function (sub) {
        sub.addEventListener("click", function (e) {
            e.preventDefault();
            requestNotificationPermission();
            var parentGroup = sub.closest(".nav-group");
            if (parentGroup) {
                document.querySelectorAll(".nav-group").forEach(function (g) {
                    if (g !== parentGroup) g.classList.remove("open");
                });
                parentGroup.classList.add("open");
            }
            var targetView = sub.getAttribute("data-target");
            var targetTab = sub.getAttribute("data-tab");
            switchView(targetView, targetTab);
        });
    });

    // 2. Horizontal Subnavigation Tabs within views
    var subtabs = document.querySelectorAll(".subnav-tab");
    subtabs.forEach(function (tabBtn) {
        tabBtn.addEventListener("click", function (e) {
            e.preventDefault();
            var subtabId = tabBtn.getAttribute("data-subtab");
            var parentPanel = tabBtn.closest(".view-panel");
            if (parentPanel) {
                activateSubTab(parentPanel.id, subtabId);
            }
        });
    });

    // 3. Jump links (e.g. from Dashboard cards)
    var jumpLinks = document.querySelectorAll(".jump-link");
    jumpLinks.forEach(function (link) {
        link.addEventListener("click", function (e) {
            e.preventDefault();
            var targetView = link.getAttribute("data-target");
            var targetTab = link.getAttribute("data-tab");
            switchView(targetView, targetTab);
        });
    });

    // 4. Utility Refresh Buttons
    var btnRefreshDevs = document.getElementById("btn-refresh-devices");
    if (btnRefreshDevs) {
        btnRefreshDevs.addEventListener("click", function (e) {
            e.preventDefault();
            pollDeviceProfiles();
        });
    }

    var btnRefreshMonDevs = document.getElementById("btn-refresh-mon-devices");
    if (btnRefreshMonDevs) {
        btnRefreshMonDevs.addEventListener("click", function (e) {
            e.preventDefault();
            pollDeviceProfiles();
        });
    }

    var btnRefreshDrift = document.getElementById("btn-refresh-drift-events");
    if (btnRefreshDrift) {
        btnRefreshDrift.addEventListener("click", function (e) {
            e.preventDefault();
            loadADWINDriftEvents();
        });
    }

    var btnRefreshSys = document.getElementById("btn-refresh-sys-status");
    if (btnRefreshSys) {
        btnRefreshSys.addEventListener("click", function (e) {
            e.preventDefault();
            pollSystemStatus();
            loadModelMetrics();
        });
    }

    // 5. Detection Explained Chips
    setupDetectionExplained();
}

function activateSubTab(viewId, subtabId) {
    var viewPanel = document.getElementById(viewId);
    if (!viewPanel) return;

    // Toggle subnav tab active state
    viewPanel.querySelectorAll(".subnav-tab").forEach(function (tab) {
        if (tab.getAttribute("data-subtab") === subtabId) {
            tab.classList.add("active");
        } else {
            tab.classList.remove("active");
        }
    });

    // Toggle tab-pane active state
    viewPanel.querySelectorAll(".tab-pane").forEach(function (pane) {
        if (pane.id === subtabId) {
            pane.classList.add("active");
        } else {
            pane.classList.remove("active");
        }
    });

    // Update active nav-subitem in sidebar if applicable
    document.querySelectorAll(".nav-subitem, .nav-item").forEach(function (item) {
        if (item.getAttribute("data-target") === viewId && item.getAttribute("data-tab") === subtabId) {
            item.classList.add("active");
        } else if (item.getAttribute("data-target") === viewId && !item.getAttribute("data-tab") && !subtabId) {
            item.classList.add("active");
        } else {
            item.classList.remove("active");
        }
    });

    // Trigger tab-specific loaders
    if (subtabId === "tab-sec-adwin") {
        loadADWINDriftEvents();
        loadModelMetrics();
    } else if (subtabId === "tab-sec-behaviour") {
        pollDeviceProfiles();
    } else if (subtabId === "tab-sec-alerts") {
        loadAlerts();
    } else if (subtabId === "tab-monitor-flows") {
        loadLogs();
    } else if (subtabId === "tab-monitor-traffic") {
        refreshTopTalkersAndPorts();
    } else if (subtabId === "tab-monitor-devices") {
        pollDeviceProfiles();
    } else if (subtabId === "tab-sys-status") {
        pollSystemStatus();
        loadModelMetrics();
    } else if (subtabId === "tab-explore-research") {
        runResearchQuery();
    } else if (subtabId === "tab-explore-history") {
        refreshAnalyticsCharts();
    }
}

function switchView(targetViewId, targetTabId) {
    if (!targetViewId) targetViewId = "dashboard-view";

    // Normalization mapping for the core environments
    if (targetViewId === "overview-view") {
        targetViewId = "dashboard-view";
    } else if (targetViewId === "monitor-view") {
        targetViewId = "monitoring-view";
    } else if (targetViewId === "alerts-view") {
        targetViewId = "security-view";
        if (!targetTabId) targetTabId = "tab-sec-alerts";
    } else if (targetViewId === "learn-view" || targetViewId === "academy-view") {
        targetViewId = "learning-view";
    } else if (targetViewId === "research-view" || targetViewId === "explore-view" || targetViewId === "reports-view" || targetViewId === "traffic-view" || targetViewId === "logs-view") {
        targetViewId = "explore-view";
    }

    currentView = targetViewId;

    // Set active class on view panels
    document.querySelectorAll(".view-panel").forEach(function (panel) {
        if (panel.id === targetViewId) {
            panel.classList.add("active");
            panel.classList.remove("hide");
        } else {
            panel.classList.remove("active");
            panel.classList.add("hide");
        }
    });

    var titleEl = document.getElementById("view-title");
    var subtitleEl = document.getElementById("view-subtitle");

    if (targetViewId === "dashboard-view") {
        if (titleEl) titleEl.innerText = "Command Overview";
        if (subtitleEl) subtitleEl.innerText = "High-level perimeter telemetry, algorithmic adaptation, and security status";
        renderDashboardOverview();
    } else if (targetViewId === "monitoring-view") {
        if (titleEl) titleEl.innerText = "Monitoring Pillar";
        if (subtitleEl) subtitleEl.innerText = "Real-time socket capture, flow table aggregation, and throughput telemetry";
        loadLogs();
        refreshTopTalkersAndPorts();
    } else if (targetViewId === "security-view") {
        if (titleEl) titleEl.innerText = "Security Pillar";
        if (subtitleEl) subtitleEl.innerText = "Adaptive Random Forest ML classifications, ADWIN concept drift, and per-device behavioral baselines";
        loadAlerts();
        loadModelMetrics();
        pollDeviceProfiles();
    } else if (targetViewId === "learning-view") {
        if (titleEl) titleEl.innerText = "Learning Pillar";
        if (subtitleEl) subtitleEl.innerText = "Contextual Protocol Academy, Explainable AI diagnostics, and Pedagogical Cyber Range";
        loadAcademyData();
        setupEducationalSimulation();
    } else if (targetViewId === "explore-view") {
        if (titleEl) titleEl.innerText = "Explore & Research Pillar";
        if (subtitleEl) subtitleEl.innerText = "Longitudinal traffic analytics, multi-criteria research telemetry workbench, and forensic exports";
        refreshAnalyticsCharts();
        runResearchQuery();
    } else if (targetViewId === "system-view") {
        if (titleEl) titleEl.innerText = "System & Runtime Environment";
        if (subtitleEl) subtitleEl.innerText = "Component health monitoring, sensor configurations, and pipeline diagnostics";
        pollSystemStatus();
        loadModelMetrics();
    }

    // Activate specific sub-tab or default to first tab in that view
    var activePanel = document.getElementById(targetViewId);
    if (activePanel) {
        if (!targetTabId) {
            var firstTab = activePanel.querySelector(".subnav-tab");
            if (firstTab) targetTabId = firstTab.getAttribute("data-subtab");
        }
        if (targetTabId) {
            activateSubTab(targetViewId, targetTabId);
        }
    }

    // Sync Accordion Group state (.open)
    var targetGroup = null;
    if (targetViewId === "monitoring-view") targetGroup = document.getElementById("nav-group-monitor");
    else if (targetViewId === "security-view") targetGroup = document.getElementById("nav-group-security");
    else if (targetViewId === "learning-view") targetGroup = document.getElementById("nav-group-learn");
    else if (targetViewId === "explore-view") targetGroup = document.getElementById("nav-group-explore");
    else if (targetViewId === "system-view") targetGroup = document.getElementById("nav-group-system");

    document.querySelectorAll(".nav-group").forEach(function (grp) {
        if (targetGroup && grp === targetGroup) {
            grp.classList.add("open");
        } else {
            grp.classList.remove("open");
        }
    });

    // Sync Standalone Dashboard Link active state
    var dashStandalone = document.querySelector(".nav-item-standalone");
    if (dashStandalone) {
        if (targetViewId === "dashboard-view") {
            dashStandalone.classList.add("active");
        } else {
            dashStandalone.classList.remove("active");
        }
    }

    // Highlight sidebar items
    document.querySelectorAll(".nav-item, .nav-subitem").forEach(function (item) {
        var matchTarget = item.getAttribute("data-target") === targetViewId;
        var itemTab = item.getAttribute("data-tab");
        if (matchTarget && (!itemTab || itemTab === targetTabId)) {
            item.classList.add("active");
        } else {
            item.classList.remove("active");
        }
    });

    console.log("[NEXz Telemetry] Active View:", targetViewId, "| Active Tab:", targetTabId);

    setTimeout(function () {
        if (throughputChart) throughputChart.resize();
        if (incidentsChart) incidentsChart.resize();
        if (protocolChart) protocolChart.resize();
        if (monitorChart) monitorChart.resize();
        if (dashThroughputChart) dashThroughputChart.resize();
    }, 60);
}

// ==========================================
// DASHBOARD INITIALIZATION
// ==========================================
function initializeDashboard() {
    showScreen("app-screen");
    initCharts();
    setupWebSocket();
    loadNICDropdowns();
    pollSystemStatus();
    pollDeviceProfiles();
    refreshAnalyticsCharts();
    requestNotificationPermission();
    setupImportWorkflow();
    loadImportBatches();
    loadWatchlists();
    systemStatusInterval = setInterval(pollSystemStatus, 2000);
    deviceProfilesInterval = setInterval(pollDeviceProfiles, 6000);
    analyticsChartsInterval = setInterval(refreshAnalyticsCharts, 10000);
    switchView("dashboard-view");
}

// ==========================================
// WEBSOCKET
// ==========================================
function setupWebSocket() {
    if (!token) return;
    if (socket) {
        socket.close();
    }

    socket = new WebSocket(WS_URL + "/api/ws/alerts");

    socket.onopen = function () {
        console.log("WebSocket console feed established.");
    };

    socket.onmessage = function (event) {
        var msg = JSON.parse(event.data);

        if (msg.type === "alert") {
            showToastAlert(msg);
            if (document.hidden && "Notification" in window && Notification.permission === "granted") {
                new Notification("NIDS Risk Alarm: " + (msg.threat_level || msg.label), {
                    body: msg.notes || "Suspicious traffic flow detected.",
                    tag: "nids-alert"
                });
            }
            if (currentView === "overview-view") {
                refreshRecentAlertsTable();
            } else if (currentView === "security-view" || currentView === "alerts-view") {
                loadAlerts();
            }
            refreshAnalyticsCharts();
        } else if (msg.type === "metrics") {
            totalBytesLastInterval += msg.bytes_processed;
        } else if (msg.type === "drift_alert") {
            showDriftToast(msg.message);
            triggerDriftUIEffects(msg.metrics);
        } else if (msg.type === "pcap_completed") {
            showToastAlert({ label: "Normal", notes: msg.message }, "PCAP Analysis Done");
            refreshOverviewData();
        } else if (msg.type === "pcap_error") {
            showToastAlert({ label: "Malicious", notes: msg.message }, "PCAP Analysis Failed");
        } else if (msg.type === "import_progress") {
            handleImportProgressEvent(msg);
        } else if (msg.type === "import_completed" || msg.type === "import_cancelled") {
            handleImportCompletedEvent(msg);
        }
    };

    socket.onerror = function (err) {
        console.error("WebSocket connection error:", err);
    };

    socket.onclose = function () {
        console.log("WebSocket disconnected.");
        if (token) {
            console.log("Retrying in 5s...");
            setTimeout(setupWebSocket, 5000);
        }
    };
}

// ==========================================
// SYSTEM STATUS POLLING & NETWORK HEALTH
// ==========================================
function pollSystemStatus() {
    fnFetch("/api/system/status").then(function (res) {
        if (!res) return;
        return res.json();
    }).then(function (data) {
        if (!data) return;

        // Update health summaries
        document.getElementById("kpi-hosts").innerText = data.active_hosts;
        document.getElementById("kpi-active-flows").innerText = data.active_flows;
        var kpiAlerts = document.getElementById("kpi-alerts");
        if (kpiAlerts) kpiAlerts.innerText = data.active_alerts;
        var alertsBadge = document.getElementById("alerts-badge");
        if (alertsBadge) {
            alertsBadge.innerText = data.active_alerts;
            if (data.active_alerts > 0) alertsBadge.classList.remove("hide");
            else alertsBadge.classList.add("hide");
        }

        // Circular Network Health Gauge & Transparent Derivation
        latestHealthFactors = data.health_factors || [];
        var healthPct = data.health_score !== undefined ? data.health_score : (100 - data.threat_score);
        var color = "var(--color-normal)";
        var statusStr = "Optimal";
        
        var healthCard = document.getElementById("health-card");
        if (!data.sniffer_running) {
            healthPct = 100; // Reset network health back to 100% when sniffing is inactive
            color = "#6b7280"; // gray color
            statusStr = "Optimal (Inactive)";
            if (healthCard) {
                healthCard.className = "kpi-card glass-panel frozen-card animate-slide-up";
            }
        } else {
            if (healthPct < 50) {
                color = "var(--color-malicious)";
                statusStr = "Critical";
            } else if (healthPct < 85) {
                color = "var(--color-suspicious)";
                statusStr = "Warning";
            }
            if (healthCard) {
                if (healthPct < 50) healthCard.className = "kpi-card glass-panel card-glow-red animate-pulse";
                else if (healthPct < 85) healthCard.className = "kpi-card glass-panel card-glow-blue";
                else healthCard.className = "kpi-card glass-panel card-glow-green";
            }
        }
        
        var gaugeEl = document.getElementById("health-gauge");
        var pctEl = document.getElementById("kpi-health-pct");
        var statusEl = document.getElementById("kpi-health-status");
        if (gaugeEl) {
            gaugeEl.style.setProperty("--gauge-value", healthPct);
            gaugeEl.style.setProperty("--gauge-color", color);
        }
        if (pctEl) pctEl.innerText = healthPct + "%";
        if (statusEl) {
            statusEl.innerText = statusStr;
            statusEl.style.color = color;
        }

        // Update packets per second
        var ppsEl = document.getElementById("pps-counter");
        if (ppsEl) {
            ppsEl.innerText = data.pps !== undefined ? data.pps : 0;
        }

        // Monitoring status badge
        var statusDot = document.getElementById("sniffer-status-dot");
        var statusText = document.getElementById("sniffer-status-text");
        var interfaceLabel = document.getElementById("active-interface-label");
        var headerBtn = document.getElementById("btn-toggle-sniff-header");
        var statusBadge = document.getElementById("sniff-status-badge");
        var monitorBtn = document.getElementById("btn-monitor-toggle");
        var monitorPps = document.getElementById("monitor-pps-display");

        if (data.sniffer_running) {
            statusDot.className = "dot sniffing";
            statusText.innerText = "Sensor Active";
            interfaceLabel.innerText = "NIC: " + data.active_interface;
            if (statusBadge) {
                statusBadge.className = "threat-badge normal";
                statusBadge.innerHTML = '<i class="fa-solid fa-circle-play"></i> Active';
            }
            if (headerBtn) {
                headerBtn.innerHTML = '<i class="fa-solid fa-pause"></i> Pause';
                headerBtn.className = "btn-sniff-toggle running";
            }
            if (monitorBtn) {
                monitorBtn.innerHTML = '<i class="fa-solid fa-pause"></i> Pause Sensor';
                monitorBtn.className = "btn-primary";
            }
            if (monitorPps) {
                monitorPps.innerText = (data.pps !== undefined ? data.pps : 0) + " Packets/sec";
            }
        } else {
            statusDot.className = "dot";
            statusText.innerText = "Sensor Idle (Manual)";
            interfaceLabel.innerText = "NIC: None";
            if (statusBadge) {
                statusBadge.className = "threat-badge suspicious";
                statusBadge.innerHTML = '<i class="fa-solid fa-circle-pause"></i> Idle';
            }
            if (headerBtn) {
                headerBtn.innerHTML = '<i class="fa-solid fa-play"></i> Start Monitor';
                headerBtn.className = "btn-sniff-toggle";
            }
            if (monitorBtn) {
                monitorBtn.innerHTML = '<i class="fa-solid fa-play"></i> Start Capture';
                monitorBtn.className = "btn-primary";
            }
            if (monitorPps) {
                monitorPps.innerText = "0 Packets/sec";
            }
        }

        // Update alerts badge in nav list
        var badge = document.getElementById("alerts-badge");
        if (data.active_alerts > 0) {
            badge.innerText = data.active_alerts;
            badge.classList.remove("hide");
        } else {
            badge.classList.add("hide");
        }

        // Update protocol distribution charts & details legend
        if (protocolChart && data.protocol_stats) {
            protocolChart.data.datasets[0].data = [
                data.protocol_stats.TCP || 0,
                data.protocol_stats.UDP || 0,
                data.protocol_stats.ICMP || 0,
                data.protocol_stats.DNS || 0,
                data.protocol_stats.HTTP || 0,
                data.protocol_stats.HTTPS || 0
            ];
            protocolChart.update();

            var legendEl = document.getElementById("protocol-stats-legend");
            if (legendEl) {
                legendEl.innerHTML = "";
                var protos = ['TCP', 'UDP', 'ICMP', 'DNS', 'HTTP', 'HTTPS'];
                var colors = ['#6366f1', '#3b82f6', '#10b981', '#f59e0b', '#8b5cf6', '#ec4899'];
                protos.forEach(function (p, i) {
                    var count = data.protocol_stats[p] || 0;
                    legendEl.innerHTML += '<div><span style="display:inline-block; width:8px; height:8px; border-radius:50%; background:' + colors[i] + '; margin-right:4px;"></span>' + p + ': <strong>' + count.toLocaleString() + '</strong></div>';
                });
            }
        }

        // Real-time Throughput Accumulation from backend sniffer get_bps()
        if (data.sniffer_running && data.bytes_rate !== undefined && data.bytes_rate > 0) {
            totalBytesLastInterval += Math.round(data.bytes_rate * 2);
        }

        // Continuously synchronize Dashboard Overview cards and gauges
        if (currentView === "dashboard-view") {
            renderDashboardOverview();
        }
    }).catch(function (err) {
        console.error("[NEXz Telemetry Error] System poll failed:", err);
    });
}

function updateDevicesPaginationUI(start, end, total, page, totalPages) {
    var rangeEl = document.getElementById("devices-page-range");
    var totalEl = document.getElementById("devices-total-count");
    var pageEl = document.getElementById("devices-current-page");
    var totalPagesEl = document.getElementById("devices-total-pages");
    var prevBtn = document.getElementById("devices-prev-page");
    var nextBtn = document.getElementById("devices-next-page");

    if (rangeEl) rangeEl.innerText = total > 0 ? (start + "–" + end) : "0–0";
    if (totalEl) totalEl.innerText = total.toLocaleString();
    if (pageEl) pageEl.innerText = page;
    if (totalPagesEl) totalPagesEl.innerText = totalPages;
    if (prevBtn) prevBtn.disabled = (page <= 1);
    if (nextBtn) nextBtn.disabled = (page >= totalPages);
}

function renderDeviceProfilesTable() {
    var tbody = document.getElementById("device-profiles-tbody");
    var monTbody = document.getElementById("mon-devices-tbody");
    var totalDevices = allFetchedDevices.length;
    var totalPages = Math.max(1, Math.ceil(totalDevices / devicesPageSize));

    if (devicesCurrentPage > totalPages) devicesCurrentPage = totalPages;
    if (devicesCurrentPage < 1) devicesCurrentPage = 1;

    console.log("[NEXz Device Profiler] Rendering device page " + devicesCurrentPage + "/" + totalPages + " (" + totalDevices + " devices in memory)");

    // Update Dashboard Behaviour badge
    var dashDevBadge = document.getElementById("dash-devices-badge");
    var dashDevDesc = document.getElementById("dash-devices-desc");
    if (dashDevBadge) {
        dashDevBadge.innerText = totalDevices + " Profiled";
    }
    if (dashDevDesc) {
        dashDevDesc.innerText = "Tracking " + totalDevices + " hosts in bounded LRU memory";
    }

    // Update System Status HST metrics
    var compHstCap = document.getElementById("comp-hst-cap");
    if (compHstCap) compHstCap.innerText = totalDevices + " / 200";

    if (totalDevices === 0) {
        if (tbody) tbody.innerHTML = '<tr><td colspan="8" class="text-center text-secondary" style="padding:24px;"><i class="fa-solid fa-fingerprint"></i> Awaiting device flows... No hosts profiled yet.</td></tr>';
        if (monTbody) monTbody.innerHTML = '<tr><td colspan="7" class="text-center text-secondary" style="padding:24px;">Awaiting network devices...</td></tr>';
        updateDevicesPaginationUI(0, 0, 0, 1, 1);
        return;
    }

    var startIdx = (devicesCurrentPage - 1) * devicesPageSize;
    var endIdx = Math.min(startIdx + devicesPageSize, totalDevices);
    var pageDevices = allFetchedDevices.slice(startIdx, endIdx);

    if (tbody) tbody.innerHTML = "";
    if (monTbody) monTbody.innerHTML = "";

    // Automatically select the first device for the comparison pane
    if (pageDevices.length > 0) {
        renderDeviceComparison(pageDevices[0]);
    }

    pageDevices.forEach(function (d) {
        var firstSeen = d.first_seen || "-";
        var lastSeen = d.last_seen || "-";
        var count = d.sample_count !== undefined ? d.sample_count : (d.flow_count !== undefined ? d.flow_count : 0);
        var bytes = d.avg_bytes !== undefined ? d.avg_bytes : 0;
        var bytesStr = bytes > 1048576 
            ? (bytes / 1048576).toFixed(2) + " MB" 
            : (bytes > 1024 ? (bytes / 1024).toFixed(1) + " KB" : bytes.toFixed(0) + " B");
        var totalB = d.total_bytes !== undefined ? d.total_bytes : 0;
        var totalBStr = totalB > 1048576 
            ? (totalB / 1048576).toFixed(2) + " MB" 
            : (totalB > 1024 ? (totalB / 1024).toFixed(1) + " KB" : totalB.toFixed(0) + " B");
        var dur = d.avg_duration_sec !== undefined ? d.avg_duration_sec.toFixed(2) + "s" : "0.00s";
        var score = d.recent_score !== undefined ? d.recent_score : (d.anomaly_score !== undefined ? d.anomaly_score : 0.0);
        var scoreStr = score.toFixed(2);

        var stateHtml = "";
        if (d.status === "Warming Up" || count < 20) {
            stateHtml = '<span class="badge bg-info"><i class="fa-solid fa-hourglass-half"></i> Warming Up (' + count + '/20)</span>';
        } else if (d.status === "Anomalous" || d.recent_alert || score >= 0.70) {
            stateHtml = '<span class="badge bg-danger"><i class="fa-solid fa-triangle-exclamation"></i> Anomalous Spike</span>';
        } else {
            stateHtml = '<span class="badge bg-success"><i class="fa-solid fa-shield-check"></i> Baseline Stable</span>';
        }

        var scoreColor = (score >= 0.70 || d.recent_alert) ? "var(--color-malicious)" : (score >= 0.40 ? "var(--color-warning)" : "var(--text-secondary)");

        // 1. Row for Security Pillar Behaviour Profiles
        if (tbody) {
            var trSec = document.createElement("tr");
            trSec.style.cursor = "pointer";
            trSec.title = "Click to inspect normal baseline vs current telemetry in Comparison Pane";
            trSec.innerHTML = 
                '<td><code>' + escapeHtml(d.ip || d.device_ip || "Unknown") + '</code></td>' +
                '<td>' + firstSeen + '</td>' +
                '<td>' + lastSeen + '</td>' +
                '<td><strong>' + count.toLocaleString() + '</strong></td>' +
                '<td>' + bytesStr + '</td>' +
                '<td>' + dur + '</td>' +
                '<td style="font-weight:700; color:' + scoreColor + ';">' + scoreStr + '</td>' +
                '<td>' + stateHtml + '</td>';
            trSec.addEventListener("click", function () {
                renderDeviceComparison(d);
            });
            tbody.appendChild(trSec);
        }

        // 2. Row for Monitor Pillar Devices Directory
        if (monTbody) {
            var trMon = document.createElement("tr");
            var protos = d.protocols || {};
            var protoStr = Object.keys(protos).slice(0, 3).join(", ") || "TCP/UDP";
            trMon.innerHTML = 
                '<td><code>' + escapeHtml(d.ip || d.device_ip || "Unknown") + '</code></td>' +
                '<td>' + firstSeen + '</td>' +
                '<td>' + lastSeen + '</td>' +
                '<td><strong>' + count.toLocaleString() + '</strong></td>' +
                '<td>' + totalBStr + '</td>' +
                '<td><span class="protocol-tag">' + escapeHtml(protoStr) + '</span></td>' +
                '<td>' + stateHtml + '</td>';
            monTbody.appendChild(trMon);
        }
    });

    updateDevicesPaginationUI(startIdx + 1, endIdx, totalDevices, devicesCurrentPage, totalPages);
}

function pollDeviceProfiles() {
    fnFetch("/api/security/device-profiles").then(function (res) {
        if (!res || !res.ok) return null;
        return res.json();
    }).then(function (resData) {
        if (!resData || resData.status !== "success") return;
        var stats = resData.stats || {};
        allFetchedDevices = resData.devices || [];

        // Update LRU capacity badge
        var badge = document.getElementById("device-lru-badge");
        if (badge) {
            var activeCount = stats.active_devices_tracked !== undefined ? stats.active_devices_tracked : allFetchedDevices.length;
            var maxCap = stats.max_device_capacity !== undefined ? stats.max_device_capacity : 200;
            var evictions = stats.total_evictions !== undefined ? stats.total_evictions : 0;
            badge.innerText = activeCount + " / " + maxCap + " Devices (" + evictions + " Evictions)";
        }

        renderDeviceProfilesTable();
    }).catch(function (e) {
        console.warn("[NEXz Device Profiler] Poll failed:", e);
    });
}

// ==========================================
// CHARTS (Chart.js)
// ==========================================
function initCharts() {
    var throughputCanvas = document.getElementById("longitudinal-chart") || document.getElementById("traffic-line-chart");
    if (throughputCanvas) {
        var throughputCtx = throughputCanvas.getContext("2d");
        throughputChart = new Chart(throughputCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Traffic Volume (Bytes)',
                    data: [],
                    borderColor: '#4f46e5',
                    backgroundColor: 'rgba(79, 70, 229, 0.08)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.3,
                    pointRadius: 3
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: { ticks: { color: getChartTextColor(), font: { size: 12, weight: '600' } } },
                    y: {
                        grid: { color: getChartGridColor() },
                        ticks: { color: getChartTextColor(), font: { size: 12, weight: '600' } },
                        beginAtZero: true
                    }
                },
                plugins: { legend: { display: false } }
            }
        });
    }

    var incidentsCanvas = document.getElementById("incidents-history-chart") || document.getElementById("incidents-bar-chart");
    if (incidentsCanvas) {
        var incidentsCtx = incidentsCanvas.getContext("2d");
        incidentsChart = new Chart(incidentsCtx, {
            type: 'bar',
            data: {
                labels: [],
                datasets: [{
                    label: 'Incident Alerts',
                    data: [],
                    backgroundColor: '#dc2626',
                    borderRadius: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: { ticks: { color: getChartTextColor(), font: { size: 12, weight: '600' } } },
                    y: {
                        grid: { color: getChartGridColor() },
                        ticks: { color: getChartTextColor(), font: { size: 12, weight: '600' } },
                        beginAtZero: true
                    }
                },
                plugins: { legend: { display: false } }
            }
        });
    }

    var protocolCanvas = document.getElementById("protocol-donut-chart") || document.getElementById("protocol-doughnut-chart");
    if (protocolCanvas) {
        var protocolCtx = protocolCanvas.getContext("2d");
        protocolChart = new Chart(protocolCtx, {
            type: 'doughnut',
            data: {
                labels: ['TCP', 'UDP', 'ICMP', 'DNS', 'HTTP', 'HTTPS'],
                datasets: [{
                    data: [0, 0, 0, 0, 0, 0],
                    backgroundColor: ['#4f46e5', '#2563eb', '#059669', '#d97706', '#7c3aed', '#db2777'],
                    borderWidth: 2,
                    borderColor: '#ffffff',
                    hoverOffset: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '68%',
                plugins: {
                    legend: { display: false }
                }
            }
        });
    }

        var dashCanvas = document.getElementById("dash-throughput-chart");
    if (dashCanvas) {
        var dashCtx = dashCanvas.getContext("2d");
        var dLabels = [];
        var dData = [];
        for (var i = 10; i >= 0; i--) {
            dLabels.push(i === 0 ? "Now" : "-" + (i * 5) + "s");
            dData.push(0);
        }
        dashThroughputChart = new Chart(dashCtx, {
            type: 'line',
            data: {
                labels: dLabels,
                datasets: [{
                    label: 'Velocity (Bytes / 5s)',
                    data: dData,
                    borderColor: '#0f766e',
                    backgroundColor: 'rgba(15, 118, 110, 0.08)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.3,
                    pointRadius: 3
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: { ticks: { color: getChartTextColor(), font: { size: 11, weight: '600' } } },
                    y: {
                        grid: { color: getChartGridColor() },
                        ticks: { color: getChartTextColor(), font: { size: 11, weight: '600' } },
                        beginAtZero: true
                    }
                },
                plugins: { legend: { display: false } }
            }
        });
    }

    var monitorCanvas = document.getElementById("monitor-throughput-chart");
    if (monitorCanvas) {
        var monitorCtx = monitorCanvas.getContext("2d");
        var initialLabels = [];
        var initialData = [];
        for (var i = 10; i >= 0; i--) {
            initialLabels.push(i === 0 ? "Now" : "-" + (i * 5) + "s");
            initialData.push(0);
        }
        monitorChart = new Chart(monitorCtx, {
            type: 'line',
            data: {
                labels: initialLabels,
                datasets: [{
                    label: 'Ingestion Rate (Bytes / 5s)',
                    data: initialData,
                    borderColor: '#2563eb',
                    backgroundColor: 'rgba(37, 99, 235, 0.08)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.3,
                    pointRadius: 3
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: { ticks: { color: getChartTextColor(), font: { size: 12, weight: '600' } } },
                    y: {
                        grid: { color: getChartGridColor() },
                        ticks: { color: getChartTextColor(), font: { size: 12, weight: '600' } },
                        beginAtZero: true
                    }
                },
                plugins: { legend: { display: false } }
            }
        });

        // 5-second interval rolling update for monitorChart
        setInterval(function () {
            if (!monitorChart) return;
            var currentBytes = totalBytesLastInterval;
            totalBytesLastInterval = 0; // reset window
            monitorChart.data.datasets[0].data.shift();
            monitorChart.data.datasets[0].data.push(currentBytes);
            monitorChart.update();

            if (dashThroughputChart) {
                dashThroughputChart.data.datasets[0].data.shift();
                dashThroughputChart.data.datasets[0].data.push(currentBytes);
                dashThroughputChart.update();
            }
        }, 5000);
    }
}

function refreshAnalyticsCharts() {
    fnFetch("/api/analytics/history").then(function (res) {
        if (!res) return;
        return res.json();
    }).then(function (bins) {
        if (!bins) return;

        var labels = bins.map(function (b) { return b.time; });
        var bytesData = bins.map(function (b) { return b.bytes; });
        var alertsData = bins.map(function (b) { return b.alerts; });

        if (throughputChart) {
            throughputChart.data.labels = labels;
            throughputChart.data.datasets[0].data = bytesData;
            throughputChart.update();
        }

        if (incidentsChart) {
            incidentsChart.data.labels = labels;
            incidentsChart.data.datasets[0].data = alertsData;
            incidentsChart.update();
        }
    }).catch(function (e) {
        console.error("Historical analytics update failed:", e);
    });
}

// ==========================================
// OVERVIEW INCIDENT GRID
// ==========================================
function refreshOverviewData() {
    refreshRecentAlertsTable();
    refreshAnalyticsCharts();
    refreshTopTalkersAndPorts();
}

function refreshRecentAlertsTable() {
    var tableBody = document.querySelector("#recent-alerts-table tbody");
    fnFetch("/api/alerts").then(function (res) {
        if (!res) return;
        return res.json();
    }).then(function (alerts) {
        if (!alerts) return;
        tableBody.innerHTML = "";
        if (alerts.length === 0) {
            tableBody.innerHTML = '<tr><td colspan="8" class="text-center text-secondary">No recent security warnings. System clean.</td></tr>';
            return;
        }
        alerts.slice(0, 5).forEach(function (alert) {
            var date = new Date(alert.timestamp);
            var row = document.createElement("tr");
            row.style.cursor = "pointer";
            row.innerHTML =
                '<td>' + date.toLocaleTimeString() + '</td>' +
                '<td><strong>' + alert.src_ip + '</strong></td>' +
                '<td><strong>' + alert.dest_ip + '</strong></td>' +
                '<td><span class="protocol-tag">' + alert.protocol + '</span></td>' +
                '<td><span class="threat-badge ' + alert.threat_level.toLowerCase() + '">' + alert.threat_level + '</span></td>' +
                '<td><strong>x' + (alert.count || 1) + '</strong></td>' +
                '<td style="text-decoration: underline;">' + (alert.notes ? alert.notes.split(" | ")[0] : 'Anomalous Connection') + '</td>' +
                '<td><button class="btn-resolve" onclick="event.stopPropagation(); resolveAlert(' + alert.id + ')">Resolve</button></td>';
            
            row.addEventListener("click", function() {
                openXAIModal(alert);
            });
            tableBody.appendChild(row);
        });
    }).catch(function (err) {
        console.error("Recent alerts fetch failed:", err);
    });
}

function acknowledgeAlert(alertId) {
    fnFetch("/api/alerts/acknowledge/" + alertId, { method: "POST" }).then(function (res) {
        if (res && res.ok) {
            console.log("[NEXz AlertManager] Alert " + alertId + " acknowledged.");
            pollSystemStatus();
            if (currentView === "overview-view") {
                refreshRecentAlertsTable();
            } else {
                loadAlerts();
            }
            if (currentModalAlert && currentModalAlert.id === alertId) {
                var stBadge = document.getElementById("modal-status-badge");
                if (stBadge) stBadge.innerText = "Status: Acknowledged";
            }
        }
    }).catch(function (e) {
        console.error("Acknowledge failed:", e);
    });
}

function resolveAlert(alertId) {
    fnFetch("/api/alerts/resolve/" + alertId, { method: "POST" }).then(function (res) {
        if (res && res.ok) {
            console.log("[NEXz AlertManager] Alert " + alertId + " resolved.");
            pollSystemStatus();
            if (currentView === "overview-view") {
                refreshRecentAlertsTable();
            } else {
                loadAlerts();
            }
            var modal = document.getElementById("xai-modal");
            if (modal && currentModalAlert && currentModalAlert.id === alertId) {
                modal.classList.remove("active");
            }
        }
    }).catch(function (e) {
        console.error("Resolve failed:", e);
    });
}

// ==========================================
// ALERTS VIEW (FILTER & SEARCH)
// ==========================================
function updateAlertsPaginationUI(start, end, total, page, totalPages) {
    var rangeEl = document.getElementById("alerts-page-range");
    var totalEl = document.getElementById("alerts-total-count");
    var pageEl = document.getElementById("alerts-current-page");
    var totalPagesEl = document.getElementById("alerts-total-pages");
    var prevBtn = document.getElementById("alerts-prev-page");
    var nextBtn = document.getElementById("alerts-next-page");

    if (rangeEl) rangeEl.innerText = total > 0 ? (start + "–" + end) : "0–0";
    if (totalEl) totalEl.innerText = total.toLocaleString();
    if (pageEl) pageEl.innerText = page;
    if (totalPagesEl) totalPagesEl.innerText = totalPages;
    if (prevBtn) prevBtn.disabled = (page <= 1);
    if (nextBtn) nextBtn.disabled = (page >= totalPages);
}

function renderFilteredAlerts() {
    var tableBody = document.querySelector("#full-alerts-table tbody");
    if (!tableBody) return;

    var searchInput = document.getElementById("alert-search-ip");
    var ipVal = (searchInput ? searchInput.value.trim().toLowerCase() : "");
    var activeFilterBtn = document.querySelector(".filter-btn.active");
    var activeFilter = activeFilterBtn ? activeFilterBtn.getAttribute("data-filter") : "all";

    allFilteredAlerts = allFetchedAlerts.filter(function (alert) {
        var matchIp = !ipVal || (alert.src_ip && alert.src_ip.toLowerCase().indexOf(ipVal) !== -1) || (alert.dest_ip && alert.dest_ip.toLowerCase().indexOf(ipVal) !== -1);
        var matchSeverity = activeFilter === "all" || (alert.threat_level && alert.threat_level.toLowerCase() === activeFilter.toLowerCase());
        return matchIp && matchSeverity;
    });

    var totalItems = allFilteredAlerts.length;
    var totalPages = Math.max(1, Math.ceil(totalItems / alertsPageSize));

    if (alertsCurrentPage > totalPages) alertsCurrentPage = totalPages;
    if (alertsCurrentPage < 1) alertsCurrentPage = 1;

    console.log("[NEXz Security] Alerts filtered: " + totalItems + " matching items | Page " + alertsCurrentPage + " of " + totalPages + " (page size: " + alertsPageSize + ")");

    tableBody.innerHTML = "";

    if (totalItems === 0) {
        tableBody.innerHTML = '<tr><td colspan="9" class="text-center text-secondary" style="padding:24px;">No active alerts match the query.</td></tr>';
        updateAlertsPaginationUI(0, 0, 0, 1, 1);
        return;
    }

    var startIdx = (alertsCurrentPage - 1) * alertsPageSize;
    var endIdx = Math.min(startIdx + alertsPageSize, totalItems);
    var pageAlerts = allFilteredAlerts.slice(startIdx, endIdx);

    pageAlerts.forEach(function (alert) {
        var date = new Date(alert.timestamp);
        var row = document.createElement("tr");
        row.style.cursor = "pointer";
        var isSim = alert.is_simulated || (alert.notes && alert.notes.indexOf("[SIMULATION]") !== -1);
        var simBadge = isSim ? '<span class="badge badge-sim" style="font-size:10px; margin-right:4px;">SIM</span>' : '';
        var statusClass = alert.status === "New" ? "border-malicious" : (alert.status === "Acknowledged" ? "border-resolved" : "");
        var statusBadge = '<span class="badge badge-status ' + statusClass + '" style="font-size:10px; margin-left:4px;">' + escapeHtml(alert.status || 'Active') + '</span>';
        var diagNote = alert.notes ? alert.notes.split(" | ")[0].replace("[SIMULATION] ", "") : 'Anomalous Transmission';

        row.innerHTML =
            '<td>' + date.toLocaleTimeString() + '</td>' +
            '<td><code>' + escapeHtml(alert.src_ip) + ':' + (alert.src_port || '-') + '</code></td>' +
            '<td><code>' + escapeHtml(alert.dest_ip) + ':' + (alert.dest_port || '-') + '</code></td>' +
            '<td><span class="protocol-tag">' + escapeHtml(alert.protocol || 'TCP') + '</span></td>' +
            '<td>' + simBadge + '<span style="font-weight:600;">' + escapeHtml(diagNote) + '</span></td>' +
            '<td><span class="threat-badge ' + (alert.threat_level || 'normal').toLowerCase() + '">' + escapeHtml(alert.threat_level || 'Normal') + '</span>' + statusBadge + '</td>' +
            '<td><strong>x' + (alert.count || 1) + '</strong></td>' +
            '<td>' + ((alert.confidence || 0) * 100).toFixed(1) + '%</td>' +
            '<td>' +
                '<div style="display:flex; gap:4px;">' +
                    '<button class="btn-xs btn-outline" title="Acknowledge alert" onclick="event.stopPropagation(); acknowledgeAlert(' + alert.id + ')">Ack</button>' +
                    '<button class="btn-resolve" title="Mark alert as resolved" onclick="event.stopPropagation(); resolveAlert(' + alert.id + ')">Resolve</button>' +
                '</div>' +
            '</td>';
        
        row.addEventListener("click", function() {
            console.log("[NEXz Security] Opening XAI diagnostic modal for alert ID " + alert.id);
            openXAIModal(alert);
        });
        tableBody.appendChild(row);
    });

    updateAlertsPaginationUI(startIdx + 1, endIdx, totalItems, alertsCurrentPage, totalPages);
}

var allFetchedAlerts = [];

function loadAlerts() {
    var searchInput = document.getElementById("alert-search-ip");

    fnFetch("/api/alerts").then(function (res) {
        if (!res) return;
        return res.json();
    }).then(function (alerts) {
        if (!alerts) return;
        allFetchedAlerts = alerts;
        console.log("[NEXz Security Feed] Ingested " + alerts.length + " active security alerts from database.");

        // Tally severity counters for Security Pillar
        var critCount = 0;
        var highCount = 0;
        var medCount = 0;
        var hasArpPoison = false;

        alerts.forEach(function (a) {
            var lvl = (a.threat_level || "").toLowerCase();
            if (lvl === "critical") critCount += (a.count || 1);
            else if (lvl === "high") highCount += (a.count || 1);
            else medCount += (a.count || 1);

            if (a.protocol === "ARP" || (a.notes && a.notes.indexOf("ARP") !== -1)) {
                hasArpPoison = true;
            }
        });

        var critEl = document.getElementById("sec-critical-count");
        var highEl = document.getElementById("sec-high-count");
        var medEl = document.getElementById("sec-medium-count");
        if (critEl) critEl.innerText = critCount;
        if (highEl) highEl.innerText = highCount;
        if (medEl) medEl.innerText = medCount;

        var arpBadge = document.getElementById("arp-status-badge");
        if (arpBadge) {
            if (hasArpPoison) {
                arpBadge.className = "badge bg-danger";
                arpBadge.innerHTML = '<i class="fa-solid fa-triangle-exclamation"></i> Spoofing Detected';
            } else {
                arpBadge.className = "badge bg-success";
                arpBadge.innerHTML = '<i class="fa-solid fa-check"></i> Subnet Clean';
            }
        }

        renderFilteredAlerts();
    }).catch(function (err) {
        console.error("[NEXz Security] Alerts load error:", err);
    });

    if (searchInput) {
        searchInput.oninput = function () {
            alertsCurrentPage = 1;
            renderFilteredAlerts();
        };
    }

    var filters = document.querySelectorAll(".filter-btn");
    filters.forEach(function (btn) {
        btn.onclick = function () {
            filters.forEach(function (b) { b.classList.remove("active"); });
            btn.classList.add("active");
            alertsCurrentPage = 1;
            renderFilteredAlerts();
        };
    });
}

// ==========================================
// LOGS VIEW (MULTI-PARAMETER FILTERS)
// ==========================================
function updateLogsPaginationUI(start, end, total, page, totalPages) {
    var rangeEl = document.getElementById("logs-page-range");
    var totalEl = document.getElementById("logs-total-count");
    var pageEl = document.getElementById("logs-current-page");
    var totalPagesEl = document.getElementById("logs-total-pages");
    var prevBtn = document.getElementById("logs-prev-page");
    var nextBtn = document.getElementById("logs-next-page");

    if (rangeEl) rangeEl.innerText = total > 0 ? (start + "–" + end) : "0–0";
    if (totalEl) totalEl.innerText = total.toLocaleString();
    if (pageEl) pageEl.innerText = page;
    if (totalPagesEl) totalPagesEl.innerText = totalPages;
    if (prevBtn) prevBtn.disabled = (page <= 1);
    if (nextBtn) nextBtn.disabled = (page >= totalPages);
}

var allFetchedLogs = [];

function renderFilteredLogs() {
    var tableBody = document.querySelector("#full-logs-table tbody");
    if (!tableBody) return;

    var searchInput = document.getElementById("log-search-ip");
    var sourceFilter = document.getElementById("log-filter-source");
    var protoFilter = document.getElementById("log-filter-proto");
    var labelFilter = document.getElementById("log-filter-label");

    var ipVal = searchInput ? searchInput.value.trim().toLowerCase() : "";
    var sourceVal = sourceFilter ? sourceFilter.value : "all";
    var protoVal = protoFilter ? protoFilter.value : "all";
    var labelVal = labelFilter ? labelFilter.value : "all";

    allFilteredLogs = allFetchedLogs.filter(function (log) {
        var matchIp = !ipVal || (log.src_ip && log.src_ip.toLowerCase().indexOf(ipVal) !== -1) || (log.dest_ip && log.dest_ip.toLowerCase().indexOf(ipVal) !== -1);
        var matchSource = sourceVal === "all" || log.source === sourceVal;
        var matchProto = protoVal === "all" || (log.protocol && log.protocol.toUpperCase() === protoVal.toUpperCase());
        var matchLabel = labelVal === "all" || (log.prediction_label && log.prediction_label.toLowerCase() === labelVal.toLowerCase());
        return matchIp && matchSource && matchProto && matchLabel;
    });

    var totalItems = allFilteredLogs.length;
    var totalPages = Math.max(1, Math.ceil(totalItems / logsPageSize));

    if (logsCurrentPage > totalPages) logsCurrentPage = totalPages;
    if (logsCurrentPage < 1) logsCurrentPage = 1;

    console.log("[NEXz Monitoring] Flow logs filtered: " + totalItems + " matching items | Page " + logsCurrentPage + " of " + totalPages + " (page size: " + logsPageSize + ")");

    tableBody.innerHTML = "";

    if (totalItems === 0) {
        tableBody.innerHTML = '<tr><td colspan="9" class="text-center text-secondary" style="padding:24px;">No traffic records match parameters.</td></tr>';
        updateLogsPaginationUI(0, 0, 0, 1, 1);
        return;
    }

    var startIdx = (logsCurrentPage - 1) * logsPageSize;
    var endIdx = Math.min(startIdx + logsPageSize, totalItems);
    var pageLogs = allFilteredLogs.slice(startIdx, endIdx);

    pageLogs.forEach(function (log) {
        var date = new Date(log.timestamp);
        var row = document.createElement("tr");
        row.style.cursor = "pointer";
        row.innerHTML =
            '<td>' + date.toLocaleTimeString() + '</td>' +
            '<td><code>' + escapeHtml(log.src_ip) + ':' + (log.src_port || '-') + '</code></td>' +
            '<td><code>' + escapeHtml(log.dest_ip) + ':' + (log.dest_port || '-') + '</code></td>' +
            '<td><span class="protocol-tag">' + escapeHtml(log.protocol || 'TCP') + '</span></td>' +
            '<td>' + (log.total_bytes !== undefined ? log.total_bytes.toLocaleString() : 0) + ' B</td>' +
            '<td><span class="threat-badge ' + (log.prediction_label || 'normal').toLowerCase() + '">' + escapeHtml(log.prediction_label || 'Normal') + '</span></td>' +
            '<td>' + ((log.confidence_score || 0) * 100).toFixed(1) + '%</td>' +
            '<td>' + escapeHtml(log.connection_state || 'ESTABLISHED') + '</td>' +
            '<td><span style="font-family:monospace; font-size:11px;">' + escapeHtml(log.info || '-') + '</span></td>';
        
        row.addEventListener("click", function() {
            console.log("[NEXz Monitoring] Inspecting flow: " + log.src_ip + " -> " + log.dest_ip);
            openLogDrawer(log);
        });
        tableBody.appendChild(row);
    });

    updateLogsPaginationUI(startIdx + 1, endIdx, totalItems, logsCurrentPage, totalPages);
}

function loadLogs() {
    var searchInput = document.getElementById("log-search-ip");
    var sourceFilter = document.getElementById("log-filter-source");
    var protoFilter = document.getElementById("log-filter-proto");
    var labelFilter = document.getElementById("log-filter-label");

    fnFetch("/api/logs?limit=250").then(function (res) {
        if (!res) return;
        return res.json();
    }).then(function (logs) {
        if (!logs) return;
        allFetchedLogs = logs;
        console.log("[NEXz Monitoring] Ingested " + logs.length + " flow records from sensor.");
        
        if (sourceFilter) {
            var uniqueSources = new Set();
            logs.forEach(function(l) {
                if (l.source && l.source !== "live") {
                    uniqueSources.add(l.source);
                }
            });
            var prevVal = sourceFilter.value;
            sourceFilter.innerHTML = '<option value="all">All Sources</option><option value="live">Live Capture</option>';
            uniqueSources.forEach(function(src) {
                var opt = document.createElement("option");
                opt.value = src;
                opt.innerText = src.replace("pcap:", "");
                sourceFilter.appendChild(opt);
            });
            sourceFilter.value = prevVal;
            if (sourceFilter.value === "") {
                sourceFilter.value = "all";
            }
        }

        renderFilteredLogs();
    }).catch(function (e) {
        console.error("[NEXz Monitoring] Logs fetch failed:", e);
    });

    if (searchInput) {
        searchInput.oninput = function () {
            logsCurrentPage = 1;
            renderFilteredLogs();
        };
    }
    if (sourceFilter) {
        sourceFilter.onchange = function () {
            logsCurrentPage = 1;
            renderFilteredLogs();
        };
    }
    if (protoFilter) {
        protoFilter.onchange = function () {
            logsCurrentPage = 1;
            renderFilteredLogs();
        };
    }
    if (labelFilter) {
        labelFilter.onchange = function () {
            logsCurrentPage = 1;
            renderFilteredLogs();
        };
    }
}

// ==========================================
// AI MODEL METRICS
// ==========================================
function loadModelMetrics() {
    fnFetch("/api/model/metrics").then(function (res) {
        if (!res) return;
        return res.json();
    }).then(function (metrics) {
        if (!metrics) return;
        var accPct = (metrics.rolling_accuracy * 100).toFixed(2) + "%";
        var samCount = (metrics.samples_processed || 0).toLocaleString();
        var winWidth = metrics.drift_width || 0;
        var varianceVal = (metrics.drift_variance !== undefined ? metrics.drift_variance : metrics.drift_estimation || 0.0).toFixed(4);

        var accEl = document.getElementById("model-accuracy-text");
        if (accEl) accEl.innerText = accPct;
        var samEl = document.getElementById("model-samples-text");
        if (samEl) samEl.innerText = samCount;

        var dWin = document.getElementById("drift-win-size");
        if (dWin) dWin.innerText = winWidth;
        var dVar = document.getElementById("drift-variance");
        if (dVar) dVar.innerText = varianceVal;

        // Elevated Threat Detection overview card
        var tSam = document.getElementById("threat-samples-processed");
        if (tSam) tSam.innerText = samCount;
        var tAcc = document.getElementById("threat-rolling-accuracy");
        if (tAcc) tAcc.innerText = accPct;

        // Dashboard Summary Card
        var dashArfDesc = document.getElementById("dash-arf-desc");
        if (dashArfDesc) dashArfDesc.innerText = samCount + " flows evaluated | Accuracy: " + accPct;
        var dashAdwinDesc = document.getElementById("dash-adwin-desc");
        if (dashAdwinDesc) dashAdwinDesc.innerText = "Window: " + winWidth + " | Error Var: " + varianceVal;

        // System Status Deck
        var compMlSam = document.getElementById("comp-ml-samples");
        if (compMlSam) compMlSam.innerText = samCount;
        var compMlAcc = document.getElementById("comp-ml-acc");
        if (compMlAcc) compMlAcc.innerText = accPct;
        var compAdwinW = document.getElementById("comp-adwin-w");
        if (compAdwinW) compAdwinW.innerText = winWidth;
    }).catch(function (e) {
        console.error("Model metrics fetch failed:", e);
    });
}

// ==========================================
// ACTIVE CAPTURE CONTROLS (PLAY/PAUSE & NIC SELECTOR)
// ==========================================
function setupSystemControl() {
    var btnToggle = document.getElementById("btn-toggle-sniff-header");
    var btnMonitor = document.getElementById("btn-monitor-toggle");
    var selectNicHeader = document.getElementById("select-nic-header");

    function executeSniffToggle() {
        console.log("[NEXz Telemetry] Sniffer toggle requested by user.");
        fnFetch("/api/system/status").then(function (res) {
            return res ? res.json() : null;
        }).then(function (statusData) {
            if (!statusData) return;
            if (statusData.sniffer_running) {
                fnFetch("/api/traffic/stop", { method: "POST" }).then(function (res) {
                    if (res && res.ok) {
                        showToastAlert({ label: "Normal", notes: "Capture monitoring paused." }, "Monitoring Paused");
                        pollSystemStatus();
                    }
                });
            } else {
                var targetInterface = (selectNicHeader && selectNicHeader.value) ? selectNicHeader.value : "Wi-Fi";
                fnFetch("/api/traffic/start?interface=" + targetInterface, { method: "POST" }).then(function (res) {
                    if (res && res.ok) {
                        showToastAlert({ label: "Normal", notes: "Sniffing monitoring resumed on " + targetInterface }, "Monitoring Resumed");
                        pollSystemStatus();
                    }
                });
            }
        });
    }

    if (btnToggle) {
        btnToggle.addEventListener("click", executeSniffToggle);
    }
    if (btnMonitor) {
        btnMonitor.addEventListener("click", executeSniffToggle);
    }

    var btnRefreshProfile = document.getElementById("btn-refresh-profile");
    if (btnRefreshProfile) {
        btnRefreshProfile.addEventListener("click", function () {
            var icon = btnRefreshProfile.querySelector("i");
            if (icon) icon.classList.add("animate-spin");
            pollProfileStatus();
            setTimeout(function () {
                if (icon) icon.classList.remove("animate-spin");
            }, 600);
        });
    }

    if (selectNicHeader) {
        selectNicHeader.addEventListener("change", function () {
            var targetIface = selectNicHeader.value;
            fnFetch("/api/system/status").then(function(r) { return r ? r.json() : null; }).then(function(statusData) {
                if (statusData && statusData.sniffer_running) {
                    // Stop first, then restart
                    fnFetch("/api/traffic/stop", { method: "POST" }).then(function () {
                        return fnFetch("/api/traffic/start?interface=" + targetIface, { method: "POST" });
                    }).then(function (res) {
                        if (res && res.ok) {
                            showToastAlert({ label: "Normal", notes: "Switched active capture to NIC: " + targetIface }, "Interface Switched");
                            pollSystemStatus();
                        }
                    });
                }
            });
        });
    }
}

// ==========================================
// SETTINGS
// ==========================================
function loadNICDropdowns() {
    var selectNic = document.getElementById("select-nic");
    var selectNicHeader = document.getElementById("select-nic-header");
    var selectNicInline = document.getElementById("select-nic-inline");
    fnFetch("/api/traffic/interfaces").then(function (res) {
        if (!res) return;
        return res.json();
    }).then(function (nics) {
        if (!nics) return;
        if (selectNic) selectNic.innerHTML = "";
        if (selectNicHeader) selectNicHeader.innerHTML = "";
        if (selectNicInline) selectNicInline.innerHTML = "";
        nics.forEach(function (nic) {
            var opt1 = document.createElement("option");
            opt1.value = nic;
            opt1.innerText = nic;
            if (selectNic) selectNic.appendChild(opt1);

            var opt2 = document.createElement("option");
            opt2.value = nic;
            opt2.innerText = nic;
            if (selectNicHeader) selectNicHeader.appendChild(opt2);

            var opt3 = document.createElement("option");
            opt3.value = nic;
            opt3.innerText = nic;
            if (selectNicInline) selectNicInline.appendChild(opt3);
        });

        // Sync active NIC selection
        fnFetch("/api/system/status").then(function (r) { return r ? r.json() : null; }).then(function (statusData) {
            if (statusData && statusData.active_interface) {
                if (selectNic) selectNic.value = statusData.active_interface;
                if (selectNicHeader) selectNicHeader.value = statusData.active_interface;
                if (selectNicInline) selectNicInline.value = statusData.active_interface;
            }
        });
    }).catch(function (e) {
        console.error("NIC list failed:", e);
    });
}

function loadSettingsData() {
    loadNICDropdowns();
    fnFetch("/api/settings/config").then(function (res) {
        if (!res || !res.ok) return null;
        return res.json();
    }).then(function (cfg) {
        if (!cfg) return;
        var modeSelect = document.getElementById("select-monitoring-mode");
        if (modeSelect && cfg.monitoring_mode) {
            modeSelect.value = cfg.monitoring_mode;
        }
        var timeoutSelect = document.getElementById("select-timeout");
        if (timeoutSelect && cfg.inactivity_timeout) {
            timeoutSelect.value = String(cfg.inactivity_timeout);
        }
        var windowSelect = document.getElementById("select-aggregation-window");
        if (windowSelect && cfg.alert_aggregation_window) {
            windowSelect.value = String(cfg.alert_aggregation_window);
        }
    }).catch(function (e) {
        console.warn("Settings fetch failed:", e);
    });
}

function setupSettingsActions() {
    var saveButtons = [document.getElementById("btn-save-settings"), document.getElementById("btn-save-settings-inline")];
    
    saveButtons.forEach(function (btnSave) {
        if (!btnSave) return;
        btnSave.onclick = function () {
            var modeSelect = document.getElementById("select-monitoring-mode-inline") || document.getElementById("select-monitoring-mode");
            var timeoutSelect = document.getElementById("select-timeout-inline") || document.getElementById("select-timeout");
            var windowSelect = document.getElementById("select-aggregation-window-inline") || document.getElementById("select-aggregation-window");

            var payload = {
                monitoring_mode: modeSelect ? modeSelect.value : "manual",
                inactivity_timeout: timeoutSelect ? parseFloat(timeoutSelect.value) : 2.0,
                alert_aggregation_window: windowSelect ? parseFloat(windowSelect.value) : 30.0
            };

            btnSave.disabled = true;
            btnSave.innerHTML = '<i class="fa-solid fa-spinner animate-spin"></i> Saving...';

            fnFetch("/api/settings/config", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            }).then(function (res) {
                if (!res || !res.ok) throw new Error("Failed to save settings");
                return res.json();
            }).then(function (data) {
                showToastAlert({ label: "Normal", notes: "Configuration saved: " + payload.monitoring_mode.toUpperCase() + " monitoring mode active." }, "Settings Saved");
                var settingsModal = document.getElementById("settings-modal");
                if (settingsModal) {
                    setTimeout(function () {
                        settingsModal.classList.remove("active");
                    }, 400);
                }
            }).catch(function (e) {
                alert("Error saving configuration: " + e.message);
            }).finally(function () {
                btnSave.disabled = false;
                btnSave.innerHTML = '<i class="fa-solid fa-floppy-disk"></i> Save Configuration';
            });
        };
    });
}

function setupDropzone() {
    var dropzones = [
        { drop: document.getElementById("pcap-dropzone"), input: document.getElementById("pcap-file-input"), status: document.getElementById("pcap-upload-status") },
        { drop: document.getElementById("pcap-dropzone-inline"), input: document.getElementById("pcap-file-input-inline"), status: document.getElementById("pcap-upload-status-inline") }
    ];

    dropzones.forEach(function (dz) {
        var dropzone = dz.drop;
        var fileInput = dz.input;
        var uploadStatus = dz.status;
        if (!dropzone || !fileInput) return;

        dropzone.onclick = function () { fileInput.click(); };

        dropzone.addEventListener("dragover", function (e) {
            e.preventDefault();
            dropzone.style.borderColor = "#6366f1";
        });

        dropzone.addEventListener("dragleave", function () {
            dropzone.style.borderColor = "";
        });

        dropzone.addEventListener("drop", function (e) {
            e.preventDefault();
            dropzone.style.borderColor = "";
            if (e.dataTransfer.files.length > 0) {
                handlePcapFile(e.dataTransfer.files[0], uploadStatus);
            }
        });

        fileInput.onchange = function () {
            if (fileInput.files.length > 0) {
                handlePcapFile(fileInput.files[0], uploadStatus);
            }
        };
    });

    function handlePcapFile(file, uploadStatus) {
        var formData = new FormData();
        formData.append("file", file);
        if (uploadStatus) uploadStatus.classList.remove("hide");
        fnFetch("/api/traffic/upload", { method: "POST", body: formData }).then(function (res) {
            if (res && res.ok) {
                showToastAlert({ label: "Normal", notes: "PCAP upload complete. Extractor running in background task." }, "PCAP Uploaded");
            } else {
                alert("Upload failed. Ensure document is a valid .pcap format.");
            }
        }).catch(function (e) {
            console.error("Upload aborted:", e);
        }).finally(function () {
            if (uploadStatus) uploadStatus.classList.add("hide");
        });
    }
}

// ==========================================
// REPORT DOWNLOAD ACTIONS
// ==========================================
function setupReportDownloads() {
    var pdfButtons = [
        document.getElementById("btn-export-pdf"),
        document.getElementById("btn-export-pdf-main"),
        document.getElementById("btn-download-pdf")
    ];
    var csvButtons = [
        document.getElementById("btn-export-csv"),
        document.getElementById("btn-export-csv-main"),
        document.getElementById("btn-download-csv")
    ];

    pdfButtons.forEach(function (btn) {
        if (!btn) return;
        btn.addEventListener("click", function () {
            btn.disabled = true;
            var originalHtml = btn.innerHTML;
            btn.innerHTML = '<i class="fa-solid fa-spinner animate-spin"></i> Compiling PDF...';
            fnFetch("/api/reports/pdf").then(function (res) {
                if (!res || !res.ok) throw new Error("Report compilation failed");
                return res.blob();
            }).then(function (blob) {
                var url = window.URL.createObjectURL(blob);
                var a = document.createElement("a");
                a.href = url;
                a.download = "NEXz_Security_Report.pdf";
                document.body.appendChild(a);
                a.click();
                a.remove();
                window.URL.revokeObjectURL(url);
            }).catch(function (e) {
                alert("Failed to export PDF report: " + e.message);
            }).finally(function () {
                btn.disabled = false;
                btn.innerHTML = originalHtml;
            });
        });
    });

    csvButtons.forEach(function (btn) {
        if (!btn) return;
        btn.addEventListener("click", function () {
            btn.disabled = true;
            var originalHtml = btn.innerHTML;
            btn.innerHTML = '<i class="fa-solid fa-spinner animate-spin"></i> Exporting CSV...';
            fnFetch("/api/reports/csv").then(function (res) {
                if (!res || !res.ok) throw new Error("CSV compilation failed");
                return res.blob();
            }).then(function (blob) {
                var url = window.URL.createObjectURL(blob);
                var a = document.createElement("a");
                a.href = url;
                a.download = "NEXz_Traffic_Logs.csv";
                document.body.appendChild(a);
                a.click();
                a.remove();
                window.URL.revokeObjectURL(url);
            }).catch(function (e) {
                alert("Failed to export CSV logs: " + e.message);
            }).finally(function () {
                btn.disabled = false;
                btn.innerHTML = originalHtml;
            });
        });
    });
}

// ==========================================
// RESEARCH TELEMETRY WORKBENCH
// ==========================================
var researchCurrentPage = 1;
var researchPageSize = 15;
var allResearchRecords = [];

function setupResearchWorkbench() {
    var btnToggleDrawer = document.getElementById("btn-toggle-filters-drawer");
    var drawer = document.getElementById("research-filters-drawer");
    if (btnToggleDrawer && drawer) {
        btnToggleDrawer.onclick = function () {
            drawer.classList.toggle("hide");
            var isHidden = drawer.classList.contains("hide");
            btnToggleDrawer.innerHTML = isHidden 
                ? '<i class="fa-solid fa-filter"></i> <span>Expand Query Filters</span>' 
                : '<i class="fa-solid fa-chevron-up"></i> <span>Collapse Query Filters</span>';
        };
    }

    var btnQuery = document.getElementById("btn-run-query") || document.getElementById("btn-run-research-query");
    var btnExport = document.getElementById("btn-export-query-csv") || document.getElementById("btn-export-research-csv");
    var btnReset = document.getElementById("btn-reset-query");

    if (btnQuery) {
        btnQuery.onclick = function () {
            researchCurrentPage = 1;
            runResearchQuery();
        };
    }

    if (btnExport) {
        btnExport.onclick = function () {
            exportResearchCsv();
        };
    }

    if (btnReset) {
        btnReset.onclick = function () {
            if (document.getElementById("res-filter-src-ip")) document.getElementById("res-filter-src-ip").value = "";
            if (document.getElementById("res-filter-dest-ip")) document.getElementById("res-filter-dest-ip").value = "";
            if (document.getElementById("res-filter-proto")) document.getElementById("res-filter-proto").value = "";
            if (document.getElementById("res-filter-label")) document.getElementById("res-filter-label").value = "";
            if (document.getElementById("res-filter-start")) document.getElementById("res-filter-start").value = "";
            if (document.getElementById("res-filter-end")) document.getElementById("res-filter-end").value = "";
            researchCurrentPage = 1;
            runResearchQuery();
        };
    }

    var prevBtn = document.getElementById("research-prev-page");
    var nextBtn = document.getElementById("research-next-page");
    var sizeSelect = document.getElementById("research-page-size");

    if (prevBtn) {
        prevBtn.onclick = function () {
            if (researchCurrentPage > 1) {
                researchCurrentPage--;
                renderResearchPage();
            }
        };
    }
    if (nextBtn) {
        nextBtn.onclick = function () {
            var totalPages = Math.max(1, Math.ceil(allResearchRecords.length / researchPageSize));
            if (researchCurrentPage < totalPages) {
                researchCurrentPage++;
                renderResearchPage();
            }
        };
    }
    if (sizeSelect) {
        sizeSelect.onchange = function () {
            researchPageSize = parseInt(this.value, 10) || 15;
            researchCurrentPage = 1;
            renderResearchPage();
        };
    }
}

function renderResearchPage() {
    var tbody = document.getElementById("res-query-tbody") || document.querySelector("#research-results-table tbody") || document.querySelector("#res-query-table tbody");
    var rangeEl = document.getElementById("research-page-range");
    var totalEl = document.getElementById("research-total-count");
    var prevBtn = document.getElementById("research-prev-page");
    var nextBtn = document.getElementById("research-next-page");

    var total = allResearchRecords.length;
    if (totalEl) totalEl.innerText = total.toLocaleString();

    if (total === 0) {
        if (tbody) {
            tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; padding:30px; color:var(--text-secondary);"><i class="fa-solid fa-inbox"></i> No matching telemetry flows found.</td></tr>';
        }
        if (rangeEl) rangeEl.innerText = "0–0";
        if (prevBtn) prevBtn.disabled = true;
        if (nextBtn) nextBtn.disabled = true;
        return;
    }

    var totalPages = Math.max(1, Math.ceil(total / researchPageSize));
    if (researchCurrentPage > totalPages) researchCurrentPage = totalPages;

    var startIdx = (researchCurrentPage - 1) * researchPageSize;
    var endIdx = Math.min(startIdx + researchPageSize, total);
    var pageSlice = allResearchRecords.slice(startIdx, endIdx);

    if (rangeEl) rangeEl.innerText = (startIdx + 1) + "–" + endIdx;
    if (prevBtn) prevBtn.disabled = researchCurrentPage <= 1;
    if (nextBtn) nextBtn.disabled = researchCurrentPage >= totalPages;

    if (!tbody) return;
    tbody.innerHTML = "";
    pageSlice.forEach(function (f) {
        var tr = document.createElement("tr");
        var badgeClass = "badge-normal";
        var lbl = f.label || f.prediction_label || "Normal";
        if (lbl === "Malicious") badgeClass = "badge-malicious";
        else if (lbl === "Suspicious") badgeClass = "badge-suspicious";

        var ts = f.timestamp ? new Date(f.timestamp).toLocaleTimeString() : "-";
        var bytesVal = f.bytes !== undefined ? f.bytes : (f.total_bytes !== undefined ? f.total_bytes : 0);
        var durVal = f.duration !== undefined ? (typeof f.duration === 'number' ? f.duration.toFixed(2) + 's' : f.duration) : '-';

        tr.innerHTML = 
            '<td>' + ts + '</td>' +
            '<td><code>' + (f.src_ip || "-") + ":" + (f.src_port || "-") + '</code></td>' +
            '<td><code>' + (f.dest_ip || "-") + ":" + (f.dest_port || "-") + '</code></td>' +
            '<td><span class="protocol-tag">' + (f.protocol || "TCP") + '</span></td>' +
            '<td>' + bytesVal.toLocaleString() + ' B</td>' +
            '<td>' + durVal + '</td>' +
            '<td><span class="badge ' + badgeClass + '">' + lbl + '</span></td>' +
            '<td><span class="text-secondary" style="font-size:11px;">' + (f.state || f.connection_state || "ESTABLISHED") + '</span></td>';

        tbody.appendChild(tr);
    });
}

function runResearchQuery() {
    console.log("[NEXz Telemetry] Executing Research & Exploration multi-criteria query.");
    var proto = document.getElementById("res-filter-proto") ? document.getElementById("res-filter-proto").value : "";
    var label = document.getElementById("res-filter-label") ? document.getElementById("res-filter-label").value : "";
    var srcIp = document.getElementById("res-filter-src-ip") ? document.getElementById("res-filter-src-ip").value.trim() : "";
    var destIp = document.getElementById("res-filter-dest-ip") ? document.getElementById("res-filter-dest-ip").value.trim() : "";
    var startTime = document.getElementById("res-filter-start") ? document.getElementById("res-filter-start").value : "";
    var endTime = document.getElementById("res-filter-end") ? document.getElementById("res-filter-end").value : "";
    var source = document.getElementById("res-filter-source") ? document.getElementById("res-filter-source").value : "";
    var batchId = document.getElementById("res-filter-batch") ? document.getElementById("res-filter-batch").value : "";

    var params = new URLSearchParams();
    if (source && source !== "all") params.append("source", source);
    if (batchId) params.append("import_batch_id", batchId);
    if (proto && proto !== "all") params.append("protocol", proto);
    if (label && label !== "all") params.append("prediction_label", label);
    if (srcIp) params.append("src_ip", srcIp);
    if (destIp) params.append("dest_ip", destIp);
    if (startTime) params.append("start_time", startTime);
    if (endTime) params.append("end_time", endTime);
    params.append("limit", "500");

    var btnQuery = document.getElementById("btn-run-query") || document.getElementById("btn-run-research-query");
    if (btnQuery) {
        btnQuery.disabled = true;
        btnQuery.innerHTML = '<i class="fa-solid fa-spinner animate-spin"></i> Filtering...';
    }

    var tbody = document.getElementById("res-query-tbody") || document.querySelector("#research-results-table tbody") || document.querySelector("#res-query-table tbody");
    if (tbody) {
        tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; padding:30px; color:var(--text-secondary);"><i class="fa-solid fa-spinner animate-spin"></i> Querying telemetry store...</td></tr>';
    }

    fnFetch("/api/research/query?" + params.toString()).then(function (res) {
        if (!res || !res.ok) throw new Error("Query execution failed");
        return res.json();
    }).then(function (data) {
        if (!data) return;

        // Update summary counters
        var sum = data.summary || {};
        var cntEl = document.getElementById("res-total-flows") || document.getElementById("res-sum-count");
        var bytesEl = document.getElementById("res-total-volume") || document.getElementById("res-sum-bytes");
        var durEl = document.getElementById("res-avg-duration") || document.getElementById("res-sum-duration");
        var shareEl = document.getElementById("res-malicious-share") || document.getElementById("res-sum-avgbytes");

        if (cntEl) cntEl.innerText = (data.total_matching !== undefined ? data.total_matching : (sum.matching_flows || 0)).toLocaleString();
        if (bytesEl) {
            var totalB = sum.total_bytes || 0;
            bytesEl.innerText = totalB > 1048576 ? (totalB / 1048576).toFixed(2) + " MB" : (totalB > 1024 ? (totalB / 1024).toFixed(1) + " KB" : totalB + " B");
        }
        if (durEl) durEl.innerText = (sum.avg_duration_sec !== undefined ? sum.avg_duration_sec : 0).toFixed(2) + "s";
        if (shareEl) {
            shareEl.innerText = (sum.malicious_share_pct !== undefined ? sum.malicious_share_pct.toFixed(1) : "0.0") + "%";
        }

        allResearchRecords = data.records || data.flows || [];
        renderResearchPage();
    }).catch(function (e) {
        console.error("Research query error:", e);
        if (tbody) {
            tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; padding:20px; color:var(--color-malicious);"><i class="fa-solid fa-triangle-exclamation"></i> Query failed: ' + e.message + '</td></tr>';
        }
    }).finally(function () {
        if (btnQuery) {
            btnQuery.disabled = false;
            btnQuery.innerHTML = '<i class="fa-solid fa-play"></i> Execute Query';
        }
    });
}

function exportResearchCsv() {
    var proto = document.getElementById("res-filter-proto") ? document.getElementById("res-filter-proto").value : "";
    var label = document.getElementById("res-filter-label") ? document.getElementById("res-filter-label").value : "";
    var srcIp = document.getElementById("res-filter-src-ip") ? document.getElementById("res-filter-src-ip").value.trim() : "";
    var destIp = document.getElementById("res-filter-dest-ip") ? document.getElementById("res-filter-dest-ip").value.trim() : "";

    var params = new URLSearchParams();
    if (proto && proto !== "all") params.append("protocol", proto);
    if (label && label !== "all") params.append("prediction_label", label);
    if (srcIp) params.append("src_ip", srcIp);
    if (destIp) params.append("dest_ip", destIp);

    var btnExport = document.getElementById("btn-export-query-csv") || document.getElementById("btn-export-research-csv");
    if (btnExport) {
        btnExport.disabled = true;
        btnExport.innerHTML = '<i class="fa-solid fa-spinner animate-spin"></i> Exporting CSV...';
    }

    fnFetch("/api/research/export?" + params.toString()).then(function (res) {
        if (!res || !res.ok) throw new Error("CSV export failed");
        return res.blob();
    }).then(function (blob) {
        var url = window.URL.createObjectURL(blob);
        var a = document.createElement("a");
        a.href = url;
        a.download = "NEXz_Research_Telemetry.csv";
        document.body.appendChild(a);
        a.click();
        a.remove();
        window.URL.revokeObjectURL(url);
    }).catch(function (e) {
        alert("Failed to export research telemetry: " + e.message);
    }).finally(function () {
        if (btnExport) {
            btnExport.disabled = false;
            btnExport.innerHTML = '<i class="fa-solid fa-file-csv"></i> Export Results CSV';
        }
    });
}

// ==========================================
// MODEL CONTROLS
// ==========================================
function setupModelControls() {
    var btnDrift = document.getElementById("btn-trigger-drift");
    var btnReset = document.getElementById("btn-reset-model");

    if (btnDrift) {
        btnDrift.onclick = function () {
            showToastAlert({ label: "Suspicious", notes: "Pushing synthetic abnormal flows to streaming pipeline..." }, "Drift Simulation");
            triggerDriftUIEffects({
                rolling_accuracy: 0.65,
                samples_processed: 450,
                drift_width: 32,
                drift_estimation: 0.35
            });
        };
    }

    if (btnReset) {
        btnReset.onclick = function () {
            if (confirm("Reset all online classifier weights back to static baseline?")) {
                fnFetch("/api/model/reset", { method: "POST" }).then(function (res) {
                    if (res && res.ok) {
                        showToastAlert({ label: "Normal", notes: "Online Adaptive model weights reset to default." }, "Weights Reset");
                        resetDriftUIEffects();
                        loadModelMetrics();
                    }
                }).catch(function (e) {
                    console.error("Reset failed:", e);
                });
            }
        };
    }
}

function triggerDriftUIEffects(metrics) {
    var ring = document.getElementById("drift-ring");
    var title = document.getElementById("drift-status-title");
    var desc = document.getElementById("drift-status-desc");
    if (ring) ring.className = "drift-ring drifted";
    if (title) {
        title.innerText = "Concept Drift Detected!";
        title.style.color = "var(--color-suspicious)";
    }
    if (desc) desc.innerText = "ADWIN detected anomaly thresholds shift. Pruning outdated branches of the Hoeffding tree.";
    
    var accEl = document.getElementById("model-accuracy-text");
    if (accEl) accEl.innerText = (metrics.rolling_accuracy * 100).toFixed(2) + "%";
    
    var samEl = document.getElementById("model-samples-text");
    if (samEl) samEl.innerText = metrics.samples_processed.toLocaleString();
    
    var winEl = document.getElementById("drift-win-size");
    if (winEl) winEl.innerText = metrics.drift_width;
    
    var varEl = document.getElementById("drift-variance");
    if (varEl) varEl.innerText = metrics.drift_estimation.toFixed(4);
}

function resetDriftUIEffects() {
    var ring = document.getElementById("drift-ring");
    var title = document.getElementById("drift-status-title");
    var desc = document.getElementById("drift-status-desc");
    if (ring) ring.className = "drift-ring stable";
    if (title) {
        title.innerText = "Network Baseline Stable";
        title.style.color = "#fff";
    }
    if (desc) desc.innerText = "No concept drift detected on streaming metrics.";
}

// ==========================================
// TOAST NOTIFICATIONS
// ==========================================
function playChirpSound(isCritical) {
    try {
        var audioCtx = new (window.AudioContext || window.webkitAudioContext)();
        var oscillator = audioCtx.createOscillator();
        oscillator.type = "sine";
        oscillator.frequency.setValueAtTime(isCritical ? 880 : 440, audioCtx.currentTime);
        oscillator.connect(audioCtx.destination);
        oscillator.start();
        oscillator.stop(audioCtx.currentTime + 0.15);
    } catch (e) { /* Audio API restrictions */ }
}

function showToastAlert(alertMsg, customTitle) {
    var container = document.getElementById("toast-container");
    if (!container) return;

    var notes = alertMsg.notes || "Suspicious traffic flow detected.";
    var isWarning = alertMsg.label === "Suspicious" || alertMsg.threat_level === "Medium" || alertMsg.threat_level === "Low";
    var isCritical = alertMsg.label === "Malicious" || alertMsg.threat_level === "Critical" || alertMsg.threat_level === "High";
    var titleText = customTitle || (alertMsg.threat_level ? (alertMsg.threat_level + " RISK ALARM") : (alertMsg.label === "Malicious" ? "CRITICAL ALARM" : "INTRUSION SUSPECT"));

    // Deduplication check: inspect current DOM toasts for identical notes
    var existingToasts = container.querySelectorAll(".toast");
    for (var i = 0; i < existingToasts.length; i++) {
        var existing = existingToasts[i];
        var body = existing.querySelector(".toast-body");
        if (body && body.innerText === notes) {
            // Found exact toast! Add/update occurrence badge
            var occurrenceBadge = existing.querySelector(".occurrence-badge");
            var currentCount = 2;
            if (occurrenceBadge) {
                currentCount = parseInt(occurrenceBadge.getAttribute("data-count"), 10) + 1;
                occurrenceBadge.setAttribute("data-count", currentCount);
                occurrenceBadge.innerText = "x" + currentCount;
            } else {
                var badgeSpan = document.createElement("span");
                badgeSpan.className = "badge bg-danger occurrence-badge";
                badgeSpan.setAttribute("data-count", "2");
                badgeSpan.innerText = "x2";
                badgeSpan.style.marginLeft = "6px";
                var header = existing.querySelector(".toast-header");
                if (header) header.appendChild(badgeSpan);
            }
            
            // Prolong notification lifetime
            if (existing.timeoutId) clearTimeout(existing.timeoutId);
            existing.style.opacity = "1";
            existing.style.transform = "translateX(0)";
            existing.timeoutId = setTimeout(function () {
                existing.style.opacity = "0";
                existing.style.transform = "translateX(120%)";
                existing.style.transition = "all 0.5s ease-out";
                setTimeout(function () { existing.remove(); }, 500);
            }, 5000);
            
            playChirpSound(isCritical);
            return;
        }
    }

    var toast = document.createElement("div");
    toast.className = "toast";
    if (isWarning) toast.className += " toast-warning";
    else if (isCritical) toast.className += " toast-danger";
    
    var icon = isCritical ? "fa-circle-radiation" : "fa-triangle-exclamation";
    
    var badgeClass = "bg-warning";
    if (alertMsg.threat_level === "Critical" || alertMsg.threat_level === "High" || alertMsg.label === "Malicious") badgeClass = "bg-danger";
    else if (alertMsg.threat_level === "Medium") badgeClass = "bg-warning";
    else if (alertMsg.threat_level === "Low") badgeClass = "bg-info";
    else badgeClass = "bg-success";
    
    var countBadge = (alertMsg.count && alertMsg.count > 1) ? ' <span class="badge bg-danger occurrence-badge" data-count="' + alertMsg.count + '">x' + alertMsg.count + '</span>' : '';
    
    toast.innerHTML =
        '<div class="toast-header">' +
        '<span class="toast-title"><i class="fa-solid ' + icon + '"></i> <strong>' + titleText + '</strong></span>' +
        '<span class="badge ' + badgeClass + '">' + (alertMsg.threat_level || alertMsg.label) + '</span>' +
        countBadge +
        '</div>' +
        '<div class="toast-body">' + notes + '</div>';
    
    container.appendChild(toast);
    playChirpSound(isCritical);

    toast.timeoutId = setTimeout(function () {
        toast.style.opacity = "0";
        toast.style.transform = "translateX(120%)";
        toast.style.transition = "all 0.5s ease-out";
        setTimeout(function () { toast.remove(); }, 500);
    }, 5000);
}

function showDriftToast(message) {
    var container = document.getElementById("toast-container");
    var toast = document.createElement("div");
    toast.className = "toast toast-warning";
    toast.innerHTML =
        '<div class="toast-header">' +
        '<span class="toast-title"><i class="fa-solid fa-bolt"></i> <strong>CONCEPT DRIFT</strong></span>' +
        '<span class="badge bg-warning">ADWIN</span>' +
        '</div>' +
        '<div class="toast-body">' + message + '</div>';
    if (container) container.appendChild(toast);
    setTimeout(function () {
        toast.style.opacity = "0";
        toast.style.transform = "translateX(120%)";
        toast.style.transition = "all 0.5s ease-out";
        setTimeout(function () { toast.remove(); }, 500);
    }, 5000);
}

// ==========================================
// MODALS AND DRAWERS HANDLERS
// ==========================================
function setupModalsAndDrawers() {
    var modalClose = document.getElementById("xai-modal-close");
    var modal = document.getElementById("xai-modal");
    if (modalClose && modal) {
        modalClose.onclick = function () {
            modal.classList.remove("active");
        };
        modal.onclick = function (e) {
            if (e.target === modal) {
                modal.classList.remove("active");
            }
        };
    }

    // Settings & PCAP Modal (Utility Component)
    var settingsModal = document.getElementById("settings-modal");
    var btnOpenSettings = document.getElementById("btn-open-settings");
    var settingsClose = document.getElementById("settings-modal-close");

    if (btnOpenSettings && settingsModal) {
        btnOpenSettings.onclick = function () {
            settingsModal.classList.add("active");
            loadSettingsData();
        };
    }
    if (settingsClose && settingsModal) {
        settingsClose.onclick = function () {
            settingsModal.classList.remove("active");
        };
    }
    if (settingsModal) {
        settingsModal.onclick = function (e) {
            if (e.target === settingsModal) {
                settingsModal.classList.remove("active");
            }
        };
    }

    var drawerClose = document.getElementById("log-drawer-close");
    var drawer = document.getElementById("log-drawer");
    if (drawerClose && drawer) {
        drawerClose.onclick = function () {
            drawer.classList.remove("active");
        };
    }

    // Initialize Cyber Range triggers
    setupEducationalSimulation();
}

function parseAlertNotes(notes) {
    var res = { 
        threat_type: "Anomaly Intrusion Signature", 
        reason: "The classifier identified packet characteristics deviating significantly from normal baseline profiles.", 
        action: "Deploy perimeter firewall blocking rules against the offending source IP address." 
    };
    if (!notes) return res;
    var parts = notes.split(" | ");
    parts.forEach(function (part) {
        if (part.indexOf("Diagnosis: ") === 0) res.threat_type = part.substring(11);
        else if (part.indexOf("Reason: ") === 0) res.reason = part.substring(8);
        else if (part.indexOf("Action: ") === 0) res.action = part.substring(8);
    });
    return res;
}

function renderHealthWhyPopover() {
    var popover = document.getElementById("health-why-popover");
    var list = document.getElementById("health-factors-list");
    if (!popover || !list) return;

    list.innerHTML = "";
    if (!latestHealthFactors || latestHealthFactors.length === 0) {
        list.innerHTML = '<li class="health-factor-item neutral">No factor penalties applied. Network perimeter operating at optimal baseline.</li>';
        return;
    }

    latestHealthFactors.forEach(function (hf) {
        var li = document.createElement("li");
        li.className = "health-factor-item " + (hf.impact || "neutral");
        var ptsStr = hf.points !== 0 ? ' (' + (hf.points > 0 ? '+' : '') + hf.points + ' pts)' : '';
        li.innerHTML =
            '<div>' +
            '<strong>' + escapeHtml(hf.factor) + ptsStr + '</strong>' +
            '<div class="text-secondary" style="font-size:11px; margin-top:2px;">' + escapeHtml(hf.detail || "") + '</div>' +
            '</div>';
        list.appendChild(li);
    });
}

function openXAIModal(alert) {
    currentModalAlert = alert;
    var xai = parseAlertNotes(alert.notes);
    var srcEl = document.getElementById("modal-src");
    var dstEl = document.getElementById("modal-dest");
    var protoEl = document.getElementById("modal-proto");
    var confEl = document.getElementById("modal-conf");
    var countEl = document.getElementById("modal-count");
    var timeEl = document.getElementById("modal-timestamps");
    var sevEl = document.getElementById("modal-severity");
    var simTag = document.getElementById("modal-sim-tag");
    var statusEl = document.getElementById("modal-status-badge");
    var compEl = document.getElementById("modal-component-badge");
    var reasonEl = document.getElementById("modal-reason");
    var chipsEl = document.getElementById("modal-factors-chips");
    var plainEl = document.getElementById("modal-plain-meaning");
    var actionEl = document.getElementById("modal-action");
    var rawEl = document.getElementById("modal-raw-details");
    var titleEl = document.getElementById("modal-threat-title");

    if (srcEl) srcEl.innerText = alert.src_ip + ":" + (alert.src_port || "-");
    if (dstEl) dstEl.innerText = alert.dest_ip + ":" + (alert.dest_port || "-");
    if (protoEl) protoEl.innerText = alert.protocol || "TCP";
    if (confEl) confEl.innerText = (alert.confidence ? Math.round(alert.confidence * 100) + "%" : "95%");
    if (countEl) countEl.innerText = (alert.count || 1) + " occurrences";
    
    if (timeEl) {
        var fTime = new Date(alert.first_seen || alert.timestamp).toLocaleTimeString();
        var lTime = new Date(alert.last_seen || alert.timestamp).toLocaleTimeString();
        timeEl.innerText = "First: " + fTime + " | Last: " + lTime;
    }

    if (sevEl) {
        sevEl.innerText = alert.threat_level || "Medium";
        sevEl.className = "threat-badge " + (alert.threat_level || "normal").toLowerCase();
    }

    var isSim = alert.is_simulated || (alert.notes && alert.notes.indexOf("[SIMULATION]") !== -1);
    if (simTag) {
        if (isSim) simTag.classList.remove("hidden");
        else simTag.classList.add("hidden");
    }

    if (statusEl) {
        statusEl.innerText = "Status: " + (alert.status || (alert.is_resolved ? "Resolved" : "Active"));
    }

    if (compEl) {
        if (alert.alert_type === "device_behaviour") compEl.innerText = "Engine: Half-Space Trees Baseline";
        else if (alert.alert_type === "arp_spoofing") compEl.innerText = "Engine: Heuristic ARP Snoop";
        else compEl.innerText = "Engine: Streaming ARF (Hoeffding Tree)";
    }

    if (reasonEl) reasonEl.innerText = xai.reason || "Deviation from expected streaming protocol baseline.";

    if (chipsEl) {
        chipsEl.innerHTML =
            '<div class="xai-factor-chip"><span>Protocol:</span> <strong>' + escapeHtml(alert.protocol || 'TCP') + '</strong></div>' +
            '<div class="xai-factor-chip"><span>Severity Weight:</span> <strong>' + escapeHtml(alert.threat_level || 'Medium') + '</strong></div>' +
            '<div class="xai-factor-chip"><span>Observation Source:</span> <strong>' + (isSim ? 'Cyber Range Sim' : 'Live Sniffer NIC') + '</strong></div>' +
            '<div class="xai-factor-chip"><span>Aggregation Count:</span> <strong>x' + (alert.count || 1) + '</strong></div>';
    }

    // Plain-Language Pedagogical Explanation for University Students
    if (plainEl) {
        var threatType = (xai.threat_type || "").toLowerCase();
        if (threatType.indexOf("dos") !== -1 || threatType.indexOf("syn") !== -1) {
            plainEl.innerText = "A high volume of half-open connection attempts was detected without completing the standard three-way TCP handshake. In production environments, this indicates an attacker attempting to deplete operating system TCP socket tables to deny service to legitimate campus users.";
        } else if (threatType.indexOf("scan") !== -1 || threatType.indexOf("probe") !== -1) {
            plainEl.innerText = "Sequential reconnaissance probing was observed across common service ports. Attackers execute automated scans to map active network ports, identify running daemon versions, and discover vulnerable entry points before launching targeted exploits.";
        } else if (threatType.indexOf("exfil") !== -1) {
            plainEl.innerText = "Unusual volumetric payload transmission to an external host was identified. This pattern violates baseline outbound egress distributions, which typically signifies an insider threat or compromised host staging and exfiltrating proprietary data.";
        } else if (threatType.indexOf("arp") !== -1) {
            plainEl.innerText = "Conflicting hardware MAC address claims were intercepted for a single IP address. This indicates ARP cache poisoning, where an attacker injects fraudulent ARP replies to intercept, decrypt, or tamper with perimeter network traffic via Man-in-the-Middle (MitM).";
        } else if (threatType.indexOf("device") !== -1) {
            plainEl.innerText = "Streaming Half-Space Trees detected that this host's current transmission volume, duration, or active protocol mix significantly deviates from its historical operational baseline established over previous observation windows.";
        } else {
            plainEl.innerText = "The streaming Hoeffding adaptive tree classifier detected that multivariate flow features (packet size distribution, inter-arrival time, and duration) crossed the decision threshold for anomalous behavior.";
        }
    }

    if (actionEl) actionEl.innerText = xai.action || "Inspect host connection history and verify socket activity.";
    if (rawEl) rawEl.innerText = JSON.stringify(alert, null, 2);
    if (titleEl) titleEl.innerHTML = '<i class="fa-solid fa-shield-virus"></i> ' + (xai.threat_type || "Security Anomaly Diagnostic");

    // Modal action button wiring
    var btnAck = document.getElementById("btn-modal-ack");
    var btnResolve = document.getElementById("btn-modal-resolve");
    var btnClose = document.getElementById("btn-modal-close");
    var btnCloseX = document.getElementById("xai-modal-close");

    if (btnAck) {
        btnAck.onclick = function () {
            if (currentModalAlert) acknowledgeAlert(currentModalAlert.id);
        };
    }
    if (btnResolve) {
        btnResolve.onclick = function () {
            if (currentModalAlert) resolveAlert(currentModalAlert.id);
        };
    }
    if (btnClose) {
        btnClose.onclick = function () {
            var m = document.getElementById("xai-modal");
            if (m) m.classList.remove("active");
        };
    }
    if (btnCloseX) {
        btnCloseX.onclick = function () {
            var m = document.getElementById("xai-modal");
            if (m) m.classList.remove("active");
        };
    }

    var modal = document.getElementById("xai-modal");
    if (modal) modal.classList.add("active");
}

function openLogDrawer(log) {
    if (!log) return;
    var timeEl = document.getElementById("drawer-time");
    var srcEl = document.getElementById("drawer-src");
    var dstEl = document.getElementById("drawer-dst");
    var sportEl = document.getElementById("drawer-sport");
    var dportEl = document.getElementById("drawer-dport");
    var protoEl = document.getElementById("drawer-proto");
    var bytesEl = document.getElementById("drawer-bytes");
    var stateEl = document.getElementById("drawer-state");
    var titleEl = document.getElementById("drawer-flow-title");

    if (timeEl) timeEl.innerText = new Date(log.timestamp).toLocaleString();
    if (srcEl) srcEl.innerText = log.src_ip + (log.src_port ? ":" + log.src_port : "");
    if (dstEl) dstEl.innerText = log.dest_ip + (log.dest_port ? ":" + log.dest_port : "");
    if (sportEl) sportEl.innerText = log.src_port || "-";
    if (dportEl) dportEl.innerText = log.dest_port || "-";
    if (protoEl) protoEl.innerText = log.protocol || "TCP";
    if (bytesEl) bytesEl.innerText = (log.total_bytes !== undefined ? log.total_bytes.toLocaleString() : 0) + " Bytes";
    if (stateEl) stateEl.innerText = log.connection_state || "N/A";
    if (titleEl) titleEl.innerText = log.src_ip + " -> " + log.dest_ip + " (" + (log.protocol || "TCP") + ")";

    renderHexDissector(log);
    
    var drawer = document.getElementById("log-drawer");
    if (drawer) drawer.classList.add("active");
}

// ==========================================
// TOP TALKERS AND PORTS ANALYTICS
// ==========================================
function refreshTopTalkersAndPorts() {
    var talkersList = document.getElementById("top-talkers-list");
    var portsList = document.getElementById("top-ports-list");

    fnFetch("/api/analytics/top-talkers").then(function (res) {
        if (!res) return;
        return res.json();
    }).then(function (data) {
        if (!data || !talkersList) return;
        talkersList.innerHTML = "";
        if (data.sources.length === 0) {
            talkersList.innerHTML = '<div class="text-secondary" style="font-size:12px;">No active IP volume logs.</div>';
            return;
        }
        data.sources.forEach(function (src) {
            var kb = (src.bytes / 1024).toFixed(1);
            var item = document.createElement("div");
            item.className = "stat-item";
            item.innerHTML = 
                '<span class="ip-label"><i class="fa-solid fa-laptop-code text-secondary"></i> ' + src.ip + '</span>' +
                '<span class="val-label"><strong>' + kb.toLocaleString() + ' KB</strong> (' + src.flows + ' flows)</span>';
            talkersList.appendChild(item);
        });
    }).catch(function (e) {
        console.error("Top talkers refresh failed:", e);
    });

    fnFetch("/api/analytics/top-ports").then(function (res) {
        if (!res) return;
        return res.json();
    }).then(function (data) {
        if (!data || !portsList) return;
        portsList.innerHTML = "";
        if (data.dest_ports.length === 0) {
            portsList.innerHTML = '<div class="text-secondary" style="font-size:12px;">No targeted ports registered.</div>';
            return;
        }
        data.dest_ports.forEach(function (p) {
            var item = document.createElement("div");
            item.className = "stat-item";
            item.innerHTML = 
                '<span class="ip-label" style="color:var(--accent-blue);"><i class="fa-solid fa-door-open"></i> Port ' + p.port + '</span>' +
                '<span class="val-label"><strong>' + p.count.toLocaleString() + ' hits</strong></span>';
            portsList.appendChild(item);
        });
    }).catch(function (e) {
        console.error("Top ports refresh failed:", e);
    });
}

// ==========================================
// EDUCATIONAL PROTOCOL ACADEMY
// ==========================================
function loadAcademyData() {
    var grid = document.getElementById("academy-grid");
    if (!grid) return;
    grid.innerHTML = '<div class="text-secondary animate-pulse" style="grid-column: 1/-1; text-align:center; padding: 40px;"><i class="fa-solid fa-spinner animate-spin"></i> Loading protocol database...</div>';

    fnFetch("/api/educational/protocols").then(function (res) {
        if (!res) return;
        return res.json();
    }).then(function (data) {
        if (!data) return;
        grid.innerHTML = "";
        data.forEach(function (p) {
            var card = document.createElement("div");
            card.className = "academy-card glass-panel " + p.protocol.toLowerCase();
            
            var headerHtml = 
                '<div class="academy-card-header">' +
                '<h3>' + escapeHtml(p.protocol) + '</h3>' +
                '<span class="protocol-tag">' + escapeHtml(p.protocol) + '</span>' +
                '</div>';
                
            // Section 1: LEARN
            var learnHtml = 
                '<div class="academy-part-block academy-part-learn">' +
                '<div class="academy-part-title"><i class="fa-solid fa-book-open"></i> 1. Learn &mdash; Standard & Purpose</div>' +
                '<div style="font-weight:700; margin-bottom:2px;">' + escapeHtml(p.name) + '</div>' +
                '<div class="text-secondary">' + escapeHtml(p.purpose) + '</div>' +
                '<div style="margin-top:6px; font-size:11.5px;"><strong>Default Port Allocations:</strong> ' + escapeHtml(p.common_ports) + '</div>' +
                '</div>';
                
            // Section 2: OBSERVE
            var exampleDetail = '';
            if (p.example) {
                var sizeKb = (p.example.bytes / 1024).toFixed(2);
                exampleDetail = 
                    '<div style="margin-top:6px; padding:6px 8px; background:rgba(0,0,0,0.04); border-radius:4px; font-size:11px;">' +
                    '<strong>Live Telemetry Sample:</strong> <code>' + escapeHtml(p.example.src_ip) + ' &rarr; ' + escapeHtml(p.example.dest_ip) + '</code> (' + sizeKb + ' KB) ' +
                    '<div class="text-secondary" style="font-size:10.5px; margin-top:2px;">' + escapeHtml(p.example.info) + '</div>' +
                    '</div>';
            } else {
                exampleDetail = '<div class="text-secondary" style="font-size:11px; margin-top:4px;"><i class="fa-solid fa-circle-minus"></i> No live transmission captured on active NIC in last 60m.</div>';
            }
            
            var obsHtml = 
                '<div class="academy-part-block academy-part-observe">' +
                '<div class="academy-part-title"><i class="fa-solid fa-chart-line"></i> 2. Observe &mdash; Perimeter Telemetry</div>' +
                '<div class="text-secondary">' + escapeHtml(p.observation || 'Telemetry active.') + '</div>' +
                exampleDetail +
                '</div>';
                
            // Section 3: SECURITY
            var secHtml = 
                '<div class="academy-part-block academy-part-security">' +
                '<div class="academy-part-title"><i class="fa-solid fa-shield-virus"></i> 3. Security &mdash; Threat Vectors & Vulnerabilities</div>' +
                '<div class="text-secondary">' + escapeHtml(p.security) + '</div>' +
                '</div>';

            // Section 4: EXPLORE
            var wiresharkFilters = {
                "TCP": "tcp.flags.syn == 1 && tcp.flags.ack == 0",
                "UDP": "udp.length > 512",
                "DNS": "dns.flags.response == 0",
                "HTTP": 'http.request.method == "POST"',
                "HTTPS": "tls.handshake.type == 1",
                "ICMP": "icmp.type == 8",
                "ARP": "arp.opcode == 2"
            };
            var filterHint = wiresharkFilters[p.protocol] || (p.protocol.toLowerCase());
            
            var exploreHtml = 
                '<div class="academy-part-block academy-part-explore">' +
                '<div class="academy-part-title"><i class="fa-solid fa-compass"></i> 4. Explore &mdash; Student Research & Filters</div>' +
                '<div class="text-secondary">' + escapeHtml(p.explore || 'Filter protocol flows in Explore tab to analyze connection statistics.') + '</div>' +
                '<div style="margin-top:6px; font-size:11px;">' +
                '<strong>Suggested Wireshark Filter:</strong> <code style="background:rgba(0,0,0,0.06); padding:2px 6px; border-radius:3px;">' + filterHint + '</code>' +
                '</div>' +
                '</div>';

            card.innerHTML = headerHtml + learnHtml + obsHtml + secHtml + exploreHtml;
            grid.appendChild(card);
        });
    }).catch(function (e) {
        console.error("Educational data load failed:", e);
        grid.innerHTML = '<div class="error-msg" style="grid-column: 1/-1;"><i class="fa-solid fa-circle-exclamation"></i> Protocol database fetch failed: ' + e.message + '</div>';
    });
}

// ==========================================
// EDUCATIONAL ATTACK SIMULATOR & HEX DISSECTOR
// ==========================================
function setupEducationalSimulation() {
    var buttons = document.querySelectorAll(".btn-sim-trigger");
    var btnStop = document.getElementById("btn-stop-simulation");
    
    buttons.forEach(function (btn) {
        btn.onclick = function () {
            var simType = btn.getAttribute("data-sim");
            var originalHtml = btn.innerHTML;
            
            // Set loading state
            btn.disabled = true;
            btn.innerHTML = '<i class="fa-solid fa-spinner animate-spin"></i> Injecting...';
            
            if (btnStop) {
                btnStop.classList.remove("hide");
                btnStop.classList.remove("hidden");
                btnStop.style.display = "inline-flex";
            }
            
            console.log("[NEXz Telemetry] Injecting Cyber Range Attack Simulation:", simType);
            fnFetch("/api/educational/simulate-attack?type=" + simType, {
                method: "POST"
            }).then(function (res) {
                if (res && res.ok) {
                    showToastAlert({
                        threat_level: simType === "normal" ? "Low" : (simType === "exfil" ? "High" : "Critical"),
                        notes: "[SIMULATION] Cyber Range synthetic traffic injected: " + simType.toUpperCase() + " flows streaming through NEXz pipeline."
                    }, "SIMULATION IN PROGRESS");
                } else {
                    alert("Failed to start traffic simulation: " + (res ? res.statusText : "network error"));
                    if (btnStop) {
                        btnStop.classList.add("hide");
                        btnStop.style.display = "none";
                    }
                }
            }).catch(function (e) {
                console.error("Simulation trigger failed:", e);
                alert("Error triggering simulation: " + e.message);
                if (btnStop) {
                    btnStop.classList.add("hide");
                    btnStop.style.display = "none";
                }
            }).finally(function () {
                btn.disabled = false;
                btn.innerHTML = originalHtml;
                
                setTimeout(function () {
                    if (btnStop && btnStop.innerHTML.indexOf("Aborting") === -1) {
                        btnStop.classList.add("hide");
                        btnStop.style.display = "none";
                    }
                }, 5000);
            });
        };
    });
    
    if (btnStop) {
        btnStop.onclick = function () {
            console.log("[NEXz Telemetry] Aborting active Cyber Range synthetic simulation.");
            btnStop.innerHTML = '<i class="fa-solid fa-spinner animate-spin"></i> Aborting...';
            btnStop.disabled = true;
            
            fnFetch("/api/educational/stop-simulation", {
                method: "POST"
            }).then(function (res) {
                if (res && res.ok) {
                    showToastAlert({
                        threat_level: "Low",
                        notes: "Active network traffic simulation has been aborted."
                    }, "SIMULATION ABORTED");
                }
            }).catch(function (e) {
                console.error("Failed to abort simulation:", e);
            }).finally(function () {
                btnStop.innerHTML = '<i class="fa-solid fa-circle-stop"></i> Abort Active Simulation';
                btnStop.disabled = false;
                btnStop.style.display = "none";
            });
        };
    }
}

function renderHexDissector(log) {
    var container = document.getElementById("drawer-hex-view");
    if (!container) return;
    
    // Helper function: IP to hex bytes
    function ipToHexBytes(ip) {
        if (!ip || ip.indexOf('.') === -1) return [192, 168, 1, 1];
        return ip.split('.').map(function (num) { return parseInt(num, 10) || 0; });
    }
    
    // Helper function: Port to 2 hex bytes
    function portToBytes(port) {
        var p = parseInt(port, 10) || 0;
        return [(p >> 8) & 0xFF, p & 0xFF];
    }
    
    // Convert IPs and Ports
    var srcIpBytes = ipToHexBytes(log.src_ip);
    var destIpBytes = ipToHexBytes(log.dest_ip);
    var srcPortBytes = portToBytes(log.src_port);
    var destPortBytes = portToBytes(log.dest_port);
    
    // Build the byte stream array
    var bytes = [];
    
    // Ethernet Header (14 bytes)
    // Destination MAC (6B) + Source MAC (6B) + EtherType (2B: 08 00 for IPv4)
    var ethBytes = [0x00, 0x0c, 0x29, 0x3e, 0x5f, 0x80, 0x00, 0x50, 0x56, 0xc0, 0x00, 0x08, 0x08, 0x00];
    bytes = bytes.concat(ethBytes.map(function(b) { return { val: b, layer: "eth", desc: "Ethernet Header Byte" }; }));
    
    // IPv4 Header (20 bytes)
    // Version/IHL (1B), DSCP (1B), Total Len (2B), ID (2B), Flags/Frag (2B), TTL (1B), Proto (1B), Checksum (2B), Src IP (4B), Dst IP (4B)
    var ipProto = log.protocol === "UDP" ? 0x11 : 0x06;
    var ipHeader = [
        0x45, 0x00, 0x00, 0x28, 
        0x1c, 0x46, 0x40, 0x00, 
        0x40, ipProto, 0x00, 0x00
    ];
    ipHeader = ipHeader.concat(srcIpBytes).concat(destIpBytes);
    bytes = bytes.concat(ipHeader.map(function(b) { return { val: b, layer: "ip", desc: "IPv4 Header Byte" }; }));
    
    // L4 Header (TCP = 20B, UDP = 8B)
    if (log.protocol === "UDP") {
        var udpHeader = srcPortBytes.concat(destPortBytes).concat([0x00, 0x08, 0x00, 0x00]);
        bytes = bytes.concat(udpHeader.map(function(b) { return { val: b, layer: "tcp", desc: "UDP Header Byte" }; }));
    } else {
        // TCP Header: Src Port (2B), Dst Port (2B), Seq (4B), Ack (4B), Header Len/Flags (2B), Window (2B), Checksum (2B), Urgent (2B)
        var tcpFlags = log.connection_state === "SYN_SENT" || log.connection_state === "SYN_RCVD" ? 0x02 : 0x18; // SYN or PSH-ACK
        var tcpHeader = srcPortBytes.concat(destPortBytes)
            .concat([0x00, 0x00, 0x04, 0xd2, 0x00, 0x00, 0x00, 0x00]) // Dummy Seq/Ack
            .concat([0x50, tcpFlags, 0xfa, 0xf0, 0x00, 0x00, 0x00, 0x00]);
        bytes = bytes.concat(tcpHeader.map(function(b) { return { val: b, layer: "tcp", desc: "TCP Header Byte" }; }));
    }
    
    // Application Payload bytes
    var payloadStr = log.info || (log.prediction_label + " traffic log capture");
    var payloadBytes = [];
    for (var i = 0; i < payloadStr.length; i++) {
        payloadBytes.push(payloadStr.charCodeAt(i) & 0xFF);
    }
    // Limit payload to 48 bytes to keep the hex view clean and readable
    if (payloadBytes.length > 48) {
        payloadBytes = payloadBytes.slice(0, 45).concat([0x2e, 0x2e, 0x2e]); // add "..."
    }
    bytes = bytes.concat(payloadBytes.map(function(b) { return { val: b, layer: "payload", desc: "Application Payload Byte" }; }));
    
    // Renders bytes in standard 16-byte hex dump rows
    var html = "";
    var rowOffset = 0;
    while (rowOffset < bytes.length) {
        var rowBytes = bytes.slice(rowOffset, rowOffset + 16);
        
        // 1. Render Row Offset (e.g. 0000, 0010, 0020)
        var offsetStr = ("0000" + rowOffset.toString(16)).slice(-4).toUpperCase();
        html += '<span class="hex-offset">' + offsetStr + '</span> ';
        
        // 2. Render Hex values (16 values, spaced)
        var hexStr = "";
        for (var j = 0; j < 16; j++) {
            if (j < rowBytes.length) {
                var b = rowBytes[j];
                var hexVal = ("00" + b.val.toString(16)).slice(-2).toUpperCase();
                hexStr += '<span class="hex-byte hex-' + b.layer + '" title="' + b.desc + '">' + hexVal + '</span> ';
            } else {
                hexStr += "   "; // spacing padding
            }
            if (j === 7) hexStr += " "; // extra spacing center split
        }
        html += hexStr;
        
        // 3. Render ASCII representation
        var asciiStr = '<span class="hex-ascii-section">';
        for (var j = 0; j < rowBytes.length; j++) {
            var b = rowBytes[j];
            // check if printable character (ASCII 32-126)
            var char = (b.val >= 32 && b.val <= 126) ? String.fromCharCode(b.val) : ".";
            asciiStr += '<span class="hex-byte hex-' + b.layer + '" title="' + b.desc + '">' + escapeHtml(char) + '</span>';
        }
        asciiStr += '</span>';
        html += asciiStr + "\n";
        
        rowOffset += 16;
    }
    
    container.innerHTML = html;
}

function escapeHtml(string) {
    return String(string).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function requestNotificationPermission() {
    if ("Notification" in window) {
        if (Notification.permission !== "granted" && Notification.permission !== "denied") {
            Notification.requestPermission();
        }
    }
}


// ==========================================
// THEME CONTROLLER (Enterprise White Default & Dark Mode)
// ==========================================
function setupTheme() {
    var savedTheme = localStorage.getItem("nexz-theme") || "theme-light";
    applyTheme(savedTheme);

    var btn = document.getElementById("btn-theme-toggle");
    if (btn) {
        btn.addEventListener("click", function () {
            var isDark = document.body.classList.contains("theme-dark");
            var targetTheme = isDark ? "theme-light" : "theme-dark";
            applyTheme(targetTheme);
            localStorage.setItem("nexz-theme", targetTheme);
        });
    }
}

function applyTheme(themeName) {
    if (themeName === "theme-dark") {
        document.body.classList.add("theme-dark");
        document.body.classList.remove("theme-light");
    } else {
        document.body.classList.add("theme-light");
        document.body.classList.remove("theme-dark");
    }

    var lbl = document.getElementById("theme-toggle-label");
    var btn = document.getElementById("btn-theme-toggle");
    if (lbl && btn) {
        var icon = btn.querySelector("i");
        if (themeName === "theme-dark") {
            lbl.innerText = "Light Mode";
            if (icon) icon.className = "fa-solid fa-sun";
        } else {
            lbl.innerText = "Dark Mode";
            if (icon) icon.className = "fa-solid fa-moon";
        }
    }
    updateChartsTheme();
}

function getChartTextColor() {
    return document.body.classList.contains("theme-dark") ? "#cbd5e1" : "#334155";
}

function getChartGridColor() {
    return document.body.classList.contains("theme-dark") ? "rgba(255, 255, 255, 0.08)" : "rgba(0, 0, 0, 0.06)";
}

function updateChartsTheme() {
    var textColor = getChartTextColor();
    var gridColor = getChartGridColor();

    [throughputChart, incidentsChart, monitorChart].forEach(function (chart) {
        if (!chart) return;
        if (chart.options && chart.options.scales) {
            if (chart.options.scales.x && chart.options.scales.x.ticks) {
                chart.options.scales.x.ticks.color = textColor;
            }
            if (chart.options.scales.y) {
                if (chart.options.scales.y.ticks) chart.options.scales.y.ticks.color = textColor;
                if (chart.options.scales.y.grid) chart.options.scales.y.grid.color = gridColor;
            }
        }
        chart.update();
    });
}

// ==========================================
// PAGINATION CONTROLS (Page-Form Architecture)
// ==========================================
function setupPaginationControls() {
    // 1. Alerts Table Pagination Listeners
    var alertsPrev = document.getElementById("alerts-prev-page");
    var alertsNext = document.getElementById("alerts-next-page");
    var alertsSize = document.getElementById("alerts-page-size");

    if (alertsPrev) {
        alertsPrev.onclick = function () {
            if (alertsCurrentPage > 1) {
                alertsCurrentPage--;
                console.log("[NEXz Security] Navigating to alerts page " + alertsCurrentPage);
                renderFilteredAlerts();
            }
        };
    }
    if (alertsNext) {
        alertsNext.onclick = function () {
            var totalPages = Math.max(1, Math.ceil(allFilteredAlerts.length / alertsPageSize));
            if (alertsCurrentPage < totalPages) {
                alertsCurrentPage++;
                console.log("[NEXz Security] Navigating to alerts page " + alertsCurrentPage);
                renderFilteredAlerts();
            }
        };
    }
    if (alertsSize) {
        alertsSize.onchange = function () {
            alertsPageSize = parseInt(this.value, 10) || 10;
            alertsCurrentPage = 1;
            console.log("[NEXz Security] Alerts page size set to " + alertsPageSize);
            renderFilteredAlerts();
        };
    }

    // 2. Device Profiles Table Pagination Listeners
    var devPrev = document.getElementById("devices-prev-page");
    var devNext = document.getElementById("devices-next-page");
    var devSize = document.getElementById("devices-page-size");

    if (devPrev) {
        devPrev.onclick = function () {
            if (devicesCurrentPage > 1) {
                devicesCurrentPage--;
                console.log("[NEXz Device Profiler] Navigating to device page " + devicesCurrentPage);
                renderDeviceProfilesTable();
            }
        };
    }
    if (devNext) {
        devNext.onclick = function () {
            var totalPages = Math.max(1, Math.ceil(allFetchedDevices.length / devicesPageSize));
            if (devicesCurrentPage < totalPages) {
                devicesCurrentPage++;
                console.log("[NEXz Device Profiler] Navigating to device page " + devicesCurrentPage);
                renderDeviceProfilesTable();
            }
        };
    }
    if (devSize) {
        devSize.onchange = function () {
            devicesPageSize = parseInt(this.value, 10) || 10;
            devicesCurrentPage = 1;
            console.log("[NEXz Device Profiler] Device profiles page size set to " + devicesPageSize);
            renderDeviceProfilesTable();
        };
    }

    // 3. Flow Logs Table Pagination Listeners
    var logsPrev = document.getElementById("logs-prev-page");
    var logsNext = document.getElementById("logs-next-page");
    var logsSize = document.getElementById("logs-page-size");

    if (logsPrev) {
        logsPrev.onclick = function () {
            if (logsCurrentPage > 1) {
                logsCurrentPage--;
                console.log("[NEXz Monitoring] Navigating to logs page " + logsCurrentPage);
                renderFilteredLogs();
            }
        };
    }
    if (logsNext) {
        logsNext.onclick = function () {
            var totalPages = Math.max(1, Math.ceil(allFilteredLogs.length / logsPageSize));
            if (logsCurrentPage < totalPages) {
                logsCurrentPage++;
                console.log("[NEXz Monitoring] Navigating to logs page " + logsCurrentPage);
                renderFilteredLogs();
            }
        };
    }
    if (logsSize) {
        logsSize.onchange = function () {
            logsPageSize = parseInt(this.value, 10) || 15;
            logsCurrentPage = 1;
            console.log("[NEXz Monitoring] Logs page size set to " + logsPageSize);
            renderFilteredLogs();
        };
    }
}

function setupHealthWhyPopover() {
    var btnWhy = document.getElementById("btn-dash-health-why") || document.getElementById("btn-health-why");
    var btnCloseWhy = document.getElementById("btn-close-health-why");
    if (btnWhy) {
        btnWhy.onclick = function (e) {
            e.stopPropagation();
            var pop = document.getElementById("health-why-popover");
            if (pop) {
                pop.classList.toggle("hidden");
                if (!pop.classList.contains("hidden")) {
                    renderHealthWhyPopover();
                }
            }
        };
    }
    if (btnCloseWhy) {
        btnCloseWhy.onclick = function (e) {
            e.stopPropagation();
            var pop = document.getElementById("health-why-popover");
            if (pop) pop.classList.add("hidden");
        };
    }
    document.addEventListener("click", function (e) {
        var pop = document.getElementById("health-why-popover");
        if (pop && !pop.classList.contains("hidden")) {
            if (!pop.contains(e.target) && btnWhy && e.target !== btnWhy && !btnWhy.contains(e.target)) {
                pop.classList.add("hidden");
            }
        }
    });
}

// ==============================================================================
// === ELEVATED COMPONENT HELPERS: DEVICE COMPARISON, ADWIN, XAI & DASHBOARD ===
// ==============================================================================

function renderDeviceComparison(d) {
    if (!d) return;
    var ip = d.ip || d.device_ip || "Unknown";
    var count = d.sample_count || 0;
    var score = d.recent_score !== undefined ? d.recent_score : 0.0;
    var avgB = d.avg_bytes || 0;
    var avgD = d.avg_duration_sec || 0;
    var totalB = d.total_bytes || 0;
    var protos = d.protocols || {};
    var protoList = Object.keys(protos).map(function (k) { return k + " (" + protos[k] + ")"; }).join(", ") || "TCP/UDP";

    var titleEl = document.getElementById("comp-ip-label");
    if (titleEl) titleEl.innerText = ip;

    var scoreBadge = document.getElementById("comp-score-badge");
    if (scoreBadge) {
        scoreBadge.innerText = "Anomaly Score: " + score.toFixed(2);
        scoreBadge.className = score >= 0.70 ? "badge bg-danger" : (score >= 0.40 ? "badge bg-warning" : "badge bg-success");
    }

    var baseSamples = document.getElementById("comp-base-samples");
    if (baseSamples) baseSamples.innerText = count + " flows";

    var baseBytes = document.getElementById("comp-base-bytes");
    if (baseBytes) baseBytes.innerText = avgB + " B / flow";

    var baseDur = document.getElementById("comp-base-dur");
    if (baseDur) baseDur.innerText = avgD + "s";

    var baseProtos = document.getElementById("comp-base-protos");
    if (baseProtos) baseProtos.innerText = protoList;

    var curStatus = document.getElementById("comp-cur-status");
    if (curStatus) curStatus.innerText = d.status || (score >= 0.70 ? "Anomalous" : "Normal");

    var curScore = document.getElementById("comp-cur-score");
    if (curScore) curScore.innerText = score.toFixed(2) + " (Threshold: 0.70)";

    var curTotalBytes = document.getElementById("comp-cur-total-bytes");
    if (curTotalBytes) curTotalBytes.innerText = (totalB > 1048576 ? (totalB / 1048576).toFixed(2) + " MB" : (totalB / 1024).toFixed(1) + " KB");

    var curLastSeen = document.getElementById("comp-cur-last-seen");
    if (curLastSeen) curLastSeen.innerText = d.last_seen || "-";

    var diagEl = document.getElementById("comp-diagnosis-text");
    if (diagEl) {
        if (count < 20) {
            diagEl.innerHTML = "<strong>Status: Reference Window Population (Warming Up)</strong><br>Half-Space Trees (HST) requires " + (20 - count) + " more flows from host <code>" + escapeHtml(ip) + "</code> to construct its initial mass reference profile. During warm-up, no false alarms are generated.";
        } else if (score >= 0.70) {
            diagEl.innerHTML = "<strong style='color:var(--color-malicious);'><i class='fa-solid fa-triangle-exclamation'></i> High Baseline Deviation Detected</strong><br>Host <code>" + escapeHtml(ip) + "</code> has produced flow characteristics that reside in sparse regions of its established Half-Space Trees partitions. The score of <strong>" + score.toFixed(2) + "</strong> exceeds the 0.70 threshold due to sudden shifts in packet volume (" + totalB + "B total) or transmission timing relative to historical sessions.";
        } else {
            diagEl.innerHTML = "<strong style='color:var(--color-normal);'><i class='fa-solid fa-circle-check'></i> Nominal Behavioral Pattern</strong><br>Host <code>" + escapeHtml(ip) + "</code> is operating within standard multidimensional density bounds. The flow payload sizes (" + avgB + " B) and protocol distribution match its established reference distribution.";
        }
    }
}

function loadADWINDriftEvents() {
    fnFetch("/api/model/drift-events").then(function (res) {
        if (!res) return;
        return res.json();
    }).then(function (data) {
        var tbody = document.getElementById("adwin-drift-tbody");
        if (!tbody) return;
        var events = (data && data.drift_events) ? data.drift_events : [];
        if (events.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="text-center text-secondary" style="padding:20px;"><i class="fa-solid fa-wave-square"></i> No concept drift events recorded. Ingestion stream distribution is currently stationary.</td></tr>';
            return;
        }

        tbody.innerHTML = "";
        events.forEach(function (e) {
            var tr = document.createElement("tr");
            tr.innerHTML = 
                '<td>' + (e.timestamp || "-") + '</td>' +
                '<td><strong>' + (e.accuracy * 100).toFixed(2) + '%</strong></td>' +
                '<td>' + (e.f1_score * 100).toFixed(2) + '%</td>' +
                '<td>' + (e.samples_processed ? e.samples_processed.toLocaleString() : "-") + '</td>' +
                '<td><span class="badge bg-warning"><i class="fa-solid fa-triangle-exclamation"></i> Drift Detected</span></td>' +
                '<td><span class="text-secondary" style="font-size:12px;">' + (e.model_response || "Split Candidate Re-evaluated") + '</span></td>';
            tbody.appendChild(tr);
        });
    }).catch(function (err) {
        console.error("ADWIN drift events fetch failed:", err);
    });
}

function renderDashboardOverview() {
    var kpiHosts = document.getElementById("kpi-hosts");
    var kpiFlows = document.getElementById("kpi-active-flows");
    var ppsCounter = document.getElementById("pps-counter");
    var interfaceLabel = document.getElementById("active-interface-label");

    var dashNic = document.getElementById("dash-nic-label");
    var dashPps = document.getElementById("dash-pps-label");
    var dashFlows = document.getElementById("dash-flows-label");
    var dashHosts = document.getElementById("dash-hosts-label");

    if (dashNic && interfaceLabel) dashNic.innerText = interfaceLabel.innerText;
    if (dashPps && ppsCounter) dashPps.innerText = ppsCounter.innerText + " PPS";
    if (dashFlows && kpiFlows) dashFlows.innerText = kpiFlows.innerText + " Flows";
    if (dashHosts && kpiHosts) dashHosts.innerText = kpiHosts.innerText + " Hosts";

    var healthPct = document.getElementById("kpi-health-pct");
    var healthStatus = document.getElementById("kpi-health-status");
    var dashPct = document.getElementById("dash-health-pct");
    var dashStatus = document.getElementById("dash-health-status");
    var dashGauge = document.getElementById("dash-health-gauge");
    var mainGauge = document.getElementById("health-gauge");

    if (dashPct && healthPct) dashPct.innerText = healthPct.innerText;
    if (dashStatus && healthStatus) {
        dashStatus.innerText = healthStatus.innerText;
        dashStatus.style.color = healthStatus.style.color;
    }
    if (dashGauge && mainGauge) {
        dashGauge.style.setProperty("--gauge-value", mainGauge.style.getPropertyValue("--gauge-value") || 100);
        dashGauge.style.setProperty("--gauge-color", mainGauge.style.getPropertyValue("--gauge-color") || "var(--color-normal)");
    }

    var scCrit = document.getElementById("sec-critical-count");
    var scHigh = document.getElementById("sec-high-count");
    var scMed = document.getElementById("sec-medium-count");
    var scRes = document.getElementById("sec-resolved-count");

    var dcCrit = document.getElementById("dash-crit-count");
    var dcHigh = document.getElementById("dash-high-count");
    var dcMed = document.getElementById("dash-med-count");
    var dcRes = document.getElementById("dash-res-count");

    if (dcCrit && scCrit) dcCrit.innerText = scCrit.innerText;
    if (dcHigh && scHigh) dcHigh.innerText = scHigh.innerText;
    if (dcMed && scMed) dcMed.innerText = scMed.innerText;
    if (dcRes && scRes) dcRes.innerText = scRes.innerText;

    var topList = document.getElementById("top-talkers-list");
    var dashTopList = document.getElementById("dash-top-talkers-list");
    if (topList && dashTopList) {
        dashTopList.innerHTML = topList.innerHTML;
    }
}

var CASE_STUDIES = {
    scan: {
        title: "1. Port Scan Reconnaissance",
        tagline: "Probing sequential or random destination ports to discover running network services",
        badge: "Reconnaissance",
        badgeClass: "badge bg-warning",
        what: "A remote or internal host sent rapid TCP SYN packets to multiple different destination ports within a short observation window without completing the full TCP three-way handshake.",
        why: "Reconnaissance is the initial phase of cyberattacks (MITRE ATT&CK T1046). Adversaries identify exposed listening services (e.g. SSH on port 22, RDP on port 3389) before launching targeted exploits.",
        telemetry: "Flow duration < 0.1s, packet size < 64 bytes, TCP SYN flag set without ACK, target port dispersion across destination IPs.",
        playbook: [
            "Navigate to <strong>Monitor &rarr; Traffic Analysis</strong> and check the <em>Top Targeted Destination Ports</em> widget.",
            "Filter <strong>Monitor &rarr; Flows</strong> by the suspicious source IP and verify TCP handshake flags (SYN-SENT vs ESTABLISHED).",
            "Determine whether the scanner is an authorized campus administrative tool (e.g. vulnerability scanner) or an unauthorized intruder.",
            "If unauthorized, acknowledge the alert in <strong>Security &rarr; Alerts</strong> and configure a perimeter firewall block on the border router."
        ]
    },
    syn: {
        title: "2. TCP SYN Flood DoS",
        tagline: "High-frequency TCP connection initialization designed to exhaust host socket tables",
        badge: "Denial of Service",
        badgeClass: "badge bg-danger",
        what: "An adversary initiates a massive volume of half-open TCP connections by sending SYN packets without sending the final ACK packet in the three-way handshake.",
        why: "Operating systems allocate memory for each half-open connection in a SYN backlog queue. When saturated, legitimate users are denied access to critical web servers, Sakai, or campus portals.",
        telemetry: "Extreme flow rate (high PPS), uniform small payload bytes (~40–60 bytes), missing ACK responses, concentrated single destination port (e.g. 80, 443).",
        playbook: [
            "Inspect <strong>Overview &rarr; Dashboard</strong> to verify the sudden spike in packets per second (PPS).",
            "Review <strong>Security &rarr; Threat Detection</strong> to see the AI confidence and penalty impact on Network Defense Posture.",
            "Deploy SYN cookies on the target host (e.g., <code>sysctl -w net.ipv4.tcp_syncookies=1</code> on Linux) or rate-limit inbound SYN packets.",
            "Track mitigation in <strong>Security &rarr; Alerts</strong> and mark the incident as Resolved once normal handshake completion rates resume."
        ]
    },
    exfil: {
        title: "3. Outbound Data Exfiltration",
        tagline: "Unauthorized bulk transmission of confidential academic or administrative data to external IP addresses",
        badge: "Data Theft",
        badgeClass: "badge bg-purple",
        what: "An internal campus machine initiated high-volume outbound data transfers to an unfamiliar external IP address over an extended continuous TCP connection.",
        why: "Data exfiltration (MITRE ATT&CK T1048) represents the final objective in intrusions involving ransomware or espionage, where proprietary student records, research datasets, or credentials are stolen.",
        telemetry: "Asymmetric byte ratio (extreme client-to-server payload volume), high cumulative byte counts (> 10MB), non-standard destination ports or encrypted channels.",
        playbook: [
            "Cross-examine the endpoint in <strong>Security &rarr; Behaviour Profiles</strong> to verify historical baseline deviation.",
            "Extract the 5-tuple from <strong>Monitor &rarr; Flows</strong> and use the Wireshark Handoff guide in <strong>Explore &rarr; Reports</strong> to inspect the packet stream.",
            "Isolate the affected workstation from the local VLAN to prevent further data loss.",
            "Revoke compromised user session tokens and conduct forensic memory analysis on the endpoint."
        ]
    },
    arp: {
        title: "4. ARP Cache Poisoning (Man-in-the-Middle)",
        tagline: "Layer 2 broadcast spoofing linking an attacker's MAC address to the default gateway's IP address",
        badge: "Layer 2 MitM",
        badgeClass: "badge bg-danger",
        what: "Gratuitous ARP replies were broadcast associating multiple IP addresses (or the subnet default gateway) with a duplicate hardware MAC address.",
        why: "ARP is a trust-based Layer 2 protocol without authentication. Poisoning enables an adversary to intercept, modify, or eavesdrop on all subnet traffic traversing to the gateway.",
        telemetry: "Duplicate MAC address observed claiming ownership of different IP nodes; sudden ARP traffic density spikes.",
        playbook: [
            "Check the <strong>Passive ARP / MitM Watch</strong> widget in <strong>Security &rarr; Threat Detection</strong> for alerted duplicate MACs.",
            "Run <code>arp -a</code> on local administrative interfaces to confirm the poisoned gateway entry.",
            "Enable Dynamic ARP Inspection (DAI) and DHCP Snooping on campus managed access switches.",
            "Track and resolve the incident within the <strong>Security &rarr; Alerts</strong> lifecycle manager."
        ]
    },
    hst: {
        title: "5. Device Baseline Anomaly (Half-Space Trees)",
        tagline: "One-class host deviation where communication patterns violate personal historical density distributions",
        badge: "Host Baseline Shift",
        badgeClass: "badge bg-info",
        what: "A tracked network device produced flow parameters that landed in low-density subspaces of its personal Half-Space Trees model, even if individual packet features did not trigger static signature rules.",
        why: "Sophisticated adversaries use 'living-off-the-land' techniques that blend in with global traffic. Personal per-device profiling catches compromised workstations whose habits shift from consumer to attacker behavior.",
        telemetry: "HST anomaly score >= 0.70, unusual protocol choice for this host (e.g. IoT sensor suddenly speaking SSH), or off-hours burst transmission.",
        playbook: [
            "Open <strong>Security &rarr; Behaviour Profiles</strong> and click the flagged device row in the table.",
            "Inspect the <strong>Device Comparison Pane</strong> to compare its Normal Baseline against Current Flow Telemetry.",
            "Read the plain-language <strong>Algorithmic Deviation Diagnosis</strong> to understand which feature dimension caused the divergence.",
            "Determine if legitimate maintenance occurred or if host malware investigation is warranted."
        ]
    }
};

function setupDetectionExplained() {
    var chips = document.querySelectorAll("#case-study-chips .case-chip");
    chips.forEach(function (chip) {
        chip.addEventListener("click", function (e) {
            e.preventDefault();
            chips.forEach(function (c) { c.classList.remove("active"); });
            chip.classList.add("active");
            var studyKey = chip.getAttribute("data-study");
            renderCaseStudy(studyKey);
        });
    });
}

function renderCaseStudy(key) {
    var study = CASE_STUDIES[key];
    if (!study) return;

    var titleEl = document.getElementById("case-study-title");
    var tagEl = document.getElementById("case-study-tagline");
    var badgeEl = document.getElementById("case-study-badge");
    var whatEl = document.getElementById("case-what-happened");
    var whyEl = document.getElementById("case-why-matter");
    var telemEl = document.getElementById("case-telemetry-box");
    var playbookEl = document.getElementById("case-playbook-steps");

    if (titleEl) titleEl.innerText = study.title;
    if (tagEl) tagEl.innerText = study.tagline;
    if (badgeEl) {
        badgeEl.innerText = study.badge;
        badgeEl.className = study.badgeClass;
    }
    if (whatEl) whatEl.innerText = study.what;
    if (whyEl) whyEl.innerText = study.why;
    if (telemEl) telemEl.innerHTML = "<strong>Telemetry Signatures:</strong> " + study.telemetry;

    if (playbookEl) {
        playbookEl.innerHTML = "";
        study.playbook.forEach(function (step) {
            var li = document.createElement("li");
            li.innerHTML = step;
            playbookEl.appendChild(li);
        });
    }
}


// ==============================================================================
// === NEXz EXTERNAL TELEMETRY IMPORT & ANALYSIS WIZARD SUBSYSTEM ===
// ==============================================================================

var currentImportBatchId = null;
var currentImportInspection = null;
var currentImportMapping = {};
var currentReplaySpeed = "1.0";
var allImportBatches = [];

function setupImportWorkflow() {
    console.log("[NEXz] Initializing Telemetry Import Subsystem.");
    
    // Stage navigation buttons
    var btnBrowse = document.getElementById("btn-browse-import");
    var fileInput = document.getElementById("import-file-input");
    var dropzone = document.getElementById("import-dropzone");
    var btnUploadInspect = document.getElementById("btn-upload-and-inspect");

    if (btnBrowse && fileInput) {
        btnBrowse.onclick = function (e) {
            e.stopPropagation();
            fileInput.click();
        };
    }

    if (dropzone && fileInput) {
        dropzone.onclick = function () {
            fileInput.click();
        };

        dropzone.ondragover = function (e) {
            e.preventDefault();
            dropzone.classList.add("dragover");
        };

        dropzone.ondragleave = function () {
            dropzone.classList.remove("dragover");
        };

        dropzone.ondrop = function (e) {
            e.preventDefault();
            dropzone.classList.remove("dragover");
            if (e.dataTransfer && e.dataTransfer.files.length > 0) {
                fileInput.files = e.dataTransfer.files;
                handleSelectedFile(fileInput.files[0]);
            }
        };

        fileInput.onchange = function () {
            if (fileInput.files.length > 0) {
                handleSelectedFile(fileInput.files[0]);
            }
        };
    }

    function handleSelectedFile(file) {
        var card = document.getElementById("selected-file-card");
        var nameEl = document.getElementById("selected-file-name");
        var sizeEl = document.getElementById("selected-file-size");
        if (card && nameEl && sizeEl) {
            nameEl.innerText = file.name;
            var sz = file.size > 1048576 ? (file.size / 1048576).toFixed(2) + " MB" : (file.size / 1024).toFixed(1) + " KB";
            sizeEl.innerText = sz;
            card.classList.remove("hide");
        }
    }

    if (btnUploadInspect) {
        btnUploadInspect.onclick = function () {
            if (!fileInput || !fileInput.files || fileInput.files.length === 0) {
                alert("Please select a valid network telemetry file first.");
                return;
            }

            var file = fileInput.files[0];
            var datasetName = document.getElementById("import-dataset-name") ? document.getElementById("import-dataset-name").value.trim() : "";
            var desc = document.getElementById("import-description") ? document.getElementById("import-description").value.trim() : "";

            btnUploadInspect.disabled = true;
            btnUploadInspect.innerHTML = '<i class="fa-solid fa-spinner animate-spin"></i> Inspecting Schema...';

            var formData = new FormData();
            formData.append("file", file);
            formData.append("dataset_name", datasetName);
            formData.append("description", desc);

            fetch(API_URL + "/api/import/upload", {
                method: "POST",
                headers: { "Authorization": "Bearer " + token },
                body: formData
            })
            .then(function (res) {
                if (!res.ok) throw new Error("Upload and schema inspection failed.");
                return res.json();
            })
            .then(function (data) {
                btnUploadInspect.disabled = false;
                btnUploadInspect.innerHTML = '<i class="fa-solid fa-arrow-right"></i> Upload & Inspect Schema';
                
                var batch = data.batch || {};
                currentImportBatchId = batch.batch_id;
                currentImportInspection = batch;
                currentImportMapping = batch.auto_mapping || {};

                renderStage2Inspection(batch);
                goToImportStage(2);
                loadImportBatches();
            })
            .catch(function (err) {
                console.error("Upload error:", err);
                alert("Failed to upload file: " + err.message);
                btnUploadInspect.disabled = false;
                btnUploadInspect.innerHTML = '<i class="fa-solid fa-arrow-right"></i> Upload & Inspect Schema';
            });
        };
    }

    // Stage 2 actions
    var btnStage2Back = document.getElementById("btn-stage2-back");
    var btnStage2Next = document.getElementById("btn-stage2-next");
    if (btnStage2Back) {
        btnStage2Back.onclick = function () { goToImportStage(1); };
    }
    if (btnStage2Next) {
        btnStage2Next.onclick = function () {
            renderStage3Mapping(currentImportInspection.headers || [], currentImportMapping, currentImportInspection.capabilities || {});
            goToImportStage(3);
        };
    }

    // Stage 3 actions
    var btnStage3Back = document.getElementById("btn-stage3-back");
    var btnStage3Auto = document.getElementById("btn-stage3-automap");
    var btnStage3Reset = document.getElementById("btn-stage3-reset");
    var btnStage3Validate = document.getElementById("btn-stage3-validate");
    var btnStage3Next = document.getElementById("btn-stage3-next");

    if (btnStage3Back) {
        btnStage3Back.onclick = function () { goToImportStage(2); };
    }
    if (btnStage3Auto) {
        btnStage3Auto.onclick = function () {
            if (currentImportInspection && currentImportInspection.auto_mapping) {
                currentImportMapping = Object.assign({}, currentImportInspection.auto_mapping);
                renderStage3Mapping(currentImportInspection.headers || [], currentImportMapping, currentImportInspection.capabilities || {});
            }
        };
    }
    if (btnStage3Reset) {
        btnStage3Reset.onclick = function () {
            currentImportMapping = {};
            renderStage3Mapping(currentImportInspection.headers || [], {}, {});
        };
    }
    if (btnStage3Validate) {
        btnStage3Validate.onclick = function () {
            runValidationPass();
        };
    }
    if (btnStage3Next) {
        btnStage3Next.onclick = function () {
            // Save mapping to backend
            fnFetch("/api/import/" + currentImportBatchId + "/mapping", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ mapping: currentImportMapping })
            })
            .then(function (res) { return res.json(); })
            .then(function (data) {
                goToImportStage(4);
            })
            .catch(function (e) {
                goToImportStage(4);
            });
        };
    }

    // Stage 4 Mode cards & replay speeds
    var modeCards = document.querySelectorAll(".mode-card");
    modeCards.forEach(function (card) {
        card.onclick = function () {
            modeCards.forEach(function (c) { c.classList.remove("active"); });
            card.classList.add("active");
            var radio = card.querySelector("input[type='radio']");
            if (radio) radio.checked = true;

            var replayPanel = document.getElementById("replay-options-panel");
            if (replayPanel) {
                if (card.getAttribute("data-mode") === "replay") {
                    replayPanel.classList.remove("hide");
                } else {
                    replayPanel.classList.add("hide");
                }
            }
        };
    });

    var speedBtns = document.querySelectorAll(".btn-speed");
    speedBtns.forEach(function (btn) {
        btn.onclick = function () {
            speedBtns.forEach(function (b) { b.classList.remove("active"); });
            btn.classList.add("active");
            currentReplaySpeed = btn.getAttribute("data-speed") || "1.0";
        };
    });

    var btnStage4Back = document.getElementById("btn-stage4-back");
    var btnStage4Execute = document.getElementById("btn-stage4-execute");
    if (btnStage4Back) {
        btnStage4Back.onclick = function () { goToImportStage(3); };
    }
    if (btnStage4Execute) {
        btnStage4Execute.onclick = function () {
            launchImportPipeline();
        };
    }

    // Stage 5 Live controls
    var btnPause = document.getElementById("btn-import-pause");
    var btnResume = document.getElementById("btn-import-resume");
    var btnCancel = document.getElementById("btn-import-cancel");

    if (btnPause) {
        btnPause.onclick = function () {
            fnFetch("/api/import/" + currentImportBatchId + "/pause", { method: "POST" })
            .then(function () {
                btnPause.classList.add("hide");
                if (btnResume) btnResume.classList.remove("hide");
                var st = document.getElementById("progress-batch-status");
                if (st) st.innerText = "Execution paused by operator.";
            });
        };
    }
    if (btnResume) {
        btnResume.onclick = function () {
            fnFetch("/api/import/" + currentImportBatchId + "/resume", { method: "POST" })
            .then(function () {
                btnResume.classList.add("hide");
                if (btnPause) btnPause.classList.remove("hide");
                var st = document.getElementById("progress-batch-status");
                if (st) st.innerText = "Resuming ingestion pipeline...";
            });
        };
    }
    if (btnCancel) {
        btnCancel.onclick = function () {
            if (confirm("Are you sure you want to stop and cancel this import? Already committed records will be kept.")) {
                fnFetch("/api/import/" + currentImportBatchId + "/cancel", { method: "POST" })
                .then(function () {
                    var st = document.getElementById("progress-batch-status");
                    if (st) st.innerText = "Cancelling import batch safely...";
                });
            }
        };
    }

    // Completed summary quick links
    var btnViewFlows = document.getElementById("btn-summary-view-flows");
    var btnViewAlerts = document.getElementById("btn-summary-view-alerts");
    var btnOpenResearch = document.getElementById("btn-summary-open-research");
    var btnExportCsv = document.getElementById("btn-summary-export-csv");
    var btnNewImport = document.getElementById("btn-summary-new-import");

    if (btnViewFlows) {
        btnViewFlows.onclick = function () {
            switchView("explore-view", "tab-explore-history");
        };
    }
    if (btnViewAlerts) {
        btnViewAlerts.onclick = function () {
            switchView("security-view", "tab-sec-alerts");
        };
    }
    if (btnOpenResearch) {
        btnOpenResearch.onclick = function () {
            switchView("explore-view", "tab-explore-research");
            var batchSel = document.getElementById("res-filter-batch");
            if (batchSel) batchSel.value = currentImportBatchId;
            var srcSel = document.getElementById("res-filter-source");
            if (srcSel) srcSel.value = "import";
            runResearchQuery();
        };
    }
    if (btnExportCsv) {
        btnExportCsv.onclick = function () {
            window.open(API_URL + "/api/import/" + currentImportBatchId + "/export?export_format=csv", "_blank");
        };
    }
    if (btnNewImport) {
        btnNewImport.onclick = function () {
            goToImportStage(1);
            var fInput = document.getElementById("import-file-input");
            if (fInput) fInput.value = "";
            var card = document.getElementById("selected-file-card");
            if (card) card.classList.add("hide");
        };
    }

    // Refresh batches button
    var btnRefreshBatches = document.getElementById("btn-refresh-import-history");
    if (btnRefreshBatches) {
        btnRefreshBatches.onclick = function () {
            loadImportBatches();
        };
    }

    // Watchlist modal controls
    setupWatchlistModal();
}

function goToImportStage(stageNum) {
    for (var i = 1; i <= 5; i++) {
        var stageEl = document.getElementById("import-stage-" + i);
        var navEl = document.getElementById("step-nav-" + i);
        if (stageEl) {
            if (i === stageNum) stageEl.classList.remove("hide");
            else stageEl.classList.add("hide");
        }
        if (navEl) {
            if (i === stageNum) {
                navEl.classList.add("active");
                navEl.classList.remove("completed");
            } else if (i < stageNum) {
                navEl.classList.remove("active");
                navEl.classList.add("completed");
            } else {
                navEl.classList.remove("active");
                navEl.classList.remove("completed");
            }
        }
    }
}

function renderStage2Inspection(batch) {
    var fmtEl = document.getElementById("stage2-detected-fmt");
    var recEl = document.getElementById("stage2-estimated-records");
    var colEl = document.getElementById("stage2-column-count");
    var mapEl = document.getElementById("stage2-automapped-count");

    if (fmtEl) fmtEl.innerText = (batch.format || "CSV").toUpperCase();
    if (recEl) recEl.innerText = (batch.estimated_records || 0).toLocaleString();
    if (colEl) colEl.innerText = (batch.headers || []).length;
    if (mapEl) mapEl.innerText = Object.keys(batch.auto_mapping || {}).length + " Fields";

    // Column pills cloud
    var pillsContainer = document.getElementById("stage2-columns-pills");
    if (pillsContainer) {
        pillsContainer.innerHTML = "";
        var autoKeys = Object.values(batch.auto_mapping || {});
        (batch.headers || []).forEach(function (col) {
            var span = document.createElement("span");
            span.className = "col-pill" + (autoKeys.indexOf(col) !== -1 ? " mapped" : "");
            span.innerText = col;
            pillsContainer.appendChild(span);
        });
    }

    // Sample data table
    var thead = document.getElementById("stage2-sample-thead");
    var tbody = document.getElementById("stage2-sample-tbody");
    if (thead && tbody) {
        thead.innerHTML = "";
        tbody.innerHTML = "";

        var headers = batch.headers || [];
        var sampleRows = batch.sample_rows || [];

        var trH = document.createElement("tr");
        headers.forEach(function (h) {
            var th = document.createElement("th");
            th.innerText = h;
            trH.appendChild(th);
        });
        thead.appendChild(trH);

        sampleRows.forEach(function (row) {
            var tr = document.createElement("tr");
            headers.forEach(function (h) {
                var td = document.createElement("td");
                td.innerText = row[h] !== undefined ? row[h] : "";
                tr.appendChild(td);
            });
            tbody.appendChild(tr);
        });
    }
}

function renderStage3Mapping(headers, currentMapping, capabilities) {
    var tbody = document.getElementById("mapping-table-tbody");
    if (!tbody) return;
    tbody.innerHTML = "";

    var canonicalDefinitions = [
        { field: "src_ip", label: "Source IP Address", req: "Mandatory (Endpoints, Profiling, Watchlist)", mandatory: true },
        { field: "dest_ip", label: "Destination IP Address", req: "Mandatory (Endpoints, Graph Analytics)", mandatory: true },
        { field: "src_port", label: "Source Port", req: "Optional (L4 Socket)", mandatory: false },
        { field: "dest_port", label: "Destination Port", req: "Optional (L4 Service Identification)", mandatory: false },
        { field: "protocol", label: "Protocol Name / Number", req: "Recommended (TCP/UDP/ICMP Analytics)", mandatory: false },
        { field: "timestamp", label: "Observation Timestamp", req: "Recommended (Time Series & Temporal Drift)", mandatory: false },
        { field: "duration", label: "Flow Duration (Seconds)", req: "Optional (Inter-arrival Statistics)", mandatory: false },
        { field: "src_bytes", label: "Source Payload Bytes", req: "ARF Volumetric Features", mandatory: false },
        { field: "dest_bytes", label: "Destination Payload Bytes", req: "ARF Volumetric Features", mandatory: false },
        { field: "total_bytes", label: "Total Flow Bytes", req: "ARF Volumetric Features", mandatory: false },
        { field: "src_pkts", label: "Source Packet Count", req: "ARF Packet Statistics", mandatory: false },
        { field: "dest_pkts", label: "Destination Packet Count", req: "ARF Packet Statistics", mandatory: false },
        { field: "packet_count", label: "Total Flow Packets", req: "ARF Packet Statistics", mandatory: false },
        { field: "label", label: "Ground Truth Label", req: "Supervised Evaluation Mode", mandatory: false },
        { field: "info", label: "L7 Metadata / Info", req: "Optional (HTTP/DNS/TLS SNI / Context)", mandatory: false }
    ];

    canonicalDefinitions.forEach(function (def) {
        var tr = document.createElement("tr");
        var isMapped = Boolean(currentMapping[def.field]);

        var optionsHtml = '<option value="">-- Unmapped --</option>';
        headers.forEach(function (h) {
            var selected = (currentMapping[def.field] === h) ? ' selected' : '';
            optionsHtml += '<option value="' + h + '"' + selected + '>' + h + '</option>';
        });

        tr.innerHTML = 
            '<td><strong>' + def.label + '</strong><br><small class="text-muted"><code>' + def.field + '</code></small></td>' +
            '<td><span style="font-size:11px; color:var(--text-secondary);">' + def.req + '</span></td>' +
            '<td><select class="header-select select-mapping-col" data-field="' + def.field + '" style="width:100%;">' + optionsHtml + '</select></td>' +
            '<td><span class="badge ' + (isMapped ? 'badge-normal' : (def.mandatory ? 'badge-malicious' : 'badge-suspicious')) + '">' +
            (isMapped ? 'Mapped' : (def.mandatory ? 'Required' : 'Optional')) + '</span></td>';

        tbody.appendChild(tr);
    });

    // Wire select change listeners
    tbody.querySelectorAll(".select-mapping-col").forEach(function (sel) {
        sel.onchange = function () {
            var fld = this.getAttribute("data-field");
            var val = this.value;
            if (val) {
                currentImportMapping[fld] = val;
            } else {
                delete currentImportMapping[fld];
            }
            // Recalculate capabilities locally
            renderStage3Mapping(headers, currentImportMapping, capabilities);
        };
    });

    renderCapabilityBadges(capabilities);
}

function renderCapabilityBadges(caps) {
    var grid = document.getElementById("capabilities-badges-grid");
    if (!grid) return;
    grid.innerHTML = "";

    var capTitles = {
        "traffic_visualization": "Traffic Visualization",
        "ip_analytics": "IP & Graph Analytics",
        "protocol_analytics": "Protocol Distribution",
        "device_inventory": "Device Host Profiling",
        "arf_classification": "Adaptive Random Forest (ML)",
        "behaviour_profiling": "HST Anomaly Profiling",
        "ioc_correlation": "Watchlist / IOC Matching",
        "label_evaluation": "Supervised Model Evaluation"
    };

    Object.keys(caps).forEach(function (k) {
        var info = caps[k];
        var card = document.createElement("div");
        var statusClass = info.supported ? "supported" : (info.status === "partial" ? "partial" : "unsupported");
        card.className = "cap-card " + statusClass;

        var pillBadge = info.supported 
            ? '<span class="badge bg-success" style="font-size:10px;">Supported</span>'
            : (info.status === "partial" ? '<span class="badge bg-warning" style="font-size:10px;">Partial</span>' : '<span class="badge" style="font-size:10px; background:var(--border-strong); color:var(--text-muted);">Disabled</span>');

        card.innerHTML = 
            '<div class="cap-header">' +
                '<span class="cap-title">' + (capTitles[k] || k) + '</span>' +
                pillBadge +
            '</div>' +
            '<div class="cap-reason">' + (info.reason || "") + '</div>';

        grid.appendChild(card);
    });
}

function runValidationPass() {
    var btn = document.getElementById("btn-stage3-validate");
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<i class="fa-solid fa-spinner animate-spin"></i> Validating Sample...';
    }

    fnFetch("/api/import/" + currentImportBatchId + "/validate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mapping: currentImportMapping })
    })
    .then(function (res) { return res.json(); })
    .then(function (data) {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = '<i class="fa-solid fa-spell-check"></i> Run Validation Pass';
        }
        var banner = document.getElementById("validation-summary-card");
        var valCount = document.getElementById("val-valid-count");
        var invCount = document.getElementById("val-invalid-count");
        var warnCount = document.getElementById("val-warn-count");
        var stBadge = document.getElementById("val-status-badge");

        if (banner) banner.classList.remove("hide");
        if (valCount) valCount.innerText = (data.valid_count || 0).toLocaleString();
        if (invCount) invCount.innerText = (data.invalid_count || 0).toLocaleString();
        if (warnCount) warnCount.innerText = (data.warning_count || 0).toLocaleString();

        if (stBadge) {
            if (data.invalid_count > 0 && data.valid_count === 0) {
                stBadge.className = "badge bg-danger";
                stBadge.innerText = "Fatal Validation Errors";
            } else if (data.invalid_count > 0) {
                stBadge.className = "badge bg-warning";
                stBadge.innerText = "Partial Rejections";
            } else {
                stBadge.className = "badge bg-success";
                stBadge.innerText = "100% Clean Sample";
            }
        }
    })
    .catch(function (e) {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = '<i class="fa-solid fa-spell-check"></i> Run Validation Pass';
        }
        alert("Validation error: " + e.message);
    });
}

function launchImportPipeline() {
    var activeModeCard = document.querySelector(".mode-card.active");
    var mode = activeModeCard ? activeModeCard.getAttribute("data-mode") : "analyze_only";
    var isolateProfile = document.getElementById("chk-isolate-profile") ? document.getElementById("chk-isolate-profile").checked : true;

    var payload = {
        mode: mode,
        replay_speed: currentReplaySpeed,
        isolate_profile: isolateProfile
    };

    var btnLaunch = document.getElementById("btn-stage4-execute");
    if (btnLaunch) {
        btnLaunch.disabled = true;
        btnLaunch.innerHTML = '<i class="fa-solid fa-spinner animate-spin"></i> Spawning Execution...';
    }

    fnFetch("/api/import/" + currentImportBatchId + "/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
    })
    .then(function (res) {
        if (!res.ok) throw new Error("Could not start import job.");
        return res.json();
    })
    .then(function (data) {
        if (btnLaunch) {
            btnLaunch.disabled = false;
            btnLaunch.innerHTML = '<i class="fa-solid fa-bolt"></i> Launch Import Pipeline';
        }
        // Reset counters in Stage 5
        resetStage5Counters();
        goToImportStage(5);
        var titleEl = document.getElementById("progress-batch-title");
        if (titleEl && currentImportInspection) {
            titleEl.innerText = "Ingesting: " + (currentImportInspection.dataset_name || currentImportInspection.filename);
        }
    })
    .catch(function (err) {
        if (btnLaunch) {
            btnLaunch.disabled = false;
            btnLaunch.innerHTML = '<i class="fa-solid fa-bolt"></i> Launch Import Pipeline';
        }
        alert("Failed to start import: " + err.message);
    });
}

function resetStage5Counters() {
    var bar = document.getElementById("import-progress-bar");
    if (bar) bar.style.width = "0%";
    var countText = document.getElementById("progress-count-text");
    if (countText) countText.innerText = "0 / 0";
    var pctText = document.getElementById("progress-pct-text");
    if (pctText) pctText.innerText = "0.0%";
    var speedText = document.getElementById("progress-speed-text");
    if (speedText) speedText.innerText = "0.0";

    ["cnt-normal", "cnt-suspicious", "cnt-malicious", "cnt-anomalies", "cnt-watchlist", "cnt-alerts"].forEach(function (id) {
        var el = document.getElementById(id);
        if (el) el.innerText = "0";
    });

    var completedActions = document.getElementById("import-completed-actions");
    if (completedActions) completedActions.classList.add("hide");

    var evalCard = document.getElementById("import-eval-card");
    if (evalCard) evalCard.classList.add("hide");

    var pauseBtn = document.getElementById("btn-import-pause");
    var resumeBtn = document.getElementById("btn-import-resume");
    if (pauseBtn) pauseBtn.classList.remove("hide");
    if (resumeBtn) resumeBtn.classList.add("hide");
}

function handleImportProgressEvent(msg) {
    if (!msg || !msg.progress) return;
    var p = msg.progress;

    var bar = document.getElementById("import-progress-bar");
    if (bar) bar.style.width = p.percentage + "%";
    var countText = document.getElementById("progress-count-text");
    if (countText) countText.innerText = (p.processed || 0).toLocaleString() + " / " + (p.total || 0).toLocaleString();
    var pctText = document.getElementById("progress-pct-text");
    if (pctText) pctText.innerText = p.percentage + "%";
    var speedText = document.getElementById("progress-speed-text");
    if (speedText) speedText.innerText = (p.records_per_sec || 0).toFixed(1);

    var n = document.getElementById("cnt-normal"); if (n) n.innerText = (p.normal_count || 0).toLocaleString();
    var s = document.getElementById("cnt-suspicious"); if (s) s.innerText = (p.suspicious_count || 0).toLocaleString();
    var m = document.getElementById("cnt-malicious"); if (m) m.innerText = (p.malicious_count || 0).toLocaleString();
    var a = document.getElementById("cnt-anomalies"); if (a) a.innerText = (p.anomaly_count || 0).toLocaleString();
    var w = document.getElementById("cnt-watchlist"); if (w) w.innerText = (p.watchlist_matches || 0).toLocaleString();
    var al = document.getElementById("cnt-alerts"); if (al) al.innerText = (p.alerts_count || 0).toLocaleString();

    var st = document.getElementById("progress-batch-status");
    if (st) st.innerText = "Status: " + p.status.toUpperCase();
}

function handleImportCompletedEvent(msg) {
    var sum = msg.final_summary || {};
    var st = document.getElementById("progress-batch-status");
    if (st) st.innerText = "Completed " + (sum.total_processed || 0).toLocaleString() + " rows in " + (sum.duration_sec || 0) + "s.";

    var bar = document.getElementById("import-progress-bar");
    if (bar) bar.style.width = "100%";
    var pctText = document.getElementById("progress-pct-text");
    if (pctText) pctText.innerText = "100.0%";

    var completedActions = document.getElementById("import-completed-actions");
    if (completedActions) completedActions.classList.remove("hide");

    // Evaluation card if present
    if (sum.eval_metrics && Object.keys(sum.eval_metrics).length > 0) {
        var em = sum.eval_metrics;
        var evalCard = document.getElementById("import-eval-card");
        if (evalCard) {
            evalCard.classList.remove("hide");
            var acc = document.getElementById("eval-acc"); if (acc) acc.innerText = (em.accuracy * 100).toFixed(2) + "%";
            var pr = document.getElementById("eval-prec"); if (pr) pr.innerText = (em.precision * 100).toFixed(2) + "%";
            var rc = document.getElementById("eval-rec"); if (rc) rc.innerText = (em.recall * 100).toFixed(2) + "%";
            var f1 = document.getElementById("eval-f1"); if (f1) f1.innerText = em.f1_score.toFixed(4);

            if (em.confusion_matrix) {
                var cm = em.confusion_matrix;
                var elNN = document.getElementById("cm-nn"); if (elNN) elNN.innerText = cm.Normal.Normal || 0;
                var elNS = document.getElementById("cm-ns"); if (elNS) elNS.innerText = cm.Normal.Suspicious || 0;
                var elNM = document.getElementById("cm-nm"); if (elNM) elNM.innerText = cm.Normal.Malicious || 0;
                var elSN = document.getElementById("cm-sn"); if (elSN) elSN.innerText = cm.Suspicious.Normal || 0;
                var elSS = document.getElementById("cm-ss"); if (elSS) elSS.innerText = cm.Suspicious.Suspicious || 0;
                var elSM = document.getElementById("cm-sm"); if (elSM) elSM.innerText = cm.Suspicious.Malicious || 0;
                var elMN = document.getElementById("cm-mn"); if (elMN) elMN.innerText = cm.Malicious.Normal || 0;
                var elMS = document.getElementById("cm-ms"); if (elMS) elMS.innerText = cm.Malicious.Suspicious || 0;
                var elMM = document.getElementById("cm-mm"); if (elMM) elMM.innerText = cm.Malicious.Malicious || 0;
            }
        }
    }

    loadImportBatches();
}

function loadImportBatches() {
    fnFetch("/api/import/history")
    .then(function (res) { return res.json(); })
    .then(function (data) {
        allImportBatches = data.batches || [];
        renderImportBatchesTable(allImportBatches);
        populateResearchBatchDropdown(allImportBatches);
    })
    .catch(function (err) {
        console.error("Failed to load import batches:", err);
    });
}

function renderImportBatchesTable(batches) {
    var tbody = document.getElementById("import-batches-tbody");
    if (!tbody) return;
    tbody.innerHTML = "";

    if (!batches || batches.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted" style="padding:24px;">No external telemetry batches imported yet.</td></tr>';
        return;
    }

    batches.forEach(function (b) {
        var tr = document.createElement("tr");
        var stBadge = '<span class="badge bg-secondary">' + b.status + '</span>';
        if (b.status === "completed") stBadge = '<span class="badge bg-success">Completed</span>';
        else if (b.status === "processing") stBadge = '<span class="badge bg-primary">Processing</span>';
        else if (b.status === "cancelled") stBadge = '<span class="badge bg-warning">Cancelled</span>';

        var dt = b.uploaded_at ? new Date(b.uploaded_at).toLocaleString() : "-";

        tr.innerHTML = 
            '<td><code>#' + b.id + '</code></td>' +
            '<td><strong>' + b.dataset_name + '</strong><br><small class="text-muted">' + b.filename + '</small></td>' +
            '<td><span class="protocol-tag">' + (b.file_type || "CSV").toUpperCase() + '</span></td>' +
            '<td><span style="font-size:12px;">' + (b.analysis_mode || "analyze_only") + '</span></td>' +
            '<td><strong>' + (b.valid_count || b.record_count || 0).toLocaleString() + '</strong></td>' +
            '<td>' + stBadge + '</td>' +
            '<td><small>' + dt + '</small></td>' +
            '<td>' +
                '<div style="display:flex; gap:6px;">' +
                    '<button class="btn-action-primary btn-sm btn-batch-open" data-batch-id="' + b.id + '" title="Open in Research"><i class="fa-solid fa-magnifying-glass"></i></button>' +
                    '<button class="btn-action-secondary btn-sm btn-batch-export" data-batch-id="' + b.id + '" title="Export CSV"><i class="fa-solid fa-download"></i></button>' +
                    '<button class="btn-action-danger btn-sm btn-batch-delete" data-batch-id="' + b.id + '" title="Purge Batch" style="color:var(--color-malicious);"><i class="fa-solid fa-trash-can"></i></button>' +
                '</div>' +
            '</td>';

        tbody.appendChild(tr);
    });

    tbody.querySelectorAll(".btn-batch-open").forEach(function (btn) {
        btn.onclick = function () {
            var bId = this.getAttribute("data-batch-id");
            switchView("explore-view", "tab-explore-research");
            var batchSel = document.getElementById("res-filter-batch");
            if (batchSel) batchSel.value = bId;
            var srcSel = document.getElementById("res-filter-source");
            if (srcSel) srcSel.value = "import";
            runResearchQuery();
        };
    });

    tbody.querySelectorAll(".btn-batch-export").forEach(function (btn) {
        btn.onclick = function () {
            var bId = this.getAttribute("data-batch-id");
            window.open(API_URL + "/api/import/" + bId + "/export?export_format=csv", "_blank");
        };
    });

    tbody.querySelectorAll(".btn-batch-delete").forEach(function (btn) {
        btn.onclick = function () {
            var bId = this.getAttribute("data-batch-id");
            if (confirm("Are you sure you want to delete batch #" + bId + "? All imported flows and attached alerts will be removed.")) {
                fnFetch("/api/import/" + bId, { method: "DELETE" })
                .then(function () {
                    loadImportBatches();
                });
            }
        };
    });
}

function populateResearchBatchDropdown(batches) {
    var sel = document.getElementById("res-filter-batch");
    if (!sel) return;
    var currentVal = sel.value;
    sel.innerHTML = '<option value="">All Batches</option>';
    batches.forEach(function (b) {
        var opt = document.createElement("option");
        opt.value = b.id;
        opt.innerText = "#" + b.id + " — " + b.dataset_name + " (" + (b.file_type || "").toUpperCase() + ")";
        if (currentVal && String(b.id) === String(currentVal)) {
            opt.selected = true;
        }
        sel.appendChild(opt);
    });
}

function setupWatchlistModal() {
    var modal = document.getElementById("watchlist-modal");
    var openBtn = document.getElementById("btn-open-watchlist-modal");
    var closeBtn = document.getElementById("btn-close-watchlist-modal");
    var closeFooter = document.getElementById("btn-close-watchlist-modal-footer");

    if (openBtn && modal) {
        openBtn.onclick = function () {
            modal.classList.remove("hide");
            loadWatchlists();
        };
    }
    if (closeBtn && modal) {
        closeBtn.onclick = function () { modal.classList.add("hide"); };
    }
    if (closeFooter && modal) {
        closeFooter.onclick = function () { modal.classList.add("hide"); };
    }

    var btnAdd = document.getElementById("btn-wl-add-single");
    if (btnAdd) {
        btnAdd.onclick = function () {
            var valInput = document.getElementById("wl-new-value");
            var typeInput = document.getElementById("wl-new-type");
            var labelInput = document.getElementById("wl-new-label");

            if (!valInput || !valInput.value.trim()) {
                alert("Please enter an IP address or domain name.");
                return;
            }

            fnFetch("/api/watchlists/add", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    value: valInput.value.trim(),
                    entry_type: typeInput ? typeInput.value : "ipv4",
                    label: labelInput && labelInput.value.trim() ? labelInput.value.trim() : "Suspicious Host"
                })
            })
            .then(function (res) { return res.json(); })
            .then(function () {
                valInput.value = "";
                loadWatchlists();
            });
        };
    }

    var fileInput = document.getElementById("wl-file-input");
    if (fileInput) {
        fileInput.onchange = function () {
            if (!fileInput.files || fileInput.files.length === 0) return;
            var file = fileInput.files[0];
            var formData = new FormData();
            formData.append("file", file);
            formData.append("label", "Threat List: " + file.name);

            fetch(API_URL + "/api/watchlists/import", {
                method: "POST",
                headers: { "Authorization": "Bearer " + token },
                body: formData
            })
            .then(function (res) { return res.json(); })
            .then(function (data) {
                alert("Imported " + data.imported_count + " new IOCs into the watchlist.");
                fileInput.value = "";
                loadWatchlists();
            })
            .catch(function (err) {
                alert("Watchlist import failed: " + err.message);
            });
        };
    }
}

function loadWatchlists() {
    fnFetch("/api/watchlists")
    .then(function (res) { return res.json(); })
    .then(function (data) {
        var tbody = document.getElementById("watchlist-tbody");
        if (!tbody) return;
        tbody.innerHTML = "";

        var entries = data.entries || [];
        if (entries.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted" style="padding:20px;">No threat watchlist entries registered yet.</td></tr>';
            return;
        }

        entries.forEach(function (e) {
            var tr = document.createElement("tr");
            tr.innerHTML = 
                '<td><code>' + e.value + '</code></td>' +
                '<td><span class="protocol-tag">' + e.entry_type.toUpperCase() + '</span></td>' +
                '<td><span class="badge badge-suspicious">' + e.label + '</span></td>' +
                '<td><small class="text-muted">' + (e.source || "manual") + '</small></td>' +
                '<td><button class="btn-action-danger btn-sm btn-wl-del" data-id="' + e.id + '" style="color:var(--color-malicious); border:none; background:transparent; cursor:pointer;"><i class="fa-solid fa-trash-can"></i></button></td>';
            tbody.appendChild(tr);
        });

        tbody.querySelectorAll(".btn-wl-del").forEach(function (btn) {
            btn.onclick = function () {
                var id = this.getAttribute("data-id");
                fnFetch("/api/watchlists/" + id, { method: "DELETE" })
                .then(function () {
                    loadWatchlists();
                });
            };
        });
    })
    .catch(function (err) {
        console.error("Watchlist fetch error:", err);
    });
}
