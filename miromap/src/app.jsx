import React, { useState, useEffect } from 'react';
import { createRoot } from 'react-dom/client';

// REPLACE THIS WITH YOUR CLOUDFLARE TUNNEL URL
const TUNNEL_URL = "https://temple-dui-deemed-customers.trycloudflare.com";

const App = () => {
  const [devices, setDevices] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [msg, setMsg] = useState(null);
  const [expandedDevices, setExpandedDevices] = useState(new Set());
  const [scanningDevices, setScanningDevices] = useState(new Set());

  const fetchDevices = async () => {
    setLoading(true);
    setMsg(null);
    try {
      const res = await fetch(`${TUNNEL_URL}/devices`);
      if (!res.ok) throw new Error("Failed to fetch devices from Scanner");
      const data = await res.json();
      setDevices(data);
    } catch (err) {
      setMsg({ type: 'error', text: err.message });
    } finally {
      setLoading(false);
    }
  };

  const fetchAlerts = async () => {
    try {
      const res = await fetch(`${TUNNEL_URL}/alerts`);
      if (res.ok) {
        const data = await res.json();
        setAlerts(data);
      }
    } catch (err) {
      console.error('Failed to fetch alerts:', err);
    }
  };

  const clearAlert = async (alertId) => {
    try {
      await fetch(`${TUNNEL_URL}/clear_alert`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ alertId })
      });
      fetchAlerts();
    } catch (err) {
      console.error('Failed to clear alert:', err);
    }
  };

  const scanDevice = async (mac) => {
    setScanningDevices(prev => new Set([...prev, mac]));
    try {
      const res = await fetch(`${TUNNEL_URL}/scan_device`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mac })
      });

      if (res.ok) {
        // Wait a bit then refresh devices to get updated nmap info
        setTimeout(() => {
          fetchDevices();
          setScanningDevices(prev => {
            const newSet = new Set(prev);
            newSet.delete(mac);
            return newSet;
          });
        }, 5000); // Wait 5 seconds for scan to complete
      }
    } catch (err) {
      console.error('Failed to scan device:', err);
      setScanningDevices(prev => {
        const newSet = new Set(prev);
        newSet.delete(mac);
        return newSet;
      });
    }
  };

  const scanNetwork = async () => {
    setLoading(true);
    try {
      await fetch(`${TUNNEL_URL}/scan_network`, {
        method: 'POST'
      });

      // Wait 3 seconds then refresh device list
      setTimeout(() => {
        fetchDevices();
        setLoading(false);
      }, 3000);
    } catch (err) {
      console.error('Failed to scan network:', err);
      setLoading(false);
    }
  };

  const toggleDeviceExpand = (mac) => {
    const newExpanded = new Set(expandedDevices);
    if (newExpanded.has(mac)) {
      newExpanded.delete(mac);
    } else {
      newExpanded.add(mac);
    }
    setExpandedDevices(newExpanded);
  };

  const syncDevices = async () => {
    setSyncing(true);
    setMsg(null);
    try {
      // 1. Get all items on the board
      const boardItems = await miro.board.get({ type: 'shape' });

      // 2. Map existing MACs
      const existingMacs = new Set();
      for (const item of boardItems) {
        try {
          const deviceId = await item.getMetadata('miromap_device_id');
          if (deviceId) {
            existingMacs.add(deviceId);
          }
        } catch (err) {
          // Item doesn't have this metadata key, skip it
        }
      }

      let createdCount = 0;
      // Place devices in a dedicated area (top section, y = -500)
      // Alerts/sticky notes can be placed elsewhere (e.g., y = 500 or different x range)
      let xPos = 0;
      const DEVICE_Y_POSITION = -500; // Devices area

      // 3. Create shapes for new devices
      for (const device of devices) {
        if (!existingMacs.has(device.mac)) {
          const name = device.vendor !== "Unknown Device" ? device.vendor :
            device.vendor === "Apple (Personal Hotspot)" ? "Personal Hotspot" :
              device.ip;

          const shape = await miro.board.createShape({
            content: `<p><b>${name}</b></p><p>${device.ip}</p>`,
            x: xPos,
            y: DEVICE_Y_POSITION,
            style: {
              fillColor: device.status === 'online' ? '#d4edda' : '#f8d7da' // Light Green or Light Red
            }
          });

          // Set metadata separately after shape creation
          await shape.setMetadata('miromap_device_id', device.mac);

          // Register link with backend
          await fetch(`${TUNNEL_URL}/link_device`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ shapeId: shape.id, mac: device.mac })
          });

          xPos += 200; // Spacing
          createdCount++;
        }
      }

      setMsg({ type: 'success', text: `Sync Complete. Created ${createdCount} new shapes in devices area.` });

    } catch (err) {
      console.error(err);
      setMsg({ type: 'error', text: "Sync failed: " + err.message });
    } finally {
      setSyncing(false);
    }
  };

  useEffect(() => {
    fetchDevices();
    fetchAlerts();

    // Auto-refresh alerts every 10 seconds
    const interval = setInterval(() => {
      fetchAlerts();
    }, 10000);

    return () => clearInterval(interval);
  }, []);

  return (
    <div className="grid container">
      <div className="cs1 ce12">
        <h1>MiroMap Auto-Sync</h1>
        <p>Automatically create shapes for discovered devices.</p>
        <p style={{ fontSize: '11px', color: '#666' }}>
          💡 Devices are placed at y=-500. Place alerts/sticky notes at y=500 or different x-range to avoid overlap.
        </p>

        <div style={{ display: 'flex', gap: '10px', marginBottom: '10px', flexWrap: 'wrap' }}>
          <button className="button button-secondary" onClick={scanNetwork} disabled={loading || syncing}>
            {loading ? "Scanning..." : "🔍 Scan Network"}
          </button>
          <button className="button button-secondary" onClick={fetchDevices} disabled={loading || syncing}>
            Refetch List
          </button>
          <button className="button button-primary" onClick={syncDevices} disabled={loading || syncing || devices.length === 0}>
            {syncing ? "Creating Shapes..." : "Sync to Board"}
          </button>
        </div>

        {msg && <div className={`toast toast-${msg.type}`}>{msg.text}</div>}

        {/* Security Alerts Section */}
        {alerts.length > 0 && (
          <div style={{ marginTop: '20px', marginBottom: '20px' }}>
            <h3 style={{ fontSize: '14px', marginBottom: '10px', color: '#d32f2f' }}>
              🚨 Security Alerts ({alerts.length})
            </h3>
            <div style={{ maxHeight: '200px', overflowY: 'auto' }}>
              {alerts.map((alert) => (
                <div key={alert.id} style={{
                  border: `2px solid ${alert.severity === 'critical' ? '#d32f2f' : '#ff9800'}`,
                  backgroundColor: alert.severity === 'critical' ? '#ffebee' : '#fff3e0',
                  padding: '10px',
                  marginBottom: '8px',
                  borderRadius: '4px',
                  fontSize: '12px'
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                    <div style={{ flex: 1 }}>
                      <div style={{ fontWeight: 'bold', marginBottom: '4px', color: '#d32f2f' }}>
                        {alert.message}
                      </div>
                      <div style={{ fontSize: '11px', color: '#666', marginBottom: '6px' }}>
                        {new Date(alert.timestamp * 1000).toLocaleString()}
                      </div>
                      {alert.details && (
                        <div style={{ fontSize: '11px', color: '#555' }}>
                          <div><strong>IP:</strong> {alert.details.ip}</div>
                          <div><strong>Conflicting MACs:</strong></div>
                          <ul style={{ margin: '2px 0 0 20px', padding: 0 }}>
                            {alert.details.conflicting_macs.map((mac, idx) => (
                              <li key={idx}>
                                {mac} ({alert.details.vendors[idx] || 'Unknown'})
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </div>
                    <button
                      onClick={() => clearAlert(alert.id)}
                      style={{
                        background: '#d32f2f',
                        color: 'white',
                        border: 'none',
                        borderRadius: '3px',
                        padding: '4px 8px',
                        cursor: 'pointer',
                        fontSize: '11px',
                        marginLeft: '10px'
                      }}
                    >
                      Clear
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Devices Section */}
        <div className="device-list" style={{ marginTop: '20px', maxHeight: '400px', overflowY: 'auto' }}>
          <h2>Discovered Devices ({devices.length})</h2>
          {devices.map((device) => {
            const isExpanded = expandedDevices.has(device.mac);
            const hasNmapInfo = device.nmap_info && Object.keys(device.nmap_info).length > 0;
            const isScanning = scanningDevices.has(device.mac);

            return (
              <div key={device.mac} className="device-card" style={{
                border: '1px solid #ccc',
                padding: '10px',
                marginBottom: '8px',
                borderRadius: '4px',
                fontSize: '12px',
                backgroundColor: '#fff'
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div style={{ flex: 1 }}>
                    <b>{device.ip}</b> - {device.vendor}
                    {device.hostname && <span style={{ color: '#666', marginLeft: '8px' }}>({device.hostname})</span>}
                  </div>
                  <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                    {!hasNmapInfo && (
                      <button
                        onClick={() => scanDevice(device.mac)}
                        disabled={isScanning}
                        style={{
                          background: isScanning ? '#ccc' : '#1976d2',
                          color: 'white',
                          border: 'none',
                          borderRadius: '3px',
                          padding: '4px 8px',
                          cursor: isScanning ? 'not-allowed' : 'pointer',
                          fontSize: '11px'
                        }}
                      >
                        {isScanning ? '⏳ Scanning...' : '🔍 Deep Scan'}
                      </button>
                    )}
                    {hasNmapInfo && (
                      <button
                        onClick={() => toggleDeviceExpand(device.mac)}
                        style={{
                          background: 'none',
                          border: 'none',
                          cursor: 'pointer',
                          fontSize: '14px',
                          padding: '4px 8px'
                        }}
                      >
                        {isExpanded ? '▼' : '▶'}
                      </button>
                    )}
                  </div>
                </div>

                {isExpanded && hasNmapInfo && (
                  <div style={{
                    marginTop: '10px',
                    paddingTop: '10px',
                    borderTop: '1px solid #eee',
                    fontSize: '11px',
                    color: '#555'
                  }}>
                    {device.nmap_info.os && device.nmap_info.os !== 'Unknown' && (
                      <div style={{ marginBottom: '6px' }}>
                        <strong>OS:</strong> {device.nmap_info.os}
                      </div>
                    )}
                    {device.nmap_info.hostname && (
                      <div style={{ marginBottom: '6px' }}>
                        <strong>Hostname:</strong> {device.nmap_info.hostname}
                      </div>
                    )}
                    {device.nmap_info.mac_vendor && (
                      <div style={{ marginBottom: '6px' }}>
                        <strong>MAC Vendor:</strong> {device.nmap_info.mac_vendor}
                      </div>
                    )}
                    {device.nmap_info.device_type && device.nmap_info.device_type !== 'Unknown Device' && (
                      <div style={{ marginBottom: '6px' }}>
                        <strong>Device Type:</strong> {device.nmap_info.device_type}
                      </div>
                    )}
                    {device.nmap_info.open_ports && device.nmap_info.open_ports.length > 0 && (
                      <div>
                        <strong>Open Ports:</strong>
                        <ul style={{ margin: '4px 0 0 0', paddingLeft: '20px' }}>
                          {device.nmap_info.open_ports.map((port, idx) => (
                            <li key={idx}>
                              {port.port}/{port.service} {port.version && `- ${port.version}`}
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};

const container = document.getElementById('root');
const root = createRoot(container);
root.render(<App />);
