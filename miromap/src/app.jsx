import React, { useState, useEffect } from 'react';
import { createRoot } from 'react-dom/client';

// REPLACE THIS WITH YOUR CLOUDFLARE TUNNEL URL
const TUNNEL_URL = "https://conclusions-effectiveness-gotten-neil.trycloudflare.com";

const App = () => {
  const [devices, setDevices] = useState([]);
  const [loading, setLoading] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [msg, setMsg] = useState(null);

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

  const syncDevices = async () => {
    setSyncing(true);
    setMsg(null);
    try {
      // 1. Get all items on the board
      const boardItems = await miro.board.get({ type: 'shape' });

      // 2. Map existing MACs
      const existingMacs = new Set();
      boardItems.forEach(item => {
        if (item.metadata && item.metadata.miromap_device_id) {
          existingMacs.add(item.metadata.miromap_device_id);
        }
      });

      let createdCount = 0;
      let xPos = 0;

      // 3. Create shapes for new devices
      for (const device of devices) {
        if (!existingMacs.has(device.mac)) {
          const name = device.vendor !== "Unknown Device" ? device.vendor :
            device.vendor === "Apple (Personal Hotspot)" ? "Personal Hotspot" :
              device.ip;

          const shape = await miro.board.createShape({
            content: `<p><b>${name}</b></p><p>${device.ip}</p>`,
            x: xPos,
            y: 0,
            style: {
              fillColor: device.status === 'online' ? '#d4edda' : '#f8d7da' // Light Green or Light Red
            },
            metadata: {
              miromap_device_id: device.mac
            }
          });

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

      setMsg({ type: 'success', text: `Sync Complete. Created ${createdCount} new shapes.` });

    } catch (err) {
      console.error(err);
      setMsg({ type: 'error', text: "Sync failed: " + err.message });
    } finally {
      setSyncing(false);
    }
  };

  useEffect(() => {
    fetchDevices();
  }, []);

  return (
    <div className="grid container">
      <div className="cs1 ce12">
        <h1>MiroMap Auto-Sync</h1>
        <p>Automatically create shapes for discovered devices.</p>

        <div style={{ display: 'flex', gap: '10px', marginBottom: '10px' }}>
          <button className="button button-secondary" onClick={fetchDevices} disabled={loading || syncing}>
            {loading ? "Scanning..." : "Refetch List"}
          </button>
          <button className="button button-primary" onClick={syncDevices} disabled={loading || syncing || devices.length === 0}>
            {syncing ? "Creating Shapes..." : "Sync to Board"}
          </button>
        </div>

        {msg && <div className={`toast toast-${msg.type}`}>{msg.text}</div>}

        <div className="device-list" style={{ marginTop: '20px' }}>
          {devices.map((device) => (
            <div key={device.mac} className="device-card" style={{
              border: '1px solid #ccc',
              padding: '8px',
              marginBottom: '5px',
              borderRadius: '4px',
              fontSize: '12px'
            }}>
              <b>{device.ip}</b> - {device.vendor}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

const container = document.getElementById('root');
const root = createRoot(container);
root.render(<App />);
