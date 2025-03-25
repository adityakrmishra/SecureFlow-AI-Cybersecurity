import React, { useState, useEffect } from 'react';
import { fetchThreatData } from '../api/threatApi';
import ThreatChart from './ThreatChart';
import RealTimeAlerts from './RealTimeAlerts';
import NetworkTraffic from './NetworkTraffic';
import IncidentList from './IncidentList';

const Dashboard = () => {
  const [threatData, setThreatData] = useState([]);
  const [alerts, setAlerts] = useState([]);

  useEffect(() => {
    const loadData = async () => {
      const data = await fetchThreatData();
      setThreatData(data.threats);
      setAlerts(data.alerts);
    };
    
    loadData();
    const interval = setInterval(loadData, 30000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="p-8 grid grid-cols-1 lg:grid-cols-3 gap-6">
      {/* Threat Overview */}
      <div className="lg:col-span-2 bg-gray-800 p-6 rounded-xl">
        <h2 className="text-2xl font-bold text-white mb-4">Threat Overview</h2>
        <ThreatChart data={threatData} />
      </div>

      {/* Real-time Alerts */}
      <div className="bg-gray-800 p-6 rounded-xl">
        <h2 className="text-2xl font-bold text-white mb-4">Active Alerts</h2>
        <RealTimeAlerts alerts={alerts} />
      </div>

      {/* Network Traffic */}
      <div className="lg:col-span-2 bg-gray-800 p-6 rounded-xl">
        <h2 className="text-2xl font-bold text-white mb-4">Network Traffic</h2>
        <NetworkTraffic />
      </div>

      {/* Recent Incidents */}
      <div className="bg-gray-800 p-6 rounded-xl">
        <h2 className="text-2xl font-bold text-white mb-4">Recent Incidents</h2>
        <IncidentList />
      </div>
    </div>
  );
};

export default Dashboard;
