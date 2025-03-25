import React from 'react';
import { FiAlertTriangle } from 'react-icons/fi';

const severityColors = {
  critical: 'bg-red-500',
  high: 'bg-orange-500',
  medium: 'bg-yellow-500'
};

const RealTimeAlerts = ({ alerts }) => {
  return (
    <div className="space-y-4">
      {alerts.map((alert, index) => (
        <div
          key={index}
          className="p-4 bg-gray-700 rounded-lg flex items-start space-x-3"
        >
          <div className={`${severityColors[alert.severity]} p-2 rounded-full`}>
            <FiAlertTriangle className="text-white text-lg" />
          </div>
          <div>
            <h3 className="text-white font-medium">{alert.title}</h3>
            <p className="text-gray-400 text-sm mt-1">{alert.description}</p>
            <span className="text-xs text-gray-500 mt-2 block">
              {new Date(alert.timestamp).toLocaleTimeString()}
            </span>
          </div>
        </div>
      ))}
    </div>
  );
};

export default RealTimeAlerts;
