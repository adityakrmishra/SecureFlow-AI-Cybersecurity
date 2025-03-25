import React from 'react';

const IncidentList = () => {
  const incidents = [
    {
      id: 1,
      type: 'Ransomware',
      status: 'Active',
      severity: 'Critical',
      timestamp: '2023-08-20T14:30:00'
    },
    {
      id: 2,
      type: 'Phishing',
      status: 'Contained',
      severity: 'High',
      timestamp: '2023-08-20T12:45:00'
    }
  ];

  return (
    <div className="overflow-x-auto">
      <table className="w-full">
        <thead>
          <tr className="text-left text-gray-400 text-sm">
            <th className="pb-3">Type</th>
            <th className="pb-3">Status</th>
            <th className="pb-3">Severity</th>
            <th className="pb-3">Time</th>
          </tr>
        </thead>
        <tbody>
          {incidents.map((incident) => (
            <tr key={incident.id} className="border-t border-gray-700">
              <td className="py-3 text-white">{incident.type}</td>
              <td className="py-3">
                <span className="px-2 py-1 bg-blue-500/20 text-blue-400 rounded-full text-xs">
                  {incident.status}
                </span>
              </td>
              <td className="py-3">
                <span className={`px-2 py-1 ${
                  incident.severity === 'Critical' 
                    ? 'bg-red-500/20 text-red-400' 
                    : 'bg-orange-500/20 text-orange-400'
                } rounded-full text-xs`}>
                  {incident.severity}
                </span>
              </td>
              <td className="py-3 text-gray-400 text-sm">
                {new Date(incident.timestamp).toLocaleTimeString()}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

export default IncidentList;
