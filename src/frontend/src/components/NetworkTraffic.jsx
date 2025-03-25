import React from 'react';
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';

const NetworkTraffic = () => {
  // Sample data - replace with real API data
  const trafficData = [
    { time: '00:00', traffic: 4000 },
    { time: '04:00', traffic: 3000 },
    { time: '08:00', traffic: 5000 },
    { time: '12:00', traffic: 2780 },
    { time: '16:00', traffic: 1890 },
    { time: '20:00', traffic: 2390 },
  ];

  return (
    <div className="h-64">
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={trafficData}>
          <XAxis dataKey="time" stroke="#6B7280" />
          <YAxis stroke="#6B7280" />
          <Tooltip
            contentStyle={{ backgroundColor: '#1F2937', border: 'none' }}
            itemStyle={{ color: '#E5E7EB' }}
          />
          <Line
            type="monotone"
            dataKey="traffic"
            stroke="#3B82F6"
            strokeWidth={2}
            dot={false}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
};

export default NetworkTraffic;
