import axios from 'axios';

const API_BASE = process.env.REACT_APP_API_URL || 'http://localhost:5000';

export const fetchThreatData = async () => {
  try {
    const response = await axios.get(`${API_BASE}/api/threats`);
    return response.data;
  } catch (error) {
    console.error('Error fetching threat data:', error);
    return { threats: [], alerts: [] };
  }
};
