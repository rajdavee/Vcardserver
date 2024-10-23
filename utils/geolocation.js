const axios = require('axios');

async function getLocationData(ip) {
  try {
    // First, try to get location from ipinfo.io
    const ipInfoResponse = await axios.get(`https://ipinfo.io/${ip}/json`);
    const ipInfoLocation = ipInfoResponse.data;

    if (ipInfoLocation.city && ipInfoLocation.country) {
      return {
        latitude: ipInfoLocation.loc ? parseFloat(ipInfoLocation.loc.split(',')[0]) : null,
        longitude: ipInfoLocation.loc ? parseFloat(ipInfoLocation.loc.split(',')[1]) : null,
        city: ipInfoLocation.city,
        country: ipInfoLocation.country
      };
    }

    // If ipinfo.io fails or provides incomplete data, try ip-api.com
    const ipApiResponse = await axios.get(`http://ip-api.com/json/${ip}`);
    const ipApiLocation = ipApiResponse.data;

    if (ipApiLocation.status === 'success') {
      return {
        latitude: ipApiLocation.lat,
        longitude: ipApiLocation.lon,
        city: ipApiLocation.city,
        country: ipApiLocation.country
      };
    }

    // If both services fail, return unknown location
    return {
      latitude: null,
      longitude: null,
      city: 'Unknown',
      country: 'Unknown'
    };
  } catch (error) {
    console.error('Error fetching location data:', error);
    return {
      latitude: null,
      longitude: null,
      city: 'Unknown',
      country: 'Unknown'
    };
  }
}

module.exports = { getLocationData };
