const axios = require('axios');

async function getLocationData(ip) {
  try {
    const [ipApiResponse, ipInfoResponse] = await Promise.all([
      axios.get(`http://ip-api.com/json/${ip}`),
      axios.get(`https://ipinfo.io/${ip}/json`)
    ]);

    const ipApiLocation = ipApiResponse.data;
    const ipInfoLocation = ipInfoResponse.data;

    if (ipInfoLocation.city && ipInfoLocation.country) {
      return {
        latitude: ipInfoLocation.loc ? parseFloat(ipInfoLocation.loc.split(',')[0]) : null,
        longitude: ipInfoLocation.loc ? parseFloat(ipInfoLocation.loc.split(',')[1]) : null,
        city: ipInfoLocation.city,
        country: ipInfoLocation.country
      };
    } else if (ipApiLocation.status === 'success') {
      return {
        latitude: ipApiLocation.lat,
        longitude: ipApiLocation.lon,
        city: ipApiLocation.city,
        country: ipApiLocation.country
      };
    }

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