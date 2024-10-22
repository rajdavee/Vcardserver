const User = require('../models/User');
const VCardScan = require('../models/VCardScan');
const axios = require('axios');

exports.getVCardAnalytics = async (req, res) => {
  try {
    const { vCardId } = req.params;
    const { userId } = req.user;

    // Check if the vCard belongs to the user
    const user = await User.findOne({ _id: userId, 'vCards._id': vCardId });
    if (!user) {
      return res.status(404).json({ error: 'vCard not found or does not belong to the user' });
    }

    const vCardScan = await VCardScan.findOne({ vCardId });
    if (!vCardScan) {
      return res.json({
        totalScans: 0,
        qrScans: 0,
        linkClicks: 0,
        previewClicks: 0,
        recentScans: [],
        locationBreakdown: {},
        deviceBreakdown: {},
        timeBreakdown: {}
      });
    }

    const scans = vCardScan.scans;

    const analytics = {
      totalScans: scans.length,
      qrScans: vCardScan.qrScans || 0,
      linkClicks: vCardScan.linkClicks || 0,
      previewClicks: vCardScan.previewClicks || 0,
      recentScans: [],
      locationBreakdown: {},
      deviceBreakdown: {},
      timeBreakdown: {
        hourly: Array(24).fill(0),
        daily: Array(7).fill(0),
        monthly: Array(12).fill(0)
      }
    };

    const uniqueIPs = new Set();

    for (const scan of scans) {
      if (!uniqueIPs.has(scan.ipAddress)) {
        uniqueIPs.add(scan.ipAddress);

        // Recent scans
        if (analytics.recentScans.length < 10) {
          analytics.recentScans.push({
            scanDate: scan.scanDate,
            location: {
              city: scan.location?.city || 'Unknown',
              country: scan.location?.country || 'Unknown'
            },
            device: scan.userAgent?.includes('Mobile') ? 'Mobile' : 'Desktop',
            scanType: scan.scanType || 'Unknown'
          });
        }

        // Location breakdown
        const country = scan.location?.country || 'Unknown';
        analytics.locationBreakdown[country] = (analytics.locationBreakdown[country] || 0) + 1;

        // Device breakdown
        const device = scan.userAgent?.includes('Mobile') ? 'Mobile' : 'Desktop';
        analytics.deviceBreakdown[device] = (analytics.deviceBreakdown[device] || 0) + 1;

        // Time breakdown
        const scanDate = new Date(scan.scanDate);
        analytics.timeBreakdown.hourly[scanDate.getHours()]++;
        analytics.timeBreakdown.daily[scanDate.getDay()]++;
        analytics.timeBreakdown.monthly[scanDate.getMonth()]++;
      }
    }

    // Update totalScans to reflect unique IP count
    analytics.totalScans = uniqueIPs.size;

    // Sort recent scans by date
    analytics.recentScans.sort((a, b) => new Date(b.scanDate) - new Date(a.scanDate));

    res.json(analytics);
  } catch (error) {
    console.error('Error fetching vCard analytics:', error);
    res.status(500).json({ error: 'Error fetching vCard analytics', details: error.message });
  }
};

// Add this new function at the end of the file
async function getLocationData(ip) {
  try {
    const response = await axios.get(`http://ip-api.com/json/${ip}`);
    if (response.data.status === 'success') {
      return {
        city: response.data.city,
        country: response.data.country,
        latitude: response.data.lat,
        longitude: response.data.lon
      };
    } else {
      throw new Error('Failed to get location data');
    }
  } catch (error) {
    console.error('Error fetching location data:', error);
    return {
      city: 'Unknown',
      country: 'Unknown',
      latitude: null,
      longitude: null
    };
  }
}
