const User = require('../models/User');
const VCardScan = require('../models/VCardScan');

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
    if (!vCardScan || !vCardScan.scans || vCardScan.scans.length === 0) {
      return res.json({
        totalScans: 0,
        recentScans: [],
        locationBreakdown: {},
        deviceBreakdown: {},
        timeBreakdown: {}
      });
    }

    const scans = vCardScan.scans;

    const analytics = {
      totalScans: scans.length,
      recentScans: scans.slice(-10).reverse().map(scan => ({
        scanDate: scan.scanDate,
        location: {
          city: scan.location?.city || 'Unknown',
          country: scan.location?.country || 'Unknown'
        },
        device: scan.userAgent.includes('Mobile') ? 'Mobile' : 'Desktop'
      })),
      locationBreakdown: {},
      deviceBreakdown: {},
      timeBreakdown: {
        hourly: Array(24).fill(0),
        daily: Array(7).fill(0),
        monthly: Array(12).fill(0)
      }
    };

    scans.forEach(scan => {
      // Location breakdown
      const country = scan.location?.country || 'Unknown';
      analytics.locationBreakdown[country] = (analytics.locationBreakdown[country] || 0) + 1;

      // Device breakdown
      const device = scan.userAgent.includes('Mobile') ? 'Mobile' : 'Desktop';
      analytics.deviceBreakdown[device] = (analytics.deviceBreakdown[device] || 0) + 1;

      // Time breakdown
      const scanDate = new Date(scan.scanDate);
      analytics.timeBreakdown.hourly[scanDate.getHours()]++;
      analytics.timeBreakdown.daily[scanDate.getDay()]++;
      analytics.timeBreakdown.monthly[scanDate.getMonth()]++;
    });

    res.json(analytics);
  } catch (error) {
    console.error('Error fetching vCard analytics:', error);
    res.status(500).json({ error: 'Error fetching vCard analytics', details: error.message });
  }
};
