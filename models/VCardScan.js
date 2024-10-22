const mongoose = require('mongoose');

const VCardScanSchema = new mongoose.Schema({
  vCardId: { type: mongoose.Schema.Types.ObjectId, ref: 'VCard', required: true },
  qrScans: { type: Number, default: 0 },
  linkClicks: { type: Number, default: 0 },
  previewClicks: { type: Number, default: 0 },
  scans: [{
    ipAddress: String,
    userAgent: String,
    scanDate: Date,
    scanType: String,
    device: String,
    location: {
      city: String,
      country: String,
      latitude: Number,
      longitude: Number
    }
  }]
});

module.exports = mongoose.model('VCardScan', VCardScanSchema);
