const mongoose = require('mongoose');

const scanSchema = new mongoose.Schema({
  ipAddress: String,
  userAgent: String,
  scanDate: {
    type: Date,
    default: Date.now
  },
  location: {
    latitude: Number,
    longitude: Number,
    city: String,
    country: String
  },
  device: {
    type: String,
    enum: ['Mobile', 'Desktop'],
    required: true
  },
  timeSpent: Number,
  scanType: {
    type: String,
    enum: ['QR', 'Link', 'Preview'],
    default: 'QR'
  }
});

const vCardScanSchema = new mongoose.Schema({
  vCardId: {
    type: mongoose.Schema.Types.ObjectId,
    required: true,
    ref: 'User.vCards'
  },
  scans: [scanSchema],
  qrScans: { type: Number, default: 0 },
  linkClicks: { type: Number, default: 0 },
  previewClicks: { type: Number, default: 0 }
});

module.exports = mongoose.model('VCardScan', vCardScanSchema);
