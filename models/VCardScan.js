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
  timeSpent: Number // Add this line to track time spent
});

const vCardScanSchema = new mongoose.Schema({
  vCardId: {
    type: mongoose.Schema.Types.ObjectId,
    required: true,
    ref: 'User.vCards'
  },
  scans: [scanSchema]
});

module.exports = mongoose.model('VCardScan', vCardScanSchema);