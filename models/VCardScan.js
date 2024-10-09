const mongoose = require('mongoose');

const vCardScanSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: false  // Changed to false
  },
  vCardId: {
    type: mongoose.Schema.Types.ObjectId,
    required: true
  },
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
  }
});

module.exports = mongoose.model('VCardScan', vCardScanSchema);