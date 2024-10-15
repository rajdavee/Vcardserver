const mongoose = require('mongoose');

const vCardSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  templateId: Number,
  fields: [{
    name: String,
    value: mongoose.Schema.Types.Mixed
  }],
  qrCode: String,
}, { timestamps: true });

module.exports = mongoose.model('VCard', vCardSchema);