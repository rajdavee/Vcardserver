const mongoose = require('mongoose');

const templateSchema = new mongoose.Schema({
  templateId: { type: Number, required: true, unique: true },
  name: { type: String, required: true },
  availablePlans: [{
    type: String,
    enum: ['Free', 'Basic', 'Pro', 'Enterprise'],
    required: true
  }]
});

module.exports = mongoose.model('Template', templateSchema);
