const mongoose = require('mongoose');

const formSubmissionSchema = new mongoose.Schema({
  vCardId: {
    type: mongoose.Schema.Types.ObjectId,
    required: true,
    ref: 'User.vCards'
  },
  submitterName: {
    type: String,
    required: true
  },
  submitterEmail: {
    type: String,
    required: true
  },
  submitterPhone: {
    type: String,
    required: false
  },
  message: {
    type: String,
    required: true
  },
  submittedAt: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model('FormSubmission', formSubmissionSchema); 