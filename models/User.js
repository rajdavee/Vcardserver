const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const vCardSchema = new mongoose.Schema({
  templateId: Number,
  fields: [{
    name: String,
    value: mongoose.Schema.Types.Mixed
  }],
  qrCode: String,
  scans: [{ type: mongoose.Schema.Types.ObjectId, ref: 'VCardScan' }]
}, { timestamps: true });

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  isVerified: { type: Boolean, default: false },
  verificationToken: String,
  verificationExpires: Date,
  lastVerificationSent: Date,
  resetPasswordToken: String,
  resetPasswordExpires: Date,
  plan: {
    name: { type: String, default: null },
    price: { type: Number, default: 0 },
    subscribedAt: { type: Date, default: null }
  },
  paymentInfo: {
    sessionId: { type: String, default: null },
    paymentDate: { type: Date, default: null },
    amount: { type: Number, default: 0 }
  },
  vCards: [vCardSchema]
});

// Password hashing middleware
userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

// Password comparison method
userSchema.methods.comparePassword = async function (candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

module.exports = mongoose.model('User', userSchema);
