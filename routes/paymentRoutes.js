const express = require('express');
const router = express.Router();
const { createCheckoutSession, handlePaymentSuccess, getUserPlan } = require('../controllers/paymentController');
const authenticateJWT = require('../middleware/authMiddleware');

// Create Checkout Session
router.post('/create-checkout-session', authenticateJWT, createCheckoutSession);

// Handle Payment Success
router.get('/payment-success', handlePaymentSuccess);
router.get('/user-plan', authenticateJWT, getUserPlan);

module.exports = router;
