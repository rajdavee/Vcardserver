const express = require('express');
const router = express.Router();
const adminController = require('../controllers/adminController');
const authenticateJWT = require('../middleware/authMiddleware');
const adminMiddleware = require('../middleware/adminMiddleware');

// Apply both JWT authentication and admin middleware to all routes
router.use(authenticateJWT, adminMiddleware);

// User management
router.get('/users', adminController.getAllUsers);
router.get('/users/:userId', adminController.getUserDetails);
router.put('/users/:userId/role', adminController.updateUserRole);
router.delete('/users/:userId', adminController.deleteUser);
router.get('/users/:userId/vcards', adminController.getUserVCards);
router.put('/users/:userId/plan', adminController.updateUserPlan);
router.get('/users/:userId/payment-history', adminController.getPaymentHistory);
router.post('/users', adminController.addUser);
router.put('/users/:userId', adminController.editUser);

// Analytics and statistics
router.get('/stats', adminController.getSystemStats);
router.get('/analytics/users', adminController.getUserAnalytics);
router.get('/analytics/vcards', adminController.getVCardAnalytics);
router.get('/analytics/scans/:vCardId', adminController.getScanDetails);
router.get('/analytics/recent-activity', adminController.getRecentActivity);
router.put('/users/:userId/promote-to-admin', adminController.promoteToAdmin);

// Search functionality
router.get('/search/users', adminController.searchUsers);

// Add these new routes
router.get('/vcards', adminController.getAllVCards);
router.get('/vcards/:vCardId', adminController.getVCardById);
router.put('/vcards/:vCardId', adminController.updateVCard);
router.delete('/vcards/:vCardId', adminController.deleteVCard);

module.exports = router;
