const User = require('../models/User');

exports.subscribeToPlan = async (req, res) => {
  try {
    const { userId } = req.user;
    const { planName, price } = req.body;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    user.plan = {
      name: planName.charAt(0).toUpperCase() + planName.slice(1).toLowerCase(), // Capitalize first letter
      price: price,
      subscribedAt: new Date(),
      availableTemplates: planName.toLowerCase() === 'basic' ? [2, 3] : [1] // Set templates based on plan
    };

    await user.save();

    res.json({ message: 'Subscribed to plan successfully', plan: user.plan });
  } catch (error) {
    console.error('Error subscribing to plan:', error);
    res.status(500).json({ error: 'Error subscribing to plan' });
  }
};
