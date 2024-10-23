const User = require('../models/User');
const VCard = require('../models/Vcard');
const VCardScan = require('../models/VCardScan');

exports.getAllUsers = async (req, res) => {
  try {
    const users = await User.find().select('-password');
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: 'Error fetching users' });
  }
};

exports.getUserDetails = async (req, res) => {
  try {
    const user = await User.findById(req.params.userId).select('-password');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    // Include vCards in the response
    const userWithVCards = {
      ...user.toObject(),
      vCards: user.vCards.map(vCard => ({
        ...vCard.toObject(),
        userId: {
          _id: user._id,
          username: user.username,
          email: user.email
        }
      }))
    };
    res.json(userWithVCards);
  } catch (error) {
    res.status(500).json({ error: 'Error fetching user details' });
  }
};

exports.updateUserRole = async (req, res) => {
  try {
    const { role } = req.body;
    const user = await User.findByIdAndUpdate(
      req.params.userId,
      { role },
      { new: true }
    ).select('-password');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: 'Error updating user role' });
  }
};

exports.deleteUser = async (req, res) => {
  try {
    const user = await User.findByIdAndDelete(req.params.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Error deleting user' });
  }
};

exports.getSystemStats = async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const totalVCards = await User.aggregate([
      { $unwind: '$vCards' },
      { $group: { _id: null, count: { $sum: 1 } } }
    ]);
    const totalScans = await VCardScan.aggregate([
      { $unwind: '$scans' },
      { $group: { _id: null, count: { $sum: 1 } } }
    ]);

    res.json({
      totalUsers,
      totalVCards: totalVCards[0]?.count || 0,
      totalScans: totalScans[0]?.count || 0
    });
  } catch (error) {
    res.status(500).json({ error: 'Error fetching system stats' });
  }
};

exports.getUserAnalytics = async (req, res) => {
  try {
    const userStats = await User.aggregate([
      {
        $group: {
          _id: null,
          totalUsers: { $sum: 1 },
          verifiedUsers: { $sum: { $cond: ['$isVerified', 1, 0] } },
          premiumUsers: { $sum: { $cond: [{ $ne: ['$plan.name', null] }, 1, 0] } }
        }
      }
    ]);

    res.json(userStats[0]);
  } catch (error) {
    res.status(500).json({ error: 'Error fetching user analytics' });
  }
};

exports.getVCardAnalytics = async (req, res) => {
  try {
    const vCardStats = await VCardScan.aggregate([
      {
        $group: {
          _id: '$vCardId',
          totalScans: { $sum: { $size: '$scans' } },
          uniqueVisitors: { $addToSet: '$scans.ipAddress' }
        }
      },
      {
        $project: {
          _id: 1,
          totalScans: 1,
          uniqueVisitors: { $size: '$uniqueVisitors' }
        }
      }
    ]);

    res.json(vCardStats);
  } catch (error) {
    res.status(500).json({ error: 'Error fetching vCard analytics' });
  }
};

exports.getUserVCards = async (req, res) => {
  try {
    const { userId } = req.params;
    console.log(`Fetching vCards for user: ${userId}`);
    
    const user = await User.findById(userId).populate('vCards');
    if (!user) {
      console.log(`User not found: ${userId}`);
      return res.status(404).json({ error: 'User not found' });
    }
    
    console.log(`Found ${user.vCards.length} vCards for user: ${userId}`);
    res.json(user.vCards);
  } catch (error) {
    console.error('Error fetching user vCards:', error);
    res.status(500).json({ error: 'Internal server error', details: error.message });
  }
};

exports.updateUserPlan = async (req, res) => {
  try {
    const { userId } = req.params;
    const { planName, price } = req.body;
    
    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { 
        'plan.name': planName, 
        'plan.price': price,
        'plan.subscribedAt': new Date()
      },
      { new: true }
    ).select('-password');

    if (!updatedUser) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(updatedUser);
  } catch (error) {
    console.error('Error updating user plan:', error);
    res.status(500).json({ error: 'Error updating user plan' });
  }
};

exports.getPaymentHistory = async (req, res) => {
  try {
    const user = await User.findById(req.params.userId).select('paymentInfo');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(user.paymentInfo);
  } catch (error) {
    res.status(500).json({ error: 'Error fetching payment history' });
  }
};

exports.getScanDetails = async (req, res) => {
  try {
    const scans = await VCardScan.find({ vCardId: req.params.vCardId });
    res.json(scans);
  } catch (error) {
    res.status(500).json({ error: 'Error fetching scan details' });
  }
};

exports.getRecentActivity = async (req, res) => {
  try {
    const recentScans = await VCardScan.aggregate([
      { $unwind: '$scans' },
      { $sort: { 'scans.scanDate': -1 } },
      { $limit: 50 },
      {
        $project: {
          vCardId: 1,
          scanDate: '$scans.scanDate',
          ipAddress: '$scans.ipAddress',
          location: '$scans.location'
        }
      }
    ]);

    res.json(recentScans);
  } catch (error) {
    res.status(500).json({ error: 'Error fetching recent activity' });
  }
};

exports.searchUsers = async (req, res) => {
  try {
    const { query } = req.query;
    const users = await User.find({
      $or: [
        { username: { $regex: query, $options: 'i' } },
        { email: { $regex: query, $options: 'i' } }
      ]
    }).select('-password');
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: 'Error searching users' });
  }
};

exports.promoteToAdmin = async (req, res) => {
    try {
      const { userId } = req.params;
      const user = await User.findByIdAndUpdate(
        userId,
        { role: 'admin' },
        { new: true }
      ).select('-password');
  
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }
  
      res.json({ message: 'User promoted to admin successfully', user });
    } catch (error) {
      res.status(500).json({ error: 'Error promoting user to admin' });
    }
  };

exports.addUser = async (req, res) => {
  try {
    const { username, email, password, role } = req.body;
    const newUser = new User({ username, email, password, role });
    await newUser.save();
    const userWithoutPassword = newUser.toObject();
    delete userWithoutPassword.password;
    res.status(201).json(userWithoutPassword);
  } catch (error) {
    res.status(500).json({ error: 'Error adding user' });
  }
};

exports.editUser = async (req, res) => {
  try {
    const { userId } = req.params;
    const { username, email, role } = req.body;
    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { username, email, role },
      { new: true }
    ).select('-password');
    if (!updatedUser) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(updatedUser);
  } catch (error) {
    res.status(500).json({ error: 'Error editing user' });
  }
};



// Add these new functions

exports.getAllVCards = async (req, res) => {
  try {
    const users = await User.find({}, 'username email vCards');
    const vCards = users.reduce((acc, user) => {
      return acc.concat(user.vCards.map(vCard => ({
        ...vCard.toObject(),
        _id: vCard._id, // Ensure the vCard ID is included
        userId: {
          _id: user._id,
          username: user.username,
          email: user.email
        }
      })));
    }, []);
    console.log('All vCards:', vCards); // Log all vCards for debugging
    res.json(vCards);
  } catch (error) {
    console.error('Error fetching vCards:', error);
    res.status(500).json({ error: 'Error fetching vCards' });
  }
};

exports.getVCardById = async (req, res) => {
  try {
    const vCard = await VCard.findById(req.params.vCardId).populate('userId', 'username email');
    if (!vCard) {
      return res.status(404).json({ error: 'VCard not found' });
    }
    res.json(vCard);
  } catch (error) {
    res.status(500).json({ error: 'Error fetching vCard' });
  }
};

exports.updateVCard = async (req, res) => {
  try {
    const { vCardId } = req.params;
    console.log(`Attempting to update vCard with ID: ${vCardId}`);
    console.log('Update data:', req.body);

    const user = await User.findOne({ 'vCards._id': vCardId });

    if (!user) {
      console.log(`User with vCard ID ${vCardId} not found`);
      return res.status(404).json({ error: 'VCard not found' });
    }

    const vCardIndex = user.vCards.findIndex(vCard => vCard._id.toString() === vCardId);

    if (vCardIndex === -1) {
      console.log(`VCard with ID ${vCardId} not found in user's vCards`);
      return res.status(404).json({ error: 'VCard not found' });
    }

    // Update the vCard
    user.vCards[vCardIndex] = { ...user.vCards[vCardIndex].toObject(), ...req.body };

    await user.save();

    console.log('VCard updated successfully:', user.vCards[vCardIndex]);
    res.json(user.vCards[vCardIndex]);
  } catch (error) {
    console.error('Error updating vCard:', error);
    res.status(500).json({ error: 'Error updating vCard', details: error.message });
  }
};

exports.deleteVCard = async (req, res) => {
  try {
    const { vCardId } = req.params;
    console.log(`Attempting to delete vCard with ID: ${vCardId}`);

    const user = await User.findOne({ 'vCards._id': vCardId });

    if (!user) {
      console.log(`User with vCard ID ${vCardId} not found`);
      return res.status(404).json({ error: 'VCard not found' });
    }

    user.vCards = user.vCards.filter(vCard => vCard._id.toString() !== vCardId);
    await user.save();

    console.log('VCard deleted successfully');
    res.json({ message: 'VCard deleted successfully' });
    } catch (error) {
    console.error('Error deleting vCard:', error);
    res.status(500).json({ error: 'Error deleting vCard', details: error.message });
  }
};

exports.updatePlanTemplates = async (req, res) => {
  try {
    const { planName } = req.params; // Change this line
    const { templates } = req.body;
    console.log(`Updating templates for plan: ${planName}`, templates);
    
    // Validate that templates is an array of numbers
    if (!Array.isArray(templates) || !templates.every(Number.isInteger)) {
      return res.status(400).json({ error: 'Templates must be an array of integers' });
    }

    // Update all users with the specified plan (case-insensitive)
    const result = await User.updateMany(
      { 'plan.name': { $regex: new RegExp(`^${planName}$`, 'i') } },
      { $set: { 'plan.availableTemplates': templates } }
    );

    console.log(`Updated ${result.modifiedCount} users`); // Change this line

    res.json({ message: 'Plan templates updated successfully', updatedCount: result.modifiedCount });
  } catch (error) {
    console.error('Error updating plan templates:', error);
    res.status(500).json({ error: 'Error updating plan templates' });
  }
};




