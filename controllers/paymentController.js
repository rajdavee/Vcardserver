const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const User = require('../models/User');
const sendEmail = require('../utils/sendEmail');
const generateInvoicePDF = require('../utils/generateInvoicePDF');

exports.createCheckoutSession = async (req, res) => {
  const { amount, planName } = req.body;
  const userId = req.user.userId; // Get userId from authenticated request

  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [{
        price_data: {
          currency: 'usd',
          product_data: { name: planName },
          unit_amount: parseInt(amount, 10),
        },
        quantity: 1,
      }],
      mode: 'payment',
      success_url: `${process.env.FRONTEND_URL}/api/payments/payment-success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.FRONTEND_URL}/dashboard`,
      client_reference_id: userId,
    });

    res.json({ id: session.id });
  } catch (error) {
    res.status(500).json({ error: error.message || 'Failed to create checkout session' });
  }
};

exports.handlePaymentSuccess = async (req, res) => {
  const { session_id } = req.query;

  if (!session_id) {
    return res.status(400).json({ success: false, error: 'No session ID provided' });
  }

  try {
    const session = await stripe.checkout.sessions.retrieve(session_id, {
      expand: ['line_items.data.price.product']
    });

    if (!session) {
      return res.status(404).json({ success: false, error: 'Session not found' });
    }

    const userId = session.client_reference_id;

    if (!userId) {
      return res.status(400).json({ success: false, error: 'User ID not found in session' });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    if (session.payment_status === 'paid') {
      const planName = session.line_items.data[0].price.product.name;
      const amount = session.amount_total / 100;

      // Update user's plan
      user.plan = {
        name: planName,
        price: amount,
        subscribedAt: new Date(),
      };

      // Update user's payment information
      user.paymentInfo = {
        sessionId: session_id,
        paymentDate: new Date(),
        amount: amount
      };

      await user.save();

      const invoicePDF = await generateInvoicePDF({
        invoiceNumber: `INV-${Date.now()}`,
        planName,
        amount,
        userEmail: user.email,
        userName: user.username,
        date: new Date(),
        companyDetails: {
          name: 'vCard Pro Inc.',
          address: '123 Business Street',
          city: 'Tech City',
          country: 'Country',
          phone: '+1 (555) 123-4567',
          email: 'support@vcardpro.com'
        }
      });

      await sendEmail({
        to: user.email,
        subject: 'Your vCard Pro Invoice',
        text: 'Thank you for your purchase. Please find your invoice attached.',
        attachments: [
          {
            filename: 'invoice.pdf',
            content: invoicePDF
          }
        ]
      });

      return res.json({ success: true, planName: planName });
    } else if (session.payment_status === 'pending') {
      return res.json({ success: false, status: 'pending' });
    } else {
      return res.json({ success: false, status: 'failed' });
    }
  } catch (error) {
    console.error('Error handling payment success:', error);
    return res.status(500).json({ success: false, error: error.message || 'Error handling payment success' });
  }
};


exports.getUserPlan = async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ planName: user.plan?.name || 'Free' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch user plan' });
  }
};