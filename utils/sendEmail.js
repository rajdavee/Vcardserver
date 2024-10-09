const nodemailer = require('nodemailer');

const sendEmail = async (options) => {
  const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT,
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });

  const mailOptions = {
    from: process.env.EMAIL_FROM,
    to: options.to, // Make sure this is set correctly
    subject: options.subject,
    text: options.text,
    html: options.html,
  };

  if (options.attachments) {
    mailOptions.attachments = options.attachments;
  }

  try {
    console.log('Sending email to:', options.to); // Add this log
    console.log('Email options:', options);
    console.log('Mail options:', mailOptions);
    await transporter.sendMail(mailOptions);
    console.log('Email sent successfully');
  } catch (error) {
    console.error('Error sending email:', error);
    throw error;
  }
};

module.exports = sendEmail;