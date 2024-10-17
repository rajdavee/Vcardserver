  const User = require('../models/User');
  const jwt = require('jsonwebtoken');
  const sendEmail = require('../utils/sendEmail');
  const vCardsJS = require('vcards-js');
  const multer = require('multer');
  const fs = require('fs-extra');
  const QRCode = require('qrcode');
  const vCard = require('vcf');
  const ejs = require('ejs');
  const path = require('path');
  const crypto = require('crypto');
  const VCardScan = require('../models/VCardScan');
  const axios = require('axios');
  const mongoose = require('mongoose');








// ----------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------
// ----------------------------{ Vcards functions }-------------------------------------
// ----------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------






// async function generateAndSaveQRCode(vCardId, user, vCardIndex) {
//   try {
//     const previewUrl = `${process.env.FRONTEND_URL}/preview?vCardId=${vCardId}`;
//     const qrCodeDataUrl = await QRCode.toDataURL(previewUrl);
//     user.vCards[vCardIndex].qrCode = qrCodeDataUrl;
//     await user.save();
//     return qrCodeDataUrl;
//   } catch (error) {
//     console.error('Error generating QR code:', error);
//     throw error;
//   }
// }



async function generateAndSaveQRCode(vCardId, user, vCardIndex) {
  try {
    const scanUrl = `${process.env.FRONTEND_URL}/api/scan/${vCardId}`;
    const qrCodeDataUrl = await QRCode.toDataURL(scanUrl);
    user.vCards[vCardIndex].qrCode = qrCodeDataUrl;
    await user.save();
    return qrCodeDataUrl;
  } catch (error) {
    console.error('Error generating QR code:', error);
    throw error;
  }
}












// exports.updateVCard = async (req, res) => {
//   try {
//     const { userId } = req.user;
//     const { vCardId } = req.params;
//     const { templateId, fields } = req.body;

//     const user = await User.findById(userId);
//     if (!user) {
//       return res.status(404).json({ error: 'User not found' });
//     }

//     const vCardIndex = user.vCards.findIndex(card => card._id.toString() === vCardId);
//     if (vCardIndex === -1) {
//       return res.status(404).json({ error: 'vCard not found' });
//     }

//     user.vCards[vCardIndex].templateId = templateId;
//     user.vCards[vCardIndex].fields = fields;

//     const vCardString = generateVCardString(user.vCards[vCardIndex]);
//     const qrCodeDataUrl = await generateAndSaveQRCode(vCardId, user, vCardIndex);

//     await user.save();

//     res.json({ 
//       message: 'vCard updated successfully',
//       vCardString,
//       qrCodeDataUrl
//     });
//   } catch (error) {
//     console.error('Error updating vCard:', error);
//     res.status(500).json({ error: 'Error updating vCard', details: error.message });
//   }
// };




exports.getVCards = async (req, res) => {
  try {
    const userId = req.user.userId;
    const user = await User.findById(userId).select('vCards');

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(user.vCards || []);
  } catch (error) {
    console.error('Error fetching vCards:', error);
    res.status(500).json({ error: 'Failed to fetch vCards' });
  }
};




exports.getVCard = async (req, res) => {
  try {
    const { vCardId } = req.params;
    const userId = req.user.userId;
    console.log(`Fetching vCard ${vCardId} for user ${userId}`);

    const user = await User.findOne({ _id: userId, 'vCards._id': vCardId });
    
    if (!user) {
      console.log(`User or vCard not found for userId: ${userId}, vCardId: ${vCardId}`);
      return res.status(404).json({ error: 'vCard not found' });
    }

    const vCard = user.vCards.id(vCardId);
    if (!vCard) {
      console.log(`vCard not found in user document for vCardId: ${vCardId}`);
      return res.status(404).json({ error: 'vCard not found in user document' });
    }

    console.log(`Successfully fetched vCard: ${JSON.stringify(vCard)}`);
    res.json({
      ...vCard.toObject(),
      qrCodeDataUrl: vCard.qrCode
    });
  } catch (error) {
    console.error('Error fetching vCard:', error);
    res.status(500).json({ error: 'Error fetching vCard', details: error.message });
  }
};





exports.getPublicVCard = async (req, res) => {
  try {
    const { id } = req.params;
    console.log(`Fetching public vCard with id: ${id}`);
    
    const user = await User.findOne({ 'vCards._id': id });
    
    if (!user) {
      console.log(`vCard not found for id: ${id}`);
      return res.status(404).json({ error: 'vCard not found' });
    }

    const vCard = user.vCards.id(id);
    
    if (!vCard) {
      console.log(`vCard not found in user document for id: ${id}`);
      return res.status(404).json({ error: 'vCard not found' });
    }

    console.log(`Successfully fetched public vCard: ${JSON.stringify(vCard)}`);
    res.json({
      ...vCard.toObject(),
      qrCodeDataUrl: vCard.qrCode
    });
  } catch (error) {
    console.error('Error fetching public vCard:', error);
    res.status(500).json({ error: 'Error fetching vCard' });
  }
};






function generateVCardString(vCardData) {
  let vCard = `BEGIN:VCARD\nVERSION:3.0\n`;
  const fieldMap = new Map(vCardData.fields.map(f => [f.name, f.value]));

  // Name
  const fullName = fieldMap.get('name') || `${fieldMap.get('firstName') || ''} ${fieldMap.get('lastName') || ''}`.trim();
  vCard += `FN:${fullName}\n`;
  vCard += `N:${fullName.split(' ').reverse().join(';')};;;\n`;

  if (fieldMap.has('phone')) vCard += `TEL;TYPE=CELL:${fieldMap.get('phone')}\n`;
  if (fieldMap.has('email')) vCard += `EMAIL:${fieldMap.get('email')}\n`;
  if (fieldMap.has('website')) vCard += `URL:${fieldMap.get('website')}\n`;
  if (fieldMap.has('jobTitle')) vCard += `TITLE:${fieldMap.get('jobTitle')}\n`;
  if (fieldMap.has('company')) vCard += `ORG:${fieldMap.get('company')}\n`;

  const address = [fieldMap.get('address'), fieldMap.get('city'), fieldMap.get('postalCode')].filter(Boolean).join(', ');
  if (address) vCard += `ADR:;;${address};;;;\n`;

  vCard += `END:VCARD`;
  return vCard;
}





async function generateQRCode(vCardData) {
  const vCardString = generateVCardString(vCardData);
  const qrCodeDataUrl = await QRCode.toDataURL(`${process.env.FRONTEND_URL}/add-contact?vCardData=${encodeURIComponent(vCardString)}`);
  return { qrCodeDataUrl, vCardString };
}




exports.createVCard = async (req, res) => {
  try {
    const { userId } = req.user;
    const { templateId, fields } = JSON.parse(req.body.data);

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const newVCard = {
      templateId,
      fields
    };

    // Handle file upload if present
    if (req.files && req.files.profileImage) {
      const file = req.files.profileImage;
      const fileName = `${Date.now()}_${file.name}`;
      await file.mv(path.join(__dirname, '..', 'uploads', fileName));
      newVCard.fields.push({ name: 'profileImage', value: `/uploads/${fileName}` });
    }

    const { qrCodeDataUrl, vCardString } = await generateQRCode(newVCard);
    
    const vCardId = new mongoose.Types.ObjectId();
    user.vCards.push({
      _id: vCardId,
      ...newVCard,
      qrCode: qrCodeDataUrl,
      vCardString: vCardString
    });

    await user.save();

    res.status(201).json({
      message: 'vCard created successfully',
      vCardId: vCardId.toString(),
      qrCodeDataUrl: qrCodeDataUrl,
      vCardString: vCardString,
      previewLink: `${process.env.FRONTEND_URL}/preview?vCardId=${vCardId.toString()}`
    });
  } catch (error) {
    console.error('Error creating vCard:', error);
    res.status(500).json({ error: 'Error creating vCard', details: error.message });
  }
};




exports.updateVCard = async (req, res) => {
  try {
    const { userId } = req.user;
    const { vCardId } = req.params;
    let { templateId, fields } = JSON.parse(req.body.data);

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const vCardIndex = user.vCards.findIndex(card => card._id.toString() === vCardId);
    if (vCardIndex === -1) {
      return res.status(404).json({ error: 'vCard not found' });
    }

    // Handle file upload if present
    if (req.files && req.files.profileImage) {
      const file = req.files.profileImage;
      const fileName = `${Date.now()}_${file.name}`;
      await file.mv(path.join(__dirname, '..', 'uploads', fileName));
      fields = fields.filter(field => field.name !== 'profileImage');
      fields.push({ name: 'profileImage', value: `/uploads/${fileName}` });
    }

    user.vCards[vCardIndex].templateId = templateId;
    user.vCards[vCardIndex].fields = fields;

    const { qrCodeDataUrl, vCardString } = await generateQRCode(user.vCards[vCardIndex]);
    user.vCards[vCardIndex].qrCode = qrCodeDataUrl;
    user.vCards[vCardIndex].vCardString = vCardString;

    await user.save();

    res.json({
      message: 'vCard updated successfully',
      qrCodeDataUrl: qrCodeDataUrl,
      vCardString: vCardString,
      previewLink: `${process.env.FRONTEND_URL}/preview?vCardId=${vCardId}`
    });
  } catch (error) {
    console.error('Error updating vCard:', error);
    res.status(500).json({ error: 'Error updating vCard', details: error.message });
  }
};























// exports.createVCard = async (req, res) => {
//   try {
//     const { userId } = req.user;
//     let templateId, fields;

//     console.log('Request body:', req.body);
//     console.log('Request files:', req.files);

//     // Check if data is sent as JSON or form-data
//     if (req.is('application/json')) {
//       ({ templateId, fields } = req.body);
//     } else if (req.body.data) {
//       try {
//         const parsedData = JSON.parse(req.body.data);
//         templateId = parsedData.templateId;
//         fields = parsedData.fields;
//       } catch (error) {
//         console.error('Error parsing JSON data:', error);
//         return res.status(400).json({ error: 'Invalid JSON data in form-data' });
//       }
//     } else {
//       console.error('No valid data found in request');
//       return res.status(400).json({ error: 'No valid data found in request' });
//     }

//     console.log('Parsed data:', { templateId, fields });

//     if (!Array.isArray(fields)) {
//       console.error('Fields is not an array:', fields);
//       return res.status(400).json({ error: 'Fields must be an array' });
//     }

//     const user = await User.findById(userId);
//     if (!user) {
//       return res.status(404).json({ error: 'User not found' });
//     }

//     const newVCard = { templateId, fields };

//     // Handle file upload if present
//     if (req.files && req.files.profileImage) {
//       const file = req.files.profileImage;
//       const fileName = `${Date.now()}-${file.name}`;
//       const uploadPath = path.join(__dirname, '..', 'public', 'uploads', fileName);
//       await file.mv(uploadPath);
//       console.log('File uploaded:', uploadPath);

//       // Add or update profileImage field
//       const profileImageIndex = fields.findIndex(field => field.name === 'profileImage');
//       if (profileImageIndex !== -1) {
//         fields[profileImageIndex].value = `/uploads/${fileName}`;
//       } else {
//         fields.push({ name: 'profileImage', value: `/uploads/${fileName}` });
//       }
//     }

//     user.vCards.push(newVCard);
//     await user.save();

//     const vCardId = user.vCards[user.vCards.length - 1]._id;
//     const vCardString = generateVCardString(newVCard);
//     const previewLink = `${process.env.FRONTEND_URL}/preview?vCardId=${vCardId}`;
//     const qrCodeDataUrl = await generateQRCode(vCardId);

//     // Update the vCard with the QR code
//     user.vCards[user.vCards.length - 1].qrCode = qrCodeDataUrl;
//     await user.save();

//     res.status(201).json({ 
//       message: 'vCard created successfully', 
//       vCardId: vCardId,
//       vCardString: vCardString,
//       previewLink: previewLink,
//       qrCodeDataUrl: qrCodeDataUrl
//     });
//   } catch (error) {
//     console.error('Error creating vCard:', error);
//     res.status(500).json({ error: 'Error creating vCard', details: error.message });
//   }
// };


exports.uploadChunk = async (req, res) => {
  if (!req.files || Object.keys(req.files).length === 0) {
    return res.status(400).send('No files were uploaded.');
  }

  const { chunk } = req.files;
  const { fileName, chunkIndex, totalChunks } = req.body;

  const uploadDir = path.join(__dirname, '..', 'public', 'uploads');
  const chunkDir = path.join(uploadDir, fileName);
  await fs.ensureDir(chunkDir);

  const chunkPath = path.join(chunkDir, `chunk_${chunkIndex}`);
  
  try {
    await chunk.mv(chunkPath);
    
    if (parseInt(chunkIndex) === parseInt(totalChunks) - 1) {
      // All chunks received, start reassembly
      const finalPath = path.join(uploadDir, fileName);
      const writeStream = fs.createWriteStream(finalPath);
      for (let i = 0; i < totalChunks; i++) {
        const chunkData = await fs.readFile(path.join(chunkDir, `chunk_${i}`));
        writeStream.write(chunkData);
      }
      writeStream.end();

      // Clean up chunk files
      await fs.remove(chunkDir);

      res.send({ message: 'File upload completed', filePath: `/uploads/${fileName}` });
    } else {
      res.send('Chunk received');
    }
  } catch (err) {
    console.error(err);
    res.status(500).send(err);
  }
};




exports.getPublicVCardPreview = async (req, res) => {
  try {
    const { vCardId } = req.params;
    console.log(`Fetching public vCard preview with id: ${vCardId}`);
    
    const user = await User.findOne({ 'vCards._id': vCardId });
    
    if (!user) {
      console.log(`vCard not found for id: ${vCardId}`);
      return res.status(404).json({ error: 'vCard not found' });
    }

    const vCard = user.vCards.id(vCardId);
    
    if (!vCard) {
      console.log(`vCard not found in user document for id: ${vCardId}`);
      return res.status(404).json({ error: 'vCard not found' });
    }

    console.log(`Successfully fetched public vCard for preview: ${JSON.stringify(vCard)}`);

    // Send the vCard data as JSON without the QR code
    res.json({
      templateId: vCard.templateId,
      fields: vCard.fields
    });
  } catch (error) {
    console.error('Error fetching public vCard preview:', error);
    res.status(500).json({ error: 'Error fetching vCard preview', details: error.message });
  }
};





exports.getVCardPreview = async (req, res) => {
  try {
    const { vCardId } = req.params;
    const ip = (req.headers['x-forwarded-for'] || req.connection.remoteAddress || '').split(',')[0].trim();
    const userAgent = req.headers['user-agent'];

    console.log(`Handling preview for vCardId: ${vCardId}`);
    console.log('IP Address:', ip);
    console.log('User Agent:', userAgent);

    const user = await User.findOne({ 'vCards._id': vCardId });

    if (!user) {
      console.log(`vCard not found for id: ${vCardId}`);
      return res.status(404).json({ error: 'vCard not found' });
    }

    const vCard = user.vCards.id(vCardId);

    if (!vCard) {
      console.log(`vCard not found in user document for id: ${vCardId}`);
      return res.status(404).json({ error: 'vCard not found in user document' });
    }

    // Check if a scan from this IP for this vCard already exists within the last 24 hours
    const twentyFourHoursAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
    let vCardScan = await VCardScan.findOne({ vCardId });

    if (vCardScan) {
      const existingScan = vCardScan.scans.find(scan => 
        scan.ipAddress === ip && scan.scanDate > twentyFourHoursAgo
      );

      if (existingScan) {
        console.log('Recent scan found, updating existing record');
        existingScan.scanDate = new Date();
        await vCardScan.save();
      } else {
        console.log('Creating new scan record');
        let location;
        try {
          const ipApiResponse = await axios.get(`http://ip-api.com/json/${ip}`);
          location = ipApiResponse.data;
          console.log('Location data:', location);
        } catch (error) {
          console.error('Error fetching location data:', error);
          location = null;
        }

        const scanData = {
          ipAddress: ip,
          userAgent,
          scanDate: new Date(),
          location: location && location.status === 'success' ? {
            latitude: location.lat,
            longitude: location.lon,
            city: location.city,
            country: location.country,
          } : null,
        };

        vCardScan.scans.push(scanData);
        await vCardScan.save();
      }
    } else {
      console.log('Creating new VCardScan document');
      let location;
      try {
        const ipApiResponse = await axios.get(`http://ip-api.com/json/${ip}`);
        location = ipApiResponse.data;
        console.log('Location data:', location);
      } catch (error) {
        console.error('Error fetching location data:', error);
        location = null;
      }

      const scanData = {
        ipAddress: ip,
        userAgent,
        scanDate: new Date(),
        location: location && location.status === 'success' ? {
          latitude: location.lat,
          longitude: location.lon,
          city: location.city,
          country: location.country,
        } : null,
      };

      vCardScan = new VCardScan({ vCardId, scans: [scanData] });
      await vCardScan.save();
    }

    console.log('Preview scan recorded or updated successfully');

    res.json({
      templateId: vCard.templateId,
      fields: vCard.fields,
      qrCodeDataUrl: vCard.qrCode
    });
  } catch (error) {
    console.error('Error fetching vCard preview:', error);
    res.status(500).json({ error: 'Error fetching vCard preview', details: error.message });
  }
};




// exports.handleQRScan = async (req, res) => {
//   try {
//     const { vCardId } = req.params;
//     let ipAddress = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
//     const userAgent = req.headers['user-agent'];
    
//     // Remove IPv6 prefix if present
//     ipAddress = ipAddress.replace(/^::ffff:/, '');

//     console.log('Handling QR scan for vCardId:', vCardId);
//     console.log('IP Address:', ipAddress);
//     console.log('User Agent:', userAgent);

//     // Fetch location data from ipapi.co
//     const locationResponse = await axios.get(`https://ipapi.co/${ipAddress}/json/`);
//     const locationData = locationResponse.data;
//     console.log('Location data:', locationData);

//     const scanData = {
//       vCardId,
//       ipAddress,
//       userAgent,
//       scanDate: new Date(),
//       location: {
//         latitude: locationData.latitude,
//         longitude: locationData.longitude,
//         city: locationData.city,
//         country: locationData.country_name
//       }
//     };

//     // Check if a scan from this IP for this vCard already exists today
//     const today = new Date();
//     today.setHours(0, 0, 0, 0);
    
//     const existingScan = await VCardScan.findOne({
//       vCardId,
//       'scans.ipAddress': ipAddress,
//       'scans.scanDate': { $gte: today }
//     });

//     if (!existingScan) {
//       console.log('Creating new scan record');
//       const newScan = new VCardScan({ vCardId, scans: [scanData] });
//       await newScan.save();
//       console.log('New scan saved:', newScan);

//       // Update the user's vCard scan count
//       const updateResult = await User.findOneAndUpdate(
//         { 'vCards._id': vCardId },
//         { $push: { 'vCards.$.scans': newScan._id } }
//       );
//       console.log('User update result:', updateResult);
//     } else {
//       console.log('Existing scan found, not creating a new record');
//     }

//     // Redirect to the vCard preview
//     res.redirect(`${process.env.FRONTEND_URL}/preview?vCardId=${vCardId}`);
//   } catch (error) {
//     console.error('Error handling QR scan:', error);
//     res.status(500).json({ error: 'Error handling QR scan', details: error.message });
//   }
// };


// Updated handleQRScan function (placeholder for future implementation)



// Replace the existing handleScan function with this updated version



exports.handleScan = async (req, res) => {
  try {
    const { vCardId } = req.params;
    const { scanType = 'QR' } = req.query;
    const ip = req.headers['x-forwarded-for'] || 
               req.connection.remoteAddress || 
               req.socket.remoteAddress ||
               (req.connection.socket ? req.connection.socket.remoteAddress : null);
    const userAgent = req.headers['user-agent'];

    console.log(`Handling ${scanType} scan for vCardId: ${vCardId}`);
    console.log('IP Address:', ip);
    console.log('User Agent:', userAgent);

    let vCardScan = await VCardScan.findOne({ vCardId });

    if (!vCardScan) {
      vCardScan = new VCardScan({ vCardId, scans: [] });
    }

    // Improved device detection
    const isMobile = /Mobile|Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(userAgent);
    const device = isMobile ? 'Mobile' : 'Desktop';

    // Use a more reliable geolocation service (you may need to sign up for an API key)
    const geoApiUrl = `https://api.ipgeolocation.io/ipgeo?apiKey=YOUR_API_KEY&ip=${ip}`;
    const geoResponse = await axios.get(geoApiUrl);
    const locationData = geoResponse.data;

    const scanData = {
      ipAddress: ip,
      userAgent,
      scanDate: new Date(),
      location: {
        latitude: locationData.latitude,
        longitude: locationData.longitude,
        city: locationData.city,
        country: locationData.country_name
      },
      device,
      scanType
    };

    vCardScan.scans.push(scanData);

    // Update the appropriate counter
    if (scanType === 'QR') {
      vCardScan.qrScans++;
    } else if (scanType === 'Link') {
      vCardScan.linkClicks++;
    } else if (scanType === 'Preview') {
      vCardScan.previewClicks++;
    }

    await vCardScan.save();

    console.log('Scan recorded successfully');
    res.status(200).json({ success: true, message: 'Scan recorded successfully' });
  } catch (error) {
    console.error('Error handling scan:', error);
    res.status(500).json({ success: false, error: 'Error handling scan' });
  }
};



// Update the getVCardAnalytics function
exports.getVCardAnalytics = async (req, res) => {
  try {
    const { vCardId } = req.params;
    const { userId } = req.user;

    const user = await User.findOne({ _id: userId, 'vCards._id': vCardId });
    if (!user) {
      return res.status(404).json({ error: 'vCard not found or does not belong to the user' });
    }

    const vCardScan = await VCardScan.findOne({ vCardId });
    if (!vCardScan) {
      return res.json({
        totalScans: 0,
        qrScans: 0,
        linkClicks: 0,
        previewClicks: 0,
        recentScans: [],
        locationBreakdown: {},
        deviceBreakdown: {},
        timeBreakdown: {}
      });
    }

    const scans = vCardScan.scans;

    const analytics = {
      totalScans: scans.length,
      qrScans: vCardScan.qrScans,
      linkClicks: vCardScan.linkClicks,
      previewClicks: vCardScan.previewClicks,
      recentScans: scans.slice(-10).reverse().map(scan => ({
        scanDate: scan.scanDate,
        location: {
          city: scan.location?.city || 'Unknown',
          country: scan.location?.country || 'Unknown'
        },
        device: scan.device,
        scanType: scan.scanType
      })),
      locationBreakdown: {},
      deviceBreakdown: {},
      timeBreakdown: {
        hourly: Array(24).fill(0),
        daily: Array(7).fill(0),
        monthly: Array(12).fill(0)
      }
    };

    scans.forEach(scan => {
      // Location breakdown
      const country = scan.location?.country || 'Unknown';
      analytics.locationBreakdown[country] = (analytics.locationBreakdown[country] || 0) + 1;

      // Device breakdown
      analytics.deviceBreakdown[scan.device] = (analytics.deviceBreakdown[scan.device] || 0) + 1;

      // Time breakdown
      const scanDate = new Date(scan.scanDate);
      analytics.timeBreakdown.hourly[scanDate.getHours()]++;
      analytics.timeBreakdown.daily[scanDate.getDay()]++;
      analytics.timeBreakdown.monthly[scanDate.getMonth()]++;
    });

    res.json(analytics);
  } catch (error) {
    console.error('Error fetching vCard analytics:', error);
    res.status(500).json({ error: 'Error fetching vCard analytics', details: error.message });
  }
};





exports.handleQRScan = async (req, res) => {

  // This function will be implemented later
  res.status(501).json({ message: 'QR scan functionality not implemented yet' });
};










exports.getVCardScanAnalytics = async (req, res) => {
  try {
    const { vCardId } = req.params;
    const { userId } = req.user;

    // Check if the vCard belongs to the user
    const user = await User.findOne({ _id: userId, 'vCards._id': vCardId });
    if (!user) {
      return res.status(404).json({ error: 'vCard not found or does not belong to the user' });
    }

    const vCardScan = await VCardScan.findOne({ vCardId });
    if (!vCardScan) {
      return res.json({ totalScans: 0, recentScans: [], locationBreakdown: {}, deviceBreakdown: {} });
    }

    const scans = vCardScan.scans;

    const analytics = {
      totalScans: scans.length,
      recentScans: scans.slice(-10).reverse().map(scan => ({
        scanDate: scan.scanDate,
        location: {
          city: scan.location.city || 'Unknown',
          country: scan.location.country || 'Unknown'
        }
      })),
      locationBreakdown: {},
      deviceBreakdown: {}
    };

    scans.forEach(scan => {
      // Location breakdown
      const country = scan.location.country || 'Unknown';
      analytics.locationBreakdown[country] = (analytics.locationBreakdown[country] || 0) + 1;

      // Device breakdown
      const device = scan.userAgent.includes('Mobile') ? 'Mobile' : 'Desktop';
      analytics.deviceBreakdown[device] = (analytics.deviceBreakdown[device] || 0) + 1;
    });

    res.json(analytics);
  } catch (error) {
    console.error('Error fetching vCard scan analytics:', error);
    res.status(500).json({ error: 'Error fetching vCard scan analytics' });
  }
};



exports.getUserScanAnalytics = async (req, res) => {
  try {
    const { userId } = req.user;

    const user = await User.findById(userId).select('vCards._id');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const vCardIds = user.vCards.map(vCard => vCard._id);
    const vCardScans = await VCardScan.find({ vCardId: { $in: vCardIds } });

    const analytics = {
      totalScans: 0,
      scansByVCard: {},
      overallLocationBreakdown: {},
      overallDeviceBreakdown: {}
    };

    vCardScans.forEach(vCardScan => {
      const scans = vCardScan.scans;
      analytics.totalScans += scans.length;
      analytics.scansByVCard[vCardScan.vCardId] = scans.length;

      scans.forEach(scan => {
        // Overall location breakdown
        const country = scan.location.country || 'Unknown';
        analytics.overallLocationBreakdown[country] = (analytics.overallLocationBreakdown[country] || 0) + 1;

        // Overall device breakdown
        const device = scan.userAgent.includes('Mobile') ? 'Mobile' : 'Desktop';
        analytics.overallDeviceBreakdown[device] = (analytics.overallDeviceBreakdown[device] || 0) + 1;
      });
    });

    res.json(analytics);
  } catch (error) {
    console.error('Error fetching user scan analytics:', error);
    res.status(500).json({ error: 'Error fetching user scan analytics' });
  }
};


exports.recordTimeSpent = async (req, res) => {
  try {
    const { vCardId } = req.params;
    const { timeSpent } = req.body;
    const ip = (req.headers['x-forwarded-for'] || req.connection.remoteAddress || '').split(',')[0].trim();

    console.log(`Recording time spent for vCardId: ${vCardId}`);
    console.log('Time spent:', timeSpent);
    console.log('IP Address:', ip);

    let vCardScan = await VCardScan.findOne({ vCardId });

    if (!vCardScan) {
      console.log(`No VCardScan found for vCardId: ${vCardId}`);
      return res.status(404).json({ error: 'VCard scan record not found' });
    }

    // Find the most recent scan for this IP within the last 24 hours
    const twentyFourHoursAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const lastScan = vCardScan.scans.find(scan => 
      scan.ipAddress === ip && scan.scanDate > twentyFourHoursAgo
    );
    
    if (lastScan) {
      // Convert timeSpent from seconds to minutes and round to 2 decimal places
      const timeSpentMinutes = Math.round((timeSpent / 60) * 100) / 100;
      // Update the timeSpent field
      lastScan.timeSpent = timeSpentMinutes;
      await vCardScan.save();

      console.log(`Time spent recorded for vCard ${vCardId}: ${lastScan.timeSpent} minutes`);
      res.status(200).json({ message: 'Time spent recorded successfully' });
    } else {
      console.log(`No recent scan found for vCardId: ${vCardId} and IP: ${ip}`);
      res.status(404).json({ error: 'No recent scan found for this vCard and IP' });
    }
  } catch (error) {
    console.error('Error recording time spent:', error);
    res.status(500).json({ error: 'Error recording time spent', details: error.message });
  }
};

// ----------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------
// ----------------------------{ auth functions }-------------------------------------
// ----------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------







exports.register = async (req, res) => {
  try {
    console.log('Register request body:', req.body);
    const { username, email, password } = req.body;
    
    // Check if user already exists
    let user = await User.findOne({ email });
    if (user) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Create verification token
    const verificationToken = crypto.randomBytes(20).toString('hex');
    const verificationExpires = Date.now() + 24 * 60 * 60 * 1000; // 24 hours

    user = new User({
      username,
      email,
      password,
      verificationToken,
      verificationExpires,
      isVerified: false
    });
    await user.save();

    // Send verification email
    const verificationUrl = `${process.env.FRONTEND_URL}/verify-email?token=${verificationToken}`;
    const message = `Please click on the following link to verify your email: ${verificationUrl}`;

    await sendEmail({
      to: user.email,
      subject: 'Email Verification',
      text: message,
    });

    res.status(201).json({ message: 'User registered successfully. Please check your email to verify your account.' });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
};


exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user || !(await user.comparePassword(password))) {
      return res.status(401).json({ error: 'Invalid credentials ' });
    }

    if (!user.isVerified) {
      return res.status(403).json({ error: 'Please verify your email before logging in' });
    }

    const token = jwt.sign(
      { userId: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Error logging in' });
  }
};




exports.forgotPassword = async (req, res) => {
  try {
    console.log('Forgot password request body:', req.body);
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const resetToken = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
    
    user.resetPasswordToken = resetToken;
    user.resetPasswordExpires = Date.now() + 10 * 60 * 1000; // Token expires in 10 minutes
    await user.save();

    const resetUrl = `${process.env.FRONTEND_URL}/reset-password?token=${resetToken}`;
    const message = `You are receiving this email because you (or someone else) have requested the reset of the password for your account.\n\nPlease click on the following link, or paste this into your browser to complete the process:\n\n${resetUrl}\n\nIf you did not request this, please ignore this email and your password will remain unchanged.`;

    console.log('Attempting to send email to:', user.email);

    try {
      await sendEmail({
        to: user.email,
        subject: 'Password Reset Request',
        text: message,
      });

      res.status(200).json({ message: 'Password reset email sent' });
    } catch (error) {
      console.error('Send email error:', error);
      user.resetPasswordToken = undefined;
      user.resetPasswordExpires = undefined;
      await user.save();

      return res.status(500).json({ error: 'Error sending password reset email' });
    }
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ error: 'Server error' });
  }
};

exports.resetPassword = async (req, res) => {
  try {
    console.log('Reset password request body:', req.body);
    console.log('Reset password token from params:', req.params.token);
    
    const { token } = req.params;
    const { password } = req.body;

    const user = await User.findOne({
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({ error: 'Password reset token is invalid or has expired' });
    }

    user.password = password;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    res.status(200).json({ message: 'Password has been reset' });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ error: 'Error resetting password' });
  }
};

exports.getCurrentUser = async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('-password');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(user);
  } catch (error) {
    console.error('Get current user error:', error);
    res.status(500).json({ error: 'Error fetching user data' });
  }
};

exports.getUserPlan = async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('plan');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ planName: user.plan?.name || 'Free' });
  } catch (error) {
    console.error('Get user plan error:', error);
    res.status(500).json({ error: 'Error fetching user plan' });
  }
};

exports.getUserInfo = async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('username email plan');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(user);
  } catch (error) {
    console.error('Get user info error:', error);
    res.status(500).json({ error: 'Error fetching user info' });
  }
};

exports.checkVerificationStatus = async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('isVerified');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ isVerified: user.isVerified });
  } catch (error) {
    console.error('Check verification status error:', error);
    res.status(500).json({ error: 'Error checking verification status' });
  }
};
exports.verifyEmail = async (req, res) => {
  try {
    const { token } = req.params;
    const user = await User.findOne({
      verificationToken: token,
      verificationExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({ error: 'Invalid or expired verification token' });
    }

    user.isVerified = true;
    user.verificationToken = undefined;
    user.verificationExpires = undefined;
    await user.save();

    res.json({ message: 'Email verified successfully. You can now log in.' });
  } catch (error) {
    console.error('Email verification error:', error);
    res.status(500).json({ error: 'Email verification failed' });
  }
};

exports.resendVerification = async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (user.isVerified) {
      return res.status(400).json({ error: 'Email already verified' });
    }

    // Check if a minute has passed since the last verification email
    if (user.lastVerificationSent && Date.now() - user.lastVerificationSent < 60000) {
      return res.status(400).json({ error: 'Please wait a minute before requesting a new verification email' });
    }

    // Create new verification token
    user.verificationToken = crypto.randomBytes(20).toString('hex');
    user.verificationExpires = Date.now() + 24 * 60 * 60 * 1000; // 24 hours
    user.lastVerificationSent = Date.now();
    await user.save();

    // Send verification email
    const verificationUrl = `${process.env.FRONTEND_URL}/verify-email?token=${user.verificationToken}`;
    const message = `Please click on the following link to verify your email: ${verificationUrl}`;

    await sendEmail({
      to: user.email,
      subject: 'Email Verification',
      text: message,
    });

    res.json({ message: 'Verification email sent. Please check your inbox.' });
  } catch (error) {
    console.error('Resend verification error:', error);
    res.status(500).json({ error: 'Failed to resend verification email' });
  }
};




exports.testGeolocation = async (req, res) => {
  try {
    const testIp = req.query.ip || '8.8.8.8'; // Use Google's public DNS as a default test IP
    console.log(`Testing geolocation for IP: ${testIp}`);

    const ipApiResponse = await axios.get(`http://ip-api.com/json/${testIp}`);
    const location = ipApiResponse.data;

    console.log('Full ip-api.com response:', JSON.stringify(location, null, 2));

    if (location.status === 'success') {
      res.json({
        success: true,
        message: 'Geolocation data retrieved successfully',
        data: {
          ip: testIp,
          city: location.city,
          country: location.country,
          latitude: location.lat,
          longitude: location.lon,
        }
      });
    } else {
      res.json({
        success: false,
        message: 'Failed to retrieve geolocation data',
        data: location
      });
    }
  } catch (error) {
    console.error('Error testing geolocation:', error);
    res.status(500).json({ success: false, error: 'Error testing geolocation' });
  }
};



module.exports = exports; 