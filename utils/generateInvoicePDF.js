const PDFDocument = require('pdfkit');
const fs = require('fs');
const path = require('path');

function generateInvoicePDF({ invoiceNumber, planName, amount, userEmail, userName, date, companyDetails }) {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ margin: 50 });
    let buffers = [];
    doc.on('data', buffers.push.bind(buffers));
    doc.on('end', () => {
      let pdfData = Buffer.concat(buffers);
      resolve(pdfData);
    });

    // Add company name instead of logo
    doc.fontSize(20)
       .text('vCard Pro', 50, 57);

    // Add company details
    doc.fontSize(10)
       .text(companyDetails.name, 200, 50, { align: 'right' })
       .text(companyDetails.address, 200, 65, { align: 'right' })
       .text(companyDetails.city + ', ' + companyDetails.country, 200, 80, { align: 'right' })
       .text(companyDetails.phone, 200, 95, { align: 'right' })
       .text(companyDetails.email, 200, 110, { align: 'right' });

    // Add invoice details
    doc.fontSize(18)
       .text('Invoice', 50, 150)
       .fontSize(10)
       .text(`Invoice Number: ${invoiceNumber}`, 50, 180)
       .text(`Invoice Date: ${date.toLocaleDateString()}`, 50, 195)
       .text(`Due Date: ${date.toLocaleDateString()}`, 50, 210);

    // Add customer details
    doc.text(`Bill To:`, 300, 180)
       .text(`${userName}`, 300, 195)
       .text(`${userEmail}`, 300, 210);

    // Add table header
    doc.fillColor('#444444')
       .fontSize(12)
       .text('Item', 50, 250)
       .text('Description', 150, 250)
       .text('Unit Price', 300, 250, { width: 90, align: 'right' })
       .text('Amount', 400, 250, { width: 90, align: 'right' });

    // Add horizontal line
    doc.strokeColor('#aaaaaa')
       .lineWidth(1)
       .moveTo(50, 275)
       .lineTo(550, 275)
       .stroke();

    // Add item
    doc.fontSize(10)
       .text('1', 50, 300)
       .text(planName, 150, 300)
       .text(`$${amount.toFixed(2)}`, 300, 300, { width: 90, align: 'right' })
       .text(`$${amount.toFixed(2)}`, 400, 300, { width: 90, align: 'right' });

    // Add total
    doc.fontSize(12)
       .text('Total:', 300, 350, { width: 90, align: 'right' })
       .text(`$${amount.toFixed(2)}`, 400, 350, { width: 90, align: 'right' });

    // Add footer
    doc.fontSize(10)
       .text('Thank you for your business!', 50, 700, { align: 'center', width: 500 });

    doc.end();
  });
}

module.exports = generateInvoicePDF;
