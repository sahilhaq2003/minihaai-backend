const mongoose = require('mongoose');

const transactionSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  amount: {
    type: String,
    required: true
  },
  status: {
    type: String,
    enum: ['Paid', 'Pending', 'Failed', 'Refunded'],
    default: 'Pending'
  },
  invoiceId: {
    type: String,
    required: true
  },
  planType: {
    type: String,
    default: 'Pro Plan'
  }
}, {
  timestamps: true
});

module.exports = mongoose.model('Transaction', transactionSchema);



