const express = require('express');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// ========== MIDDLEWARE ==========
app.use(cors());
app.use(express.json());

// ========== HEALTH CHECK ==========
app.get('/', (req, res) => {
  res.json({ 
    status: '🛡️ Bhai Scam Shield Backend Running',
    message: 'Server is live!',
    timestamp: new Date().toISOString()
  });
});

// ========== API STATUS ==========
app.get('/api/status', (req, res) => {
  res.json({
    success: true,
    apis: {
      etherscan: process.env.ETHERSCAN_API_KEY ? 'configured' : 'missing',
      bscscan: process.env.BSCSCAN_API_KEY ? 'configured' : 'missing',
      polygonscan: process.env.POLYGONSCAN_API_KEY ? 'configured' : 'missing',
      coinmarketcap: process.env.CMC_API_KEY ? 'configured' : 'missing',
      virustotal: process.env.VIRUSTOTAL_API_KEY ? 'configured' : 'missing',
      googleSafe: process.env.GOOGLE_SAFE_API_KEY ? 'configured' : 'missing',
      whoisfreaks: process.env.WHOISFREAKS_API_KEY ? 'configured' : 'missing',
      chainbase: process.env.CHAINBASE_API_KEY ? 'configured' : 'missing'
    },
    environment: process.env.NODE_ENV || 'development'
  });
});

// ========== SCAN ENDPOINT ==========
app.post('/api/scan', (req, res) => {
  const { input, chain = 'ethereum' } = req.body;
  
  if (!input) {
    return res.status(400).json({ 
      success: false, 
      error: 'Input required' 
    });
  }

  // Mock response for testing
  const mockRiskScore = Math.floor(Math.random() * 60) + 20; // 20-80 range
  
  let riskLevel, riskEmoji;
  if (mockRiskScore <= 20) { riskLevel = 'SAFE'; riskEmoji = '🟢'; }
  else if (mockRiskScore <= 40) { riskLevel = 'LOW'; riskEmoji = '🟡'; }
  else if (mockRiskScore <= 60) { riskLevel = 'MEDIUM'; riskEmoji = '🟠'; }
  else if (mockRiskScore <= 80) { riskLevel = 'HIGH'; riskEmoji = '🔴'; }
  else { riskLevel = 'CRITICAL'; riskEmoji = '💀'; }

  res.json({
    success: true,
    scanId: 'SCAN_' + Math.random().toString(36).substring(2, 15).toUpperCase(),
    timestamp: new Date().toISOString(),
    input,
    chain,
    risk: {
      score: mockRiskScore,
      level: riskLevel,
      emoji: riskEmoji,
      confidence: 85,
      completeness: 70
    },
    reasons: [
      'Test mode - API keys not fully configured',
      'Contract verification pending',
      'Market data unavailable'
    ],
    apiCount: 3,
    apisUsed: ['Etherscan', 'CoinMarketCap', 'VirusTotal'],
    verified: false
  });
});

// ========== GET SCAN RESULT ==========
app.get('/api/scan/:scanId', (req, res) => {
  const { scanId } = req.params;
  
  res.json({
    success: true,
    scanId,
    timestamp: new Date().toISOString(),
    input: '0x1234...5678',
    chain: 'ethereum',
    risk: {
      score: 45,
      level: 'MEDIUM',
      emoji: '🟠',
      confidence: 80,
      completeness: 65
    },
    reasons: [
      'Contract not verified',
      'Low liquidity detected',
      'New domain (15 days old)'
    ],
    apiCount: 4,
    apisUsed: ['Etherscan', 'CoinMarketCap', 'WhoisFreaks', 'VirusTotal'],
    verified: false
  });
});

// ========== START SERVER ==========
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Bhai Scam Shield backend running on port ${PORT}`);
  console.log(`🔗 http://localhost:${PORT}`);
  console.log(`📡 Environment: ${process.env.NODE_ENV || 'development'}`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down...');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('SIGINT received, shutting down...');
  process.exit(0);
});
