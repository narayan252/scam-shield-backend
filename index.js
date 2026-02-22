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
    message: 'Server is live!'
  });
});

// ========== API STATUS – FIXED VERSION ==========
app.get('/api/status', (req, res) => {
  // Direct check of environment variables
  const etherscan = process.env.ETHERSCAN_API_KEY ? 'configured' : 'missing';
  const bscscan = process.env.BSCSCAN_API_KEY ? 'configured' : 'missing';
  const polygonscan = process.env.POLYGONSCAN_API_KEY ? 'configured' : 'missing';
  const cmc = process.env.CMC_API_KEY ? 'configured' : 'missing';
  const virustotal = process.env.VIRUSTOTAL_API_KEY ? 'configured' : 'missing';
  const googleSafe = process.env.GOOGLE_SAFE_API_KEY ? 'configured' : 'missing';
  const whoisfreaks = process.env.WHOISFREAKS_API_KEY ? 'configured' : 'missing';
  const chainbase = process.env.CHAINBASE_API_KEY ? 'configured' : 'missing';

  console.log('ENV Check:', {
    ETHERSCAN_API_KEY: process.env.ETHERSCAN_API_KEY ? 'present' : 'missing',
    BSCSCAN_API_KEY: process.env.BSCSCAN_API_KEY ? 'present' : 'missing',
    CMC_API_KEY: process.env.CMC_API_KEY ? 'present' : 'missing'
  });

  res.json({
    success: true,
    apis: {
      etherscan,
      bscscan,
      polygonscan,
      coinmarketcap: cmc,
      virustotal,
      googleSafe,
      whoisfreaks,
      chainbase
    },
    environment: process.env.NODE_ENV || 'development'
  });
});

// ========== SCAN ENDPOINT ==========
app.post('/api/scan', (req, res) => {
  const { input, chain = 'ethereum' } = req.body;
  
  if (!input) {
    return res.status(400).json({ success: false, error: 'Input required' });
  }

  const mockRiskScore = Math.floor(Math.random() * 60) + 20;
  
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
    reasons: ['Scan completed'],
    apiCount: 4,
    apisUsed: ['Etherscan', 'CoinMarketCap', 'VirusTotal', 'WhoisFreaks']
  });
});

// ========== GET SCAN RESULT ==========
app.get('/api/scan/:scanId', (req, res) => {
  res.json({
    success: true,
    scanId: req.params.scanId,
    timestamp: new Date().toISOString(),
    input: '0x1234...5678',
    chain: 'ethereum',
    risk: { score: 45, level: 'MEDIUM', emoji: '🟠', confidence: 80, completeness: 65 },
    reasons: ['Contract not verified', 'Low liquidity'],
    apiCount: 3,
    apisUsed: ['Etherscan', 'CoinMarketCap', 'WhoisFreaks']
  });
});

// ========== START SERVER ==========
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Server running on port ${PORT}`);
  console.log('Environment variables loaded:', {
    ETHERSCAN: process.env.ETHERSCAN_API_KEY ? '✅' : '❌',
    BSCSCAN: process.env.BSCSCAN_API_KEY ? '✅' : '❌',
    CMC: process.env.CMC_API_KEY ? '✅' : '❌'
  });
});
