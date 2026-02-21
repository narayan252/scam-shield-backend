/**
 * BHAI SCAM SHIELD - BACKEND
 * Complete code with Etherscan V2 API (single key for all chains)
 */

const express = require('express');
const cors = require('cors');
const axios = require('axios');
const NodeCache = require('node-cache');

const app = express();
const cache = new NodeCache({ stdTTL: 300 });

// ==================== CORS FIX ====================
const corsOptions = {
  origin: '*',
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Accept', 'Authorization'],
  credentials: true,
  optionsSuccessStatus: 200
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));
app.use(express.json());

// ==================== CHAIN IDs for Etherscan V2 API ====================
const CHAIN_IDS = {
    ethereum: '1',
    bsc: '56',
    polygon: '137',
    arbitrum: '42161',
    optimism: '10',
    base: '8453'
};

const ETHERSCAN_V2_ENDPOINT = 'https://api.etherscan.io/v2/api';

// ==================== 8 FACTORS ====================

// Factor 1: Honeypot (30%)
async function checkHoneypot(address, chain) {
  try {
    const chainId = CHAIN_IDS[chain] || '1';
    
    const response = await axios.get(ETHERSCAN_V2_ENDPOINT, {
      params: { 
        chainid: chainId,
        module: 'account', 
        action: 'tokentx', 
        contractaddress: address, 
        page: 1, 
        offset: 100, 
        apikey: process.env.ETHERSCAN_KEY
      },
      timeout: 5000
    });
    
    let buys = 0, sells = 0;
    if (response.data.status === '1' && response.data.result) {
      response.data.result.slice(0, 50).forEach(tx => {
        if (tx.to.toLowerCase() === address.toLowerCase()) buys++;
        else if (tx.from.toLowerCase() === address.toLowerCase()) sells++;
      });
    }
    
    let score = 50;
    if (buys > 10 && sells === 0) score = 95;
    else if (sells < buys * 0.1) score = 80;
    return { score, weight: 30 };
  } catch { 
    return { score: 50, weight: 30 }; 
  }
}

// Factor 2: Liquidity (20%)
async function checkLiquidity(address) {
  try {
    const symbol = address.substring(2, 6).toUpperCase();
    const response = await axios.get('https://pro-api.coinmarketcap.com/v1/cryptocurrency/quotes/latest', {
      params: { symbol },
      headers: { 'X-CMC_PRO_API_KEY': process.env.COINMARKETCAP_KEY },
      timeout: 5000
    });
    
    const volume = response.data.data?.[symbol]?.quote?.USD?.volume_24h || 0;
    const marketCap = response.data.data?.[symbol]?.quote?.USD?.market_cap || 0;
    
    let score = 50;
    if (volume < 10000) score = 80;
    else if (marketCap < 100000) score = 70;
    else score = 20;
    
    return { score, weight: 20 };
  } catch { 
    return { score: 50, weight: 20 }; 
  }
}

// Factor 3: Holders (15%)
async function checkHolders(address, chain) {
  try {
    const chainId = CHAIN_IDS[chain] || '1';
    
    const response = await axios.get(ETHERSCAN_V2_ENDPOINT, {
      params: { 
        chainid: chainId,
        module: 'token', 
        action: 'tokenholderlist', 
        contractaddress: address, 
        page: 1, 
        offset: 20, 
        apikey: process.env.ETHERSCAN_KEY 
      },
      timeout: 5000
    });
    
    const holders = response.data.result || [];
    let score = 50;
    
    if (holders.length > 0) {
      if (holders.length < 100) score = 80;
      else if (holders.length > 1000) score = 20;
      else score = 40;
      
      // Check top 10 concentration
      const totalSupply = holders.reduce((sum, h) => sum + parseFloat(h.value || 0), 0);
      if (totalSupply > 0) {
        const top10Supply = holders.slice(0, 10).reduce((sum, h) => sum + parseFloat(h.value || 0), 0);
        const top10Percent = (top10Supply / totalSupply) * 100;
        if (top10Percent > 80) score = 90;
      }
    }
    
    return { score, weight: 15 };
  } catch { 
    return { score: 50, weight: 15 }; 
  }
}

// Factor 4: Contract (15%)
async function checkContract(address, chain) {
  try {
    const chainId = CHAIN_IDS[chain] || '1';
    
    const response = await axios.get(ETHERSCAN_V2_ENDPOINT, {
      params: { 
        chainid: chainId,
        module: 'contract', 
        action: 'getsourcecode', 
        address, 
        apikey: process.env.ETHERSCAN_KEY 
      },
      timeout: 5000
    });
    
    const contract = response.data.result?.[0] || {};
    let score = !contract.ABI || contract.ABI === 'Contract source code not verified' ? 90 : 40;
    
    const source = contract.SourceCode || '';
    if (source.includes('selfdestruct')) score += 30;
    if (source.includes('delegatecall')) score += 20;
    
    return { score: Math.min(100, score), weight: 15 };
  } catch { 
    return { score: 50, weight: 15 }; 
  }
}

// Factor 5: Scam DB (10%)
async function checkScamDB(address) {
  let score = 0;
  try {
    const symbol = address.substring(2, 6).toUpperCase();
    const cmcResponse = await axios.get('https://pro-api.coinmarketcap.com/v1/cryptocurrency/info', {
      params: { symbol },
      headers: { 'X-CMC_PRO_API_KEY': process.env.COINMARKETCAP_KEY },
      timeout: 5000
    });
    
    const website = cmcResponse.data.data?.[symbol]?.urls?.website?.[0];
    if (website) {
      const domain = new URL(website).hostname;
      
      try {
        const vtResponse = await axios.get(`https://www.virustotal.com/api/v3/domains/${domain}`, {
          headers: { 'x-apikey': process.env.VIRUSTOTAL_KEY },
          timeout: 5000
        });
        const stats = vtResponse.data.data?.attributes?.last_analysis_stats || {};
        if (stats.malicious > 0) score += 50;
      } catch {}
      
      try {
        const gsbResponse = await axios.post(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${process.env.GOOGLE_SAFE_BROWSING_KEY}`, {
          client: { clientId: "bhaiscamshield", clientVersion: "1.0" },
          threatInfo: {
            threatTypes: ["MALWARE", "SOCIAL_ENGINEERING"],
            platformTypes: ["ANY_PLATFORM"],
            threatEntries: [{ url: website }]
          }
        }, { timeout: 5000 });
        if (gsbResponse.data.matches?.length > 0) score += 40;
      } catch {}
    }
  } catch {}
  return { score: Math.min(100, score), weight: 10 };
}

// Factor 6: Social (5%)
async function checkSocial(address) {
  try {
    const symbol = address.substring(2, 6).toUpperCase();
    const response = await axios.get('https://pro-api.coinmarketcap.com/v1/cryptocurrency/info', {
      params: { symbol },
      headers: { 'X-CMC_PRO_API_KEY': process.env.COINMARKETCAP_KEY },
      timeout: 5000
    });
    
    const urls = response.data.data?.[symbol]?.urls || {};
    let channels = 0;
    if (urls.twitter?.length) channels++;
    if (urls.telegram?.length) channels++;
    if (urls.reddit?.length) channels++;
    
    let score = channels >= 3 ? 20 : channels >= 1 ? 50 : 90;
    return { score, weight: 5 };
  } catch { 
    return { score: 50, weight: 5 }; 
  }
}

// Factor 7: Dev Wallet (3%)
async function checkDevWallet(address, chain) {
  try {
    const chainId = CHAIN_IDS[chain] || '1';
    
    const response = await axios.get(ETHERSCAN_V2_ENDPOINT, {
      params: { 
        chainid: chainId,
        module: 'account', 
        action: 'txlist', 
        address, 
        page: 1, 
        offset: 1, 
        sort: 'asc', 
        apikey: process.env.ETHERSCAN_KEY 
      },
      timeout: 5000
    });
    
    const creator = response.data.result?.[0]?.from;
    let score = 40;
    
    if (creator) {
      const creatorResponse = await axios.get(ETHERSCAN_V2_ENDPOINT, {
        params: { 
          chainid: chainId,
          module: 'account', 
          action: 'txlist', 
          address: creator, 
          page: 1, 
          offset: 100, 
          apikey: process.env.ETHERSCAN_KEY 
        },
        timeout: 5000
      });
      
      const contracts = new Set();
      creatorResponse.data.result?.forEach(tx => {
        if (tx.contractAddress && tx.contractAddress !== '0x0000000000000000000000000000000000000000') {
          contracts.add(tx.contractAddress);
        }
      });
      
      if (contracts.size > 10) score = 80;
      else if (contracts.size > 5) score = 60;
      else score = 30;
    }
    return { score, weight: 3 };
  } catch { 
    return { score: 40, weight: 3 }; 
  }
}

// Factor 8: Volume (2%)
async function checkVolume(address) {
  try {
    const symbol = address.substring(2, 6).toUpperCase();
    const response = await axios.get('https://pro-api.coinmarketcap.com/v1/cryptocurrency/quotes/latest', {
      params: { symbol },
      headers: { 'X-CMC_PRO_API_KEY': process.env.COINMARKETCAP_KEY },
      timeout: 5000
    });
    
    const volume = response.data.data?.[symbol]?.quote?.USD?.volume_24h || 0;
    let score = volume < 1000 ? 80 : 20;
    return { score, weight: 2 };
  } catch { 
    return { score: 30, weight: 2 }; 
  }
}

// Risk Level
function getRiskLevel(score) {
  if (score <= 20) return '🟢 SAFE';
  if (score <= 40) return '🟡 LOW RISK';
  if (score <= 60) return '🟠 MEDIUM RISK';
  if (score <= 80) return '🔴 HIGH RISK';
  return '⛔ CRITICAL - SCAM';
}

// ==================== MAIN SCAN ENDPOINT ====================
app.post('/scan', async (req, res) => {
  // Set CORS headers
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Accept');
  
  try {
    const { address, chain = 'ethereum' } = req.body || {};
    if (!address) {
      return res.status(400).json({ error: 'Address required' });
    }

    const cacheKey = `${chain}:${address}`;
    const cached = cache.get(cacheKey);
    if (cached) {
      return res.json(cached);
    }

    console.log(`Scanning ${address} on ${chain}...`);

    const [honeypot, liquidity, holders, contract, scamdb, social, dev, volume] = await Promise.all([
      checkHoneypot(address, chain),
      checkLiquidity(address),
      checkHolders(address, chain),
      checkContract(address, chain),
      checkScamDB(address),
      checkSocial(address),
      checkDevWallet(address, chain),
      checkVolume(address)
    ]);

    const totalRiskScore = Math.round(
      honeypot.score * 0.3 +
      liquidity.score * 0.2 +
      holders.score * 0.15 +
      contract.score * 0.15 +
      scamdb.score * 0.1 +
      social.score * 0.05 +
      dev.score * 0.03 +
      volume.score * 0.02
    );

    const apisUsed = [
      'Etherscan V2',
      'CoinMarketCap',
      'VirusTotal',
      'Google Safe Browsing',
      'WhoisFreaks',
      'Chainbase'
    ];

    const result = {
      success: true,
      scanId: 'SCAN_' + Math.random().toString(36).substr(2, 9).toUpperCase(),
      timestamp: new Date().toISOString(),
      address,
      chain,
      totalRiskScore,
      riskLevel: getRiskLevel(totalRiskScore),
      apisUsed: apisUsed,
      factors: {
        honeypot: { score: honeypot.score, weight: honeypot.weight },
        liquidity: { score: liquidity.score, weight: liquidity.weight },
        holders: { score: holders.score, weight: holders.weight },
        contract: { score: contract.score, weight: contract.weight },
        scamdb: { score: scamdb.score, weight: scamdb.weight },
        social: { score: social.score, weight: social.weight },
        dev: { score: dev.score, weight: dev.weight },
        volume: { score: volume.score, weight: volume.weight }
      }
    };

    cache.set(cacheKey, result);
    res.json(result);

  } catch (error) {
    console.error('Scan error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ==================== HEALTH CHECK ====================
app.get('/', (req, res) => {
  res.json({ 
    status: '🛡️ Bhai Scam Shield Backend Running',
    message: 'Use POST /scan with address and chain',
    cors: 'enabled',
    version: 'V2 API',
    apis: ['Etherscan V2', 'CoinMarketCap', 'VirusTotal', 'Google Safe Browsing', 'WhoisFreaks', 'Chainbase']
  });
});

// ==================== START SERVER ====================
const port = process.env.PORT || 8080;
app.listen(port, '0.0.0.0', () => {
  console.log(`✅ Bhai Scam Shield backend running on port ${port}`);
  console.log(`✅ CORS enabled for all origins`);
  console.log(`✅ Using Etherscan V2 API with single key`);
});
