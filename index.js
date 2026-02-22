// ========== 🔴 FIX 1: Partial Data Warning System ==========
function getPartialDataWarnings(apiResults) {
    const warnings = [];
    const apiStatus = {
        etherscan: apiResults.contract?.success || false,
        bscscan: apiResults.bscscan?.success || false,
        polygonscan: apiResults.polygonscan?.success || false,
        coinmarketcap: apiResults.market?.success || false,
        coingecko: apiResults.coingecko?.success || false,
        virustotal: apiResults.virustotal?.success || false,
        googleSafe: apiResults.google?.success || false,
        whoisfreaks: apiResults.whois?.success || false,
        chainbase: apiResults.holders?.success || false
    };
    
    const failedApis = Object.entries(apiStatus)
        .filter(([_, success]) => !success)
        .map(([name]) => name);
    
    if (failedApis.length > 0) {
        warnings.push(`⚠️ Partial data: ${failedApis.length} APIs unavailable (${failedApis.join(', ')})`);
    }
    
    // Specific warnings
    if (apiResults.contract && !apiResults.contract.sourceCode) {
        warnings.push('📄 Source code not available – contract analysis limited');
    }
    
    if (apiResults.whois && !apiResults.whois.ageDays) {
        warnings.push('🌐 Whois data blocked – domain age unknown');
    }
    
    if (apiResults.virustotal && apiResults.virustotal.quotaExceeded) {
        warnings.push('🦠 VirusTotal quota exceeded – using cached data');
    }
    
    if (apiResults.market && !apiResults.market.success) {
        warnings.push('💰 Market data unavailable – token may be unlisted');
    }
    
    if (apiResults.holders && apiResults.holders.holderCount === 0) {
        warnings.push('👥 Holder data unavailable – may be new token');
    }
    
    return warnings;
}

// ========== 🔴 FIX 2: Age-Based Rules for New Tokens ==========
function applyAgeBasedRules(apiResults, reasons) {
    const contractAge = apiResults.contract?.creationDate 
        ? (Date.now() - new Date(apiResults.contract.creationDate).getTime()) / (1000 * 60 * 60 * 24)
        : null;
    
    const domainAge = apiResults.whois?.ageDays;
    const tokenAge = Math.min(contractAge || Infinity, domainAge || Infinity);
    
    // New token (less than 30 days old)
    if (tokenAge < 30) {
        reasons.push('🆕 Token/Domain less than 30 days old');
        
        // Adjust risk based on other factors
        if (apiResults.holders?.holderCount < 100) {
            reasons.push('⚠️ New token with few holders – normal for new projects');
            // Don't increase risk automatically
        }
        
        if (apiResults.market?.marketCap < 100000) {
            reasons.push('💰 New token with low market cap – normal for new projects');
            // Don't increase risk automatically
        }
        
        // Special rule: New but verified contract with code
        if (apiResults.contract?.verified && apiResults.contract.sourceCode) {
            reasons.push('✅ New but verified contract with source code');
            return -10; // Lower risk
        }
        
        // New + no source + hidden whois = suspicious
        if (!apiResults.contract?.verified && apiResults.whois?.registrarHidden) {
            reasons.push('🚨 New token with unverified contract and hidden registrar – HIGH RISK');
            return 20; // Increase risk
        }
    }
    
    // Old token (more than 1 year)
    if (tokenAge > 365) {
        reasons.push('📅 Established token (1+ years old)');
        return -15; // Lower risk
    }
    
    return 0;
}

// ========== 🔴 FIX 3: Proxy/DAO Whitelist ==========
const PROXY_WHITELIST = [
    // Known proxy contracts
    '0x1a9c8182c09f4c2a0b0a6b8b0b0b0b0b0b0b0b0b', // Example
    '0x2b9c8182c09f4c2a0b0a6b8b0b0b0b0b0b0b0b0c'
];

const DAO_CONTRACTS = [
    '0x9a0a7b3c9d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s', // Example DAO
    '0x8b0a7b3c9d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8t'
];

const LEGIT_UPGRADEABLE = [
    '0x7a250d5630b4cf539739df2c5dacb4c659f2488d', // Uniswap
    '0x1f9840a85d5af5bf1d1762f925bdaddc4201f984'  // UNI token
];

function isWhitelistedProxy(address) {
    const addr = address.toLowerCase();
    return PROXY_WHITELIST.includes(addr) || 
           DAO_CONTRACTS.includes(addr) || 
           LEGIT_UPGRADEABLE.includes(addr);
}

function analyzeProxyContract(contractInfo, address) {
    if (!contractInfo.proxy) return { isRisky: false, reason: '' };
    
    // Check whitelist first
    if (isWhitelistedProxy(address)) {
        return { 
            isRisky: false, 
            reason: '✅ Whitelisted proxy/DAO contract' 
        };
    }
    
    // Check if it's a known upgradeable pattern
    if (contractInfo.sourceCode?.includes('UUPS') || 
        contractInfo.sourceCode?.includes('TransparentUpgradeableProxy')) {
        return {
            isRisky: false,
            reason: '🔄 Standard upgradeable pattern'
        };
    }
    
    // Check if implementation is verified
    if (contractInfo.implementation) {
        return {
            isRisky: true,
            reason: `⚠️ Proxy with implementation ${contractInfo.implementation.substring(0, 10)}... – verify implementation`
        };
    }
    
    return {
        isRisky: true,
        reason: '🚨 Proxy contract with unverified implementation'
    };
}

// ========== 🔴 FIX 4: CoinGecko Fallback Already Done ==========
// (Already implemented in previous code - keep as is)

// ========== 🔴 FIX 5: Testing Framework ==========
async function runAccuracyTest() {
    const testCases = [
        // Format: { input, chain, expectedRisk, type }
        { input: '0xdac17f958d2ee523a2206206994597c13d831ec7', chain: 'ethereum', expectedRisk: 'LOW', type: 'safe' }, // USDT
        { input: '0x7a250d5630b4cf539739df2c5dacb4c659f2488d', chain: 'ethereum', expectedRisk: 'LOW', type: 'safe' }, // Uniswap
        { input: '0x6982508145454ce325ddbe47a25d4ec3d2311933', chain: 'ethereum', expectedRisk: 'MEDIUM', type: 'meme' }, // PEPE
        { input: '0x95ad61b0a150d79219dcf64e1e6cc01f0b64c4ce', chain: 'ethereum', expectedRisk: 'MEDIUM', type: 'meme' }, // SHIB
        // Add more test cases
    ];
    
    const results = {
        total: testCases.length,
        passed: 0,
        failed: [],
        accuracy: 0,
        falsePositives: 0,
        falseNegatives: 0
    };
    
    for (const test of testCases) {
        try {
            // Simulate scan (replace with actual API call)
            const response = await axios.post('http://localhost:3000/api/scan', {
                input: test.input,
                chain: test.chain
            });
            
            const riskLevel = response.data.risk.level;
            const passed = riskLevel === test.expectedRisk;
            
            if (passed) {
                results.passed++;
            } else {
                results.failed.push({
                    input: test.input,
                    expected: test.expectedRisk,
                    got: riskLevel,
                    type: test.type
                });
                
                if (test.type === 'safe' && riskLevel !== 'SAFE' && riskLevel !== 'LOW') {
                    results.falsePositives++;
                } else if (test.type === 'scam' && (riskLevel === 'SAFE' || riskLevel === 'LOW')) {
                    results.falseNegatives++;
                }
            }
        } catch (error) {
            results.failed.push({
                input: test.input,
                error: error.message
            });
        }
    }
    
    results.accuracy = (results.passed / results.total) * 100;
    
    return results;
}

// Test endpoint (protected, only enable in development)
if (process.env.NODE_ENV !== 'production') {
    app.get('/api/test/accuracy', async (req, res) => {
        const results = await runAccuracyTest();
        res.json(results);
    });
}

// ========== INTEGRATE ALL FIXES INTO MAIN SCAN FUNCTION ==========
// Add this to your main scan endpoint after collecting results:

// Add partial data warnings
const warnings = getPartialDataWarnings(apiResults);

// Apply age-based rules
const ageAdjustment = applyAgeBasedRules(apiResults, reasons);

// Apply proxy whitelist
if (apiResults.contract?.proxy) {
    const proxyAnalysis = analyzeProxyContract(apiResults.contract, input);
    if (!proxyAnalysis.isRisky) {
        // Lower risk for whitelisted proxies
        baseRisk = Math.max(20, baseRisk - 15);
        reasons.push(proxyAnalysis.reason);
    } else {
        baseRisk += 15;
        reasons.push(proxyAnalysis.reason);
    }
}

// Adjust risk based on age
baseRisk += ageAdjustment;

// Add warnings to response
response.warnings = warnings;
