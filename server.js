// Load environment variables FIRST - before anything else
require('dotenv').config();

// Add debug output
console.log('🔍 Environment loaded:');
console.log('API Key exists:', !!process.env.GEMINI_API_KEY);
console.log('API Key length:', process.env.GEMINI_API_KEY ? process.env.GEMINI_API_KEY.length : 0);

const express = require('express');
const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const { createProxyMiddleware } = require('http-proxy-middleware');
const PIIDetector = require('./pii-detector');
const CertificateManager = require('./cert-manager');

class AIProxyProtector {
  constructor() {
    this.app = express();
    this.config = this.loadConfig();
    this.piiDetector = new PIIDetector(this.config.geminiApiKey);
    this.certManager = new CertificateManager();
    this.stats = {
      requestsBlocked: 0,
      requestsAllowed: 0,
      piiDetections: 0
    };
    
    this.setupMiddleware();
    this.setupRoutes();
  }

  loadConfig() {
    const configPath = path.join(__dirname, 'config.json');
    if (fs.existsSync(configPath)) {
      return JSON.parse(fs.readFileSync(configPath, 'utf8'));
    }
    
    // Default config
    return {
      geminiApiKey: process.env.GEMINI_API_KEY || '',
      proxyPort: 8080,
      webPort: 3000,
      logLevel: 'info',
      aiPlatforms: {
        'chat.openai.com': true,
        'claude.ai': true,
        'bard.google.com': true,
        'copilot.microsoft.com': true
      }
    };
  }

  saveConfig() {
    fs.writeFileSync(path.join(__dirname, 'config.json'), JSON.stringify(this.config, null, 2));
  }

  setupMiddleware() {
    this.app.use(cors());
    this.app.use(express.json({ limit: '10mb' }));
    this.app.use(express.static('web-interface'));
  }

  setupRoutes() {
    // Web interface API
    this.app.get('/api/status', (req, res) => {
      res.json({
        status: 'running',
        stats: this.stats,
        config: this.config
      });
    });

    this.app.post('/api/config', (req, res) => {
      this.config = { ...this.config, ...req.body };
      this.saveConfig();
      res.json({ success: true });
    });

    // Main proxy handler
    this.app.use('*', this.createProxyHandler());
  }

  createProxyHandler() {
    return async (req, res, next) => {
      const host = req.get('host');
      const isAIPlatform = Object.keys(this.config.aiPlatforms).some(platform => 
        host && host.includes(platform) && this.config.aiPlatforms[platform]
      );

      if (!isAIPlatform) {
        return next();
      }

      console.log(`Intercepting request to ${host}${req.originalUrl}`);

      // Check if this is a chat submission
      if (req.method === 'POST' && this.isChatEndpoint(req.originalUrl)) {
        const blocked = await this.handleChatRequest(req, res);
        if (blocked) return;
      }

      // Proxy the request
      this.proxyRequest(req, res, host);
    };
  }

  isChatEndpoint(url) {
    const chatEndpoints = [
      '/backend-api/conversation', // ChatGPT
      '/api/organizations/', // Claude
      '/v1/chat/completions', // Generic OpenAI API
    ];
    
    return chatEndpoints.some(endpoint => url.includes(endpoint));
  }

  async handleChatRequest(req, res) {
    try {
      let body = '';
      
      req.on('data', chunk => {
        body += chunk.toString();
      });

      req.on('end', async () => {
        const prompt = this.extractPrompt(body, req.get('host'));
        
        if (prompt) {
          console.log('Analyzing prompt:', prompt.substring(0, 100) + '...');
          
          // Quick pre-screen
          const quickCheck = this.piiDetector.quickPIICheck(prompt);
          let hasPII = false;
          
          if (quickCheck) {
            // Full AI analysis
            hasPII = await this.piiDetector.detectPII(prompt);
          }

          if (hasPII) {
            this.stats.requestsBlocked++;
            this.stats.piiDetections++;
            
            res.status(403).json({
              error: 'PII Detected',
              message: 'Your request contains personally identifiable information and has been blocked for security reasons.',
              blocked: true,
              suggestion: 'Please remove any personal information such as names, emails, phone numbers, or addresses and try again.'
            });
            
            console.log('🚫 Request blocked - PII detected');
            return true; // Request blocked
          }
        }

        this.stats.requestsAllowed++;
        console.log('✅ Request allowed - No PII detected');
        
        // Continue with original request
        this.forwardRequest(req, res, body);
      });

      return false; // Will be handled async
    } catch (error) {
      console.error('Error handling chat request:', error);
      this.stats.requestsAllowed++; // Fail open
      return false;
    }
  }

  extractPrompt(body, host) {
    try {
      const data = JSON.parse(body);
      
      // ChatGPT format
      if (data.messages) {
        const lastMessage = data.messages[data.messages.length - 1];
        return lastMessage?.content || '';
      }
      
      // Claude format
      if (data.prompt) {
        return data.prompt;
      }
      
      // Generic format
      if (data.input) {
        return data.input;
      }
      
      return '';
    } catch (error) {
      console.error('Error extracting prompt:', error);
      return '';
    }
  }

  forwardRequest(req, res, body) {
    const host = req.get('host');
    const target = `https://${host}`;
    
    const proxy = createProxyMiddleware({
      target,
      changeOrigin: true,
      secure: false,
      onProxyReq: (proxyReq) => {
        if (body) {
          proxyReq.write(body);
        }
      }
    });
    
    proxy(req, res);
  }

  proxyRequest(req, res, host) {
    const target = `https://${host}`;
    
    const proxy = createProxyMiddleware({
      target,
      changeOrigin: true,
      secure: false
    });
    
    proxy(req, res);
  }

  start() {
    // Start web interface
    this.app.listen(this.config.webPort, () => {
      console.log(`🌐 Web interface running on http://localhost:${this.config.webPort}`);
    });

    // Start HTTPS proxy
    if (this.config.geminiApiKey) {
      const certPath = path.join(__dirname, 'certificates', 'chat.openai.com.crt');
      const keyPath = path.join(__dirname, 'certificates', 'chat.openai.com.key');
      
      if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
        const options = {
          cert: fs.readFileSync(certPath),
          key: fs.readFileSync(keyPath)
        };

        https.createServer(options, this.app).listen(this.config.proxyPort, () => {
          console.log(`🛡️  AI Proxy Protector running on port ${this.config.proxyPort}`);
          console.log(`📊 Configure at http://localhost:${this.config.webPort}`);
          this.printSetupInstructions();
        });
      } else {
        console.error('❌ Certificates not found. Run: npm run setup');
      }
    } else {
      console.error('❌ Please set GEMINI_API_KEY environment variable or configure it in the web interface');
    }
  }

  printSetupInstructions() {
    console.log('\n📋 SETUP INSTRUCTIONS:');
    console.log('1. Install CA certificate from: ./certificates/ca.crt');
    console.log('2. Set system proxy to: localhost:8080');
    console.log('3. Configure your Gemini API key in the web interface');
    console.log('4. Visit ChatGPT and test the protection\n');
  }
}

// Start the server
if (require.main === module) {
  const protector = new AIProxyProtector();
  protector.start();
}

module.exports = AIProxyProtector;