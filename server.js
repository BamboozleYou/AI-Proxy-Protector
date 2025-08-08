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
    
    // Debug output for constructor
    console.log('🔧 Config in constructor:');
    console.log('geminiApiKey exists:', !!this.config.geminiApiKey);
    console.log('geminiApiKey length:', this.config.geminiApiKey ? this.config.geminiApiKey.length : 0);
    console.log('proxyPort:', this.config.proxyPort);
    console.log('webPort:', this.config.webPort);
    
    this.piiDetector = new PIIDetector(this.config.geminiApiKey);
    this.certManager = new CertificateManager();
    this.stats = {
      requestsBlocked: 0,
      requestsAllowed: 0,
      piiDetections: 0,
      startTime: new Date()
    };
    
    this.setupMiddleware();
    this.setupRoutes();
  }

  loadConfig() {
    const configPath = path.join(__dirname, 'config.json');
    if (fs.existsSync(configPath)) {
      const fileConfig = JSON.parse(fs.readFileSync(configPath, 'utf8'));
      // Always use environment variable for API key if available
      fileConfig.geminiApiKey = process.env.GEMINI_API_KEY || fileConfig.geminiApiKey || '';
      return fileConfig;
    }
    
    // Default config
    return {
      geminiApiKey: process.env.GEMINI_API_KEY || '',
      proxyPort: parseInt(process.env.PROXY_PORT) || 8080,
      webPort: parseInt(process.env.WEB_PORT) || 3000,
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
    
    // Request logging
    this.app.use((req, res, next) => {
      console.log(`${new Date().toISOString()} ${req.method} ${req.url}`);
      next();
    });
  }

  setupRoutes() {
    // Web interface API
    this.app.get('/api/status', (req, res) => {
      res.json({
        status: 'running',
        stats: this.stats,
        config: {
          hasApiKey: !!this.config.geminiApiKey,
          proxyPort: this.config.proxyPort,
          webPort: this.config.webPort
        },
        uptime: Date.now() - this.stats.startTime
      });
    });

    this.app.post('/api/config', (req, res) => {
      this.config = { ...this.config, ...req.body };
      this.saveConfig();
      
      // Recreate PII detector with new API key if provided
      if (req.body.geminiApiKey) {
        this.piiDetector = new PIIDetector(req.body.geminiApiKey);
      }
      
      res.json({ success: true });
    });

    // Catch-all proxy handler
    this.app.use('*', this.createProxyHandler());
  }

  createProxyHandler() {
    return async (req, res, next) => {
      const host = req.get('host');
      
      // Check if this is an AI platform
      const isAIPlatform = Object.keys(this.config.aiPlatforms).some(platform => 
        host && host.includes(platform) && this.config.aiPlatforms[platform]
      );

      if (!isAIPlatform) {
        return res.status(404).json({ error: 'Not an AI platform' });
      }

      console.log(`🤖 AI Platform detected: ${host}`);

      // Handle POST requests to chat endpoints
      if (req.method === 'POST' && this.isChatEndpoint(req.originalUrl)) {
        await this.handleChatRequest(req, res, host);
      } else {
        // Proxy other requests normally
        this.proxyRequest(req, res, host);
      }
    };
  }

  isChatEndpoint(url) {
    const chatEndpoints = [
      '/backend-api/conversation', // ChatGPT
      '/api/organizations/', // Claude
      '/v1/chat/completions', // Generic OpenAI API
      '/api/generate' // Other AI platforms
    ];
    
    return chatEndpoints.some(endpoint => url.includes(endpoint));
  }

  async handleChatRequest(req, res, host) {
    let body = '';
    
    req.on('data', chunk => {
      body += chunk.toString();
    });

    req.on('end', async () => {
      try {
        const prompt = this.extractPrompt(body, host);
        
        if (prompt && prompt.length > 10) { // Skip very short prompts
          console.log(`📝 Analyzing prompt: "${prompt.substring(0, 50)}..."`);
          
          const hasPII = await this.piiDetector.detectPII(prompt);
          
          if (hasPII) {
            this.stats.requestsBlocked++;
            this.stats.piiDetections++;
            
            console.log('🚫 Request blocked - PII detected');
            
            return res.status(403).json({
              error: 'PII Detected',
              message: 'Your request contains personally identifiable information and has been blocked.',
              suggestion: 'Please remove personal information like names, emails, phone numbers, or addresses.',
              blocked: true,
              timestamp: new Date().toISOString()
            });
          }
        }

        this.stats.requestsAllowed++;
        console.log('✅ Request allowed - No PII detected');
        
        // Forward the request
        this.proxyRequestWithBody(req, res, host, body);
        
      } catch (error) {
        console.error('Error processing request:', error);
        this.stats.requestsAllowed++; // Fail open
        this.proxyRequestWithBody(req, res, host, body);
      }
    });
  }

  extractPrompt(body, host) {
    try {
      const data = JSON.parse(body);
      
      // ChatGPT format
      if (data.messages && Array.isArray(data.messages)) {
        const lastMessage = data.messages[data.messages.length - 1];
        return lastMessage?.content || '';
      }
      
      // Claude format
      if (data.prompt) {
        return data.prompt;
      }
      
      // Generic formats
      if (data.input) return data.input;
      if (data.text) return data.text;
      if (data.query) return data.query;
      
    } catch (error) {
      // Not JSON, try to extract text
      return body.substring(0, 1000); // First 1000 chars
    }
    
    return '';
  }

  proxyRequestWithBody(req, res, host, body) {
    const target = `https://${host}`;
    
    const proxy = createProxyMiddleware({
      target,
      changeOrigin: true,
      secure: false,
      onProxyReq: (proxyReq, req, res) => {
        if (body) {
          proxyReq.setHeader('Content-Length', Buffer.byteLength(body));
          proxyReq.write(body);
        }
      },
      onError: (err, req, res) => {
        console.error('Proxy error:', err);
        res.status(500).json({ error: 'Proxy error' });
      }
    });
    
    proxy(req, res);
  }

  proxyRequest(req, res, host) {
    const target = `https://${host}`;
    
    const proxy = createProxyMiddleware({
      target,
      changeOrigin: true,
      secure: false,
      onError: (err, req, res) => {
        console.error('Proxy error:', err);
        res.status(500).json({ error: 'Proxy error' });
      }
    });
    
    proxy(req, res);
  }

  async start() {
    // Start web interface
    this.app.listen(this.config.webPort, '0.0.0.0', () => {
      console.log(`🌐 Web interface: http://localhost:${this.config.webPort}`);
    });

    // Start HTTPS proxy
    const certPath = path.join(__dirname, 'certificates', 'chat.openai.com.crt');
    const keyPath = path.join(__dirname, 'certificates', 'chat.openai.com.key');
    
    if (!fs.existsSync(certPath) || !fs.existsSync(keyPath)) {
      console.error('❌ Certificates not found. Run: npm run setup');
      return;
    }

    const options = {
      cert: fs.readFileSync(certPath),
      key: fs.readFileSync(keyPath)
    };

    https.createServer(options, this.app).listen(this.config.proxyPort, '0.0.0.0', () => {
      console.log('\n🛡️  AI Proxy Protector Started!');
      console.log(`📊 Dashboard: http://localhost:${this.config.webPort}`);
      console.log(`🔒 Proxy running on port: ${this.config.proxyPort}`);
      
      if (!this.config.geminiApiKey) {
        console.log('⚠️  No Gemini API key found in .env file');
      }
      
      this.printMacOSProxyInstructions();
    });
  }

  printMacOSProxyInstructions() {
    console.log('\n📋 macOS PROXY SETUP:');
    console.log('1. System Preferences → Network');
    console.log('2. Select your connection → Advanced → Proxies');
    console.log('3. Check "Web Proxy (HTTP)" and "Secure Web Proxy (HTTPS)"');
    console.log(`4. Server: 127.0.0.1, Port: ${this.config.proxyPort}`);
    console.log('5. Click OK and Apply');
    console.log('\n🧪 TEST: Visit ChatGPT and try entering an email address\n');
  }
}

if (require.main === module) {
  const protector = new AIProxyProtector();
  protector.start();
}

module.exports = AIProxyProtector;
