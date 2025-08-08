// Load environment variables FIRST
require('dotenv').config();

console.log('🔍 Environment loaded:');
console.log('API Key exists:', !!process.env.GEMINI_API_KEY);
console.log('API Key length:', process.env.GEMINI_API_KEY ? process.env.GEMINI_API_KEY.length : 0);

const express = require('express');
const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const net = require('net');
const url = require('url');
const { createProxyMiddleware } = require('http-proxy-middleware');
const PIIDetector = require('./pii-detector');
const CertificateManager = require('./cert-manager');

class AIProxyProtector {
  constructor() {
    this.app = express();
    this.config = this.loadConfig();
    
    console.log('🔧 Config loaded:');
    console.log('API Key exists:', !!this.config.geminiApiKey);
    
    this.piiDetector = new PIIDetector(this.config.geminiApiKey);
    this.stats = {
      requestsBlocked: 0,
      requestsAllowed: 0,
      piiDetections: 0,
      startTime: new Date()
    };
    
    this.setupMiddleware();
    this.setupRoutes();
    
    this.aiPlatforms = [
      'chat.openai.com',
      'claude.ai',
      'bard.google.com',
      'copilot.microsoft.com',
      'gemini.google.com'
    ];
  }

  loadConfig() {
    return {
      geminiApiKey: process.env.GEMINI_API_KEY || '',
      proxyPort: parseInt(process.env.PROXY_PORT) || 8080,
      webPort: parseInt(process.env.WEB_PORT) || 3000,
      aiPlatforms: {
        'chat.openai.com': true,
        'claude.ai': true,
        'bard.google.com': true,
        'copilot.microsoft.com': true
      }
    };
  }

  setupMiddleware() {
    this.app.use(cors());
    this.app.use(express.json({ limit: '10mb' }));
    this.app.use(express.static('web-interface'));
  }

  setupRoutes() {
    // API endpoints
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

    // Regular HTTP proxy for non-AI platforms
    this.app.use('*', (req, res, next) => {
      const host = req.get('host');
      
      if (!host) {
        return res.status(400).send('Bad Request');
      }

      // Check if this is an AI platform
      const isAIPlatform = this.aiPlatforms.some(platform => host.includes(platform));

      if (isAIPlatform) {
        console.log(`🤖 AI Platform detected: ${host}`);
        return this.handleAIPlatform(req, res, host);
      } else {
        // Pass through other websites normally
        return this.proxyRegularWebsite(req, res, host);
      }
    });
  }

  async handleAIPlatform(req, res, host) {
    // Handle AI platform requests with PII detection
    if (req.method === 'POST' && this.isChatEndpoint(req.originalUrl)) {
      let body = '';
      
      req.on('data', chunk => {
        body += chunk.toString();
      });

      req.on('end', async () => {
        try {
          const prompt = this.extractPrompt(body);
          
          if (prompt && prompt.length > 10) {
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
                blocked: true
              });
            }
          }

          this.stats.requestsAllowed++;
          console.log('✅ Request allowed - No PII detected');
          
          // Forward the request if no PII
          this.forwardRequest(req, res, host, body);
          
        } catch (error) {
          console.error('Error processing AI request:', error);
          this.forwardRequest(req, res, host, body);
        }
      });
    } else {
      // Non-chat requests to AI platforms - pass through
      this.proxyRegularWebsite(req, res, host);
    }
  }

  proxyRegularWebsite(req, res, host) {
    const isHttps = req.connection.encrypted;
    const target = `${isHttps ? 'https' : 'http'}://${host}`;
    
    const proxy = createProxyMiddleware({
      target,
      changeOrigin: true,
      secure: false,
      onError: (err, req, res) => {
        console.error('Proxy error:', err.message);
        if (!res.headersSent) {
          res.status(500).send('Proxy error');
        }
      }
    });
    
    proxy(req, res);
  }

  forwardRequest(req, res, host, body) {
    const target = `https://${host}`;
    
    const proxy = createProxyMiddleware({
      target,
      changeOrigin: true,
      secure: false,
      onProxyReq: (proxyReq) => {
        if (body && req.method === 'POST') {
          proxyReq.setHeader('Content-Length', Buffer.byteLength(body));
          proxyReq.write(body);
        }
      },
      onError: (err, req, res) => {
        console.error('Proxy forward error:', err.message);
        if (!res.headersSent) {
          res.status(500).json({ error: 'Proxy error' });
        }
      }
    });
    
    proxy(req, res);
  }

  isChatEndpoint(url) {
    const chatEndpoints = [
      '/backend-api/conversation',
      '/api/organizations/',
      '/v1/chat/completions',
      '/api/generate'
    ];
    
    return chatEndpoints.some(endpoint => url.includes(endpoint));
  }

  extractPrompt(body) {
    try {
      const data = JSON.parse(body);
      
      if (data.messages && Array.isArray(data.messages)) {
        const lastMessage = data.messages[data.messages.length - 1];
        return lastMessage?.content || '';
      }
      
      if (data.prompt) return data.prompt;
      if (data.input) return data.input;
      if (data.text) return data.text;
      
    } catch (error) {
      return body.substring(0, 1000);
    }
    
    return '';
  }

  // Handle HTTPS CONNECT requests for SSL tunneling
  handleConnect(req, clientSocket, head) {
    const { hostname, port } = url.parse(`http://${req.url}`);
    const isAIPlatform = this.aiPlatforms.some(platform => hostname.includes(platform));
    
    if (isAIPlatform) {
      console.log(`🔐 HTTPS CONNECT to AI platform: ${hostname}`);
      // For AI platforms, we need to intercept with our certificate
      this.handleAIConnect(req, clientSocket, head, hostname, port);
    } else {
      // For regular websites, create normal tunnel
      this.handleRegularConnect(req, clientSocket, head, hostname, port);
    }
  }

  handleAIConnect(req, clientSocket, head, hostname, port) {
    // Load our certificate for this AI platform
    const certPath = path.join(__dirname, 'certificates', `${hostname}.crt`);
    const keyPath = path.join(__dirname, 'certificates', `${hostname}.key`);
    
    if (!fs.existsSync(certPath) || !fs.existsSync(keyPath)) {
      console.error(`❌ No certificate found for ${hostname}`);
      clientSocket.end('HTTP/1.1 500 Internal Server Error\r\n\r\n');
      return;
    }

    // Send successful CONNECT response
    clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');

    // Create HTTPS server with our certificate
    const options = {
      cert: fs.readFileSync(certPath),
      key: fs.readFileSync(keyPath)
    };

    const httpsServer = https.createServer(options, this.app);
    
    // Handle the TLS connection
    const tlsSocket = new require('tls').TLSSocket(clientSocket, {
      isServer: true,
      server: httpsServer,
      ...options
    });

    httpsServer.emit('connection', tlsSocket);
  }

  handleRegularConnect(req, clientSocket, head, hostname, port) {
    // Create direct tunnel for regular websites
    const serverSocket = net.connect(port || 443, hostname, () => {
      clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      serverSocket.write(head);
      serverSocket.pipe(clientSocket);
      clientSocket.pipe(serverSocket);
    });

    serverSocket.on('error', (err) => {
      console.error(`Tunnel error for ${hostname}:`, err.message);
      clientSocket.end();
    });

    clientSocket.on('error', (err) => {
      console.error('Client socket error:', err.message);
      serverSocket.end();
    });
  }

  async start() {
    // Start web interface
    this.app.listen(this.config.webPort, '0.0.0.0', () => {
      console.log(`🌐 Web interface: http://localhost:${this.config.webPort}`);
    });

    // Create HTTP proxy server
    const httpServer = http.createServer(this.app);
    
    // Handle HTTPS CONNECT requests
    httpServer.on('connect', (req, clientSocket, head) => {
      this.handleConnect(req, clientSocket, head);
    });

    httpServer.listen(this.config.proxyPort, '0.0.0.0', () => {
      console.log('\n🛡️  AI Proxy Protector Started!');
      console.log(`🔗 HTTP/HTTPS Proxy running on port: ${this.config.proxyPort}`);
      console.log(`📊 Dashboard: http://localhost:${this.config.webPort}`);
      
      if (!this.config.geminiApiKey) {
        console.log('⚠️  No Gemini API key configured');
      }
      
      this.printSetupInstructions();
    });
  }

  printSetupInstructions() {
    console.log('\n📋 SETUP INSTRUCTIONS:');
    console.log('1. ✅ CA certificate should be installed');
    console.log('2. ✅ Set system proxy to: 127.0.0.1:' + this.config.proxyPort);
    console.log('3. ✅ API key configured');
    console.log('4. 🧪 Test: Visit any website (should work normally)');
    console.log('5. 🧪 Test: Visit ChatGPT and try entering an email address (should be blocked)');
    console.log('\n🔧 To disable proxy: System Preferences → Network → Proxies → Uncheck boxes\n');
  }
}

if (require.main === module) {
  const protector = new AIProxyProtector();
  protector.start();
}

module.exports = AIProxyProtector;
