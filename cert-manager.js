const forge = require('node-forge');
const fs = require('fs');
const path = require('path');

class CertificateManager {
  constructor() {
    this.certDir = path.join(__dirname, 'certificates');
    this.ensureCertDir();
  }

  ensureCertDir() {
    if (!fs.existsSync(this.certDir)) {
      fs.mkdirSync(this.certDir, { recursive: true });
    }
  }

  generateCA() {
    console.log('Generating CA certificate...');
    
    // Generate CA key pair
    const caKeys = forge.pki.rsa.generateKeyPair(2048);
    
    // Create CA certificate
    const caCert = forge.pki.createCertificate();
    caCert.publicKey = caKeys.publicKey;
    caCert.serialNumber = '01';
    caCert.validity.notBefore = new Date();
    caCert.validity.notAfter = new Date();
    caCert.validity.notAfter.setFullYear(caCert.validity.notBefore.getFullYear() + 10);

    const caAttrs = [{
      name: 'commonName',
      value: 'AI Proxy Protector CA'
    }, {
      name: 'organizationName',
      value: 'AI Proxy Protector'
    }, {
      name: 'organizationalUnitName',
      value: 'Security'
    }];

    caCert.setSubject(caAttrs);
    caCert.setIssuer(caAttrs);
    caCert.setExtensions([{
      name: 'basicConstraints',
      cA: true
    }, {
      name: 'keyUsage',
      keyCertSign: true,
      digitalSignature: true,
      keyEncipherment: true
    }]);

    // Sign CA certificate
    caCert.sign(caKeys.privateKey, forge.md.sha256.create());

    // Save CA files
    const caPem = forge.pki.certificateToPem(caCert);
    const caKeyPem = forge.pki.privateKeyToPem(caKeys.privateKey);

    fs.writeFileSync(path.join(this.certDir, 'ca.crt'), caPem);
    fs.writeFileSync(path.join(this.certDir, 'ca.key'), caKeyPem);

    return { cert: caCert, key: caKeys.privateKey };
  }

  generateServerCert(hostname = 'chat.openai.com') {
    console.log(`Generating certificate for ${hostname}...`);

    // Load CA
    const caCertPem = fs.readFileSync(path.join(this.certDir, 'ca.crt'), 'utf8');
    const caKeyPem = fs.readFileSync(path.join(this.certDir, 'ca.key'), 'utf8');
    const caCert = forge.pki.certificateFromPem(caCertPem);
    const caKey = forge.pki.privateKeyFromPem(caKeyPem);

    // Generate server key pair
    const serverKeys = forge.pki.rsa.generateKeyPair(2048);

    // Create server certificate
    const serverCert = forge.pki.createCertificate();
    serverCert.publicKey = serverKeys.publicKey;
    serverCert.serialNumber = new Date().getTime().toString();
    serverCert.validity.notBefore = new Date();
    serverCert.validity.notAfter = new Date();
    serverCert.validity.notAfter.setFullYear(serverCert.validity.notBefore.getFullYear() + 1);

    const serverAttrs = [{
      name: 'commonName',
      value: hostname
    }];

    serverCert.setSubject(serverAttrs);
    serverCert.setIssuer(caCert.subject.attributes);
    serverCert.setExtensions([{
      name: 'subjectAltName',
      altNames: [{
        type: 2, // DNS
        value: hostname
      }, {
        type: 2,
        value: `*.${hostname}`
      }]
    }]);

    // Sign with CA
    serverCert.sign(caKey, forge.md.sha256.create());

    // Save server files
    const serverCertPem = forge.pki.certificateToPem(serverCert);
    const serverKeyPem = forge.pki.privateKeyToPem(serverKeys.privateKey);

    const certPath = path.join(this.certDir, `${hostname}.crt`);
    const keyPath = path.join(this.certDir, `${hostname}.key`);

    fs.writeFileSync(certPath, serverCertPem);
    fs.writeFileSync(keyPath, serverKeyPem);

    return { certPath, keyPath };
  }

  setup() {
    // Check if CA exists
    const caPath = path.join(this.certDir, 'ca.crt');
    if (!fs.existsSync(caPath)) {
      this.generateCA();
    }

    // Generate certificates for AI platforms
    const platforms = ['chat.openai.com', 'claude.ai', 'bard.google.com', 'copilot.microsoft.com'];
    
    platforms.forEach(platform => {
      const certPath = path.join(this.certDir, `${platform}.crt`);
      if (!fs.existsSync(certPath)) {
        this.generateServerCert(platform);
      }
    });

    console.log('Certificate setup complete!');
    console.log(`Install the CA certificate: ${caPath}`);
  }
}

// Run setup if called directly
if (require.main === module) {
  const certManager = new CertificateManager();
  certManager.setup();
}

module.exports = CertificateManager;