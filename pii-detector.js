class PIIDetector {
  constructor(geminiApiKey) {
    this.apiKey = geminiApiKey;
    this.apiUrl = 'https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent';
  }

  async detectPII(text) {
    try {
      const prompt = `Analyze the following text for personally identifiable information (PII) including but not limited to:
- Names, email addresses, phone numbers
- Social security numbers, credit card numbers
- Addresses, dates of birth
- IP addresses, user IDs, passwords
- Medical information, financial data
- Any other sensitive personal information

Text to analyze: "${text}"

Respond with only:
- "PII_DETECTED" if any PII is found
- "NO_PII" if no PII is found

Do not include any other explanation.`;

      const response = await fetch(this.apiUrl + `?key=${this.apiKey}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          contents: [{
            parts: [{ text: prompt }]
          }]
        })
      });

      if (!response.ok) {
        console.error('Gemini API error:', response.status, response.statusText);
        return false; // Fail open for user experience
      }

      const data = await response.json();
      const result = data.candidates[0]?.content?.parts[0]?.text?.trim();
      
      console.log('PII Detection Result:', result);
      return result === 'PII_DETECTED';
    } catch (error) {
      console.error('PII detection error:', error);
      return false; // Fail open on error
    }
  }

  // Quick regex-based pre-screening for performance
  quickPIICheck(text) {
    const piiPatterns = [
      /\b\d{3}-\d{2}-\d{4}\b/, // SSN
      /\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/, // Credit card
      /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/, // Email
      /\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/, // Phone number
      /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/, // IP address
    ];

    return piiPatterns.some(pattern => pattern.test(text));
  }
}

module.exports = PIIDetector;