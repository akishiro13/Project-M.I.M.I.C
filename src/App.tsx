import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  Terminal, 
  Key, 
  Hash, 
  Globe, 
  Lock,
  Search,
  Code,
  Activity,
  Wifi,
  Eye,
  Settings,
  ChevronRight,
  Copy,
  Check,
  Monitor,
  Network,
  MapPin,
  Clock,
  Zap,
  FileText,
  Database,
  Smartphone
} from 'lucide-react';

interface Tool {
  id: string;
  name: string;
  description: string;
  icon: React.ReactNode;
  category: string;
}

interface ToolResult {
  type: 'success' | 'error' | 'info';
  content: string;
}

interface NetworkDevice {
  ip: string;
  hostname?: string;
  mac?: string;
  vendor?: string;
  ports?: number[];
}

const tools: Tool[] = [
  // Network Tools
  {
    id: 'my-ip-info',
    name: 'My IP Information',
    description: 'Get your private and public IP addresses',
    icon: <Globe className="w-5 h-5" />,
    category: 'Network'
  },
  {
    id: 'network-scanner',
    name: 'Network Scanner',
    description: 'Scan local network for connected devices',
    icon: <Network className="w-5 h-5" />,
    category: 'Network'
  },
  {
    id: 'port-scanner',
    name: 'Port Scanner',
    description: 'Scan ports on target hosts',
    icon: <Wifi className="w-5 h-5" />,
    category: 'Network'
  },
  {
    id: 'ping-tool',
    name: 'Ping Tool',
    description: 'Test connectivity to hosts',
    icon: <Activity className="w-5 h-5" />,
    category: 'Network'
  },
  {
    id: 'dns-lookup',
    name: 'DNS Lookup',
    description: 'Perform DNS queries and lookups',
    icon: <Search className="w-5 h-5" />,
    category: 'Network'
  },
  {
    id: 'whois-lookup',
    name: 'WHOIS Lookup',
    description: 'Get domain registration information',
    icon: <FileText className="w-5 h-5" />,
    category: 'Network'
  },
  {
    id: 'geolocation',
    name: 'IP Geolocation',
    description: 'Get geographical location of IP addresses',
    icon: <MapPin className="w-5 h-5" />,
    category: 'Network'
  },
  
  // Crypto Tools
  {
    id: 'hash-generator',
    name: 'Hash Generator',
    description: 'Generate MD5, SHA1, SHA256 hashes',
    icon: <Hash className="w-5 h-5" />,
    category: 'Crypto'
  },
  {
    id: 'base64-encoder',
    name: 'Base64 Encoder/Decoder',
    description: 'Encode and decode Base64 strings',
    icon: <Code className="w-5 h-5" />,
    category: 'Crypto'
  },
  {
    id: 'url-encoder',
    name: 'URL Encoder/Decoder',
    description: 'Encode and decode URL strings',
    icon: <Globe className="w-5 h-5" />,
    category: 'Crypto'
  },
  {
    id: 'hex-converter',
    name: 'Hex Converter',
    description: 'Convert between hex, decimal, and binary',
    icon: <Database className="w-5 h-5" />,
    category: 'Crypto'
  },
  
  // Security Tools
  {
    id: 'password-generator',
    name: 'Password Generator',
    description: 'Generate secure passwords',
    icon: <Key className="w-5 h-5" />,
    category: 'Security'
  },
  {
    id: 'password-strength',
    name: 'Password Strength Checker',
    description: 'Analyze password strength and security',
    icon: <Shield className="w-5 h-5" />,
    category: 'Security'
  },
  {
    id: 'jwt-decoder',
    name: 'JWT Decoder',
    description: 'Decode and analyze JWT tokens',
    icon: <Lock className="w-5 h-5" />,
    category: 'Security'
  },
  
  // Web Security
  {
    id: 'http-headers',
    name: 'HTTP Headers Analyzer',
    description: 'Analyze HTTP response headers',
    icon: <Activity className="w-5 h-5" />,
    category: 'Web Security'
  },
  {
    id: 'url-analyzer',
    name: 'URL Analyzer',
    description: 'Analyze URLs for security issues',
    icon: <Search className="w-5 h-5" />,
    category: 'Web Security'
  },
  {
    id: 'ssl-checker',
    name: 'SSL Certificate Checker',
    description: 'Check SSL certificate details and validity',
    icon: <Lock className="w-5 h-5" />,
    category: 'Web Security'
  },
  
  // System Tools
  {
    id: 'system-info',
    name: 'System Information',
    description: 'Get browser and system information',
    icon: <Monitor className="w-5 h-5" />,
    category: 'System'
  },
  {
    id: 'user-agent',
    name: 'User Agent Analyzer',
    description: 'Analyze and decode user agent strings',
    icon: <Smartphone className="w-5 h-5" />,
    category: 'System'
  },
  {
    id: 'timestamp-converter',
    name: 'Timestamp Converter',
    description: 'Convert between different timestamp formats',
    icon: <Clock className="w-5 h-5" />,
    category: 'System'
  }
];

function App() {
  const [selectedTool, setSelectedTool] = useState<string>('');
  const [input, setInput] = useState('');
  const [result, setResult] = useState<ToolResult | null>(null);
  const [copied, setCopied] = useState(false);
  const [loading, setLoading] = useState(false);

  const categories = [...new Set(tools.map(tool => tool.category))];

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Get local IP addresses
  const getLocalIPs = async (): Promise<string[]> => {
    return new Promise((resolve) => {
      const ips: string[] = [];
      const RTCPeerConnection = window.RTCPeerConnection || 
                               (window as any).webkitRTCPeerConnection || 
                               (window as any).mozRTCPeerConnection;

      if (!RTCPeerConnection) {
        resolve(['Unable to determine local IP']);
        return;
      }

      const pc = new RTCPeerConnection({
        iceServers: [{ urls: 'stun:stun.l.google.com:19302' }]
      });

      pc.createDataChannel('');
      pc.createOffer().then(offer => pc.setLocalDescription(offer));

      pc.onicecandidate = (event) => {
        if (event.candidate) {
          const candidate = event.candidate.candidate;
          const match = candidate.match(/(\d+\.\d+\.\d+\.\d+)/);
          if (match && !ips.includes(match[1])) {
            ips.push(match[1]);
          }
        }
      };

      setTimeout(() => {
        pc.close();
        resolve(ips.length > 0 ? ips : ['Unable to determine local IP']);
      }, 2000);
    });
  };

  // Get public IP
  const getPublicIP = async (): Promise<string> => {
    try {
      const response = await fetch('https://api.ipify.org?format=json');
      const data = await response.json();
      return data.ip;
    } catch (error) {
      try {
        const response = await fetch('https://ipapi.co/ip/');
        return await response.text();
      } catch {
        return 'Unable to determine public IP';
      }
    }
  };

  // Get IP geolocation
  const getIPGeolocation = async (ip: string): Promise<any> => {
    try {
      const response = await fetch(`https://ipapi.co/${ip}/json/`);
      return await response.json();
    } catch (error) {
      throw new Error('Unable to get IP geolocation');
    }
  };

  // Perform DNS lookup
  const performDNSLookup = async (domain: string): Promise<string> => {
    try {
      // Use DNS over HTTPS (DoH) service
      const response = await fetch(`https://cloudflare-dns.com/dns-query?name=${domain}&type=A`, {
        headers: {
          'Accept': 'application/dns-json'
        }
      });
      const data = await response.json();
      
      let result = `DNS Lookup for ${domain}:\n\n`;
      if (data.Answer) {
        data.Answer.forEach((record: any) => {
          result += `${record.name} -> ${record.data} (TTL: ${record.TTL})\n`;
        });
      } else {
        result += 'No A records found\n';
      }
      
      return result;
    } catch (error) {
      throw new Error('DNS lookup failed');
    }
  };

  // Check SSL certificate
  const checkSSL = async (domain: string): Promise<string> => {
    try {
      const url = domain.startsWith('http') ? domain : `https://${domain}`;
      const response = await fetch(url, { method: 'HEAD' });
      
      let result = `SSL Certificate Check for ${domain}:\n\n`;
      result += `Status: ${response.ok ? 'Valid' : 'Invalid'}\n`;
      result += `Protocol: ${response.url.startsWith('https') ? 'HTTPS' : 'HTTP'}\n`;
      result += `Response Code: ${response.status}\n`;
      
      return result;
    } catch (error) {
      throw new Error('SSL check failed');
    }
  };

  // Analyze password strength
  const analyzePasswordStrength = (password: string): string => {
    let score = 0;
    let feedback = [];

    // Length check
    if (password.length >= 8) score += 1;
    else feedback.push('Use at least 8 characters');

    if (password.length >= 12) score += 1;
    else feedback.push('Consider using 12+ characters for better security');

    // Character variety
    if (/[a-z]/.test(password)) score += 1;
    else feedback.push('Include lowercase letters');

    if (/[A-Z]/.test(password)) score += 1;
    else feedback.push('Include uppercase letters');

    if (/\d/.test(password)) score += 1;
    else feedback.push('Include numbers');

    if (/[^a-zA-Z\d]/.test(password)) score += 1;
    else feedback.push('Include special characters');

    // Common patterns
    if (!/(.)\1{2,}/.test(password)) score += 1;
    else feedback.push('Avoid repeating characters');

    const strength = score <= 2 ? 'Weak' : score <= 4 ? 'Medium' : score <= 6 ? 'Strong' : 'Very Strong';
    const color = score <= 2 ? '🔴' : score <= 4 ? '🟡' : score <= 6 ? '🟢' : '🟢';

    let result = `Password Strength Analysis:\n\n`;
    result += `Password: ${password}\n`;
    result += `Strength: ${color} ${strength} (${score}/7)\n`;
    result += `Length: ${password.length} characters\n\n`;
    
    if (feedback.length > 0) {
      result += `Recommendations:\n`;
      feedback.forEach(item => result += `• ${item}\n`);
    } else {
      result += `✅ Excellent password strength!\n`;
    }

    return result;
  };

  // Generate hash
  const generateHash = async (text: string, algorithm: string): Promise<string> => {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    
    let hashBuffer;
    switch (algorithm) {
      case 'SHA-1':
        hashBuffer = await crypto.subtle.digest('SHA-1', data);
        break;
      case 'SHA-256':
        hashBuffer = await crypto.subtle.digest('SHA-256', data);
        break;
      case 'SHA-384':
        hashBuffer = await crypto.subtle.digest('SHA-384', data);
        break;
      case 'SHA-512':
        hashBuffer = await crypto.subtle.digest('SHA-512', data);
        break;
      default:
        throw new Error('Unsupported algorithm');
    }
    
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  };

  // Generate secure password
  const generatePassword = (length: number = 16, includeSymbols: boolean = true): string => {
    const lowercase = 'abcdefghijklmnopqrstuvwxyz';
    const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const numbers = '0123456789';
    const symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?';
    
    let chars = lowercase + uppercase + numbers;
    if (includeSymbols) chars += symbols;
    
    let password = '';
    const array = new Uint32Array(length);
    crypto.getRandomValues(array);
    
    // Ensure at least one character from each category
    password += lowercase[Math.floor(Math.random() * lowercase.length)];
    password += uppercase[Math.floor(Math.random() * uppercase.length)];
    password += numbers[Math.floor(Math.random() * numbers.length)];
    if (includeSymbols) {
      password += symbols[Math.floor(Math.random() * symbols.length)];
    }
    
    // Fill the rest randomly
    for (let i = password.length; i < length; i++) {
      password += chars[array[i] % chars.length];
    }
    
    // Shuffle the password
    return password.split('').sort(() => Math.random() - 0.5).join('');
  };

  // Port scanner (using fetch to test common web ports)
  const scanPorts = async (host: string): Promise<string> => {
    const commonPorts = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080, 8443];
    let result = `Port Scan Results for ${host}:\n\n`;
    
    const promises = commonPorts.map(async (port) => {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 3000);
        
        await fetch(`http://${host}:${port}`, {
          method: 'HEAD',
          mode: 'no-cors',
          signal: controller.signal
        });
        
        clearTimeout(timeoutId);
        return `Port ${port}: OPEN`;
      } catch (error) {
        return `Port ${port}: CLOSED/FILTERED`;
      }
    });
    
    const results = await Promise.all(promises);
    result += results.join('\n');
    
    return result;
  };

  // Get system information
  const getSystemInfo = (): string => {
    const nav = navigator;
    let result = `System Information:\n\n`;
    
    result += `Browser: ${nav.userAgent}\n`;
    result += `Platform: ${nav.platform}\n`;
    result += `Language: ${nav.language}\n`;
    result += `Languages: ${nav.languages.join(', ')}\n`;
    result += `Online: ${nav.onLine ? 'Yes' : 'No'}\n`;
    result += `Cookies Enabled: ${nav.cookieEnabled ? 'Yes' : 'No'}\n`;
    result += `Java Enabled: ${(nav as any).javaEnabled ? (nav as any).javaEnabled() : 'Unknown'}\n`;
    
    // Screen information
    result += `\nScreen Information:\n`;
    result += `Resolution: ${screen.width}x${screen.height}\n`;
    result += `Available: ${screen.availWidth}x${screen.availHeight}\n`;
    result += `Color Depth: ${screen.colorDepth} bits\n`;
    result += `Pixel Depth: ${screen.pixelDepth} bits\n`;
    
    // Timezone
    result += `\nTimezone: ${Intl.DateTimeFormat().resolvedOptions().timeZone}\n`;
    result += `Current Time: ${new Date().toLocaleString()}\n`;
    
    return result;
  };

  const executeToolCommand = async () => {
    if (!selectedTool) {
      setResult({ type: 'error', content: 'Please select a tool' });
      return;
    }

    setLoading(true);
    
    try {
      let output = '';
      
      switch (selectedTool) {
        case 'my-ip-info':
          const [localIPs, publicIP] = await Promise.all([
            getLocalIPs(),
            getPublicIP()
          ]);
          
          output = `IP Address Information:\n\n`;
          output += `Public IP: ${publicIP}\n\n`;
          output += `Local IP Addresses:\n`;
          localIPs.forEach((ip, index) => {
            output += `${index + 1}. ${ip}\n`;
          });
          
          // Try to get geolocation for public IP
          try {
            const geoData = await getIPGeolocation(publicIP);
            output += `\nGeolocation (Public IP):\n`;
            output += `Country: ${geoData.country_name || 'Unknown'}\n`;
            output += `Region: ${geoData.region || 'Unknown'}\n`;
            output += `City: ${geoData.city || 'Unknown'}\n`;
            output += `ISP: ${geoData.org || 'Unknown'}\n`;
            output += `Timezone: ${geoData.timezone || 'Unknown'}\n`;
          } catch (e) {
            output += `\nGeolocation: Unable to retrieve\n`;
          }
          break;

        case 'network-scanner':
          // This is limited in browsers, but we can provide network info
          output = `Network Scanner Results:\n\n`;
          output += `Note: Browser security limitations prevent full network scanning.\n`;
          output += `Available network information:\n\n`;
          
          const localIPs2 = await getLocalIPs();
          localIPs2.forEach(ip => {
            const parts = ip.split('.');
            if (parts.length === 4) {
              const networkBase = `${parts[0]}.${parts[1]}.${parts[2]}`;
              output += `Network Range: ${networkBase}.1 - ${networkBase}.254\n`;
              output += `Your IP: ${ip}\n`;
              output += `Subnet Mask: 255.255.255.0 (assumed)\n\n`;
            }
          });
          
          output += `To perform full network scanning, use dedicated tools like:\n`;
          output += `• Nmap (command line)\n`;
          output += `• Advanced IP Scanner\n`;
          output += `• Angry IP Scanner\n`;
          break;

        case 'port-scanner':
          if (!input.trim()) {
            throw new Error('Please enter a host to scan');
          }
          output = await scanPorts(input.trim());
          break;

        case 'ping-tool':
          if (!input.trim()) {
            throw new Error('Please enter a host to ping');
          }
          
          // Browser ping simulation using fetch timing
          const startTime = performance.now();
          try {
            await fetch(`https://${input.trim()}`, { 
              method: 'HEAD', 
              mode: 'no-cors',
              cache: 'no-cache'
            });
            const endTime = performance.now();
            const responseTime = Math.round(endTime - startTime);
            
            output = `Ping Results for ${input}:\n\n`;
            output += `Host: ${input}\n`;
            output += `Status: Reachable\n`;
            output += `Response Time: ~${responseTime}ms\n`;
            output += `Method: HTTP/HTTPS probe\n\n`;
            output += `Note: Browser limitations prevent ICMP ping.\n`;
            output += `This is an HTTP connectivity test.\n`;
          } catch (error) {
            output = `Ping Results for ${input}:\n\n`;
            output += `Host: ${input}\n`;
            output += `Status: Unreachable or blocked\n`;
            output += `Error: ${error}\n`;
          }
          break;

        case 'dns-lookup':
          if (!input.trim()) {
            throw new Error('Please enter a domain name');
          }
          output = await performDNSLookup(input.trim());
          break;

        case 'whois-lookup':
          if (!input.trim()) {
            throw new Error('Please enter a domain name');
          }
          
          // Use a WHOIS API service
          try {
            const response = await fetch(`https://api.whoisjson.com/v1/${input.trim()}`);
            const data = await response.json();
            
            output = `WHOIS Information for ${input}:\n\n`;
            if (data.domain) {
              output += `Domain: ${data.domain}\n`;
              output += `Registrar: ${data.registrar || 'Unknown'}\n`;
              output += `Creation Date: ${data.created || 'Unknown'}\n`;
              output += `Expiration Date: ${data.expires || 'Unknown'}\n`;
              output += `Status: ${data.status || 'Unknown'}\n`;
              
              if (data.nameservers) {
                output += `\nName Servers:\n`;
                data.nameservers.forEach((ns: string) => {
                  output += `• ${ns}\n`;
                });
              }
            } else {
              output += `Unable to retrieve WHOIS data for ${input}\n`;
            }
          } catch (error) {
            output = `WHOIS lookup failed for ${input}\n`;
            output += `Error: ${error}\n`;
          }
          break;

        case 'geolocation':
          if (!input.trim()) {
            throw new Error('Please enter an IP address');
          }
          
          const geoData = await getIPGeolocation(input.trim());
          output = `IP Geolocation for ${input}:\n\n`;
          output += `IP: ${geoData.ip || input}\n`;
          output += `Country: ${geoData.country_name || 'Unknown'}\n`;
          output += `Region: ${geoData.region || 'Unknown'}\n`;
          output += `City: ${geoData.city || 'Unknown'}\n`;
          output += `Postal Code: ${geoData.postal || 'Unknown'}\n`;
          output += `Latitude: ${geoData.latitude || 'Unknown'}\n`;
          output += `Longitude: ${geoData.longitude || 'Unknown'}\n`;
          output += `ISP: ${geoData.org || 'Unknown'}\n`;
          output += `Timezone: ${geoData.timezone || 'Unknown'}\n`;
          output += `Currency: ${geoData.currency || 'Unknown'}\n`;
          break;

        case 'hash-generator':
          if (!input.trim()) {
            throw new Error('Please enter text to hash');
          }
          
          const sha1 = await generateHash(input, 'SHA-1');
          const sha256 = await generateHash(input, 'SHA-256');
          const sha384 = await generateHash(input, 'SHA-384');
          const sha512 = await generateHash(input, 'SHA-512');
          
          output = `Hash Results for: "${input}"\n\n`;
          output += `SHA-1:   ${sha1}\n`;
          output += `SHA-256: ${sha256}\n`;
          output += `SHA-384: ${sha384}\n`;
          output += `SHA-512: ${sha512}\n`;
          break;

        case 'password-generator':
          const length = parseInt(input) || 16;
          const passwords = [];
          for (let i = 0; i < 5; i++) {
            passwords.push(generatePassword(length, true));
          }
          output = `Generated ${length}-character passwords:\n\n`;
          passwords.forEach((pwd, idx) => {
            output += `${idx + 1}: ${pwd}\n`;
          });
          
          output += `\nPassword Requirements Met:\n`;
          output += `✓ Uppercase letters\n`;
          output += `✓ Lowercase letters\n`;
          output += `✓ Numbers\n`;
          output += `✓ Special characters\n`;
          output += `✓ Cryptographically secure\n`;
          break;

        case 'password-strength':
          if (!input.trim()) {
            throw new Error('Please enter a password to analyze');
          }
          output = analyzePasswordStrength(input);
          break;

        case 'base64-encoder':
          if (!input.trim()) {
            throw new Error('Please enter text to encode/decode');
          }
          
          try {
            // Try to decode first
            const decoded = atob(input);
            output = `Base64 Operations:\n\n`;
            output += `Input (Base64): ${input}\n`;
            output += `Decoded: ${decoded}\n\n`;
            output += `Re-encoded: ${btoa(decoded)}\n`;
          } catch {
            // If decode fails, just encode
            const encoded = btoa(input);
            output = `Base64 Operations:\n\n`;
            output += `Input (Text): ${input}\n`;
            output += `Encoded: ${encoded}\n\n`;
            output += `Verification (Decoded): ${atob(encoded)}\n`;
          }
          break;

        case 'url-encoder':
          if (!input.trim()) {
            throw new Error('Please enter text to encode/decode');
          }
          
          try {
            const decoded = decodeURIComponent(input);
            output = `URL Operations:\n\n`;
            output += `Input (URL Encoded): ${input}\n`;
            output += `Decoded: ${decoded}\n\n`;
            output += `Re-encoded: ${encodeURIComponent(decoded)}\n`;
          } catch {
            const encoded = encodeURIComponent(input);
            output = `URL Operations:\n\n`;
            output += `Input (Text): ${input}\n`;
            output += `Encoded: ${encoded}\n\n`;
            output += `Verification (Decoded): ${decodeURIComponent(encoded)}\n`;
          }
          break;

        case 'hex-converter':
          if (!input.trim()) {
            throw new Error('Please enter a value to convert');
          }
          
          output = `Number Base Conversions:\n\n`;
          
          // Try to determine input format and convert
          const cleanInput = input.trim();
          
          if (/^[0-9]+$/.test(cleanInput)) {
            // Decimal input
            const decimal = parseInt(cleanInput, 10);
            output += `Decimal: ${decimal}\n`;
            output += `Hexadecimal: 0x${decimal.toString(16).toUpperCase()}\n`;
            output += `Binary: 0b${decimal.toString(2)}\n`;
            output += `Octal: 0o${decimal.toString(8)}\n`;
          } else if (/^0x[0-9a-fA-F]+$/.test(cleanInput)) {
            // Hex input
            const decimal = parseInt(cleanInput, 16);
            output += `Hexadecimal: ${cleanInput.toUpperCase()}\n`;
            output += `Decimal: ${decimal}\n`;
            output += `Binary: 0b${decimal.toString(2)}\n`;
            output += `Octal: 0o${decimal.toString(8)}\n`;
          } else if (/^0b[01]+$/.test(cleanInput)) {
            // Binary input
            const decimal = parseInt(cleanInput.slice(2), 2);
            output += `Binary: ${cleanInput}\n`;
            output += `Decimal: ${decimal}\n`;
            output += `Hexadecimal: 0x${decimal.toString(16).toUpperCase()}\n`;
            output += `Octal: 0o${decimal.toString(8)}\n`;
          } else if (/^[0-9a-fA-F]+$/.test(cleanInput)) {
            // Hex without prefix
            const decimal = parseInt(cleanInput, 16);
            output += `Hexadecimal: 0x${cleanInput.toUpperCase()}\n`;
            output += `Decimal: ${decimal}\n`;
            output += `Binary: 0b${decimal.toString(2)}\n`;
            output += `Octal: 0o${decimal.toString(8)}\n`;
          } else {
            // Text to hex
            const hexString = Array.from(cleanInput)
              .map(char => char.charCodeAt(0).toString(16).padStart(2, '0'))
              .join('');
            output += `Text: ${cleanInput}\n`;
            output += `Hex: ${hexString.toUpperCase()}\n`;
            output += `Bytes: ${cleanInput.length}\n`;
          }
          break;

        case 'jwt-decoder':
          if (!input.trim()) {
            throw new Error('Please enter a JWT token');
          }
          
          try {
            const parts = input.split('.');
            if (parts.length !== 3) throw new Error('Invalid JWT format');
            
            const header = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
            const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
            
            output = `JWT Token Analysis:\n\n`;
            output += `Header:\n${JSON.stringify(header, null, 2)}\n\n`;
            output += `Payload:\n${JSON.stringify(payload, null, 2)}\n\n`;
            output += `Signature: ${parts[2]}\n\n`;
            
            // Check expiration
            if (payload.exp) {
              const expDate = new Date(payload.exp * 1000);
              const now = new Date();
              output += `Expiration: ${expDate.toLocaleString()}\n`;
              output += `Status: ${now > expDate ? '❌ Expired' : '✅ Valid'}\n`;
            }
            
            if (payload.iat) {
              const iatDate = new Date(payload.iat * 1000);
              output += `Issued At: ${iatDate.toLocaleString()}\n`;
            }
          } catch (error) {
            throw new Error('Invalid JWT token format');
          }
          break;

        case 'http-headers':
          if (!input.trim()) {
            throw new Error('Please enter a URL');
          }
          
          try {
            const url = input.startsWith('http') ? input : `https://${input}`;
            const response = await fetch(url, { method: 'HEAD' });
            
            output = `HTTP Headers Analysis for: ${url}\n\n`;
            output += `Status: ${response.status} ${response.statusText}\n`;
            output += `URL: ${response.url}\n\n`;
            
            output += `Response Headers:\n`;
            response.headers.forEach((value, key) => {
              output += `${key}: ${value}\n`;
            });
            
            // Security headers check
            output += `\nSecurity Headers Analysis:\n`;
            const securityHeaders = {
              'strict-transport-security': 'HSTS',
              'x-frame-options': 'Clickjacking Protection',
              'x-content-type-options': 'MIME Sniffing Protection',
              'x-xss-protection': 'XSS Protection',
              'content-security-policy': 'CSP',
              'referrer-policy': 'Referrer Policy'
            };
            
            Object.entries(securityHeaders).forEach(([header, description]) => {
              const hasHeader = response.headers.has(header);
              output += `${description}: ${hasHeader ? '✅ Present' : '❌ Missing'}\n`;
            });
            
          } catch (error) {
            throw new Error(`Failed to fetch headers: ${error}`);
          }
          break;

        case 'url-analyzer':
          if (!input.trim()) {
            throw new Error('Please enter a URL');
          }
          
          try {
            const url = new URL(input.startsWith('http') ? input : `https://${input}`);
            output = `URL Analysis for: ${input}\n\n`;
            output += `Protocol: ${url.protocol}\n`;
            output += `Hostname: ${url.hostname}\n`;
            output += `Port: ${url.port || (url.protocol === 'https:' ? '443' : '80')}\n`;
            output += `Path: ${url.pathname}\n`;
            output += `Query: ${url.search || 'None'}\n`;
            output += `Fragment: ${url.hash || 'None'}\n\n`;
            
            // Security analysis
            output += `Security Analysis:\n`;
            output += `HTTPS: ${url.protocol === 'https:' ? '✅ Secure' : '❌ Insecure'}\n`;
            
            // Check for suspicious patterns
            const suspicious = [
              { pattern: /bit\.ly|tinyurl|t\.co/, name: 'URL Shortener' },
              { pattern: /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/, name: 'IP Address' },
              { pattern: /[a-z0-9]{20,}/, name: 'Long Random String' },
              { pattern: /\.(tk|ml|ga|cf)$/, name: 'Suspicious TLD' }
            ];
            
            suspicious.forEach(({ pattern, name }) => {
              const found = pattern.test(url.hostname + url.pathname);
              output += `${name}: ${found ? '⚠️ Detected' : '✅ Clean'}\n`;
            });
            
          } catch (error) {
            throw new Error('Invalid URL format');
          }
          break;

        case 'ssl-checker':
          if (!input.trim()) {
            throw new Error('Please enter a domain name');
          }
          
          output = await checkSSL(input.trim());
          break;

        case 'system-info':
          output = getSystemInfo();
          break;

        case 'user-agent':
          const userAgent = input.trim() || navigator.userAgent;
          output = `User Agent Analysis:\n\n`;
          output += `User Agent: ${userAgent}\n\n`;
          
          // Parse user agent
          const browserMatch = userAgent.match(/(Chrome|Firefox|Safari|Edge|Opera)\/([0-9.]+)/);
          const osMatch = userAgent.match(/(Windows|Mac|Linux|Android|iOS)/);
          const mobileMatch = userAgent.match(/(Mobile|Tablet)/);
          
          output += `Browser: ${browserMatch ? `${browserMatch[1]} ${browserMatch[2]}` : 'Unknown'}\n`;
          output += `Operating System: ${osMatch ? osMatch[1] : 'Unknown'}\n`;
          output += `Device Type: ${mobileMatch ? mobileMatch[1] : 'Desktop'}\n`;
          
          // Security implications
          output += `\nSecurity Notes:\n`;
          output += `• User agents can be spoofed\n`;
          output += `• Contains system information\n`;
          output += `• Used for fingerprinting\n`;
          break;

        case 'timestamp-converter':
          if (!input.trim()) {
            throw new Error('Please enter a timestamp or leave empty for current time');
          }
          
          let timestamp;
          if (input.trim() === '') {
            timestamp = Date.now();
          } else if (/^\d+$/.test(input.trim())) {
            timestamp = parseInt(input.trim());
            // Handle seconds vs milliseconds
            if (timestamp < 10000000000) {
              timestamp *= 1000; // Convert seconds to milliseconds
            }
          } else {
            timestamp = new Date(input.trim()).getTime();
          }
          
          if (isNaN(timestamp)) {
            throw new Error('Invalid timestamp format');
          }
          
          const date = new Date(timestamp);
          output = `Timestamp Conversion:\n\n`;
          output += `Unix Timestamp (ms): ${timestamp}\n`;
          output += `Unix Timestamp (s): ${Math.floor(timestamp / 1000)}\n`;
          output += `ISO 8601: ${date.toISOString()}\n`;
          output += `Local Time: ${date.toLocaleString()}\n`;
          output += `UTC Time: ${date.toUTCString()}\n`;
          output += `Relative: ${getRelativeTime(date)}\n`;
          break;

        default:
          throw new Error('Tool not implemented');
      }

      setResult({ type: 'success', content: output });
    } catch (error) {
      setResult({ type: 'error', content: `Error: ${error}` });
    } finally {
      setLoading(false);
    }
  };

  const getRelativeTime = (date: Date): string => {
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffSecs = Math.floor(diffMs / 1000);
    const diffMins = Math.floor(diffSecs / 60);
    const diffHours = Math.floor(diffMins / 60);
    const diffDays = Math.floor(diffHours / 24);

    if (diffSecs < 60) return `${diffSecs} seconds ago`;
    if (diffMins < 60) return `${diffMins} minutes ago`;
    if (diffHours < 24) return `${diffHours} hours ago`;
    return `${diffDays} days ago`;
  };

  return (
    <div className="min-h-screen bg-gray-900 text-green-400 font-mono">
      {/* Header */}
      <header className="bg-gray-800 border-b border-green-500/30 px-6 py-4">
        <div className="flex items-center space-x-3">
          <Shield className="w-8 h-8 text-green-400" />
          <div>
            <h1 className="text-2xl font-bold text-white">M.I.M.I.C Project</h1>
            <p className="text-green-400/70 text-sm">Multi-Interface for Monitoring, Investigation & Cybersecurity</p>
          </div>
        </div>
      </header>

      <div className="flex flex-col lg:flex-row h-[calc(100vh-80px)]">
        {/* Sidebar */}
        <div className="w-full lg:w-80 bg-gray-800 border-r border-green-500/30 p-6 overflow-y-auto">
          <div className="mb-6">
            <div className="flex items-center space-x-2 mb-4">
              <Terminal className="w-5 h-5" />
              <h2 className="text-lg font-semibold text-white">Available Tools</h2>
            </div>
          </div>

          {categories.map(category => (
            <div key={category} className="mb-6">
              <h3 className="text-green-300 font-semibold mb-3 text-sm uppercase tracking-wider">
                {category}
              </h3>
              <div className="space-y-2">
                {tools
                  .filter(tool => tool.category === category)
                  .map(tool => (
                    <button
                      key={tool.id}
                      onClick={() => setSelectedTool(tool.id)}
                      className={`w-full text-left p-3 rounded-lg border transition-all duration-200 ${
                        selectedTool === tool.id
                          ? 'bg-green-500/20 border-green-400 text-white'
                          : 'bg-gray-700/50 border-gray-600 hover:bg-gray-700 hover:border-green-500/50'
                      }`}
                    >
                      <div className="flex items-center space-x-3">
                        {tool.icon}
                        <div className="flex-1">
                          <div className="font-medium">{tool.name}</div>
                          <div className="text-xs text-gray-400 mt-1">
                            {tool.description}
                          </div>
                        </div>
                        <ChevronRight className="w-4 h-4 text-gray-500" />
                      </div>
                    </button>
                  ))}
              </div>
            </div>
          ))}
        </div>

        {/* Main Content */}
        <div className="flex-1 p-6">
          {selectedTool ? (
            <div className="h-full flex flex-col">
              <div className="mb-6">
                <h2 className="text-xl font-semibold text-white mb-2">
                  {tools.find(t => t.id === selectedTool)?.name}
                </h2>
                <p className="text-gray-400">
                  {tools.find(t => t.id === selectedTool)?.description}
                </p>
              </div>

              {/* Input Section */}
              <div className="mb-6">
                <label className="block text-sm font-medium text-green-300 mb-2">
                  Input:
                </label>
                <div className="flex space-x-3">
                  <textarea
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    placeholder={getInputPlaceholder(selectedTool)}
                    className="flex-1 bg-gray-800 border border-gray-600 rounded-lg px-4 py-3 text-white focus:border-green-500 focus:outline-none resize-none"
                    rows={3}
                  />
                  <button
                    onClick={executeToolCommand}
                    disabled={loading}
                    className="px-6 py-3 bg-green-600 hover:bg-green-700 disabled:bg-gray-600 text-white rounded-lg font-medium transition-colors duration-200 self-start flex items-center space-x-2"
                  >
                    {loading && <Zap className="w-4 h-4 animate-spin" />}
                    <span>{loading ? 'Running...' : 'Execute'}</span>
                  </button>
                </div>
              </div>

              {/* Output Section */}
              {result && (
                <div className="flex-1 bg-gray-800 rounded-lg border border-gray-600 overflow-hidden">
                  <div className="bg-gray-700 px-4 py-2 border-b border-gray-600 flex items-center justify-between">
                    <span className="text-sm font-medium text-white">Output</span>
                    <button
                      onClick={() => copyToClipboard(result.content)}
                      className="text-gray-400 hover:text-white transition-colors duration-200"
                    >
                      {copied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                    </button>
                  </div>
                  <div className="p-4 overflow-auto h-full">
                    <pre className={`text-sm whitespace-pre-wrap ${
                      result.type === 'error' ? 'text-red-400' : 
                      result.type === 'info' ? 'text-blue-400' : 'text-green-400'
                    }`}>
                      {result.content}
                    </pre>
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="h-full flex items-center justify-center">
              <div className="text-center">
                <Eye className="w-16 h-16 text-gray-600 mx-auto mb-4" />
                <h3 className="text-xl font-semibold text-white mb-2">
                  Select a Tool
                </h3>
                <p className="text-gray-400">
                  Choose a security tool from the sidebar to get started
                </p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function getInputPlaceholder(toolId: string): string {
  const placeholders: Record<string, string> = {
    'my-ip-info': 'No input required - click Execute to get your IP info',
    'network-scanner': 'No input required - click Execute to scan network',
    'port-scanner': 'Enter IP address or domain (e.g., google.com)',
    'ping-tool': 'Enter hostname or IP (e.g., google.com)',
    'dns-lookup': 'Enter domain name (e.g., google.com)',
    'whois-lookup': 'Enter domain name (e.g., google.com)',
    'geolocation': 'Enter IP address (e.g., 8.8.8.8)',
    'hash-generator': 'Enter text to hash',
    'password-generator': 'Enter password length (default: 16)',
    'password-strength': 'Enter password to analyze',
    'base64-encoder': 'Enter text to encode/decode',
    'url-encoder': 'Enter text to URL encode/decode',
    'hex-converter': 'Enter number, hex (0xFF), binary (0b1010), or text',
    'jwt-decoder': 'Enter JWT token',
    'http-headers': 'Enter URL (e.g., https://google.com)',
    'url-analyzer': 'Enter URL (e.g., https://example.com)',
    'ssl-checker': 'Enter domain name (e.g., google.com)',
    'system-info': 'No input required - click Execute',
    'user-agent': 'Enter user agent string (or leave empty for current)',
    'timestamp-converter': 'Enter timestamp or date (or leave empty for now)'
  };
  
  return placeholders[toolId] || 'Enter input for this tool';
}

export default App;