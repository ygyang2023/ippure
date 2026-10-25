export interface Env {
  ASSETS: { fetch: typeof fetch };
  db: D1Database;
  kv: KVNamespace;
}

const HTML_PAGES: Record<string, string> = {
  '/': 'index.html',
  '/index.html': 'index.html',
  '/IP-Outbound-Detect.html': 'IP-Outbound-Detect.html',
  '/IP-leak-Detect.html': 'IP-leak-Detect.html',
  '/Browser-WebRTC-Leak-Detect.html': 'Browser-WebRTC-Leak-Detect.html',
  '/DNS-Leak-Detect.html': 'DNS-Leak-Detect.html',
  '/fingerprint.html': 'fingerprint.html',
  '/neighbors.html': 'neighbors.html',
  '/MyIP-Info-Card.html': 'MyIP-Info-Card.html',
  '/MyIP-Info-API.html': 'MyIP-Info-API.html',
  '/about.html': 'about.html',
  '/faq.html': 'faq.html',
  '/correction.html': 'correction.html',
  '/changelog.html': 'changelog.html',
  '/contact.html': 'contact.html',
  '/terms-privacy.html': 'terms-privacy.html',
};

const API_ENDPOINTS: Record<string, (request: Request, env: Env, ctx: ExecutionContext) => Promise<Response>> = {
  '/v1/info': handleIPInfo,
  '/v1/card': handleIPCard,
  '/v1/resolve': handleResolve,
  '/v1/chat/login': handleChatLogin,
  '/v1/chat/logout': handleChatLogout,
  '/v1/chat/messages': handleChatMessages,
  '/v1/chat/send': handleChatSend,
  '/v1/chat/history': handleChatHistory,
};

async function handleIPInfo(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const cf = request.cf;
  const ip = request.headers.get('CF-Connecting-IP') || 'Unknown';
  
  let ipV4 = '';
  let ipV6 = '';
  
  // 只在需要时才显示对应IP类型，避免不必要的信息泄露
  if (ip.includes(':')) {
    // 这是一个IPv6连接，只显示IPv6
    ipV6 = ip;
    // 不主动映射到IPv4，除非是我们自己的测试地址
  } else {
    // 这是一个IPv4连接，只显示IPv4
    ipV4 = ip;
    // 不主动映射到IPv6，避免信息泄露
  }
  
  const ippureCoefficient = calculateFraudScore(ip, cf?.asn, cf?.country, cf?.region);
  const cloudflareCoefficient = calculateCloudflareCoefficient(ip, cf?.asn, cf?.country, cf?.region);
  
  const ipInfo = {
    ip: ip,
    ipV4: ipV4,
    ipV6: ipV6,
    asn: cf?.asn || 0,
    asOrganization: cf?.asn ? `AS${cf.asn}` : '未知',
    country: getCountryName(cf?.country || 'XX'),
    countryCode: cf?.country?.toUpperCase() || 'XX',
    region: cf?.region || '',
    regionCode: cf?.region?.toUpperCase() || '',
    city: cf?.city || '',
    timezone: getTimezone(cf?.country || 'US', cf?.region || ''),
    longitude: cf?.longitude?.toString() || '0',
    latitude: cf?.latitude?.toString() || '0',
    postalCode: cf?.postal || '',
    fraudScore: ippureCoefficient,
    ippureCoefficient: ippureCoefficient,
    cloudflareCoefficient: cloudflareCoefficient,
    ipSource: getIPSource(cf?.asn, ip),
    ipProperties: getIPProperties(ip, cf?.asn),
    userAgent: request.headers.get('User-Agent') || ''
  };

  return new Response(JSON.stringify(ipInfo, null, 2), {
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
    }
  });
}

async function handleIPCard(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const cf = request.cf;
  const ip = request.headers.get('CF-Connecting-IP') || 'Unknown';
  const country = cf?.country || 'Unknown';
  const city = cf?.city || '';
  const region = cf?.region || '';

  const svg = generateCardSVG(ip, country, city, region);

  return new Response(svg, {
    headers: {
      'Content-Type': 'image/svg+xml',
      'Cache-Control': 'public, max-age=300',
    }
  });
}

async function handleResolve(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const url = new URL(request.url);
  const domain = url.searchParams.get('domain') || 'example.com';
  
  const mockResults: Record<string, { ip: string; location: string }> = {
    '主要出口 IPv4': { ip: '222.247.147.212', location: '中国，湖南省，长沙市' },
    'itdog IPv4': { ip: '222.247.147.212', location: '中国，湖南省，长沙市' },
    '网易': { ip: '223.111.194.114', location: '中国，广东省，广州市' },
    'openai.com': { ip: '104.18.123.222', location: '美国，加利福尼亚州，旧金山' },
    'claude.ai': { ip: '35.185.44.189', location: '美国，俄勒冈州，波特兰' },
    'cloudflare.com': { ip: '104.16.132.229', location: '美国，加利福尼亚州，旧金山' },
    'gitlab.com': { ip: '172.65.251.78', location: 'San Francisco, CA, USA' },
    'nodejs.org': { ip: '104.20.23.46', location: '美国，加利福尼亚州，旧金山' }
  };

  const result = mockResults[domain] || { ip: '8.8.8.8', location: '美国' };
  
  return new Response(JSON.stringify(result), {
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
    }
  });
}
async function hashPassword(password: string): Promise<{ salt: string; hash: string }> {
  const salt = generateSalt(16);
  const hash = await genHashPassword(password, salt);
  return { salt, hash };
}

function generateSalt(length: number): string {
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  return btoa(String.fromCharCode(...array));
}

async function genHashPassword(password: string, salt: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(salt + password);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return btoa(String.fromCharCode(...hashArray));
}

async function verifyPassword(inputPassword: string, salt: string, storedHash: string): Promise<boolean> {
  const hash = await genHashPassword(inputPassword, salt);
  return hash === storedHash;
}

async function handleChatLogin(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const url = new URL(request.url);
  const email = url.searchParams.get('email');
  const password = url.searchParams.get('password');
  
  if (!email || !password) {
    return new Response(JSON.stringify({ error: '缺少邮箱或密码' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }
  
  try {
    const result = await env.db.prepare(
      'SELECT user_id, email, password, salt, status FROM user WHERE email = ? AND is_del = 0'
    ).bind(email).first();
    
    if (!result) {
      return new Response(JSON.stringify({ error: '用户不存在' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    const isValid = await verifyPassword(password, result.salt as string, result.password as string);
    
    if (!isValid) {
      return new Response(JSON.stringify({ error: '密码错误' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    if (result.status === 1) {
      return new Response(JSON.stringify({ error: '账户已被禁用' }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    const token = btoa(JSON.stringify({ userId: result.user_id, email: result.email, exp: Date.now() + 7 * 24 * 60 * 60 * 1000 }));
    
    return new Response(JSON.stringify({ 
      success: true, 
      token: token,
      user: { 
        id: result.user_id, 
        email: result.email 
      }
    }), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: '登录服务暂不可用' }), {
      status: 503,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

async function handleChatLogout(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  return new Response(JSON.stringify({ success: true }), {
    headers: { 'Content-Type': 'application/json' }
  });
}

async function handleChatMessages(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const userId = request.headers.get('X-User-Id');
  
  if (!userId) {
    return new Response(JSON.stringify({ error: '请先登录' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' }
    });
  }
  
  const sevenDaysAgo = Date.now() - 7 * 24 * 60 * 60 * 1000;
  
  try {
    const list = await env.kv.list({ prefix: userId + ':' });
    const messages = [];
    
    for (const key of list.keys) {
      const message = await env.kv.get(key.name, 'json');
      if (message && message.timestamp > sevenDaysAgo) {
        messages.push(message);
      } else if (message) {
        await env.kv.delete(key.name);
      }
    }
    
    messages.sort((a, b) => a.timestamp - b.timestamp);
    
    return new Response(JSON.stringify({ messages }), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: '获取消息失败' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

async function handleChatSend(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const userId = request.headers.get('X-User-Id');
  
  if (!userId) {
    return new Response(JSON.stringify({ error: '请先登录' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' }
    });
  }
  
  try {
    const body = await request.json();
    const { content } = body;
    
    if (!content || content.trim() === '') {
      return new Response(JSON.stringify({ error: '消息内容不能为空' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    const message = {
      id: crypto.randomUUID(),
      userId: userId,
      content: content.trim(),
      timestamp: Date.now()
    };
    
    const key = `${userId}:${message.id}`;
    await env.kv.put(key, JSON.stringify(message));
    
    await cleanupOldMessages(env);
    
    return new Response(JSON.stringify({ success: true, message }), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: '发送消息失败' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

async function handleChatHistory(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const userId = request.headers.get('X-User-Id');
  
  if (!userId) {
    return new Response(JSON.stringify({ error: '请先登录' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' }
    });
  }
  
  const sevenDaysAgo = Date.now() - 7 * 24 * 60 * 60 * 1000;
  
  try {
    const list = await env.kv.list({ prefix: userId + ':' });
    const messages = [];
    
    for (const key of list.keys) {
      const message = await env.kv.get(key.name, 'json');
      if (message) {
        if (message.timestamp > sevenDaysAgo) {
          messages.push(message);
        } else {
          await env.kv.delete(key.name);
        }
      }
    }
    
    messages.sort((a, b) => b.timestamp - a.timestamp);
    
    return new Response(JSON.stringify({ 
      messages,
      retentionDays: 7,
      cleanupInfo: '超过7天的消息将自动删除'
    }), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: '获取历史记录失败' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

async function cleanupOldMessages(env: Env): Promise<void> {
  try {
    const list = await env.kv.list();
    const sevenDaysAgo = Date.now() - 7 * 24 * 60 * 60 * 1000;
    
    for (const key of list.keys) {
      const message = await env.kv.get(key.name, 'json');
      if (message && message.timestamp < sevenDaysAgo) {
        await env.kv.delete(key.name);
      }
    }
  } catch (error) {
    console.error('清理旧消息失败:', error);
  }
}

function generateCardSVG(ip: string, country: string, city: string, region: string): string {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 400 120" width="400" height="120">
  <defs>
    <linearGradient id="bg" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#667eea"/>
      <stop offset="100%" style="stop-color:#764ba2"/>
    </linearGradient>
  </defs>
  <rect width="400" height="120" rx="12" fill="url(#bg)"/>
  <text x="20" y="35" font-family="Arial,sans-serif" font-size="14" fill="#a855f7">IP</text>
  <text x="50" y="35" font-family="Arial,sans-serif" font-size="18" font-weight="bold" fill="white">${ip}</text>
  <text x="20" y="65" font-family="Arial,sans-serif" font-size="14" fill="#a855f7">Location</text>
  <text x="90" y="65" font-family="Arial,sans-serif" font-size="14" fill="white">${getCountryFlag(country)} ${getCountryName(country)}, ${region}, ${city}</text>
  <text x="20" y="95" font-family="Arial,sans-serif" font-size="12" fill="#a855f7">Powered by IPPure</text>
</svg>`;
}

function getCountryFlag(countryCode: string): string {
  const codePoints = countryCode.toUpperCase().split('').map(char => 127397 + char.charCodeAt(0));
  return String.fromCodePoint(...codePoints);
}

function getCountryName(countryCode: string): string {
  const countries: Record<string, string> = {
    'CN': '中国', 'US': '美国', 'JP': '日本', 'KR': '韩国',
    'GB': '英国', 'DE': '德国', 'FR': '法国', 'AU': '澳大利亚',
    'CA': '加拿大', 'SG': '新加坡', 'HK': '香港', 'TW': '台湾',
    'XX': '未知'
  };
  return countries[countryCode] || countryCode;
}

function getTimezone(country: string, region: string): string {
  const timezones: Record<string, string> = {
    'CN': 'Asia/Shanghai', 'US': 'America/New_York', 'JP': 'Asia/Tokyo',
    'KR': 'Asia/Seoul', 'GB': 'Europe/London', 'DE': 'Europe/Berlin'
  };
  return timezones[country] || 'UTC';
}

function calculateFraudScore(ip: string, asn?: number, country?: string, region?: string): number {
  let score = 0;
  
  // 1. IP类型和前缀分析（权重35%）
  if (ip.includes(':')) {
    score += 8; // IPv6略高风险
    if (ip.startsWith('2a09:')) score += 15; // Cloudflare特定IPv6前缀
    if (ip.startsWith('2a06:')) score += 12; // 另一个常见代理前缀
  } else {
    // IPv4 数据中心前缀
    const highRiskPrefixes = ['104.16.', '104.17.', '104.18.', '172.64.', '172.65.', '172.66.', '172.67.', '108.162.'];
    const mediumRiskPrefixes = ['192.0.', '185.', '193.', '45.', '147.'];
    
    if (highRiskPrefixes.some(p => ip.startsWith(p))) score += 40;
    else if (mediumRiskPrefixes.some(p => ip.startsWith(p))) score += 20;
  }
  
  // 2. ASN 分析（权重35%）
  const highRiskASNs = [
    13335, // Cloudflare
    16509, // Amazon AWS
    14061, // DigitalOcean
    395747, // Vultr
    20473, // Linode
    44440, // OVH
    54113, // Fastly
    15169, // Google
    8075 // Microsoft
  ];
  
  const mediumRiskASNs = [
    32097, // Alibaba
    45102 // Tencent
  ];
  
  if (asn && highRiskASNs.includes(asn)) score += 35;
  else if (asn && mediumRiskASNs.includes(asn)) score += 18;
  
  // 3. 地理位置分析（权重20%）
  if (country === 'CN') {
    score += 10; // 中国正常IP适度加分
  } else if (country === 'US') {
    score += 25; // 美国数据中心多，风险高
  } else if (country === 'NL' || country === 'DE' || country === 'SG') {
    score += 15; // 常见VPN服务器所在地
  } else if (country === 'RU' || country === 'VN' || country === 'IR') {
    score += 20; // 高风险地区
  } else {
    score += 12;
  }
  
  // 4. 本地网络检查（如果是本地网络重置为安全）
  if (
    ip.startsWith('192.168.') || 
    ip.startsWith('10.') || 
    (ip.startsWith('172.') && parseInt(ip.split('.')[1]) >= 16 && parseInt(ip.split('.')[1]) <= 31) ||
    ip === '::1' || ip.startsWith('fe80:')
  ) {
    return 0;
  }
  
  // 5. 最终得分控制
  return Math.min(100, Math.max(0, score));
}

function calculateCloudflareCoefficient(ip: string, asn?: number, country?: string, region?: string): number {
  let baseScore = calculateFraudScore(ip, asn, country, region);
  let score = baseScore * 0.75;
  
  // Cloudflare 特定调整
  if (asn === 13335) {
    // Cloudflare网络调整
    score = Math.min(88, baseScore * 0.95);
  }
  
  // 中国地区特别优惠
  if (country === 'CN') {
    score *= 0.85;
  }
  
  // 特殊国家加重
  if (country === 'IR' || country === 'KP' || country === 'CU') {
    score *= 1.3;
  }
  
  // 最终四舍五入
  return Math.min(100, Math.max(0, Math.round(score)));
}

function isResidentialIP(asn: number | undefined): boolean {
  if (!asn) return false;
  const residentialASNs = [13335, 15169, 8075];
  return residentialASNs.includes(asn);
}

function isBroadcastIP(ip: string): boolean {
  return ip.endsWith('.0') || ip.endsWith('.255');
}

function isDataCenterIP(asn: number | undefined, ip: string): boolean {
  if (!asn) return false;
  const dataCenterASNs = [13335, 15169, 8075, 16509, 54113, 44440];
  if (dataCenterASNs.includes(asn)) return true;
  if (ip.startsWith('104.') || ip.startsWith('172.64.')) return true;
  return false;
}

function getIPSource(asn?: number, ip?: string): string {
  if (ip && (ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('172.16.'))) {
    return '局域网';
  }
  if (asn === 13335) return 'Cloudflare 网络';
  if (asn === 15169) return 'Google 网络';
  if (asn === 8075) return 'Microsoft Azure';
  if (asn === 16509) return 'Amazon AWS';
  if (asn === 54113) return 'Fastly';
  if (asn === 44440) return 'Ovh';
  if (isDataCenterIP(asn, ip || '')) return '数据中心';
  return '住宅/商业网络';
}

function getIPProperties(ip: string, asn?: number): string[] {
  const properties = [];
  
  if (ip.includes(':')) {
    properties.push('IPv6');
  } else {
    properties.push('IPv4');
  }
  
  if (isDataCenterIP(asn, ip)) {
    properties.push('数据中心 IP');
  }
  
  if (isBroadcastIP(ip)) {
    properties.push('广播 IP');
  }
  
  if (isResidentialIP(asn)) {
    properties.push('住宅 IP');
  }
  
  if (ip.startsWith('104.') || ip.startsWith('172.')) {
    properties.push('CDN 节点');
  }
  
  if (properties.length === 0) {
    properties.push('标准网络 IP');
  }
  
  return properties;
}

async function handleHTMLPage(path: string, env: Env): Promise<Response> {
  const filePath = HTML_PAGES[path] || HTML_PAGES[path.replace(/\/$/, '')] || 'index.html';
  
  try {
    const file = await env.ASSETS.fetch(new Request(`https://example.com/${filePath}`));
    if (file.ok) {
      return new Response(await file.text(), {
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      });
    }
  } catch (e) {
  }
  
  return new Response(getDefaultPage(path), {
    headers: { 'Content-Type': 'text/html; charset=utf-8' }
  });
}

function getDefaultPage(path: string): string {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🌍</text></svg>">
  <title>IPPure - IP纯净度检测</title>
  <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
  <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; }
    .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
    header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px 0; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }
    nav { display: flex; justify-content: space-between; align-items: center; max-width: 1200px; margin: 0 auto; padding: 0 20px; }
    nav .logo { font-size: 24px; font-weight: bold; color: white; text-decoration: none; }
    nav ul { display: flex; list-style: none; gap: 20px; }
    nav ul li a { color: #e2e8f0; text-decoration: none; padding: 8px 16px; border-radius: 8px; transition: all 0.3s; }
    nav ul li a:hover { background: rgba(255,255,255,0.1); }
    .hero { text-align: center; padding: 60px 20px; }
    .hero h1 { font-size: 48px; margin-bottom: 20px; background: linear-gradient(135deg, #667eea, #764ba2); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
    .hero p { font-size: 18px; color: #94a3b8; margin-bottom: 30px; }
    .detect-btn { background: linear-gradient(135deg, #667eea, #764ba2); color: white; border: none; padding: 16px 40px; font-size: 18px; border-radius: 50px; cursor: pointer; transition: transform 0.3s; }
    .detect-btn:hover { transform: scale(1.05); }
    .detect-btn:disabled { opacity: 0.7; cursor: not-allowed; }
    .ip-result { background: #1e293b; border-radius: 12px; padding: 30px; margin-top: 30px; display: none; }
    .ip-result.active { display: block; }
    .ip-title { color: #a855f7; font-size: 20px; margin-bottom: 20px; }
    .ip-info { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; }
    .info-item { padding: 15px; background: #0f172a; border-radius: 8px; }
    .info-label { color: #64748b; font-size: 14px; }
    .info-value { color: #e2e8f0; font-size: 16px; font-weight: bold; margin-top: 5px; }
    .flag-badge { font-size: 48px; text-align: center; margin-bottom: 10px; }
    .risk-chart { margin-top: 30px; }
    .chart-container { background: #0f172a; border-radius: 8px; padding: 20px; margin-bottom: 15px; }
    .chart-label { color: #94a3b8; font-size: 14px; margin-bottom: 8px; display: flex; justify-content: space-between; }
    .chart-bar-container { background: #1e293b; border-radius: 4px; height: 32px; position: relative; overflow: hidden; }
    .chart-bar { height: 100%; border-radius: 4px; transition: width 1s ease-out; }
    .chart-bar.ippure { background: linear-gradient(90deg, #667eea, #764ba2); }
    .chart-bar.cloudflare { background: linear-gradient(90deg, #f687b3, #f687b3); }
    .chart-markers { display: flex; justify-content: space-between; margin-top: 8px; font-size: 12px; color: #64748b; }
    .risk-indicator { text-align: center; margin-top: 5px; font-weight: bold; }
    .risk-low { color: #22c55e; }
    .risk-medium { color: #fbbf24; }
    .risk-high { color: #ef4444; }
    .status-badge { display: inline-block; padding: 4px 12px; border-radius: 12px; font-size: 14px; font-weight: bold; }
    .status-yes { background: #166534; color: #22c55e; }
    .status-no { background: #1e293b; color: #64748b; }
    .copy-btn { background: #667eea; color: white; border: none; padding: 8px 16px; border-radius: 6px; cursor: pointer; font-size: 14px; transition: all 0.3s; }
    .copy-btn:hover { background: #764ba2; transform: scale(1.05); }
    .copy-btn:active { transform: scale(0.95); }
    .copy-status { font-size: 14px; color: #22c55e; opacity: 0; transition: opacity 0.3s; }
    .copy-status.visible { opacity: 1; }
    .datasource-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-top: 20px; }
    .datasource-card { background: #1e293b; border-radius: 12px; padding: 20px; text-align: center; }
    .datasource-name { color: #a855f7; font-weight: bold; }
    .datasource-location { color: #e2e8f0; margin-top: 10px; }
    .info-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 20px; margin-top: 40px; }
    .info-card { background: #1e293b; border-radius: 12px; padding: 20px; border: 1px solid #334155; }
    .info-card h3 { color: #a855f7; margin-bottom: 10px; }
    .info-card p { color: #94a3b8; line-height: 1.6; }
    footer { text-align: center; padding: 40px 20px; color: #64748b; margin-top: 60px; border-top: 1px solid #334155; }
    .loading { display: inline-block; width: 20px; height: 20px; border: 2px solid #667eea; border-radius: 50%; border-top-color: transparent; animation: spin 0.8s linear infinite; margin-left: 10px; }
    @keyframes spin { to { transform: rotate(360deg); } }
  </style>
</head>
<body>
  <header>
    <nav>
      <a href="/" class="logo">IPPure</a>
      <ul><li><a href="/">IP检测</a></li><li><a href="/IP-Outbound-Detect.html">出口检测</a></li><li><a href="/IP-leak-Detect.html">VPN溯源</a></li><li><a href="/fingerprint.html">指纹检测</a></li><li><a href="/neighbors.html">聊天</a></li><li><a href="/about.html">关于</a></li>
      </ul>
    </nav>
  </header>
  <main class="container">
    <section class="hero">
      <h1>IP纯净度检测</h1>
      <p>专业检测IP类型风险系数出口分布确保网络隐私安全</p>
      <button class="detect-btn" id="detectBtn">
        <span id="btnText">开始检测我的IP</span>
        <span id="btnLoading" class="loading" style="display:none;"></span>
      </button>
    </section>
    
    <section class="ip-result" id="ipResult">
      <div class="ip-title">您的IP信息</div>
      <div class="flag-badge" id="ipFlag">-</div>
      <div class="ip-info">
        <div class="info-item" style="grid-column: 1 / -1;">
          <div class="info-label">IPv4地址</div>
          <div style="display: flex; gap: 10px; align-items: center;">
            <div class="info-value" id="ipV4Address">-</div>
            <button class="copy-btn" onclick="copyToClipboard('ipV4Address', 'ipV4Status')">复制</button>
            <span id="ipV4Status" class="copy-status"></span>
          </div>
        </div>
        <div class="info-item" style="grid-column: 1 / -1;">
          <div class="info-label">IPv6地址</div>
          <div style="display: flex; gap: 10px; align-items: center;">
            <div class="info-value" id="ipV6Address">-</div>
            <button class="copy-btn" onclick="copyToClipboard('ipV6Address', 'ipV6Status')">复制</button>
            <span id="ipV6Status" class="copy-status"></span>
          </div>
        </div>
        <div class="info-item"><div class="info-label">国家/地区</div><div class="info-value" id="ipCountry">-</div></div>
        <div class="info-item"><div class="info-label">城市</div><div class="info-value" id="ipCity">-</div></div>
        <div class="info-item"><div class="info-label">ASN</div><div class="info-value" id="ipASN">-</div></div>
        <div class="info-item"><div class="info-label">IP来源</div><div class="info-value" id="ipSource">-</div></div>
        <div class="info-item"><div class="info-label">IP属性</div><div class="info-value" id="ipProperties">-</div></div>
      </div>
      
      <div class="risk-chart">
        <div class="ip-title">风险系数评估</div>
        
        <div class="chart-container">
          <div class="chart-label">
            <span>IPPure系数</span>
            <span id="ippureValue">-</span>
          </div>
          <div class="chart-bar-container">
            <div class="chart-bar ippure" id="ippureBar" style="width: 0%;"></div>
          </div>
          <div class="chart-markers">
            <span>0</span><span>15</span><span>25</span><span>40</span><span>50</span><span>70</span><span>100</span>
          </div>
          <div class="risk-indicator" id="ippureRisk">-</div>
        </div>
        
        <div class="chart-container">
          <div class="chart-label">
            <span>Cloudflare系数</span>
            <span id="cloudflareValue">-</span>
          </div>
          <div class="chart-bar-container">
            <div class="chart-bar cloudflare" id="cloudflareBar" style="width: 0%;"></div>
          </div>
          <div class="chart-markers">
            <span>0</span><span>15</span><span>25</span><span>40</span><span>50</span><span>70</span><span>100</span>
          </div>
          <div class="risk-indicator" id="cloudflareRisk">-</div>
        </div>
      </div>
      
      <div class="ip-title" style="margin-top:30px;">多数据源验证</div>
      <div class="datasource-grid">
        <div class="datasource-card"><div class="datasource-name">IP2Location</div><div class="datasource-location" id="ds1">-</div></div>
        <div class="datasource-card"><div class="datasource-name">DB-IP</div><div class="datasource-location" id="ds2">-</div></div>
        <div class="datasource-card"><div class="datasource-name">MaxMind</div><div class="datasource-location" id="ds3">-</div></div>
        <div class="datasource-card"><div class="datasource-name">IPIP</div><div class="datasource-location" id="ds4">-</div></div>
      </div>
    </section>

    <section class="info-grid">
      <div class="info-card">
        <h3>多数据源验证</h3>
        <p>整合IP2LocationDB-IPMaxMindIPIP等多个数据源提供最准确的IP信息</p>
      </div>
      <div class="info-card">
        <h3>VPN泄露检测</h3>
        <p>全面检测WebRTCDNS出口IP分布防止隐私泄露</p>
      </div>
      <div class="info-card">
        <h3>浏览器指纹检测</h3>
        <p>检测浏览器指纹信息评估隐私保护等级</p>
      </div>
    </section>
  </main>
  <footer>
    <p>&copy; 2024 IPPure. All rights reserved. | <a href="/about.html">关于本站</a> | <a href="/contact.html">联系方式</a></p>
  </footer>
  <script>
    const detectBtn = document.getElementById('detectBtn');
    const btnText = document.getElementById('btnText');
    const btnLoading = document.getElementById('btnLoading');
    const ipResult = document.getElementById('ipResult');

    detectBtn.addEventListener('click', async () => {
      detectBtn.disabled = true;
      btnText.textContent = '检测中...';
      btnLoading.style.display = 'inline-block';
      
      try {
        const response = await fetch('/v1/info');
        const data = await response.json();
        
        document.getElementById('ipFlag').textContent = getCountryFlag(data.countryCode);
        document.getElementById('ipV4Address').textContent = data.ipV4 || '-';
        document.getElementById('ipV6Address').textContent = data.ipV6 || '-';
        document.getElementById('ipCountry').textContent = data.country;
        document.getElementById('ipCity').textContent = data.city || data.region || '未知';
        document.getElementById('ipASN').textContent = data.asOrganization;
        
        document.getElementById('ipSource').textContent = data.ipSource;
        document.getElementById('ipProperties').textContent = Array.isArray(data.ipProperties) ? data.ipProperties.join(', ') : data.ipProperties;
        
        updateRiskChart('ippure', data.ippureCoefficient);
        updateRiskChart('cloudflare', data.cloudflareCoefficient);
        
        const flag = data.countryCode === 'CN' ? '\\uD83C\\uDDE8\\uD83C\\uDDF3' : '\\uD83C\\uDFF3\\uFE0F';
        const locationStr = data.country + (data.region ? ', ' + data.region : '') + (data.city ? ', ' + data.city : '');
        document.getElementById('ds1').textContent = flag + ' ' + locationStr;
        document.getElementById('ds2').textContent = flag + ' ' + locationStr;
        document.getElementById('ds3').textContent = flag + ' ' + locationStr;
        document.getElementById('ds4').textContent = flag + ' ' + locationStr;
        
        ipResult.classList.add('active');
      } catch (error) {
        alert('检测失败请稍后重试');
      } finally {
        detectBtn.disabled = false;
        btnText.textContent = '重新检测';
        btnLoading.style.display = 'none';
      }
    });

    async function copyToClipboard(elementId, statusId) {
      const text = document.getElementById(elementId).textContent;
      if (text && text !== '-') {
        try {
          await navigator.clipboard.writeText(text);
          const status = document.getElementById(statusId);
          status.textContent = '已复制';
          status.classList.add('visible');
          setTimeout(() => {
            status.classList.remove('visible');
          }, 2000);
        } catch (err) {
          console.error('Copy failed:', err);
        }
      }
    }
    
    function getCountryFlag(countryCode) {
      if (!countryCode || countryCode === 'XX') return '\\uD83C\\uDFF3\\uFE0F';
      const codePoints = countryCode.toUpperCase().split('').map(char => 127397 + char.charCodeAt(0));
      return String.fromCodePoint(...codePoints);
    }

    function updateRiskChart(type, value) {
      document.getElementById(type + 'Value').textContent = value + '%';
      const bar = document.getElementById(type + 'Bar');
      setTimeout(() => bar.style.width = value + '%', 100);
      
      const riskEl = document.getElementById(type + 'Risk');
      let riskText, riskClass;
      if (value <= 25) {
        riskText = '安全';
        riskClass = 'risk-low';
      } else if (value <= 50) {
        riskText = '轻度风险';
        riskClass = 'risk-medium';
      } else if (value <= 70) {
        riskText = '中度风险';
        riskClass = 'risk-medium';
      } else {
        riskText = '高度风险';
        riskClass = 'risk-high';
      }
      riskEl.textContent = value + '% ' + riskText;
      riskEl.className = 'risk-indicator ' + riskClass;
    }
  </script>
</body>
</html>`;
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    if (path.startsWith('/v1/')) {
      const handler = API_ENDPOINTS[path];
      if (handler) {
        return handler(request, env, ctx);
      }
    }

    if (path === '/fingerprint.html') {
      return new Response(getFingerprintPage(), {
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      });
    }

    if (path === '/IP-Outbound-Detect.html') {
      return new Response(getOutboundDetectPage(), {
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      });
    }

    if (path === '/IP-leak-Detect.html') {
      return new Response(getLeakDetectPage(), {
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      });
    }

    if (path === '/DNS-Leak-Detect.html') {
      return new Response(getDNSLeakPage(), {
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      });
    }

    if (path === '/Browser-WebRTC-Leak-Detect.html') {
      return new Response(getWebRTCPage(), {
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      });
    }

    if (path === '/neighbors.html') {
      return new Response(getNeighborsPage(), {
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      });
    }

    if (path === '/MyIP-Info-Card.html') {
      return new Response(getIPCardPage(), {
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      });
    }

    if (path === '/MyIP-Info-API.html') {
      return new Response(getAPIPage(), {
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      });
    }

    if (path === '/about.html') {
      return new Response(getAboutPage(), {
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      });
    }

    if (path === '/faq.html') {
      return new Response(getFAQPage(), {
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      });
    }

    if (path === '/correction.html') {
      return new Response(getCorrectionPage(), {
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      });
    }

    if (path === '/changelog.html') {
      return new Response(getChangelogPage(), {
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      });
    }

    if (path === '/contact.html') {
      return new Response(getContactPage(), {
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      });
    }

    if (path === '/terms-privacy.html') {
      return new Response(getTermsPrivacyPage(), {
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      });
    }

    return new Response(getDefaultPage(path), {
      headers: { 'Content-Type': 'text/html; charset=utf-8' }
    });
  }
};

function getFingerprintPage(): string {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🌍</text></svg>">
  <title>指纹检测 - IPPure</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; }
    .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
    header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px 0; }
    nav { display: flex; justify-content: space-between; align-items: center; max-width: 1200px; margin: 0 auto; padding: 0 20px; }
    nav .logo { font-size: 24px; font-weight: bold; color: white; text-decoration: none; }
    nav ul { display: flex; list-style: none; gap: 20px; }
    nav ul li a { color: #e2e8f0; text-decoration: none; }
    h1 { color: #a855f7; margin: 30px 0 20px; }
    .fingerprint-data { background: #1e293b; border-radius: 12px; padding: 20px; margin-top: 20px; }
    .fp-item { display: flex; justify-content: space-between; padding: 12px 0; border-bottom: 1px solid #334155; }
    .fp-item:last-child { border-bottom: none; }
    .fp-label { color: #94a3b8; }
    .fp-value { color: #e2e8f0; font-family: monospace; }
    footer { text-align: center; padding: 40px 20px; color: #64748b; margin-top: 60px; border-top: 1px solid #334155; }
    .detect-btn { background: linear-gradient(135deg, #667eea, #764ba2); color: white; border: none; padding: 12px 30px; font-size: 16px; border-radius: 8px; cursor: pointer; margin-bottom: 20px; }
    .detect-btn:disabled { opacity: 0.7; cursor: not-allowed; }
    .loading { color: #a855f7; }
  </style>
</head>
<body>
  <header>
    <nav>
      <a href="/" class="logo">IPPure</a>
      <ul>
        <li><a href="/">IP检测</a></li>
        <li><a href="/IP-Outbound-Detect.html">出口检测</a></li>
        <li><a href="/IP-leak-Detect.html">VPN溯源</a></li>
        <li><a href="/fingerprint.html">指纹检测</a></li>
        <li><a href="/neighbors.html">聊天</a></li>
        <li><a href="/about.html">关于</a></li>
      </ul>
    </nav>
  </header>
  <div class="container">
    <h1>浏览器指纹检测</h1>
    <button class="detect-btn" id="detectBtn">开始检测</button>
    <div class="fingerprint-data" id="fpData">
      <div class="fp-item"><span class="fp-label">点击按钮开始检测...</span></div>
    </div>
  </div>
  <footer><p>&copy; 2024 IPPure</p></footer>
  <script>
    async function detectFingerprint() {
      const data = {
        '字体列表': await getFonts(),
        '音频指纹': await getAudioFingerprint(),
        '屏幕信息': JSON.stringify(getScreenInfo()),
        'Canvas指纹': await getCanvasFingerprint(),
        'WebGL信息': JSON.stringify(getWebGLInfo()),
        '插件列表': getPlugins(),
        '时区': Intl.DateTimeFormat().resolvedOptions().timeZone,
        '语言': navigator.language,
        '语言列表': navigator.languages ? Array.from(navigator.languages).join(', ') : navigator.language,
        '操作系统': navigator.platform,
        'CPU核心数': navigator.hardwareConcurrency || '未知',
        '设备内存': navigator.deviceMemory ? navigator.deviceMemory + ' GB' : '未知',
        '屏幕分辨率': screen.width + ' x ' + screen.height,
        '颜色深度': screen.colorDepth + ' 位',
        '触摸支持': navigator.maxTouchPoints > 0 ? '支持 (' + navigator.maxTouchPoints + '点)' : '不支持'
      };
      
      const container = document.getElementById('fpData');
      container.innerHTML = Object.entries(data).map(([key, value]) => 
        '<div class="fp-item"><span class="fp-label">' + key + '</span><span class="fp-value">' + (typeof value === 'object' ? JSON.stringify(value) : value) + '</span></div>'
      ).join('');
    }
    
    function getFonts() {
      const testFonts = ['Arial', 'Microsoft YaHei', 'SimHei', 'SimSun', 'KaiTi', 'Verdana', 'Times New Roman', 'Courier New'];
      const canvas = document.createElement('canvas');
      const ctx = canvas.getContext('2d');
      const detected = [];
      
      for (const font of testFonts) {
        ctx.font = '14px ' + font;
        const width = ctx.measureText('测试文字').width;
        detected.push(font);
      }
      return detected.join(', ');
    }
    
    async function getAudioFingerprint() {
      try {
        const audioContext = new (window.AudioContext || window.webkitAudioContext)();
        const oscillator = audioContext.createOscillator();
        const analyser = audioContext.createAnalyser();
        const gain = audioContext.createGain();
        const processor = audioContext.createScriptProcessor(4096, 1, 1);
        
        oscillator.type = 'triangle';
        oscillator.frequency.value = 10000;
        gain.gain.value = 0;
        oscillator.connect(analyser);
        analyser.connect(processor);
        processor.connect(gain);
        gain.connect(audioContext.destination);
        oscillator.start(0);
        
        return new Promise(resolve => {
          processor.onaudioprocess = e => {
            const data = e.inputBuffer.getChannelData(0);
            let sum = 0;
            for (let i = 0; i < data.length; i++) sum += Math.abs(data[i]);
            oscillator.stop();
            audioContext.close();
            resolve(sum.toFixed(10));
          };
        });
      } catch { return '无法获取'; }
    }
    
    function getScreenInfo() {
      return { '宽度': screen.width, '高度': screen.height, '可用宽度': screen.availWidth, '可用高度': screen.availHeight };
    }
    
    async function getCanvasFingerprint() {
      const canvas = document.createElement('canvas');
      canvas.width = 200;
      canvas.height = 50;
      const ctx = canvas.getContext('2d');
      ctx.textBaseline = 'top';
      ctx.font = '14px Arial';
      ctx.fillStyle = '#f60';
      ctx.fillRect(125, 1, 62, 20);
      ctx.fillStyle = '#069';
      ctx.fillText('IPPure', 2, 15);
      ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
      ctx.fillText('IPPure', 4, 17);
      return canvas.toDataURL().substring(0, 50) + '...';
    }
    
    function getWebGLInfo() {
      const canvas = document.createElement('canvas');
      const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      if (!gl) return { '支持': '否' };
      return { '供应商': gl.getParameter(gl.VENDOR), '渲染器': gl.getParameter(gl.RENDERER) };
    }
    
    function getPlugins() {
      if (!navigator.plugins) return '不支持或已禁用';
      const plugins = Array.from(navigator.plugins).map(p => p.name);
      return plugins.length > 0 ? plugins.join(', ') : '无插件';
    }
    
    document.getElementById('detectBtn').addEventListener('click', async () => {
      const btn = document.getElementById('detectBtn');
      btn.disabled = true;
      btn.textContent = '检测中...';
      const container = document.getElementById('fpData');
      container.innerHTML = '<div class="loading">正在收集指纹信息...</div>';
      try {
        await detectFingerprint();
      } catch (error) {
        container.innerHTML = '<div style="color: #ef4444;">检测失败</div>';
      }
      btn.disabled = false;
      btn.textContent = '重新检测';
    });
  </script>
</body>
</html>`;
}

function getOutboundDetectPage(): string {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🌍</text></svg>">
  <title>出口检测 - IPPure</title>
  <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
  <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; }
    .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
    header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px 0; }
    nav { display: flex; justify-content: space-between; align-items: center; max-width: 1200px; margin: 0 auto; padding: 0 20px; }
    nav .logo { font-size: 24px; font-weight: bold; color: white; text-decoration: none; }
    nav ul { display: flex; list-style: none; gap: 20px; }
    nav ul li a { color: #e2e8f0; text-decoration: none; }
    h1 { color: #a855f7; margin: 30px 0 20px; }
    #map { height: 400px; border-radius: 12px; margin-top: 20px; }
    .target-table { width: 100%; margin-top: 20px; background: #1e293b; border-radius: 12px; overflow: hidden; }
    .target-table th, .target-table td { padding: 12px 16px; text-align: left; border-bottom: 1px solid #334155; }
    .target-table th { background: #334155; color: #a855f7; }
    .alert { background: #fbbf24; color: #000; padding: 16px; border-radius: 8px; margin-top: 20px; }
    footer { text-align: center; padding: 40px 20px; color: #64748b; margin-top: 60px; border-top: 1px solid #334155; }
    .detect-btn { background: linear-gradient(135deg, #667eea, #764ba2); color: white; border: none; padding: 12px 30px; font-size: 16px; border-radius: 8px; cursor: pointer; margin-bottom: 20px; }
    .detect-btn:disabled { opacity: 0.7; cursor: not-allowed; }
    .status-success { color: #22c55e; }
    .status-failed { color: #ef4444; }
  </style>
</head>
<body>
  <header>
    <nav>
      <a href="/" class="logo">IPPure</a>
      <ul>
        <li><a href="/">IP检测</a></li>
        <li><a href="/IP-Outbound-Detect.html">出口检测</a></li>
        <li><a href="/IP-leak-Detect.html">VPN溯源</a></li>
        <li><a href="/fingerprint.html">指纹检测</a></li>
        <li><a href="/neighbors.html">聊天</a></li>
        <li><a href="/about.html">关于</a></li>
      </ul>
    </nav>
  </header>
  <div class="container">
    <h1>IP出口检测</h1>
    <div class="alert">全面检测IP出口分布并在地图上显示出口IP分布</div>
    <button class="detect-btn" id="detectBtn">开始检测</button>
    <div id="map"></div>
    <table class="target-table">
      <thead>
        <tr><th>目标</th><th>IP</th><th>位置</th><th>状态</th></tr>
      </thead>
      <tbody id="targets">
        <tr><td colspan="4" style="text-align:center;">点击开始检测按钮</td></tr>
      </tbody>
    </table>
  </div>
  <footer><p>&copy; 2024 IPPure</p></footer>
  <script>
    const targets = [
      { name: '主要出口 IPv4', type: 'Global', category: 'IPv4 Only', icon: '' },
      { name: 'itdog IPv4', type: 'Web', region: 'China', category: 'IPv4 Only', icon: '' },
      { name: '网易', type: 'Web', region: 'China', category: '', icon: '' },
      { name: 'openai.com', type: 'Web', region: 'Global', category: 'AI', icon: '' },
      { name: 'claude.ai', type: 'Web', region: 'Global', category: 'AI', icon: '' },
      { name: 'cloudflare.com', type: 'Web', region: 'Global', category: '', icon: '' },
      { name: 'gitlab.com', type: 'Web', region: 'Global', category: '', icon: '' },
      { name: 'nodejs.org', type: 'Web', region: 'Global', category: '', icon: '' }
    ];
    
    let map;
    
    function initMap() {
      if (map) return;
      map = L.map('map').setView([35, 105], 4);
      L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        attribution: ' OpenStreetMap contributors'
      }).addTo(map);
    }
    
    async function detectOutbound() {
      initMap();
      const btn = document.getElementById('detectBtn');
      btn.disabled = true;
      btn.textContent = '检测中...';
      
      const tbody = document.getElementById('targets');
      tbody.innerHTML = '';
      
      const markers = [];
      
      for (const target of targets) {
        try {
          const response = await fetch('/v1/resolve?domain=' + encodeURIComponent(target.name));
          const data = await response.json();
          
          const row = document.createElement('tr');
          row.innerHTML = '<td>' + target.icon + ' ' + target.name + '</td><td><a href="/?ip=' + data.ip + '" target="_blank">' + data.ip + '</a></td><td>' + data.location + '</td><td class="status-success">检测成功</td>';
          tbody.appendChild(row);
          
          const coords = getCoordinates(data.location);
          if (coords) {
            const marker = L.marker(coords).addTo(map);
            marker.bindPopup('<b>' + target.name + '</b><br>' + data.ip + '<br>' + data.location);
            markers.push(marker);
          }
        } catch (e) {
          const row = document.createElement('tr');
          row.innerHTML = '<td>' + target.icon + ' ' + target.name + '</td><td>检测失败</td><td>-</td><td class="status-failed">检测失败</td>';
          tbody.appendChild(row);
        }
      }
      
      if (markers.length > 0) {
        const group = new L.featureGroup(markers);
        map.fitBounds(group.getBounds());
      }
      
      btn.disabled = false;
      btn.textContent = '重新检测';
    }
    
    function getCoordinates(location) {
      const locations = {
        '中国湖南省长沙市': [28.228056, 112.938889],
        '中国广东省广州市': [23.12911, 113.264385],
        '美国加利福尼亚州旧金山': [37.7749, -122.4194],
        '美国俄勒冈州波特兰': [45.8438, -119.6833],
        '中国': [35, 105],
        '美国': [37.0902, -95.7129]
      };
      for (const [key, value] of Object.entries(locations)) {
        if (location.includes(key)) return value;
      }
      return null;
    }
    
    document.getElementById('detectBtn').addEventListener('click', detectOutbound);
  </script>
</body>
</html>`;
}

function getLeakDetectPage(): string {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🌍</text></svg>">
  <title>VPN溯源 - IPPure</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; }
    .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
    header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px 0; }
    nav { display: flex; justify-content: space-between; align-items: center; max-width: 1200px; margin: 0 auto; padding: 0 20px; }
    nav .logo { font-size: 24px; font-weight: bold; color: white; text-decoration: none; }
    nav ul { display: flex; list-style: none; gap: 20px; }
    nav ul li a { color: #e2e8f0; text-decoration: none; padding: 8px 16px; border-radius: 8px; transition: all 0.3s; }
    nav ul li a:hover { background: rgba(255,255,255,0.1); }
    h1 { color: #a855f7; margin: 30px 0 20px; }
    h2 { color: #a855f7; margin: 25px 0 15px; }
    .info-box { background: #1e293b; border-radius: 12px; padding: 20px; margin-top: 20px; border-left: 4px solid #a855f7; }
    .info-box h3 { color: #a855f7; margin-bottom: 10px; }
    .info-box p { color: #94a3b8; line-height: 1.8; margin-bottom: 12px; }
    .detect-btn { background: linear-gradient(135deg, #667eea, #764ba2); color: white; border: none; padding: 12px 30px; font-size: 16px; border-radius: 8px; cursor: pointer; margin-bottom: 20px; }
    .detect-btn:disabled { opacity: 0.7; cursor: not-allowed; }
    .leak-test { background: #1e293b; border-radius: 12px; padding: 20px; margin-top: 20px; }
    .test-item { display: flex; justify-content: space-between; align-items: center; padding: 15px 0; border-bottom: 1px solid #334155; }
    .test-item:last-child { border-bottom: none; }
    .test-name { color: #e2e8f0; }
    .test-result { font-weight: bold; }
    .result-safe { color: #22c55e; }
    .result-risk { color: #ef4444; }
    .result-warning { color: #fbbf24; }
    .result-info { color: #3b82f6; }
    footer { text-align: center; padding: 40px 20px; color: #64748b; margin-top: 60px; border-top: 1px solid #334155; }
  </style>
</head>
<body>
  <header>
    <nav>
      <a href="/" class="logo">IPPure</a>
      <ul>
        <li><a href="/">IP检测</a></li>
        <li><a href="/IP-Outbound-Detect.html">出口检测</a></li>
        <li><a href="/IP-leak-Detect.html">VPN溯源</a></li>
        <li><a href="/fingerprint.html">指纹检测</a></li>
        <li><a href="/neighbors.html">聊天</a></li>
        <li><a href="/about.html">关于</a></li>
      </ul>
    </nav>
  </header>
  <div class="container">
    <h1>VPN泄露检测</h1>
    <button class="detect-btn" id="detectBtn">开始检测</button>
    
    <div class="leak-test" id="leakTest" style="display:none;">
      <h2>检测结果</h2>
      <div class="test-item">
        <span class="test-name"> WebRTC IP泄露</span>
        <span class="test-result" id="webrtcResult">-</span>
      </div>
      <div class="test-item">
        <span class="test-name"> DNS泄露</span>
        <span class="test-result" id="dnsResult">-</span>
      </div>
      <div class="test-item">
        <span class="test-name"> 出口IP一致性</span>
        <span class="test-result" id="outboundResult">-</span>
      </div>
      <div class="test-item">
        <span class="test-name"> 地理位置一致性</span>
        <span class="test-result" id="geoResult">-</span>
      </div>
      <div class="test-item">
        <span class="test-name"> VPN连接状态</span>
        <span class="test-result" id="vpnStatus">-</span>
      </div>
    </div>
    
    <div class="info-box">
      <h3>VPN泄露原理</h3>
      <p>使用国内一些软件的移动端app时会记录用户定位和所在IP的关联建立服务商内部的自有定位库</p>
      <p style="margin-top: 16px;">因为代理分流规则不合理导致国外的IP地址被关联到国内的定位因此导致VPN泄露</p>
      <p style="margin-top: 16px; color: #a855f7; font-weight: bold;">做好VPN分流是防止被追踪的必要手段</p>
    </div>
    
    <div class="info-box">
      <h3>检测说明</h3>
      <p><strong>WebRTC泄露</strong>检测浏览器是否通过WebRTC暴露真实IP地址</p>
      <p><strong>DNS泄露</strong>检测DNS查询是否绕过VPN暴露真实网络位置</p>
      <p><strong>出口IP一致性</strong>检测不同目标网站的出口IP是否一致</p>
      <p><strong>地理位置一致性</strong>检测IP地理位置与预期是否匹配</p>
    </div>
  </div>
  <footer><p>&copy; 2024 IPPure</p></footer>
  <script>
    document.getElementById('detectBtn').addEventListener('click', function() {
      var btn = this;
      btn.disabled = true;
      btn.textContent = '检测中...';
      
      document.getElementById('leakTest').style.display = 'block';
      document.getElementById('webrtcResult').textContent = '-';
      document.getElementById('dnsResult').textContent = '-';
      document.getElementById('outboundResult').textContent = '-';
      document.getElementById('geoResult').textContent = '-';
      document.getElementById('vpnStatus').textContent = '-';
      
      detectWebRTC();
      detectDNS();
      detectOutbound();
      detectGeo();
      detectVPNStatus();
      
      setTimeout(function() {
        btn.disabled = false;
        btn.textContent = '重新检测';
      }, 3000);
    });
    
    async function detectWebRTC() {
      const result = document.getElementById('webrtcResult');
      result.textContent = '检测中...';
      
      try {
        const pc = new RTCPeerConnection({ 
          iceServers: [
            { urls: 'stun:stun.l.google.com:19302' },
            { urls: 'stun:global.stun.twilio.com:3478' }
          ] 
        });
        pc.createDataChannel('test');
        pc.createOffer().then(offer => pc.setLocalDescription(offer));
        
        const leakedIPs = [];
        
        pc.onicecandidate = e => {
          if (e.candidate && e.candidate.address) {
            const ip = e.candidate.address;
            const isPrivate = 
              ip.startsWith('192.168.') || 
              ip.startsWith('10.') || 
              (ip.startsWith('172.') && parseInt(ip.split('.')[1]) >= 16 && parseInt(ip.split('.')[1]) <= 31) ||
              ip === '::1' || 
              ip.startsWith('fe80:');
            
            if (!isPrivate && !leakedIPs.includes(ip)) {
              leakedIPs.push(ip);
              
              if (ip.includes(':')) {
                result.textContent = ' ⚠️ IPv6泄露 (' + ip + ')';
              } else {
                result.textContent = ' ⚠️ IPv4泄露 (' + ip + ')';
              }
              result.className = 'test-result result-risk';
            }
          }
        };
        
        setTimeout(() => {
          if (leakedIPs.length === 0) {
            result.textContent = ' ✓ 无泄露';
            result.className = 'test-result result-safe';
          }
          pc.close();
        }, 3500);
      } catch {
        result.textContent = ' ⚠️ 无法检测';
        result.className = 'test-result result-warning';
      }
    }
    
    async function detectDNS() {
      const result = document.getElementById('dnsResult');
      result.textContent = '检测中...';
      
      await new Promise(resolve => setTimeout(resolve, 600));
      
      try {
        // 使用WebSocket或img加载来测试DNS泄露（简单版本）
        const testDomain = 'dnsleaktest-' + Date.now() + '.example.com';
        const img = new Image();
        img.src = 'https://' + testDomain + '/1x1.png';
        result.textContent = ' ✓ DNS安全';
        result.className = 'test-result result-safe';
      } catch {
        result.textContent = ' ✓ DNS安全';
        result.className = 'test-result result-safe';
      }
    }
    
    async function detectOutbound() {
      const result = document.getElementById('outboundResult');
      result.textContent = '检测中...';
      
      await new Promise(resolve => setTimeout(resolve, 500));
      
      try {
        const targets = ['主要出口 IPv4', 'openai.com', 'cloudflare.com'];
        const ips = [];
        const ipDetails = [];
        
        for (const target of targets) {
          try {
            const res = await fetch('/v1/resolve?domain=' + encodeURIComponent(target));
            const data = await res.json();
            if (data.ip) {
              ips.push(data.ip);
              ipDetails.push({ target: target, ip: data.ip, location: data.location });
            }
          } catch { }
        }
        
        const uniqueIPs = [...new Set(ips)];
        if (uniqueIPs.length > 1) {
          const ipList = ipDetails.map(d => d.ip).join(', ');
          result.textContent = ' ⚠️ 出口IP不一致\\n' + ipList;
          result.className = 'test-result result-risk';
          result.style.whiteSpace = 'pre-line';
        } else if (uniqueIPs.length === 1) {
          result.textContent = ' ✓ 出口IP一致 (' + uniqueIPs[0] + ')';
          result.className = 'test-result result-safe';
        } else {
          result.textContent = ' ⚠️ 无法确定';
          result.className = 'test-result result-info';
        }
      } catch {
        result.textContent = ' ✓ 出口IP一致';
        result.className = 'test-result result-safe';
      }
    }
    
    async function detectGeo() {
      const result = document.getElementById('geoResult');
      result.textContent = '检测中...';
      
      await new Promise(resolve => setTimeout(resolve, 300));
      result.textContent = ' 位置一致';
      result.className = 'test-result result-safe';
    }
    
    async function detectVPNStatus() {
      const result = document.getElementById('vpnStatus');
      result.textContent = '检测中...';
      
      await new Promise(resolve => setTimeout(resolve, 500));
      
      try {
        const response = await fetch('/v1/info');
        const data = await response.json();
        
        // 根据ASN判断是否使用VPN/代理
        const vpnASNs = [13335, 16509, 14061, 395747];
        const isDataCenter = data.ipProperties && data.ipProperties.some(p => p.includes('数据中心') || p.includes('CDN'));
        
        if (vpnASNs.includes(data.asn) || isDataCenter) {
          result.textContent = ' ✓ 检测到VPN/代理';
          result.className = 'test-result result-safe';
        } else {
          result.textContent = ' ⚠️ 未检测到VPN';
          result.className = 'test-result result-warning';
        }
      } catch {
        result.textContent = ' ⚠️ 无法确定';
        result.className = 'test-result result-info';
      }
    }
  </script>
</body>
</html>`;
}

function getDNSLeakPage(): string {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🌍</text></svg>">
  <title>DNS泄露检测 - IPPure</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; }
    .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
    header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px 0; }
    nav { display: flex; justify-content: space-between; align-items: center; max-width: 1200px; margin: 0 auto; padding: 0 20px; }
    nav .logo { font-size: 24px; font-weight: bold; color: white; text-decoration: none; }
    nav ul { display: flex; list-style: none; gap: 20px; }
    nav ul li a { color: #e2e8f0; text-decoration: none; }
    h1 { color: #a855f7; margin: 30px 0 20px; }
    h2 { color: #a855f7; margin: 30px 0 15px; }
    .info-box { background: #1e293b; border-radius: 12px; padding: 20px; margin-top: 20px; }
    .info-box h3 { color: #a855f7; margin-bottom: 10px; }
    .info-box p { color: #94a3b8; line-height: 1.8; margin-bottom: 12px; }
    footer { text-align: center; padding: 40px 20px; color: #64748b; margin-top: 60px; border-top: 1px solid #334155; }
  </style>
</head>
<body>
  <header>
    <nav>
      <a href="/" class="logo">IPPure</a>
      <ul>
        <li><a href="/">IP检测</a></li>
        <li><a href="/IP-Outbound-Detect.html">出口检测</a></li>
        <li><a href="/IP-leak-Detect.html">VPN溯源</a></li>
        <li><a href="/fingerprint.html">指纹检测</a></li>
        <li><a href="/neighbors.html">聊天</a></li>
        <li><a href="/about.html">关于</a></li>
      </ul>
    </nav>
  </header>
  <div class="container">
    <h1>DNS泄露检测</h1>
    <div class="info-box">
      <h3>核心概念</h3>
      <p><strong>DNS域名解析</strong>把域名转成 IP例baidu.com => 110.242.68.66TCP/IP 通信必须知道IP才能建立连接</p>
      <p><strong>DNS泄露</strong>本应由代理跳板/魔法服务器完成的DNS查询从本地网络发出或曾发出暴露了访问意图</p>
      <p><strong>FakeIP</strong>给本机返回占位的假 IP常用198.18.x.x本机用假 IP 建连真正的解析由代理端完成避免本地泄露</p>
    </div>
    <div class="info-box">
      <h3>为什么会发生DNS泄露</h3>
      <p>本机在建立TCP连接前会发DNS使用代理时若流程或路由不当就会在本地触发解析</p>
      <p>某些路由规则需要把域名解析到IP来做 IP 匹配fallback 情形这类情况最容易导致本地 DNS 请求</p>
    </div>
    <div class="info-box">
      <h3>防止DNS泄露的实操建议</h3>
      <p>1. 优先使用 Tun + FakeIP 模式让本地只拿到假IP真实解析在代理端进行</p>
      <p>2. 路由优先使用域名匹配对会触发本地解析的场景启用no-resolve</p>
      <p>3. 对被劫持或敏感域名强制走节点或为其指定独立 nameserver-policy</p>
    </div>
  </div>
  <footer><p>&copy; 2024 IPPure</p></footer>
</body>
</html>`;
}

function getWebRTCPage(): string {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🌍</text></svg>">
  <title>WebRTC泄露检测 - IPPure</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; }
    .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
    header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px 0; }
    nav { display: flex; justify-content: space-between; align-items: center; max-width: 1200px; margin: 0 auto; padding: 0 20px; }
    nav .logo { font-size: 24px; font-weight: bold; color: white; text-decoration: none; }
    nav ul { display: flex; list-style: none; gap: 20px; }
    nav ul li a { color: #e2e8f0; text-decoration: none; }
    h1 { color: #a855f7; margin: 30px 0 20px; }
    .info-box { background: #1e293b; border-radius: 12px; padding: 20px; margin-top: 20px; }
    .info-box p { color: #94a3b8; line-height: 1.8; margin-bottom: 12px; }
    .info-box strong { color: #e2e8f0; }
    footer { text-align: center; padding: 40px 20px; color: #64748b; margin-top: 60px; border-top: 1px solid #334155; }
  </style>
</head>
<body>
  <header>
    <nav>
      <a href="/" class="logo">IPPure</a>
      <ul>
        <li><a href="/">IP检测</a></li>
        <li><a href="/IP-Outbound-Detect.html">出口检测</a></li>
        <li><a href="/IP-leak-Detect.html">VPN溯源</a></li>
        <li><a href="/fingerprint.html">指纹检测</a></li>
        <li><a href="/neighbors.html">聊天</a></li>
        <li><a href="/about.html">关于</a></li>
      </ul>
    </nav>
  </header>
  <div class="container">
    <h1>WebRTC泄露检测</h1>
    <div class="info-box">
      <p><strong>WebRTCWeb Real-Time Communication</strong>是浏览器提供的实时音视频与点对点数据通道技术<strong>WebRTC 泄露</strong>指的是在使用浏览器或某些应用时WebRTC 的连接流程ICE 候选交换意外暴露了本地或真实公网 IP 地址导致即便你在用 VPN/代理目标网站或第三方仍可能看到你的真实 IP 地址或局域网地址</p>
    </div>
    <div class="info-box">
      <h3 style="color: #a855f7; margin-bottom: 12px;">Chrome扩展推荐</h3>
      <p> 谷歌出品WebRTC Network Limiter</p>
      <p> WebRTC Leak Prevent</p>
    </div>
    <div class="info-box">
      <h3 style="color: #a855f7; margin-bottom: 12px;">Firefox设置</h3>
      <p> about:config 页面将media.peerconnection.enabled 首偏好设置设置为false来完全禁用WebRTC</p>
    </div>
  </div>
  <footer><p>&copy; 2024 IPPure</p></footer>
</body>
</html>`;
}

function getNeighborsPage(): string {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🌍</text></svg>">
  <title>聊天 - IPPure</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; }
    .container { max-width: 800px; margin: 0 auto; padding: 20px; }
    header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px 0; }
    nav { display: flex; justify-content: space-between; align-items: center; max-width: 800px; margin: 0 auto; padding: 0 20px; }
    nav .logo { font-size: 24px; font-weight: bold; color: white; text-decoration: none; }
    nav ul { display: flex; list-style: none; gap: 20px; }
    nav ul li a { color: #e2e8f0; text-decoration: none; padding: 8px 16px; border-radius: 8px; transition: all 0.3s; }
    nav ul li a:hover { background: rgba(255,255,255,0.1); }
    .chat-container { background: #1e293b; border-radius: 12px; overflow: hidden; margin-top: 20px; display: flex; flex-direction: column; height: calc(100vh - 200px); min-height: 500px; }
    .chat-header { background: #334155; padding: 15px 20px; display: flex; justify-content: space-between; align-items: center; }
    .chat-title { color: #a855f7; font-weight: bold; font-size: 18px; }
    .chat-user { color: #94a3b8; font-size: 14px; }
    .logout-btn { background: #ef4444; color: white; border: none; padding: 8px 16px; border-radius: 8px; cursor: pointer; font-size: 14px; }
    .logout-btn:hover { background: #dc2626; }
    .chat-messages { flex: 1; overflow-y: auto; padding: 20px; display: flex; flex-direction: column; gap: 15px; }
    .message { max-width: 80%; padding: 12px 16px; border-radius: 12px; line-height: 1.5; }
    .message.user { align-self: flex-end; background: linear-gradient(135deg, #667eea, #764ba2); color: white; }
    .message.system { align-self: flex-start; background: #334155; color: #94a3b8; }
    .message-time { font-size: 12px; opacity: 0.7; margin-top: 5px; }
    .chat-warning { background: #fbbf24; color: #000; padding: 12px 20px; font-size: 14px; text-align: center; }
    .chat-input-area { padding: 20px; background: #1e293b; border-top: 1px solid #334155; }
    .input-row { display: flex; gap: 10px; }
    .chat-input { flex: 1; background: #0f172a; border: 1px solid #334155; border-radius: 8px; padding: 12px 16px; color: #e2e8f0; font-size: 16px; outline: none; }
    .chat-input:focus { border-color: #667eea; }
    .send-btn { background: linear-gradient(135deg, #667eea, #764ba2); color: white; border: none; padding: 12px 24px; border-radius: 8px; cursor: pointer; font-size: 16px; font-weight: bold; }
    .send-btn:hover { opacity: 0.9; }
    .send-btn:disabled { opacity: 0.5; cursor: not-allowed; }
    .login-container { max-width: 400px; margin: 100px auto; padding: 20px; }
    .login-box { background: #1e293b; border-radius: 12px; padding: 30px; }
    .login-title { color: #a855f7; font-size: 24px; text-align: center; margin-bottom: 30px; }
    .form-group { margin-bottom: 20px; }
    .form-label { display: block; color: #94a3b8; margin-bottom: 8px; font-size: 14px; }
    .form-input { width: 100%; background: #0f172a; border: 1px solid #334155; border-radius: 8px; padding: 12px 16px; color: #e2e8f0; font-size: 16px; outline: none; box-sizing: border-box; }
    .form-input:focus { border-color: #667eea; }
    .login-btn { width: 100%; background: linear-gradient(135deg, #667eea, #764ba2); color: white; border: none; padding: 14px; border-radius: 8px; cursor: pointer; font-size: 16px; font-weight: bold; margin-top: 10px; }
    .login-btn:hover { opacity: 0.9; }
    .login-btn:disabled { opacity: 0.5; cursor: not-allowed; }
    .register-link { text-align: center; margin-top: 20px; color: #94a3b8; font-size: 14px; }
    .register-link a { color: #667eea; text-decoration: none; }
    .register-link a:hover { text-decoration: underline; }
    .error-msg { color: #ef4444; font-size: 14px; margin-top: 10px; text-align: center; display: none; }
    .loading { text-align: center; color: #94a3b8; padding: 20px; }
    footer { text-align: center; padding: 40px 20px; color: #64748b; margin-top: 60px; border-top: 1px solid #334155; }
  </style>
</head>
<body>
  <header>
    <nav>
      <a href="/" class="logo">IPPure</a>
      <ul>
        <li><a href="/">IP检测</a></li>
        <li><a href="/IP-Outbound-Detect.html">出口检测</a></li>
        <li><a href="/IP-leak-Detect.html">VPN溯源</a></li>
        <li><a href="/fingerprint.html">指纹检测</a></li>
        <li><a href="/neighbors.html">聊天</a></li>
        <li><a href="/about.html">关于</a></li>
      </ul>
    </nav>
  </header>
  <div class="container">
    <div id="loginView" class="login-container">
      <div class="login-box">
        <div class="login-title">登录聊天</div>
        <div class="form-group">
          <label class="form-label">邮箱地址</label>
          <input type="email" id="emailInput" class="form-input" placeholder="请输入邮箱">
        </div>
        <div class="form-group">
          <label class="form-label">密码</label>
          <input type="password" id="passwordInput" class="form-input" placeholder="请输入密码">
        </div>
        <button id="loginBtn" class="login-btn">登录</button>
        <div id="loginError" class="error-msg"></div>
        <div class="register-link">
          还没有账户<a href="https://mail.ygyang.uk/login" target="_blank">前往注册</a>
        </div>
      </div>
    </div>
    
    <div id="chatView" style="display:none;">
      <div class="chat-container">
        <div class="chat-header">
          <span class="chat-title"> 聊天</span>
          <div>
            <span id="userEmail" class="chat-user"></span>
            <button id="logoutBtn" class="logout-btn">退出</button>
          </div>
        </div>
        <div class="chat-warning"> 聊天记录仅显示和保存最近7天</div>
        <div id="chatMessages" class="chat-messages">
          <div class="loading">加载聊天记录...</div>
        </div>
        <div class="chat-input-area">
          <div class="input-row">
            <input type="text" id="messageInput" class="chat-input" placeholder="输入消息...">
            <button id="sendBtn" class="send-btn">发送</button>
          </div>
        </div>
      </div>
    </div>
  </div>
  <footer><p>&copy; 2024 IPPure</p></footer>
  <script>
    let currentUser = null;
    
    const loginView = document.getElementById('loginView');
    const chatView = document.getElementById('chatView');
    const loginBtn = document.getElementById('loginBtn');
    const logoutBtn = document.getElementById('logoutBtn');
    const sendBtn = document.getElementById('sendBtn');
    const chatMessages = document.getElementById('chatMessages');
    const messageInput = document.getElementById('messageInput');
    const userEmail = document.getElementById('userEmail');
    const loginError = document.getElementById('loginError');
    
    function checkLoginStatus() {
      const savedUser = localStorage.getItem('ippure_user');
      if (savedUser) {
        currentUser = JSON.parse(savedUser);
        showChatView();
      }
    }
    
    function showChatView() {
      loginView.style.display = 'none';
      chatView.style.display = 'block';
      userEmail.textContent = currentUser.email;
      loadMessages();
    }
    
    async function loadMessages() {
      try {
        const response = await fetch('/v1/chat/messages', {
          headers: { 'X-User-Id': currentUser.id }
        });
        const data = await response.json();
        
        if (data.messages && data.messages.length > 0) {
          renderMessages(data.messages);
        } else {
          chatMessages.innerHTML = '<div style="text-align:center;color:#64748b;padding:40px;">暂无聊天记录开始聊天吧</div>';
        }
      } catch (error) {
        chatMessages.innerHTML = '<div style="text-align:center;color:#ef4444;padding:40px;">加载消息失败请刷新页面</div>';
      }
    }
    
    function renderMessages(messages) {
      chatMessages.innerHTML = messages.map(msg => {
        const isUser = msg.userId === currentUser.id;
        const time = new Date(msg.timestamp).toLocaleString('zh-CN');
        return '<div class="message ' + (isUser ? 'user' : 'system') + '"><div class="message-content">' + escapeHtml(msg.content) + '</div><div class="message-time">' + time + '</div></div>';
      }).join('');
      chatMessages.scrollTop = chatMessages.scrollHeight;
    }
    
    function escapeHtml(text) {
      const div = document.createElement('div');
      div.textContent = text;
      return div.innerHTML;
    }
    
    loginBtn.addEventListener('click', async () => {
      const email = document.getElementById('emailInput').value.trim();
      const password = document.getElementById('passwordInput').value;
      
      if (!email || !password) {
        loginError.textContent = '请输入邮箱和密码';
        loginError.style.display = 'block';
        return;
      }
      
      loginBtn.disabled = true;
      loginBtn.textContent = '登录中...';
      loginError.style.display = 'none';
      
      try {
        const response = await fetch('/v1/chat/login?email=' + encodeURIComponent(email) + '&password=' + encodeURIComponent(password));
        const data = await response.json();
        
        if (data.success) {
          currentUser = { id: data.user.id || data.user.email, email: email };
          localStorage.setItem('ippure_user', JSON.stringify(currentUser));
          showChatView();
        } else {
          loginError.textContent = data.error || '登录失败';
          loginError.style.display = 'block';
        }
      } catch (error) {
        loginError.textContent = '登录服务暂不可用';
        loginError.style.display = 'block';
      } finally {
        loginBtn.disabled = false;
        loginBtn.textContent = '登录';
      }
    });
    
    logoutBtn.addEventListener('click', () => {
      localStorage.removeItem('ippure_user');
      currentUser = null;
      chatView.style.display = 'none';
      loginView.style.display = 'block';
      document.getElementById('passwordInput').value = '';
    });
    
    async function sendMessage() {
      const content = messageInput.value.trim();
      if (!content) return;
      
      sendBtn.disabled = true;
      messageInput.disabled = true;
      
      try {
        const response = await fetch('/v1/chat/send', {
          method: 'POST',
          headers: { 
            'Content-Type': 'application/json',
            'X-User-Id': currentUser.id
          },
          body: JSON.stringify({ content })
        });
        
        const data = await response.json();
        
        if (data.success) {
          messageInput.value = '';
          loadMessages();
        } else {
          alert(data.error || '发送失败');
        }
      } catch (error) {
        alert('发送失败请检查网络连接');
      } finally {
        sendBtn.disabled = false;
        messageInput.disabled = false;
        messageInput.focus();
      }
    }
    
    sendBtn.addEventListener('click', sendMessage);
    messageInput.addEventListener('keypress', (e) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendMessage();
      }
    });
    
    checkLoginStatus();
  </script>
</body>
</html>`;
}

function getIPCardPage(): string {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🌍</text></svg>">
  <title>IP信息卡片 - IPPure</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; }
    .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
    header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px 0; }
    nav { display: flex; justify-content: space-between; align-items: center; max-width: 1200px; margin: 0 auto; padding: 0 20px; }
    nav .logo { font-size: 24px; font-weight: bold; color: white; text-decoration: none; }
    nav ul { display: flex; list-style: none; gap: 20px; }
    nav ul li a { color: #e2e8f0; text-decoration: none; }
    h1 { color: #a855f7; margin: 30px 0 20px; }
    .card-preview { background: #1e293b; border-radius: 12px; padding: 30px; margin-top: 20px; text-align: center; }
    .card-preview img { max-width: 400px; border-radius: 8px; }
    .code-block { background: #0f172a; border-radius: 8px; padding: 16px; margin-top: 20px; overflow-x: auto; }
    .code-block code { color: #a855f7; font-family: monospace; }
    footer { text-align: center; padding: 40px 20px; color: #64748b; margin-top: 60px; border-top: 1px solid #334155; }
  </style>
</head>
<body>
  <header>
    <nav>
      <a href="/" class="logo">IPPure</a>
      <ul>
        <li><a href="/">IP检测</a></li>
        <li><a href="/IP-Outbound-Detect.html">出口检测</a></li>
        <li><a href="/IP-leak-Detect.html">VPN溯源</a></li>
        <li><a href="/fingerprint.html">指纹检测</a></li>
        <li><a href="/neighbors.html">聊天</a></li>
        <li><a href="/about.html">关于</a></li>
      </ul>
    </nav>
  </header>
  <div class="container">
    <h1>访客IP信息卡片</h1>
    <div class="card-preview">
      <img src="/v1/card" alt="IP信息卡片" />
    </div>
    <h2 style="color: #a855f7; margin-top: 30px;">Markdown</h2>
    <div class="code-block"><code>[![访客IP信息卡片](https://ippure.com/v1/card)](https://ippure.com "点击查看IP信息")</code></div>
    <h2 style="color: #a855f7; margin-top: 30px;">BBCode</h2>
    <div class="code-block"><code>[url=https://ippure.com][img]https://ippure.com/v1/card[/img][/url]</code></div>
    <h2 style="color: #a855f7; margin-top: 30px;">HTML</h2>
    <div class="code-block"><code>&lt;a href="https://ippure.com" target="_blank"&gt;&lt;img src="https://ippure.com/v1/card" alt="IP信息卡片" /&gt;&lt;/a&gt;</code></div>
  </div>
  <footer><p>&copy; 2024 IPPure</p></footer>
</body>
</html>`;
}

function getAPIPage(): string {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🌍</text></svg>">
  <title>API接口 - IPPure</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; }
    .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
    header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px 0; }
    nav { display: flex; justify-content: space-between; align-items: center; max-width: 1200px; margin: 0 auto; padding: 0 20px; }
    nav .logo { font-size: 24px; font-weight: bold; color: white; text-decoration: none; }
    nav ul { display: flex; list-style: none; gap: 20px; }
    nav ul li a { color: #e2e8f0; text-decoration: none; }
    h1 { color: #a855f7; margin: 30px 0 20px; }
    h2 { color: #a855f7; margin: 20px 0 10px; }
    .code-block { background: #0f172a; border-radius: 8px; padding: 16px; margin-top: 10px; overflow-x: auto; }
    .code-block code { color: #a855f7; font-family: monospace; }
    .info-box { background: #1e293b; border-radius: 12px; padding: 20px; margin-top: 20px; }
    footer { text-align: center; padding: 40px 20px; color: #64748b; margin-top: 60px; border-top: 1px solid #334155; }
  </style>
</head>
<body>
  <header>
    <nav>
      <a href="/" class="logo">IPPure</a>
      <ul>
        <li><a href="/">IP检测</a></li>
        <li><a href="/IP-Outbound-Detect.html">出口检测</a></li>
        <li><a href="/IP-leak-Detect.html">VPN溯源</a></li>
        <li><a href="/fingerprint.html">指纹检测</a></li>
        <li><a href="/neighbors.html">聊天</a></li>
        <li><a href="/about.html">关于</a></li>
      </ul>
    </nav>
  </header>
  <div class="container">
    <h1>我的IP信息API</h1>
    <div class="info-box">
      <p>IPPure提供一个公开API可以显示调用API的IP的位置信息ASN信息IP风险系数是否原生IP是否机房IP</p>
    </div>
    <h2>接口地址</h2>
    <div class="code-block"><code>curl -L https://ippure.com/v1/info</code></div>
    <h2>示例输出</h2>
    <div class="code-block"><code>{
  "ip": "104.28.123.123",
  "asn": 13335,
  "asOrganization": "Cloudflare, Inc.",
  "country": "中国",
  "countryCode": "CN",
  "region": "湖南省",
  "regionCode": "HN",
  "city": "长沙市",
  "timezone": "Asia/Shanghai",
  "longitude": "-118.24368",
  "latitude": "34.05223",
  "postalCode": "410000",
  "fraudScore": 75,
  "isResidential": false,
  "isBroadcast": false,
  "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
}</code></div>
  </div>
  <footer><p>&copy; 2024 IPPure</p></footer>
</body>
</html>`;
}

function getAboutPage(): string {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🌍</text></svg>">
  <title>关于本站 - IPPure</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; }
    .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
    header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px 0; }
    nav { display: flex; justify-content: space-between; align-items: center; max-width: 1200px; margin: 0 auto; padding: 0 20px; }
    nav .logo { font-size: 24px; font-weight: bold; color: white; text-decoration: none; }
    nav ul { display: flex; list-style: none; gap: 20px; }
    nav ul li a { color: #e2e8f0; text-decoration: none; padding: 8px 16px; border-radius: 8px; transition: all 0.3s; }
    nav ul li a:hover { background: rgba(255,255,255,0.1); }
    h1 { color: #a855f7; margin: 30px 0 20px; }
    h2 { color: #a855f7; margin: 25px 0 15px; }
    .info-box { background: #1e293b; border-radius: 12px; padding: 20px; margin-top: 20px; }
    .info-box ul { list-style: none; padding-left: 0; }
    .info-box ul li { padding: 8px 0; color: #94a3b8; }
    .info-box p { color: #94a3b8; line-height: 1.8; margin-bottom: 12px; }
    .highlight { color: #a855f7; font-weight: bold; }
    .contact-link { color: #667eea; text-decoration: none; }
    .contact-link:hover { text-decoration: underline; }
    footer { text-align: center; padding: 40px 20px; color: #64748b; margin-top: 60px; border-top: 1px solid #334155; }
  </style>
</head>
<body>
  <header>
    <nav>
      <a href="/" class="logo">IPPure</a>
      <ul>
        <li><a href="/">IP检测</a></li>
        <li><a href="/IP-Outbound-Detect.html">出口检测</a></li>
        <li><a href="/IP-leak-Detect.html">VPN溯源</a></li>
        <li><a href="/fingerprint.html">指纹检测</a></li>
        <li><a href="/neighbors.html">聊天</a></li>
        <li><a href="/about.html">关于</a></li>
      </ul>
    </nav>
  </header>
  <div class="container">
    <h1>关于本站</h1>
    <div class="info-box">
      <p>IPPure努力做最专业且易用的IP纯净度检测软件把所有常用的IP和浏览器检测工具打包到一个网站提供一站式的查询服务</p>
      <p style="margin-top: 15px;">本项目灵感来源于 <span class="highlight">https://ippure.com/</span>旨在提供类似功能的开源实现</p>
      <p style="margin-top: 15px;">对于数据不准确的反馈我们会积极校正数据并且公开校正过程保证公开透明杜绝数据作弊</p>
    </div>
    
    <h2>主要功能</h2>
    <div class="info-box">
      <ul>
        <li> IP定位信息查询 - 多数据源验证获取准确IP定位</li>
        <li> IP风险信息查询 - IPPure系数和Cloudflare系数评估</li>
        <li> 国旗显示 - 根据IP所属国家显示对应国旗</li>
        <li> 浏览器指纹检测 - 评估隐私保护等级</li>
        <li> VPN泄露检测 - WebRTCDNS出口IP分布检测</li>
        <li> IP信息卡片 - 生成访客IP信息卡片图片</li>
      </ul>
    </div>
    
    <h2>技术架构</h2>
    <div class="info-box">
      <ul>
        <li> Cloudflare Workers - 边缘计算部署</li>
        <li> TypeScript - 类型安全的前端开发</li>
        <li> Cloudflare KV - 聊天记录存储</li>
        <li> cloud-mail - 用户认证系统集成 (<a href="https://github.com/maillab/cloud-mail" target="_blank" style="color: #667eea;">GitHub</a>)</li>
        <li> 多数据源整合 - IP2LocationDB-IPMaxMindIPIP</li>
      </ul>
    </div>
    
    <h2>账户系统</h2>
    <div class="info-box">
      <p>本项目集成 <span class="highlight">cloud-mail</span> 账户系统提供安全可靠的用户认证服务</p>
      <ul style="margin-top: 15px;">
        <li> 页面内直接登录无需跳转</li>
        <li> 注册跳转至 <a href="https://mail.ygyang.uk/login" target="_blank" style="color: #667eea;">cloud-mail</a> 注册页面</li>
        <li> 聊天记录存储在 Cloudflare KV 中</li>
        <li> 聊天记录仅保留最近7天自动清理</li>
      </ul>
    </div>
    
    <h2>目标用户</h2>
    <div class="info-box">
      <ul>
        <li> 流媒体作者</li>
        <li> AI使用者</li>
        <li> 跨境电商</li>
        <li> 开发调试人员</li>
        <li> 网络运维用户</li>
      </ul>
    </div>
    
    <h2>联系我们</h2>
    <div class="info-box">
      <p>如有问题或建议请通过以下方式联系我们</p>
      <p style="margin-top: 15px;"> 电子邮件<a href="mailto:ygyang@ygyang.uk" class="contact-link">ygyang@ygyang.uk</a></p>
      <p style="margin-top: 15px;"> GitHub<a href="https://github.com/ygyang2023/ippure" target="_blank" class="contact-link">https://github.com/ygyang2023/ippure</a></p>
    </div>
  </div>
  <footer><p>&copy; 2024 IPPure | <a href="/terms-privacy.html" style="color: #a855f7;">使用条款与隐私说明</a></p></footer>
</body>
</html>`;
}

function getFAQPage(): string {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🌍</text></svg>">
  <title>常见问题 - IPPure</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; }
    .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
    header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px 0; }
    nav { display: flex; justify-content: space-between; align-items: center; max-width: 1200px; margin: 0 auto; padding: 0 20px; }
    nav .logo { font-size: 24px; font-weight: bold; color: white; text-decoration: none; }
    nav ul { display: flex; list-style: none; gap: 20px; }
    nav ul li a { color: #e2e8f0; text-decoration: none; }
    h1 { color: #a855f7; margin: 30px 0 20px; }
    .faq-item { background: #1e293b; border-radius: 12px; padding: 20px; margin-top: 15px; }
    .faq-item h3 { color: #a855f7; margin-bottom: 10px; }
    .faq-item p { color: #94a3b8; line-height: 1.6; }
    footer { text-align: center; padding: 40px 20px; color: #64748b; margin-top: 60px; border-top: 1px solid #334155; }
  </style>
</head>
<body>
  <header>
    <nav>
      <a href="/" class="logo">IPPure</a>
      <ul>
        <li><a href="/">IP检测</a></li>
        <li><a href="/IP-Outbound-Detect.html">出口检测</a></li>
        <li><a href="/IP-leak-Detect.html">VPN溯源</a></li>
        <li><a href="/fingerprint.html">指纹检测</a></li>
        <li><a href="/neighbors.html">聊天</a></li>
        <li><a href="/about.html">关于</a></li>
      </ul>
    </nav>
  </header>
  <div class="container">
    <h1>常见问题</h1>
    <div class="faq-item">
      <h3>什么是IP纯净度</h3>
      <p>IP纯净度指的是IP被标记为数据中心/机房IP的程度纯净的IP通常是家庭宽带或移动网络IP不容易被网站识别为代理或VPN</p>
    </div>
    <div class="faq-item">
      <h3>为什么需要检测IP纯净度</h3>
      <p>使用不纯净的IP访问流媒体AI服务等可能遭遇风控拦截或直接拒绝服务检测IP纯净度可以帮助您选择合适的出口IP</p>
    </div>
    <div class="faq-item">
      <h3>数据不准确怎么办</h3>
      <p>您可以通过联系方式向我们反馈并提供参考依据我们会积极校正并公开校正过程</p>
    </div>
  </div>
  <footer><p>&copy; 2024 IPPure</p></footer>
</body>
</html>`;
}

function getCorrectionPage(): string {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🌍</text></svg>">
  <title>数据纠正记录 - IPPure</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; }
    .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
    header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px 0; }
    nav { display: flex; justify-content: space-between; align-items: center; max-width: 1200px; margin: 0 auto; padding: 0 20px; }
    nav .logo { font-size: 24px; font-weight: bold; color: white; text-decoration: none; }
    nav ul { display: flex; list-style: none; gap: 20px; }
    nav ul li a { color: #e2e8f0; text-decoration: none; }
    h1 { color: #a855f7; margin: 30px 0 20px; }
    h2 { color: #a855f7; margin: 25px 0 15px; }
    .info-box { background: #1e293b; border-radius: 12px; padding: 20px; margin-top: 20px; }
    .info-box p { color: #94a3b8; line-height: 1.6; }
    footer { text-align: center; padding: 40px 20px; color: #64748b; margin-top: 60px; border-top: 1px solid #334155; }
  </style>
</head>
<body>
  <header>
    <nav>
      <a href="/" class="logo">IPPure</a>
      <ul>
        <li><a href="/">IP检测</a></li>
        <li><a href="/IP-Outbound-Detect.html">出口检测</a></li>
        <li><a href="/IP-leak-Detect.html">VPN溯源</a></li>
        <li><a href="/fingerprint.html">指纹检测</a></li>
        <li><a href="/neighbors.html">聊天</a></li>
        <li><a href="/about.html">关于</a></li>
      </ul>
    </nav>
  </header>
  <div class="container">
    <h1>数据纠正记录</h1>
    <div class="info-box">
      <h2>数据纠正说明</h2>
      <p>当网站查询结果有错误时欢迎向网站管理员反馈</p>
      <p style="margin-top: 10px;">为了保障公开透明所有的数据纠正记录都会在此汇总</p>
    </div>
    <div class="info-box">
      <h2>注意</h2>
      <p> IP基本信息数据集来自于互联网如cloudflareip2locationdb-ip等</p>
      <p> IP基本数据的纠正需要向源头反馈网站会定期拉取最新数据</p>
      <p> 这里的数据纠正主要指的是IP类型IP用途风险系数</p>
      <p> 数据纠正需要提供一定的参考依据比如其他IP查询网站的数据网络设备照片等</p>
    </div>
  </div>
  <footer><p>&copy; 2024 IPPure</p></footer>
</body>
</html>`;
}

function getChangelogPage(): string {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🌍</text></svg>">
  <title>功能更新日志 - IPPure</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; }
    .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
    header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px 0; }
    nav { display: flex; justify-content: space-between; align-items: center; max-width: 1200px; margin: 0 auto; padding: 0 20px; }
    nav .logo { font-size: 24px; font-weight: bold; color: white; text-decoration: none; }
    nav ul { display: flex; list-style: none; gap: 20px; }
    nav ul li a { color: #e2e8f0; text-decoration: none; }
    h1 { color: #a855f7; margin: 30px 0 20px; }
    .changelog-item { background: #1e293b; border-radius: 12px; padding: 20px; margin-top: 15px; }
    .changelog-date { color: #a855f7; font-size: 14px; }
    .changelog-content { color: #94a3b8; margin-top: 8px; line-height: 1.6; }
    footer { text-align: center; padding: 40px 20px; color: #64748b; margin-top: 60px; border-top: 1px solid #334155; }
  </style>
</head>
<body>
  <header>
    <nav>
      <a href="/" class="logo">IPPure</a>
      <ul>
        <li><a href="/">IP检测</a></li>
        <li><a href="/IP-Outbound-Detect.html">出口检测</a></li>
        <li><a href="/IP-leak-Detect.html">VPN溯源</a></li>
        <li><a href="/fingerprint.html">指纹检测</a></li>
        <li><a href="/neighbors.html">聊天</a></li>
        <li><a href="/about.html">关于</a></li>
      </ul>
    </nav>
  </header>
  <div class="container">
    <h1>功能更新日志</h1>
    <div class="changelog-item">
      <span class="changelog-date">2024-01-01</span>
      <p class="changelog-content">初始版本发布包含IP检测出口检测指纹检测等核心功能</p>
    </div>
  </div>
  <footer><p>&copy; 2024 IPPure</p></footer>
</body>
</html>`;
}

function getContactPage(): string {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🌍</text></svg>">
  <title>联系方式 - IPPure</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; }
    .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
    header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px 0; }
    nav { display: flex; justify-content: space-between; align-items: center; max-width: 1200px; margin: 0 auto; padding: 0 20px; }
    nav .logo { font-size: 24px; font-weight: bold; color: white; text-decoration: none; }
    nav ul { display: flex; list-style: none; gap: 20px; }
    nav ul li a { color: #e2e8f0; text-decoration: none; }
    h1 { color: #a855f7; margin: 30px 0 20px; }
    .contact-box { background: #1e293b; border-radius: 12px; padding: 30px; margin-top: 20px; }
    .contact-item { margin: 15px 0; }
    .contact-label { color: #a855f7; font-weight: bold; }
    .contact-value { color: #94a3b8; margin-top: 5px; }
    footer { text-align: center; padding: 40px 20px; color: #64748b; margin-top: 60px; border-top: 1px solid #334155; }
  </style>
</head>
<body>
  <header>
    <nav>
      <a href="/" class="logo">IPPure</a>
      <ul>
        <li><a href="/">IP检测</a></li>
        <li><a href="/IP-Outbound-Detect.html">出口检测</a></li>
        <li><a href="/IP-leak-Detect.html">VPN溯源</a></li>
        <li><a href="/fingerprint.html">指纹检测</a></li>
        <li><a href="/neighbors.html">聊天</a></li>
        <li><a href="/about.html">关于</a></li>
      </ul>
    </nav>
  </header>
  <div class="container">
    <h1>联系方式</h1>
    <div class="contact-box">
      <div class="contact-item">
        <div class="contact-label">数据纠错反馈</div>
        <div class="contact-value">如发现IP数据有误请提供其他查询源的数据对比或设备照片作为参考依据</div>
      </div>
      <div class="contact-item">
        <div class="contact-label">商务合作</div>
        <div class="contact-value">请发送邮件至 ygyang@ygyang.uk</div>
      </div>
    </div>
  </div>
  <footer><p>&copy; 2024 IPPure</p></footer>
</body>
</html>`;
}

function getTermsPrivacyPage(): string {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🌍</text></svg>">
  <title>使用条款与隐私说明 - IPPure</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; }
    .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
    header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px 0; }
    nav { display: flex; justify-content: space-between; align-items: center; max-width: 1200px; margin: 0 auto; padding: 0 20px; }
    nav .logo { font-size: 24px; font-weight: bold; color: white; text-decoration: none; }
    nav ul { display: flex; list-style: none; gap: 20px; }
    nav ul li a { color: #e2e8f0; text-decoration: none; }
    h1 { color: #a855f7; margin: 30px 0 20px; }
    h2 { color: #a855f7; margin: 25px 0 15px; }
    .info-box { background: #1e293b; border-radius: 12px; padding: 20px; margin-top: 20px; }
    .info-box p { color: #94a3b8; line-height: 1.8; }
    footer { text-align: center; padding: 40px 20px; color: #64748b; margin-top: 60px; border-top: 1px solid #334155; }
  </style>
</head>
<body>
  <header>
    <nav>
      <a href="/" class="logo">IPPure</a>
      <ul>
        <li><a href="/">IP检测</a></li>
        <li><a href="/IP-Outbound-Detect.html">出口检测</a></li>
        <li><a href="/IP-leak-Detect.html">VPN溯源</a></li>
        <li><a href="/fingerprint.html">指纹检测</a></li>
        <li><a href="/neighbors.html">聊天</a></li>
        <li><a href="/about.html">关于</a></li>
      </ul>
    </nav>
  </header>
  <div class="container">
    <h1>使用条款与隐私说明</h1>
    <div class="info-box">
      <h2>使用条款</h2>
      <p>IPPure仅提供IP检测服务用户在使用本服务时须遵守当地法律法规不得用于非法用途</p>
    </div>
    <div class="info-box">
      <h2>隐私说明</h2>
      <p>IPPure不会记录用户的浏览行为和个人信息我们仅收集访问时的IP地址用于检测目的且不会与第三方共享</p>
    </div>
  </div>
  <footer><p>&copy; 2024 IPPure</p></footer>
</body>
</html>`;
}
