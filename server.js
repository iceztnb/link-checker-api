const express = require('express');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

const OFFICIAL_BRANDS = [
    // --- โซเชียลมีเดียยอดนิยมในไทย ---
    { name: 'Instagram', keywords: ['instagram', 'instagam', 'instgram', 'instagrm'], officialDomains: ['instagram.com', 'ig.me'] },
    { name: 'TikTok', keywords: ['tiktok', 'tik-tok', 'tikt0k'], officialDomains: ['tiktok.com', 'tiktokv.com', 'byteoversea.com'] },
    { name: 'Facebook', keywords: ['facebook', 'facebooc', 'faceb0ok', 'facebok', 'fb'], officialDomains: ['facebook.com', 'fb.com', 'messenger.com'] },
    { name: 'LINE', keywords: ['line', 'line-me', 'line-official', 'liff'], officialDomains: ['line.me', 'line.naver.jp', 'line-apps.com'] },
    { name: 'X (Twitter)', keywords: ['twitter', 'twittwer', 'x.com'], officialDomains: ['twitter.com', 'x.com'] },
    { name: 'YouTube', keywords: ['youtube', 'youtub', 'yotube'], officialDomains: ['youtube.com', 'youtu.be'] },

    // --- แบงก์และกระเป๋าเงินในไทย ---
    { name: 'Kasikorn Bank (KBank)', keywords: ['kasikornbank', 'kasikorn', 'kbank', 'kasik0rn'], officialDomains: ['kasikornbank.com', 'kasikornsecurities.com'] },
    { name: 'Siam Commercial Bank (SCB)', keywords: ['scb', 'scbeasy', 'scbx'], officialDomains: ['scb.co.th', 'scbx.com'] },
    { name: 'Krungthai Bank (KTB)', keywords: ['krungthai', 'ktb', 'krungthaibank'], officialDomains: ['krungthai.com', 'ktb.co.th'] },
    { name: 'Bangkok Bank', keywords: ['bangkokbank', 'bualuang'], officialDomains: ['bangkokbank.com'] },
    { name: 'Krungsri Bank', keywords: ['krungsri', 'bay'], officialDomains: ['krungsri.com'] },
    { name: 'TrueMoney', keywords: ['truemoney', 'truemoneywallet', 'tmn'], officialDomains: ['truemoney.com'] },

    // --- ช้อปปิ้งออนไลน์ ---
    { name: 'Shopee', keywords: ['shopee', 'shope'], officialDomains: ['shopee.co.th', 'shopee.com'] },
    { name: 'Lazada', keywords: ['lazada', 'lazad'], officialDomains: ['lazada.co.th', 'lazada.com'] }
];

const PHISHING_KEYWORDS = [
  'login', 'signin', 'verify', 'update-account', 'secure-bank', 
  'free-gift', 'bonus', 'claim', 'wallet', 'otp', 'reward', 'cashback', 'loan'
];

function calculateLevenshtein(a, b) {
  const matrix = Array.from({ length: a.length + 1 }, () => Array(b.length + 1).fill(0));
  for (let i = 0; i <= a.length; i++) matrix[i][0] = i;
  for (let j = 0; j <= b.length; j++) matrix[0][j] = j;

  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      matrix[i][j] = Math.min(
        matrix[i - 1][j] + 1,
        matrix[i][j - 1] + 1,
        matrix[i - 1][j - 1] + cost
      );
    }
  }
  return matrix[a.length][b.length];
}

function analyzeUrl(inputUrl) {
  let urlObj;
  let formattedUrl = inputUrl.trim();
  if (!/^https?:\/\//i.test(formattedUrl)) {
    formattedUrl = 'http://' + formattedUrl;
  }

  try {
    urlObj = new URL(formattedUrl);
  } catch (e) {
    return { error: 'รูปแบบ URL ไม่ถูกต้อง' };
  }

  const hostname = urlObj.hostname.toLowerCase();
  const protocol = urlObj.protocol;
  const fullPath = (urlObj.pathname + urlObj.search).toLowerCase();

  let riskScore = 0;
  const findings = [];

  // 1. HTTP Protocol
  if (protocol === 'http:') {
    riskScore += 25;
    findings.push({
      type: 'warning',
      title: 'ใช้โปรโตคอล HTTP แบบไม่ปลอดภัย',
      desc: 'ลิงก์นี้ไม่มีการเข้ารหัส SSL/TLS (http://) ข้อมูลที่รับส่งอาจถูกดักจับได้'
    });
  }

  // 2. Typosquatting Check
  for (const brand of TARGET_BRANDS) {
    const mainDomain = brand.domain;
    if (hostname === mainDomain || hostname.endsWith('.' + mainDomain)) {
      continue;
    }

    let detectedImpersonation = false;
    let similarityPercent = 0;

    for (const kw of brand.keywords) {
      if (hostname.includes(kw)) {
        detectedImpersonation = true;
        similarityPercent = 90;
        break;
      }

      const baseHost = hostname.replace(/^www\./, '').split('.')[0];
      const baseBrand = mainDomain.split('.')[0];
      const dist = calculateLevenshtein(baseHost, baseBrand);
      const maxLen = Math.max(baseHost.length, baseBrand.length);
      const sim = Math.round((1 - dist / maxLen) * 100);

      if (sim >= 70 && sim < 100) {
        detectedImpersonation = true;
        similarityPercent = sim;
        break;
      }
    }

    if (detectedImpersonation) {
      riskScore += 55;
      findings.push({
        type: 'danger',
        title: `ตรวจพบการสวมรอยแบรนด์ (${brand.name})`,
        desc: `โดเมน "${hostname}" เลียนแบบแบรนด์ ${brand.name} (ความคล้ายคลึง ~${similarityPercent}%) แต่ไม่ใช่เว็บทางการ (${brand.domain})`
      });
      break;
    }
  }

  // 3. Raw IP Check
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
    riskScore += 30;
    findings.push({
      type: 'warning',
      title: 'ใช้ IP Address แทนชื่อโดเมน',
      desc: 'มิจฉาชีพมักใช้ IP Address โดยตรงเพื่อหลีกเลี่ยงการลงทะเบียนชื่อโดเมน'
    });
  }

  // 4. Subdomain Stacking
  const domainParts = hostname.split('.');
  if (domainParts.length > 3) {
    riskScore += 15;
    findings.push({
      type: 'warning',
      title: 'มีการใช้ Subdomain ซ้อนหลายชั้น',
      desc: `พบชื่อโดเมนย่อย ${domainParts.length - 2} ชั้น ซึ่งอาจใช้หลอกตาให้ดูเหมือนเว็บจริง`
    });
  }

  // 5. Suspicious Keywords
  const foundKeywords = PHISHING_KEYWORDS.filter(kw => hostname.includes(kw) || fullPath.includes(kw));
  if (foundKeywords.length > 0) {
    riskScore += 20;
    findings.push({
      type: 'warning',
      title: 'พบคำค้นหาสุ่มเสี่ยงมิจฉาชีพ',
      desc: `พบคำว่า [${foundKeywords.join(', ')}] ซึ่งนิยมใช้ในหน้าเว็บตกทอง หรือหน้าดูดรหัสผ่าน`
    });
  }

  riskScore = Math.min(100, riskScore);
  let status = 'normal';
  let statusText = 'ปกติ (ไม่พบความผิดปกติเชิงโครงสร้าง)';
  let color = 'green';

  if (riskScore >= 70) {
    status = 'danger';
    statusText = 'อันตรายสูง (มีแนวโน้มเป็นลิงก์ปลอม / Phishing)';
    color = 'red';
  } else if (riskScore >= 30) {
    status = 'warning';
    statusText = 'ควรระวัง (พบจุดน่าสงสัยบางประการ)';
    color = 'yellow';
  }

  return {
    url: formattedUrl,
    hostname,
    riskScore,
    status,
    statusText,
    color,
    findings,
    analyzedAt: new Date().toISOString()
  };
}

app.post('/api/check-link', (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'กรุณาระบุ URL ที่ต้องการตรวจสอบ' });
  const result = analyzeUrl(url);
  if (result.error) return res.status(400).json(result);
  return res.json(result);
});

app.get('/', (req, res) => res.send('Link Guard API Online!'));

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
