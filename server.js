const express = require('express');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// ข้อมูลแบรนด์และโซเชียลมีเดีย
const TARGET_BRANDS = [
    { name: 'Instagram', keywords: ['instagram', 'instagam', 'instgram', 'instagrm'], officialDomains: ['instagram.com', 'ig.me'] },
    { name: 'TikTok', keywords: ['tiktok', 'tik-tok', 'tikt0k'], officialDomains: ['tiktok.com', 'tiktokv.com', 'byteoversea.com'] },
    { name: 'Facebook', keywords: ['facebook', 'facebooc', 'faceb0ok', 'facebok', 'fb'], officialDomains: ['facebook.com', 'fb.com', 'messenger.com'] },
    { name: 'LINE', keywords: ['line', 'line-me', 'line-official', 'liff'], officialDomains: ['line.me', 'line.naver.jp', 'line-apps.com'] },
    { name: 'X (Twitter)', keywords: ['twitter', 'twittwer', 'x.com'], officialDomains: ['twitter.com', 'x.com'] },
    { name: 'YouTube', keywords: ['youtube', 'youtub', 'yotube'], officialDomains: ['youtube.com', 'youtu.be'] }
];

// ฟังก์ชันคำนวณ Levenshtein Distance สำหรับเช็ก Typosquatting
function calculateLevenshteinDistance(a, b) {
    const matrix = [];
    for (let i = 0; i <= b.length; i++) matrix[i] = [i];
    for (let j = 0; j <= a.length; j++) matrix[0][j] = j;
    for (let i = 1; i <= b.length; i++) {
        for (let j = 1; j <= a.length; j++) {
            if (b.charAt(i - 1) === a.charAt(j - 1)) {
                matrix[i][j] = matrix[i - 1][j - 1];
            } else {
                matrix[i][j] = Math.min(matrix[i - 1][j - 1] + 1, matrix[i][j - 1] + 1, matrix[i - 1][j] + 1);
            }
        }
    }
    return matrix[b.length][a.length];
}

function getSimilarityRatio(s1, s2) {
    const longer = s1.length > s2.length ? s1 : s2;
    if (longer.length === 0) return 1.0;
    const distance = calculateLevenshteinDistance(s1, s2);
    return (longer.length - distance) / parseFloat(longer.length);
}

function analyzeUrl(inputUrl) {
    let formattedUrl = inputUrl;
    if (!/^https?:\/\//i.test(formattedUrl)) {
        formattedUrl = 'http://' + formattedUrl;
    }

    try {
        const parsed = new URL(formattedUrl);
        const protocol = parsed.protocol.replace(':', '').toLowerCase();
        const hostname = parsed.hostname.toLowerCase();
        const pathname = parsed.pathname + parsed.search + parsed.hash;

        let riskScore = 0;
        let findings = [];

        if (protocol !== 'https') {
            riskScore += 25;
            findings.push({
                severity: 'high',
                category: 'Protocol',
                title: 'ไม่มีการเข้ารหัสความปลอดภัย (HTTP)',
                desc: 'เว็บไซต์นี้ไม่ได้ใช้ HTTPS เสี่ยงต่อการถูกดักจับข้อมูล'
            });
        }

        const hostParts = hostname.split('.');
        let mainDomain = hostParts.length > 2 ? hostParts.slice(-2).join('.') : hostname;
        let rootName = mainDomain.split('.')[0];

        TARGET_BRANDS.forEach(brand => {
            const isOfficial = brand.officialDomains.some(d => hostname === d || hostname.endsWith('.' + d));
            if (!isOfficial) {
                brand.officialDomains.forEach(offDom => {
                    const targetName = offDom.split('.')[0];
                    const similarity = getSimilarityRatio(rootName, targetName);
                    if (similarity >= 0.70) {
                        riskScore += 60;
                        findings.push({
                            severity: 'critical',
                            category: 'Typosquatting',
                            title: `ตรวจพบการสะกดเลียนแบบแบรนด์ ${brand.name}`,
                            desc: `โดเมน "${rootName}" มีความคล้ายคลึงกับเว็บทางการ "${targetName}" เข้าข่ายมิจฉาชีพปลอมแปลงเว็บ`
                        });
                    }
                });
            }
        });

        riskScore = Math.min(riskScore, 100);

        return {
            riskScore,
            findings,
            details: {
                protocol,
                hostname,
                subdomain: hostParts.length > 2 ? hostParts.slice(0, -2).join('.') : 'ไม่มี',
                pathname
            }
        };
    } catch (e) {
        return { error: 'รูปแบบ URL ไม่ถูกต้อง' };
    }
}

// Route หลักสำหรับเช็กลิงก์
app.post('/api/check-link', (req, res) => {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: 'กรุณาระบุ URL' });
    const result = analyzeUrl(url);
    if (result.error) return res.status(400).json(result);
    res.json(result);
});

app.get('/', (req, res) => {
    res.send('Link Guard API Online!');
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
