const puppeteer = require('puppeteer');
const fs = require('fs');
const path = require('path');

(async () => {
  const downloadDir = path.resolve(__dirname, 'tmp_downloads');
  fs.mkdirSync(downloadDir, { recursive: true });

  const browser = await puppeteer.launch({ args: ['--no-sandbox', '--disable-setuid-sandbox'] });
  const page = await browser.newPage();

  // Enable downloads to our folder
  const client = await page.target().createCDPSession();
  await client.send('Page.setDownloadBehavior', { behavior: 'allow', downloadPath: downloadDir });

  const scanId = '2356dbe1-2995-4046-a7a1-2720a5c98d3e';
  const url = `http://localhost:3006/scans/${scanId}`;

  console.log('Navigating to', url);
  await page.goto(url, { waitUntil: 'networkidle2', timeout: 30000 }).catch(e => { console.error('Goto failed', e); process.exit(1); });

  // Observe responses to detect the generate-from-scan POST and final download
  let generateResp = null;
  page.on('response', async (res) => {
    try {
      const req = res.request();
      const url = req.url();
      const method = req.method();
      if (method === 'POST' && url.includes('/api/reports/generate-from-scan')) {
        console.log('Detected POST /generate-from-scan, status', res.status());
        const json = await res.json().catch(() => null);
        generateResp = json;
        console.log('POST response body:', json);
      }
    } catch (e) {
      // ignore
    }
  });

  // Click the Download PDF button
  const [btn] = await page.$x("//button[contains(normalize-space(.),'Download PDF') or contains(normalize-space(.),'⬇️ Download PDF')]" );
  if (!btn) {
    console.error('Download button not found on page');
    await browser.close();
    process.exit(1);
  }

  console.log('Clicking Download PDF');
  await btn.click();

  // Wait up to 30s for the generate POST to be observed
  const start = Date.now();
  while (!generateResp && Date.now() - start < 30000) {
    await new Promise(r => setTimeout(r, 300));
  }

  if (!generateResp) {
    console.error('generate-from-scan POST not observed');
  } else if (!generateResp.reportId) {
    console.error('generate response has no reportId', generateResp);
  } else {
    console.log('Got reportId:', generateResp.reportId);
  }

  // Wait for a downloaded PDF file to appear
  const dlStart = Date.now();
  let downloadedFile = null;
  while (Date.now() - dlStart < 120000) {
    const files = fs.readdirSync(downloadDir).filter(f => f.toLowerCase().endsWith('.pdf'));
    if (files.length > 0) { downloadedFile = files[0]; break; }
    await new Promise(r => setTimeout(r, 500));
  }

  if (downloadedFile) {
    const p = path.join(downloadDir, downloadedFile);
    const s = fs.statSync(p);
    console.log('Download succeeded:', p, 'size', s.size);
  } else {
    console.error('No PDF download detected in', downloadDir);
  }

  await browser.close();
})();