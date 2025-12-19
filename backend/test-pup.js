const puppeteer = require('puppeteer');

(async () => {
    try {
        console.log('Launching Puppeteer...');
        const browser = await puppeteer.launch({
            headless: true,
            executablePath: '/usr/bin/chromium',
            args: [
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-dev-shm-usage',
                '--disable-gpu'
            ]
        });
        console.log('Success! Browser launched.');
        const page = await browser.newPage();
        console.log('Page created.');
        await browser.close();
        console.log('Browser closed.');
    } catch (e) {
        console.error('Puppeteer Error:', e);
        process.exit(1);
    }
})();
