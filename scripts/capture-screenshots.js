/**
 * Automated screenshot capture script for SafeWeb AI
 * Captures all pages at desktop and mobile resolutions
 * 
 * Usage: node scripts/capture-screenshots.js
 * Requires: npm install puppeteer
 */

import puppeteer from 'puppeteer';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

// ES module equivalent of __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Configuration
const BASE_URL = 'http://localhost:5173';
const OUTPUT_DIR = path.join(__dirname, '../screenshots');
const VIEWPORTS = {
  desktop: { width: 1440, height: 900, name: 'desktop' },
  tablet: { width: 768, height: 1024, name: 'tablet' },
  mobile: { width: 375, height: 812, name: 'mobile' },
};

// Pages to capture
const PAGES = [
  { path: '/', name: 'landing' },
  { path: '/login', name: 'login' },
  { path: '/register', name: 'register' },
  { path: '/dashboard', name: 'dashboard' },
  { path: '/scan', name: 'scan-website' },
  { path: '/history', name: 'scan-history' },
  { path: '/learn', name: 'learn' },
  { path: '/docs', name: 'documentation' },
  { path: '/services', name: 'services' },
  { path: '/about', name: 'about' },
  { path: '/contact', name: 'contact' },
  { path: '/profile', name: 'profile' },
  { path: '/admin', name: 'admin-dashboard' },
  { path: '/terms', name: 'terms' },
  { path: '/privacy', name: 'privacy' },
];

// Create output directory
if (!fs.existsSync(OUTPUT_DIR)) {
  fs.mkdirSync(OUTPUT_DIR, { recursive: true });
}

async function captureScreenshot(browser, page, viewport, pagePath, pageName) {
  try {
    console.log(`📸 Capturing: ${pageName} (${viewport.name})`);
    
    await page.setViewport({
      width: viewport.width,
      height: viewport.height,
      deviceScaleFactor: 2, // High-DPI for retina
    });
    
    await page.goto(`${BASE_URL}${pagePath}`, {
      waitUntil: 'networkidle0',
      timeout: 30000,
    });
    
    // Wait for animations to settle
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    // Optional: Wait for terminal background canvas
    await page.waitForSelector('canvas', { timeout: 5000 }).catch(() => {});
    
    const filename = `${pageName}-${viewport.name}.png`;
    const filepath = path.join(OUTPUT_DIR, filename);
    
    await page.screenshot({
      path: filepath,
      fullPage: true, // Capture entire page (scrollable content)
      type: 'png',
    });
    
    console.log(`✅ Saved: ${filename}`);
  } catch (error) {
    console.error(`❌ Failed to capture ${pageName} (${viewport.name}):`, error.message);
  }
}

async function captureAllPages() {
  console.log('🚀 Starting screenshot capture...\n');
  
  // Try to find Chrome on Windows
  const possiblePaths = [
    'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
    'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
    process.env.LOCALAPPDATA + '\\Google\\Chrome\\Application\\chrome.exe',
    process.env.PROGRAMFILES + '\\Google\\Chrome\\Application\\chrome.exe',
  ];
  
  let executablePath = possiblePaths.find(path => fs.existsSync(path));
  
  const browser = await puppeteer.launch({
    headless: 'new',
    executablePath: executablePath,
    args: ['--no-sandbox', '--disable-setuid-sandbox'],
  });
  
  const page = await browser.newPage();
  
  // Capture each page at each viewport size
  for (const viewport of Object.values(VIEWPORTS)) {
    console.log(`\n📱 Viewport: ${viewport.name} (${viewport.width}x${viewport.height})`);
    
    for (const pageConfig of PAGES) {
      await captureScreenshot(browser, page, viewport, pageConfig.path, pageConfig.name);
    }
  }
  
  await browser.close();
  
  console.log(`\n✅ All screenshots saved to: ${OUTPUT_DIR}`);
  console.log(`📊 Total: ${PAGES.length} pages × ${Object.keys(VIEWPORTS).length} viewports = ${PAGES.length * Object.keys(VIEWPORTS).length} images`);
}

// Run
captureAllPages().catch(console.error);
