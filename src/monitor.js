const axios = require('axios');
const cheerio = require('cheerio');
const { detectCredentials, scanForDomains } = require('./scanner');

// Social media platforms to monitor
const SOCIAL_SOURCES = [
  {
    name: 'Reddit',
    url: 'https://www.reddit.com/search/?q={domain}&sort=new',
    type: 'search'
  },
  {
    name: 'Twitter Search (Nitter)',
    url: 'https://nitter.net/search?f=tweets&q={domain}',
    type: 'html'
  }
];

class Monitor {
  constructor(domains, options = {}) {
    this.domains = domains;
    this.interval = options.interval || 30 * 60 * 1000;
    this.verbose = options.verbose || false;
    this.once = options.once || false;
    this.isRunning = false;
    this.lastCheck = null;
    this.findings = [];
  }

  async start() {
    this.isRunning = true;
    console.log('🚀 Starting social media monitoring...\n');

    await this.check();

    if (this.once) {
      console.log('\n✅ Single scan completed');
      this.printSummary();
      return;
    }

    console.log(`\n⏳ Continuous monitoring active. Checking every ${this.interval / 60000} minutes...`);
    console.log('Press Ctrl+C to stop.\n');

    this.intervalId = setInterval(async () => {
      await this.check();
    }, this.interval);
  }

  stop() {
    this.isRunning = false;
    if (this.intervalId) {
      clearInterval(this.intervalId);
    }
  }

  async check() {
    this.lastCheck = new Date();
    console.log(`\n[${this.lastCheck.toISOString()}] Checking social media...`);

    let totalScanned = 0;
    let threatsFound = 0;

    for (const source of SOCIAL_SOURCES) {
      try {
        if (this.verbose) {
          console.log(`  📂 Checking ${source.name}...`);
        }

        const posts = await this.fetchPosts(source);
        totalScanned += posts.length;

        for (const post of posts) {
          const findings = await this.analyzePost(post, source);
          if (findings.length > 0) {
            threatsFound += findings.length;
            this.findings.push(...findings);
            this.alert(findings);
          }
        }
      } catch (error) {
        console.error(`  ❌ Error checking ${source.name}: ${error.message}`);
      }
    }

    console.log(`  ✅ Scanned ${totalScanned} posts, found ${threatsFound} potential leak(s)`);
  }

  async fetchPosts(source) {
    const posts = [];
    
    for (const domain of this.domains) {
      try {
        const url = source.url.replace('{domain}', encodeURIComponent(domain));
        
        const response = await axios.get(url, {
          timeout: 10000,
          headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
          }
        });

        if (source.type === 'search') {
          const $ = cheerio.load(response.data);
          // Parse Reddit posts
          $('a[href*="/r/"]').each((i, el) => {
            const href = $(el).attr('href');
            const title = $(el).text();
            if (href && title) {
              posts.push({
                title: title,
                url: href.startsWith('http') ? href : `https://www.reddit.com${href}`,
                domain: domain
              });
            }
          });
        } else if (source.type === 'html') {
          const $ = cheerio.load(response.data);
          // Parse tweets
          $('.tweet').each((i, el) => {
            const content = $(el).text();
            const link = $(el).find('a').first().attr('href');
            if (content) {
              posts.push({
                title: content.substring(0, 100),
                url: link || url,
                domain: domain
              });
            }
          });
        }
      } catch (error) {
        if (this.verbose) {
          console.error(`    Error fetching ${domain}: ${error.message}`);
        }
      }
    }

    return posts;
  }

  async analyzePost(post, source) {
    const findings = [];
    const content = post.title;

    // Check for domain matches
    const domainMatches = scanForDomains(content, [post.domain]);
    
    if (domainMatches.length > 0) {
      const credentials = detectCredentials(content);
      
      if (credentials.length > 0) {
        findings.push({
          timestamp: new Date().toISOString(),
          source: source.name,
          title: post.title,
          url: post.url,
          matchedDomains: domainMatches,
          credentials: credentials,
          snippet: content.substring(0, 200)
        });
      }
    }

    return findings;
  }

  alert(findings) {
    for (const finding of findings) {
      console.log('\n🚨 ALERT: Potential Credential Leak Detected!');
      console.log('='.repeat(50));
      console.log(`Source: ${finding.source}`);
      console.log(`Title: ${finding.title}`);
      console.log(`URL: ${finding.url}`);
      console.log(`Matched Domains: ${finding.matchedDomains.join(', ')}`);
      console.log(`Credential Types: ${finding.credentials.join(', ')}`);
      console.log(`\nSnippet: ${finding.snippet}...`);
      console.log('='.repeat(50));
    }
  }

  printSummary() {
    console.log('\n📊 Summary');
    console.log('='.repeat(30));
    console.log(`Total findings: ${this.findings.length}`);
    
    if (this.findings.length > 0) {
      console.log('\nDetails:');
      for (const finding of this.findings) {
        console.log(`  - [${finding.timestamp}] ${finding.source}: ${finding.title.substring(0, 50)}`);
      }
    }
  }
}

module.exports = Monitor;
