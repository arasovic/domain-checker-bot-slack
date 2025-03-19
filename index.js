// ES Modules (ESM) formatında import ifadeleri
import 'dotenv/config';
import whoisImport from 'whois';
import { WebClient } from '@slack/web-api';
import cron from 'node-cron';
import moment from 'moment';
import { promisify } from 'util';
import fs from 'fs/promises';
import fetch from 'node-fetch';

// Convert whois.lookup to promise
const whoisLookup = promisify(whoisImport.lookup);

// Initialize Slack client
const slack = new WebClient(process.env.SLACK_TOKEN);
const slackChannel = process.env.SLACK_CHANNEL;

// Get domains from .env file
const domains = process.env.DOMAINS.split(',').map(domain => domain.trim());
const warningDays = parseInt(process.env.WARNING_DAYS) || 30;

// Debug mode for more detailed logging
const DEBUG = process.env.DEBUG === 'true';

// Use RDAP instead of WHOIS
const USE_RDAP = process.env.USE_RDAP === 'true';

/**
 * Get domain type (e.g. standard or LDAP)
 * @param {string} domain - Domain name
 * @returns {string} - Domain type
 */
function getDomainType(domain) {
  if (domain.includes('ldap') || domain.endsWith('.ldap')) {
    return 'ldap';
  }
  return 'standard';
}

/**
 * Save raw data to file for debugging
 * @param {string} domain - Domain name
 * @param {string} data - Raw WHOIS or RDAP data
 * @param {string} type - Type of data ('whois' or 'rdap')
 */
async function saveDataToFile(domain, data, type = 'whois') {
  if (!DEBUG) return;
  
  try {
    const fileName = `debug_${type}_${domain.replace(/\./g, '_')}.txt`;
    await fs.writeFile(fileName, typeof data === 'object' ? JSON.stringify(data, null, 2) : data, 'utf8');
    console.log(`Debug data saved to ${fileName}`);
  } catch (error) {
    console.error(`Error saving debug data: ${error.message}`);
  }
}

/**
 * Get domain expiration date using RDAP
 * @param {string} domain - Domain name
 * @returns {Date|null} - Expiration date or null if not found
 */
async function getRdapExpirationDate(domain) {
  try {
    console.log(`Fetching RDAP data for ${domain}`);
    
    // Extract TLD to determine the RDAP server
    const tld = domain.split('.').pop();
    
    // First, try direct IANA RDAP server
    const ianaUrl = `https://rdap.org/domain/${domain}`;
    
    console.log(`Trying RDAP query: ${ianaUrl}`);
    const response = await fetch(ianaUrl, {
      headers: {
        'Accept': 'application/rdap+json'
      }
    });
    
    // Check if successful
    if (!response.ok) {
      console.warn(`RDAP query failed with status: ${response.status}`);
      
      // Try alternative RDAP endpoints
      const alternativeUrls = [
        `https://rdap.verisign.com/com/v1/domain/${domain}`,
        `https://rdap.registry.in/domain/${domain}`,
        `https://rdap.nic.${tld}/domain/${domain}`
      ];
      
      for (const url of alternativeUrls) {
        try {
          console.log(`Trying alternative RDAP endpoint: ${url}`);
          const altResponse = await fetch(url, {
            headers: {
              'Accept': 'application/rdap+json'
            }
          });
          
          if (altResponse.ok) {
            const rdapData = await altResponse.json();
            await saveDataToFile(domain, rdapData, 'rdap');
            
            // Extract expiration date
            if (rdapData.events) {
              const expiryEvent = rdapData.events.find(event => 
                event.eventAction === 'expiration' || 
                event.eventAction === 'registration expiration');
              
              if (expiryEvent && expiryEvent.eventDate) {
                console.log(`RDAP expiry date found: ${expiryEvent.eventDate}`);
                return new Date(expiryEvent.eventDate);
              }
            }
          }
        } catch (altError) {
          console.error(`Error with alternative RDAP endpoint: ${altError.message}`);
        }
      }
      
      return null;
    }
    
    const rdapData = await response.json();
    await saveDataToFile(domain, rdapData, 'rdap');
    
    // Extract expiration date from RDAP response
    if (rdapData.events) {
      const expiryEvent = rdapData.events.find(event => 
        event.eventAction === 'expiration' || 
        event.eventAction === 'registration expiration');
      
      if (expiryEvent && expiryEvent.eventDate) {
        console.log(`RDAP expiry date found: ${expiryEvent.eventDate}`);
        return new Date(expiryEvent.eventDate);
      }
    }
    
    console.warn('No expiration date found in RDAP data');
    return null;
  } catch (error) {
    console.error(`Error fetching RDAP data: ${error.message}`);
    return null;
  }
}

/**
 * Parse expiration date from whois data
 * @param {string} whoisData - Raw whois data
 * @param {string} domainType - Type of domain (standard or ldap)
 * @returns {Date|null} - Expiration date or null if not found
 */
function parseExpirationDate(whoisData, domainType = 'standard') {
  if (!whoisData) return null;
  
  if (DEBUG) {
    console.log('Parsing WHOIS data:');
    console.log('-------------------');
    console.log(whoisData.substring(0, 500) + '...');
    console.log('-------------------');
  }
  
  // Common patterns for expiration dates in whois data
  const patterns = [
    // Standard domain patterns
    /Registry Expiry Date: (.+)/i,
    /Expiration Date: (.+)/i,
    /Expiry Date: (.+)/i,
    /Expiry date: (.+)/i,
    /Expires on: (.+)/i,
    /Expires: (.+)/i,
    /expire: (.+)/i,
    /Registry Expiry Date:\s*(.+)/i,
    /Registrar Registration Expiration Date:\s*(.+)/i,
    /Domain Expiration Date:\s*(.+)/i,
    /Domain Expires:\s*(.+)/i,
    /Registrar Registration Expiration Date: (.+)/i,
    /expire-date:\s*(.+)/i,
    /Valid Until:\s*(.+)/i,
    /Renewal date:\s*(.+)/i,
    /paid-till:\s*(.+)/i,
    /validity:\s*(.+)/i,
    // LDAP specific patterns (if needed)
    /LDAP Expiration Date: (.+)/i,
    /LDAP Certificate Expiry: (.+)/i,
    /certificate expiration date: (.+)/i
  ];

  // Specific handling for LDAP domains if needed
  if (domainType === 'ldap') {
    // Add any LDAP-specific parsing logic here
    console.log('Processing as LDAP domain');
    // For LDAP domains, you might need to query specific services
    // This is a placeholder for potential LDAP-specific logic
  }
  
  for (const pattern of patterns) {
    const match = whoisData.match(pattern);
    if (match && match[1]) {
      const rawDate = match[1].trim();
      // Try to parse the date
      try {
        if (DEBUG) console.log(`Found date match: ${rawDate}`);
        return new Date(rawDate);
      } catch (e) {
        console.error(`Failed to parse date: ${rawDate}`, e);
      }
    }
  }
  
  // If we couldn't find a date with the patterns above, log the beginning of the WHOIS data for debugging
  console.warn('Could not find expiration date in WHOIS data');
  return null;
}

/**
 * Check a domain and send notification if expiration is approaching
 * @param {string} domain - Domain to check
 */
async function checkDomain(domain) {
  try {
    console.log(`Checking domain: ${domain}`);
    const domainType = getDomainType(domain);
    
    let expirationDate = null;
    
    // Try RDAP first if enabled
    if (USE_RDAP) {
      expirationDate = await getRdapExpirationDate(domain);
    }
    
    // Fall back to WHOIS if RDAP failed or is disabled
    if (!expirationDate && !USE_RDAP) {
      // Get WHOIS data
      const whoisData = await whoisLookup(domain);
      
      // Save raw WHOIS data for debugging if enabled
      await saveDataToFile(domain, whoisData, 'whois');
      
      // Parse expiration date
      expirationDate = parseExpirationDate(whoisData, domainType);
    }
    
    if (!expirationDate) {
      console.error(`Could not find expiration date for ${domain}`);
      
      // Send notification about the error if configured
      if (process.env.NOTIFY_ERRORS === 'true') {
        const errorMessage = {
          channel: slackChannel,
          text: `Could not find expiration date for domain: ${domain}`, // Added fallback text
          blocks: [
            {
              type: "header",
              text: {
                type: "plain_text",
                text: "⚠️ Domain Check Error",
                emoji: true
              }
            },
            {
              type: "section",
              text: {
                type: "mrkdwn",
                text: `Could not find expiration date for domain: *${domain}*\n\nPlease check the domain manually or verify the data output format.`
              }
            }
          ]
        };
        await slack.chat.postMessage(errorMessage);
        console.log(`Error notification sent for ${domain}`);
      }
      return;
    }
    
    const now = new Date();
    const daysRemaining = Math.ceil((expirationDate - now) / (1000 * 60 * 60 * 24));
    
    console.log(`Domain: ${domain}, Expires: ${expirationDate.toISOString()}, Days remaining: ${daysRemaining}`);
    
    // Send notification if domain is expiring soon
    if (daysRemaining <= warningDays) {
      const formattedDate = moment(expirationDate).format('MMMM Do, YYYY');
      
      let emoji = '🟢';
      if (daysRemaining <= 7) {
        emoji = '🔴';
      } else if (daysRemaining <= 14) {
        emoji = '🟠';
      } else if (daysRemaining <= 30) {
        emoji = '🟡';
      }
      
      const message = {
        channel: slackChannel,
        text: `Domain ${domain} will expire in ${daysRemaining} days (${formattedDate})`, // Added fallback text
        blocks: [
          {
            type: "header",
            text: {
              type: "plain_text",
              text: `${emoji} Domain Expiration Warning`,
              emoji: true
            }
          },
          {
            type: "section",
            fields: [
              {
                type: "mrkdwn",
                text: `*Domain:*\n${domain}`
              },
              {
                type: "mrkdwn",
                text: `*Expiration Date:*\n${formattedDate}`
              }
            ]
          },
          {
            type: "section",
            text: {
              type: "mrkdwn",
              text: `This domain will expire in *${daysRemaining} days*. Please renew it if needed.`
            }
          },
          {
            type: "divider"
          }
        ]
      };
      
      const result = await slack.chat.postMessage(message);
      console.log(`Notification sent for ${domain}`);
    }
  } catch (error) {
    console.error(`Error checking domain ${domain}:`, error);
    
    // Send error notification if configured
    if (process.env.NOTIFY_ERRORS === 'true') {
      try {
        const errorMessage = {
          channel: slackChannel,
          text: `Error checking domain ${domain}: ${error.message}`, // Added fallback text
          blocks: [
            {
              type: "header",
              text: {
                type: "plain_text",
                text: "🚨 Domain Check Error",
                emoji: true
              }
            },
            {
              type: "section",
              text: {
                type: "mrkdwn",
                text: `Error checking domain: *${domain}*\n\n\`\`\`${error.message}\`\`\``
              }
            }
          ]
        };
        await slack.chat.postMessage(errorMessage);
        console.log(`Error notification sent for ${domain}`);
      } catch (slackError) {
        console.error('Error sending error notification to Slack:', slackError);
      }
    }
  }
}

/**
 * Check LDAP domain expiration
 * @param {string} domain - LDAP domain to check
 */
async function checkLDAPDomain(domain) {
  console.log(`Checking LDAP domain: ${domain}`);
  // This function would implement specific logic for LDAP domains
  // For now, we'll use the same checkDomain function with the domain type flag
  await checkDomain(domain);
}

/**
 * Check all domains
 */
async function checkAllDomains() {
  console.log(`Starting domain check at ${new Date().toISOString()}`);
  
  for (const domain of domains) {
    if (domain.includes('ldap') || domain.endsWith('.ldap')) {
      await checkLDAPDomain(domain);
    } else {
      await checkDomain(domain);
    }
    // Add a small delay between checks to avoid rate limiting
    await new Promise(resolve => setTimeout(resolve, 2000));
  }
  
  console.log(`Completed domain check at ${new Date().toISOString()}`);
}

// Run once at startup
checkAllDomains();

// Schedule regular checks using cron
const cronSchedule = process.env.CRON_SCHEDULE || "0 9 * * *";
cron.schedule(cronSchedule, checkAllDomains);

console.log(`Domain checker bot started. Checking domains: ${domains.join(', ')}`);
console.log(`Scheduled to run at: ${cronSchedule}`);
console.log(`Using ${USE_RDAP ? 'RDAP' : 'WHOIS'} for domain checks`);