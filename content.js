// 1. Expanded Database of Patterns (Targeting high-risk and structural formats)
const SENSITIVE_PATTERNS = {
    // ─── Original Patterns ────────────────────────────────────────────────────
    "Google API Key": /AIza[0-9A-Za-z\-]{35}/g,
    "OpenAI API Key": /sk-[a-zA-Z0-9]{20,}/g,
    "AWS Access Key": /AKIA[0-9A-Z]{16}/g,
    "GitHub Token": /(ghp|github_pat)_[0-9a-zA-Z_]{20,}/g,
    "Crypto Private Key / Seed": /\b[0-9a-fA-F]{64}\b/g,
    "RSA Private Key": /-----BEGIN RSA PRIVATE KEY-----/g,
    "Database Connection String": /(mongodb\+srv|postgres|mysql|redis):\/\/[^\s]+/g,
    "Database Connection Strings": /\b(Server|Data Source|jdbc|Initial Catalog|Database)=.+?;.*(Password|pwd|User ID|uid)=.+?;/gi,
    // NEW: "Generic" Heavy Net. This single line catches thousands of custom vendor API keys
    // by looking for the assignment syntax rather than a fixed vendor prefix!
    "Potential Custom API Key": /(?:key|api|token|secret|password|auth)[a-z0-9_ .\-,]{0,25}(?:=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([0-9a-zA-Z\-_=]{8,64})['"]/gi,

    // ─── Payment & Financial ──────────────────────────────────────────────────

    // Stripe live secret key: sk_live_... (20–250 alphanumeric chars after prefix)
    "Stripe Secret Key": /sk_live_[0-9a-zA-Z]{20,250}/g,

    // Stripe publishable key
    "Stripe Publishable Key": /pk_live_[0-9a-zA-Z]{20,250}/g,

    // Stripe restricted key
    "Stripe Restricted Key": /rk_live_[0-9a-zA-Z]{20,250}/g,

    // Stripe webhook signing secret
    "Stripe Webhook Secret": /whsec_[0-9a-zA-Z]{32,}/g,

    // PayPal client ID (18-char alphanumeric)
    "PayPal Client ID": /\bA[0-9A-Za-z]{17,80}(?=.*[A-Z])(?=.*[0-9])/g,

    // PayPal client secret
    "PayPal Client Secret": /(?:paypal[_\-. ]?(?:client[_\-. ]?)?secret\s*[:=]\s*)([A-Za-z0-9\-_]{32,})/gi,

    // Square access token
    "Square Access Token": /EAAA[a-zA-Z0-9\-_]{60,}/g,

    // Braintree tokenization key
    "Braintree Tokenization Key": /[0-9a-z]{8}_[0-9a-z]{4}_[0-9a-z]{4}_[0-9a-z]{4}_[0-9a-z]{12}/g,

    // ─── Communication & Messaging ────────────────────────────────────────────

    // Slack Bot/App/User OAuth token
    "Slack Token": /xox[baprs]-[0-9a-zA-Z\-]{10,250}/g,

    // Slack Webhook URL
    "Slack Webhook URL": /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8,}\/B[A-Z0-9]{8,}\/[a-zA-Z0-9]{24,}/g,

    // Slack Signing Secret (32-char hex)
    "Slack Signing Secret": /[0-9a-f]{32}/g,

    // Twilio Account SID
    "Twilio Account SID": /AC[a-f0-9]{32}/g,

    // Twilio Auth Token (32-char hex, often paired with SID)
    "Twilio Auth Token": /(?:twilio[_\-. ]?(?:auth[_\-. ]?)?token\s*[:=]\s*)([a-f0-9]{32})/gi,

    // Sendgrid API key
    "SendGrid API Key": /SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}/g,

    // Mailchimp API key: <key>-us<dc>
    "Mailchimp API Key": /[0-9a-f]{32}-us[0-9]{1,2}/g,

    // Mailgun API key
    "Mailgun API Key": /key-[0-9a-zA-Z]{32}/g,

    // Postmark server token
    "Postmark Server Token": /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g,

    // Vonage / Nexmo API secret
    "Vonage API Secret": /(?:vonage|nexmo)[_\-. ]?(?:api[_\-. ]?)?secret\s*[:=]\s*([A-Za-z0-9]{16,})/gi,

    // ─── Cloud Providers ──────────────────────────────────────────────────────

    // AWS Secret Access Key (always follows an Access Key ID)
    "AWS Secret Access Key": /(?:aws[_\-. ]?)?secret[_\-. ]?(?:access[_\-. ]?)?key\s*[:=]\s*([A-Za-z0-9\/+=]{40})/gi,

    // AWS Session Token (base64, >100 chars)
    "AWS Session Token": /(?:aws[_\-. ]?)?session[_\-. ]?token\s*[:=]\s*([A-Za-z0-9\/+=]{100,})/gi,

    // Azure Storage Account Key (base64, 88 chars)
    "Azure Storage Key": /(?:DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=)([A-Za-z0-9+\/]{86}==)/g,

    // Azure SAS Token
    "Azure SAS Token": /(?:sv=\d{4}-\d{2}-\d{2}&s[sco]=.{1,30}&sp=.{1,10}&se=\d{4}.+&sig=)[A-Za-z0-9%+\/=]{20,}/g,

    // Azure Client Secret (GUID-like with suffix)
    "Azure Client Secret": /(?:azure[_\-. ]?)?client[_\-. ]?secret\s*[:=]\s*([A-Za-z0-9~.\-_]{34,})/gi,

    // Google Cloud Service Account JSON (detection of the JSON structure)
    "GCP Service Account Key": /"type"\s*:\s*"service_account"/g,

    // Google OAuth2 Client Secret
    "Google OAuth Client Secret": /GOCSPX-[A-Za-z0-9\-_]{28}/g,
 
    // Heroku API Key (UUID-like)
    "Heroku API Key": /(?:heroku[_\-. ]?)?api[_\-. ]?key\s*[:=]\s*([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/gi,

    // Cloudflare API Token
    "Cloudflare API Token": /[A-Za-z0-9\-_]{40}/g,

    // Cloudflare Global API Key (32-char hex)
    "Cloudflare Global API Key": /(?:cloudflare[_\-. ]?)?(?:global[_\-. ]?)?api[_\-. ]?key\s*[:=]\s*([a-f0-9]{32,37})/gi,

    // DigitalOcean Personal Access Token
    "DigitalOcean Token": /dop_v1_[a-f0-9]{64}/g,

    // DigitalOcean OAuth token
    "DigitalOcean OAuth Token": /doo_v1_[a-f0-9]{64}/g,

    // Linode Personal Access Token
    "Linode API Token": /(?:linode[_\-. ]?)?(?:api[_\-. ]?)?token\s*[:=]\s*([A-Za-z0-9]{64})/gi,

    // Vultr API Key
    "Vultr API Key": /(?:vultr[_\-. ]?)?api[_\-. ]?key\s*[:=]\s*([A-Z0-9]{36})/gi,

    // ─── Source Control & DevOps ──────────────────────────────────────────────

    // GitLab Personal Access Token
    "GitLab Personal Access Token": /glpat-[0-9a-zA-Z\-_]{20}/g,

    // GitLab Deploy Token
    "GitLab Deploy Token": /gldt-[0-9a-zA-Z\-_]{20}/g,

    // GitLab Runner Token
    "GitLab Runner Token": /GR1348941[0-9a-zA-Z\-_]{20}/g,

    // Bitbucket App Password
    "Bitbucket App Password": /(?:bitbucket[_\-. ]?)?(?:app[_\-. ]?)?password\s*[:=]\s*([A-Za-z0-9]{16,})/gi,

    // npm Access Token
    "npm Access Token": /npm_[A-Za-z0-9]{36}/g,

    // CircleCI Personal API Token
    "CircleCI API Token": /(?:circleci[_\-. ]?)?(?:api[_\-. ]?)?token\s*[:=]\s*([a-f0-9]{40})/gi,

    // Travis CI Token
    "Travis CI Token": /(?:travis[_\-. ]?)?(?:api[_\-. ]?)?token\s*[:=]\s*([A-Za-z0-9\-_]{22,})/gi,

    // Terraform Cloud API Token
    "Terraform Cloud Token": /[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9\-_]{60,}/g,

    // Docker Hub Personal Access Token
    "Docker Hub Token": /dckr_pat_[A-Za-z0-9\-_]{27}/g,

    // ─── Analytics & Monitoring ───────────────────────────────────────────────

    // Datadog API Key (32-char hex)
    "Datadog API Key": /(?:datadog[_\-. ]?)?api[_\-. ]?key\s*[:=]\s*([a-f0-9]{32})/gi,

    // Datadog Application Key (40-char hex)
    "Datadog App Key": /(?:datadog[_\-. ]?)?(?:app|application)[_\-. ]?key\s*[:=]\s*([a-f0-9]{40})/gi,

    // New Relic License Key
    "New Relic License Key": /NRAK-[A-Z0-9]{27}/g,

    // New Relic Insert Key
    "New Relic Insert Key": /NRII-[A-Za-z0-9\-_]{32}/g,

    // Sentry DSN (contains secret in URL)
    "Sentry DSN": /https:\/\/[a-f0-9]{32}@o[0-9]+\.ingest\.sentry\.io\/[0-9]+/g,

    // Mixpanel Project Token
    "Mixpanel Token": /(?:mixpanel[_\-. ]?)?(?:project[_\-. ]?)?token\s*[:=]\s*([a-f0-9]{32})/gi,

    // Segment Write Key
    "Segment Write Key": /(?:segment[_\-. ]?)?write[_\-. ]?key\s*[:=]\s*([A-Za-z0-9]{30,})/gi,

    // ─── Infrastructure & Storage ─────────────────────────────────────────────

    // Cloudinary API Secret
    "Cloudinary API Secret": /(?:cloudinary[_\-. ]?)?api[_\-. ]?secret\s*[:=]\s*([A-Za-z0-9\-_]{27,})/gi,

    // Cloudinary URL (includes key + secret)
    "Cloudinary URL": /cloudinary:\/\/[0-9]{6,}:[A-Za-z0-9\-_]{27,}@[a-z0-9\-]+/g,

    // Firebase Web API Key
    "Firebase API Key": /AIza[0-9A-Za-z\-]{35}/g,

    // Firebase Service Account private key (PEM inline)
    "Firebase Private Key": /-----BEGIN PRIVATE KEY-----[\\n\s]+[A-Za-z0-9+\/=\s\\n]+-----END PRIVATE KEY-----/g,

    // Supabase service role key (JWT-like starting with eyJ)
    "Supabase Service Role Key": /eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+/g,

    // PlanetScale service token
    "PlanetScale Service Token": /pscale_tkn_[A-Za-z0-9\-_]{32,}/g,

    // PlanetScale OAuth token
    "PlanetScale OAuth Token": /pscale_oauth_[A-Za-z0-9\-_]{32,}/g,

    // Vercel Access Token
    "Vercel Access Token": /(?:vercel[_\-. ]?)?(?:access[_\-. ]?)?token\s*[:=]\s*([A-Za-z0-9]{24})/gi,

    // ─── AI & ML Providers ────────────────────────────────────────────────────

    // Anthropic API Key
    "Anthropic API Key": /sk-ant-[a-zA-Z0-9\-_]{32,}/g,

    // Hugging Face Access Token
    "Hugging Face Token": /hf_[A-Za-z0-9]{34,}/g,

    // Cohere API Key
    "Cohere API Key": /(?:cohere[_\-. ]?)?api[_\-. ]?key\s*[:=]\s*([A-Za-z0-9\-_]{40})/gi,

    // Replicate API Token
    "Replicate API Token": /r8_[A-Za-z0-9]{37}/g,

    // ─── Social & Marketing ───────────────────────────────────────────────────

    // Twitter / X Bearer Token
    "Twitter Bearer Token": /AAAAAAAAAA[A-Za-z0-9%\-_]{80,}/g,

    // Twitter API Secret
    "Twitter API Secret": /(?:twitter[_\-. ]?)?(?:api[_\-. ]?)?secret\s*[:=]\s*([A-Za-z0-9]{45,})/gi,

    // Facebook App Secret
    "Facebook App Secret": /(?:facebook|fb)[_\-. ]?(?:app[_\-. ]?)?secret\s*[:=]\s*([a-f0-9]{32})/gi,

    // Facebook Access Token
    "Facebook Access Token": /EAA[A-Za-z0-9]{20,}/g,

    // HubSpot API Key (legacy GUID)
    "HubSpot API Key": /(?:hubspot[_\-. ]?)?(?:api[_\-. ]?)?key\s*[:=]\s*([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})/gi,

    // HubSpot Private App Token
    "HubSpot Private App Token": /pat-[a-z]{2}1-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/g,

    // Shopify Admin API Key
    "Shopify Admin API Key": /shpat_[a-fA-F0-9]{32}/g,

    // Shopify Storefront Access Token
    "Shopify Storefront Token": /shpss_[a-fA-F0-9]{32}/g,

    // ─── Generic Credentials (high-signal patterns) ───────────────────────────

    // Generic Bearer token in Authorization headers
    "Bearer Token (Authorization Header)": /Authorization:\s*Bearer\s+([A-Za-z0-9\-_=.]{20,})/gi,

    // Generic Basic Auth credentials in a URL
    "Basic Auth in URL": /https?:\/\/[^:\s]+:[^@\s]{6,}@[^\s]+/g,

    // PEM-encoded private key (generic, catches EC, DSA, ECDSA, etc.)
    "PEM Private Key": /-----BEGIN (?:EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/g,

    // JWT (header.payload.signature) — any token, not just Supabase
    "JSON Web Token (JWT)": /eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+/g,

    // Generic high-entropy secret assignment (e.g. SECRET=abcXYZ123... in .env files)
    "High-Entropy Secret Assignment (.env style)": /^(?:export\s+)?[A-Z][A-Z0-9_]{3,}(?:_KEY|_SECRET|_TOKEN|_PASSWORD|_PWD|_CREDENTIAL)\s*=\s*(?!https?:\/\/)(?!<)[^\s]{8,}/gm,
};

document.addEventListener('paste', function (e) {
    const pastedText = (e.clipboardData || window.clipboardData).getData('text');
    let detectedSecrets = [];

    
    for (const [keyName, regex] of Object.entries(SENSITIVE_PATTERNS)) {

        // FIX: Using .match() instead of .test() stops the pointer bug!
        const matches = pastedText.match(regex);

        if (matches) {
            detectedSecrets.push(keyName);
        }
    }

    if (detectedSecrets.length > 0) {
        e.preventDefault();
        e.stopPropagation();
        showWarningModal(pastedText, e.target, detectedSecrets);
    }
}, true);

// 2. The Auto-Redaction Function
function redactText(text) {
    let cleanText = text;

    // Clean exact API patterns
    cleanText = cleanText.replace(/sk-[a-zA-Z0-9]{20,}/g, "[HIDDEN_OPENAI_KEY]");
    cleanText = cleanText.replace(/AIza[0-9A-Za-z\-]{35}/g, "[HIDDEN_GOOGLE_KEY]");
    cleanText = cleanText.replace(/AKIA[0-9A-Z]{16}/g, "[HIDDEN_AWS_KEY]");
    cleanText = cleanText.replace(/(ghp|github_pat)_[0-9a-zA-Z_]{20,}/g, "[HIDDEN_GITHUB_TOKEN]");

    // Clean generic database credentials
    cleanText = cleanText.replace(/(password|pwd|passwd|User ID|uid)=([^;]+)/gi, "$1=[HIDDEN_CREDENTIAL]");

    return cleanText;
}

function showWarningModal(text, targetInput, secretsFound) {
    if (document.getElementById('ai-warden-modal')) return;

    const modal = document.createElement('div');
    modal.id = 'ai-warden-modal';

    // CHANGED: We map the tags to say "May be: [Secret Name]"
    const secretsListHTML = secretsFound.map(s => `<span class="secret-tag"> ${s}</span>`).join(' ');

    modal.innerHTML = `
        <div class="ai-warden-content">
            <h3 style="color: #ff9f1a;">⚠️ Pause and Review</h3>
            <p>We detected patterns that look like sensitive credentials. Please review the highlighted snippets before sending them to a public AI.</p>
            
            <div class="detected-box">
                <strong>Potential Matches:</strong> ${secretsListHTML}
            </div>

            <div class="text-preview">
                "${text.substring(0, 150)}${text.length > 150 ? '...' : ''}"
            </div>

            <div class="actions">
                <button id="cancel-paste" class="btn-secondary">Cancel</button>
                <button id="redact-paste" class="btn-primary" style="background: #ffa500; color: black;">Redact & Paste</button>
                <button id="confirm-paste" class="btn-primary">Paste Anyway</button>
            </div>
        </div>
    `;

    document.body.appendChild(modal);

    // Event Listeners remain exactly the same
    document.getElementById('cancel-paste').addEventListener('click', () => {
        modal.remove();
    });

    document.getElementById('redact-paste').addEventListener('click', () => {
        const cleanedText = redactText(text);
        simulateHumanPaste(targetInput, cleanedText);
        modal.remove();
    });

    document.getElementById('confirm-paste').addEventListener('click', () => {
        simulateHumanPaste(targetInput, text);
        modal.remove();
    });
}
// ─── NEW HELPER FUNCTION ─────────────────────────────────────────────────────
// This forces heavy JS apps (React/Vue used by AI sites) to know text was entered
function simulateHumanPaste(element, text) {
    element.focus();

    // Insert the text
    document.execCommand('insertText', false, text);

    // Fire an input event so the website knows the value changed!
    const event = new Event('input', { bubbles: true });
    element.dispatchEvent(event);
}