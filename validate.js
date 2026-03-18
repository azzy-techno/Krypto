/* ═══════════════════════════════════════════════════════════════
   KRYPTO — validate.js
   Full contact form validation & security layer
   Protections: SQL injection, XSS, spam patterns, bot honeypot,
                rate limiting, profanity filter, malicious URLs
═══════════════════════════════════════════════════════════════ */

(function () {
    'use strict';

    /* ── CONFIG ────────────────────────────────────────────── */
    const RATE_LIMIT_MS   = 60 * 1000;   // 1 submit per minute
    const MAX_SUBMITS     = 3;            // max 3 submits per session
    const MIN_MSG_LENGTH  = 20;
    const MAX_MSG_LENGTH  = 2000;

    /* ── STATE ─────────────────────────────────────────────── */
    let lastSubmitTime  = 0;
    let submitCount     = parseInt(sessionStorage.getItem('kts_submits') || '0', 10);
    let isSubmitting    = false;

    /* ── PATTERN LIBRARY ───────────────────────────────────── */

    // SQL injection keywords & patterns
    const SQL_PATTERNS = [
        /(\b)(select|insert|update|delete|drop|alter|create|truncate|exec|execute|union|declare|cast|convert|char|nchar|varchar|nvarchar|xp_|sp_|0x)(\b)/i,
        /(--|;|\/\*|\*\/|xp_|@@|sys\.|information_schema)/i,
        /('|('')|`|´|″|‟)(.*?)(or|and)(\s+)(1=1|'1'='1'|true)/i,
        /\b(or|and)\b\s+\d+\s*=\s*\d+/i,
        /'\s*(or|and)\s*'/i,
    ];

    // XSS / script injection patterns
    const XSS_PATTERNS = [
        /<\s*(script|iframe|object|embed|form|input|button|link|style|img|svg|video|audio|meta|base)[^>]*>/i,
        /javascript\s*:/i,
        /on\w+\s*=\s*["'`]/i,              // onclick=, onerror=, etc.
        /data\s*:\s*text\s*\/\s*(html|javascript)/i,
        /&#(x[0-9a-f]+|[0-9]+);/i,         // HTML entities used for obfuscation
        /(vbscript|livescript|mocha)\s*:/i,
        /expression\s*\(/i,
    ];

    // Spam / scam trigger phrases
    const SPAM_PATTERNS = [
        /\b(click here|buy now|free offer|limited time|act now|guaranteed|winner|you have won|congratulations|dear friend|million dollar|lottery|inheritance|nigerian prince|wire transfer|western union|money transfer|make money fast|work from home|earn \$|100% free|no cost|risk free|opt.?in|unsubscribe|bulk email|mass email)\b/i,
        /\b(viagra|cialis|casino|poker|betting|gambling|crypto investment|bitcoin profit|nft drop|forex signal)\b/i,
    ];

    // Malicious URL patterns in message body
    const URL_SPAM_PATTERN = /(https?:\/\/[^\s]+){3,}/i;  // 3+ URLs = spam

    // Profanity — basic list, extend as needed
    const PROFANITY = [
        /\bf+u+c+k+\b/i, /\bs+h+i+t+\b/i, /\ba+s+s+h+o+l+e+\b/i,
        /\bb+i+t+c+h+\b/i, /\bc+u+n+t+\b/i, /\bd+i+c+k+\b/i,
        /\bp+u+s+s+y+\b/i, /\bw+h+o+r+e+\b/i, /\bn+i+g+g+[ae]+r+\b/i,
    ];

    // Disposable / throwaway email domains
    const DISPOSABLE_DOMAINS = new Set([
        'mailinator.com','guerrillamail.com','throwaway.email','temp-mail.org',
        'fakeinbox.com','maildrop.cc','yopmail.com','trashmail.com',
        'getnada.com','sharklasers.com','guerrillamailblock.com','grr.la',
        'guerrillamail.info','guerrillamail.biz','guerrillamail.de',
        'spam4.me','tempinbox.com','dispostable.com','mailnull.com',
        'spamgourmet.com','10minutemail.com','getairmail.com','filzmail.com',
    ]);

    /* ── HELPERS ───────────────────────────────────────────── */

    function stripTags(str) {
        return str.replace(/<[^>]*>/g, '');
    }

    function normalize(str) {
        // collapse unicode lookalikes, excess whitespace
        return str
            .replace(/[\u00AD\u200B-\u200F\u2028\u2029\uFEFF]/g, '')  // zero-width chars
            .replace(/\s+/g, ' ')
            .trim();
    }

    function testPatterns(value, patterns) {
        return patterns.some(p => p.test(value));
    }

    function getEmailDomain(email) {
        const parts = email.split('@');
        return parts.length === 2 ? parts[1].toLowerCase().trim() : '';
    }

    /* ── FIELD VALIDATORS ──────────────────────────────────── */

    const validators = {

        name(value) {
            const v = normalize(stripTags(value));
            if (!v)                              return 'Name is required.';
            if (v.length < 2)                    return 'Name must be at least 2 characters.';
            if (v.length > 80)                   return 'Name must be under 80 characters.';
            if (!/^[\p{L}\s'\-\.]+$/u.test(v))  return 'Name contains invalid characters.';
            if (testPatterns(v, SQL_PATTERNS))   return 'Invalid characters detected in name.';
            if (testPatterns(v, XSS_PATTERNS))   return 'Invalid content detected.';
            return null;
        },

        company(value) {
            const v = normalize(stripTags(value));
            if (!v)                              return 'Company name is required.';
            if (v.length < 2)                    return 'Company name must be at least 2 characters.';
            if (v.length > 100)                  return 'Company name must be under 100 characters.';
            if (testPatterns(v, SQL_PATTERNS))   return 'Invalid characters detected.';
            if (testPatterns(v, XSS_PATTERNS))   return 'Invalid content detected.';
            return null;
        },

        email(value) {
            const v = normalize(value).toLowerCase();
            if (!v)                              return 'Email address is required.';
            // RFC 5322 simplified
            if (!/^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/.test(v))
                                                 return 'Please enter a valid email address.';
            if (v.length > 150)                  return 'Email address is too long.';
            if ((v.match(/@/g) || []).length > 1) return 'Invalid email address.';
            if (DISPOSABLE_DOMAINS.has(getEmailDomain(v)))
                                                 return 'Disposable email addresses are not accepted.';
            if (testPatterns(v, SQL_PATTERNS))   return 'Invalid characters in email.';
            if (testPatterns(v, XSS_PATTERNS))   return 'Invalid content in email.';
            return null;
        },

        phone(value) {
            const v = normalize(value).replace(/[\s\-\(\)\.]/g, '');
            if (!v)                              return 'Contact number is required.';
            if (!/^\+?[0-9]{7,15}$/.test(v))    return 'Enter a valid phone number (7–15 digits).';
            return null;
        },

        message(value) {
            const v = normalize(stripTags(value));
            if (!v)                              return 'Message is required.';
            if (v.length < MIN_MSG_LENGTH)       return `Message must be at least ${MIN_MSG_LENGTH} characters. Tell us more about your needs.`;
            if (v.length > MAX_MSG_LENGTH)       return `Message must be under ${MAX_MSG_LENGTH} characters.`;
            if (testPatterns(v, SQL_PATTERNS))   return 'Your message contains characters that are not allowed.';
            if (testPatterns(v, XSS_PATTERNS))   return 'Your message contains content that is not allowed.';
            if (testPatterns(v, SPAM_PATTERNS))  return 'Your message looks like spam. Please write a genuine enquiry.';
            if (URL_SPAM_PATTERN.test(v))        return 'Too many URLs detected. Please write a genuine message.';
            if (testPatterns(v, PROFANITY))      return 'Please keep your message professional and respectful.';
            // Repetition check — same char repeated 8+ times
            if (/(.)\1{7,}/.test(v))             return 'Message contains too many repeated characters.';
            // All caps check (if > 60 chars and > 70% caps)
            if (v.length > 60) {
                const upper = (v.match(/[A-Z]/g) || []).length;
                const alpha = (v.match(/[a-zA-Z]/g) || []).length;
                if (alpha > 0 && upper / alpha > 0.7) return 'Please do not write in all capitals.';
            }
            return null;
        },
    };

    /* ── FIELD MAP (fieldId → validator key) ───────────────── */
    const fieldMap = {
        fname:    'name',
        fcompany: 'company',
        femail:   'email',
        fphone:   'phone',
        fmessage: 'message',
    };

    /* ── UI HELPERS ────────────────────────────────────────── */

    function showError(fieldId, msg) {
        const input = document.getElementById(fieldId);
        const errEl = document.getElementById('err-' + fieldId);
        if (!input || !errEl) return;
        input.classList.add('field-invalid');
        input.classList.remove('field-valid');
        errEl.textContent = msg;
        errEl.style.display = 'block';
    }

    function showValid(fieldId) {
        const input = document.getElementById(fieldId);
        const errEl = document.getElementById('err-' + fieldId);
        if (!input || !errEl) return;
        input.classList.remove('field-invalid');
        input.classList.add('field-valid');
        errEl.textContent = '';
        errEl.style.display = 'none';
    }

    function clearField(fieldId) {
        const input = document.getElementById(fieldId);
        const errEl = document.getElementById('err-' + fieldId);
        if (input) { input.classList.remove('field-invalid', 'field-valid'); }
        if (errEl) { errEl.textContent = ''; errEl.style.display = 'none'; }
    }

    function showBanner(type, msg) {
        const successEl = document.getElementById('formSuccess');
        const errorEl   = document.getElementById('formError');
        const errorText = document.getElementById('formErrorText');
        if (type === 'success') {
            if (successEl) { successEl.style.display = 'flex'; }
            if (errorEl)   { errorEl.style.display   = 'none'; }
        } else {
            if (errorEl)   { errorEl.style.display   = 'flex'; }
            if (successEl) { successEl.style.display = 'none'; }
            if (errorText && msg) errorText.textContent = msg;
        }
    }

    function hideBanners() {
        const successEl = document.getElementById('formSuccess');
        const errorEl   = document.getElementById('formError');
        if (successEl) successEl.style.display = 'none';
        if (errorEl)   errorEl.style.display   = 'none';
    }

    function setSubmitting(state) {
        isSubmitting = state;
        const btn      = document.getElementById('submitBtn');
        const label    = btn && btn.querySelector('.btn-label');
        const loading  = btn && btn.querySelector('.btn-loading');
        if (!btn) return;
        btn.disabled = state;
        if (label)   label.style.display  = state ? 'none'   : 'inline-flex';
        if (loading) loading.style.display = state ? 'inline-flex' : 'none';
    }

    /* ── VALIDATE SINGLE FIELD ─────────────────────────────── */

    function validateField(fieldId) {
        const validatorKey = fieldMap[fieldId];
        if (!validatorKey) return true;
        const input = document.getElementById(fieldId);
        if (!input) return true;
        const error = validators[validatorKey](input.value);
        if (error) { showError(fieldId, error); return false; }
        showValid(fieldId);
        return true;
    }

    /* ── VALIDATE ENTIRE FORM ──────────────────────────────── */

    function validateAll() {
        let valid = true;
        Object.keys(fieldMap).forEach(id => {
            if (!validateField(id)) valid = false;
        });
        return valid;
    }

    /* ── RATE LIMIT CHECK ──────────────────────────────────── */

    function checkRateLimit() {
        const now = Date.now();
        if (submitCount >= MAX_SUBMITS) {
            showBanner('error', 'You have reached the maximum number of submissions per session. Please contact us directly by phone or email.');
            return false;
        }
        if (now - lastSubmitTime < RATE_LIMIT_MS) {
            const wait = Math.ceil((RATE_LIMIT_MS - (now - lastSubmitTime)) / 1000);
            showBanner('error', `Please wait ${wait} second${wait !== 1 ? 's' : ''} before submitting again.`);
            return false;
        }
        return true;
    }

    /* ── HONEYPOT CHECK ────────────────────────────────────── */

    function checkHoneypot() {
        const hp = document.getElementById('_gotcha');
        // If honeypot field has any value, it's a bot — silently "succeed"
        return !hp || hp.value === '';
    }

    /* ── TIMING CHECK ──────────────────────────────────────── */
    // Bots fill forms instantly — real humans take > 3 seconds
    const formLoadTime = Date.now();

    function checkTiming() {
        return (Date.now() - formLoadTime) > 3000;
    }

    /* ── SUBMIT HANDLER ────────────────────────────────────── */

    async function handleSubmit(e) {
        e.preventDefault();
        if (isSubmitting) return;

        hideBanners();

        // Bot checks (silent fail — don't tell bots they were caught)
        if (!checkHoneypot() || !checkTiming()) {
            showBanner('success');  // fake success to confuse bots
            return;
        }

        // Rate limiting
        if (!checkRateLimit()) return;

        // Field validation
        if (!validateAll()) {
            showBanner('error', 'Please fix the errors below before sending.');
            // Scroll to first invalid field
            const firstInvalid = document.querySelector('.field-invalid');
            if (firstInvalid) firstInvalid.scrollIntoView({ behavior: 'smooth', block: 'center' });
            return;
        }

        // All good — submit
        setSubmitting(true);

        const form    = document.getElementById('contactForm');
        const data    = new FormData(form);

        try {
            const response = await fetch(form.action, {
                method:  'POST',
                body:    data,
                headers: { 'Accept': 'application/json' },
            });

            if (response.ok) {
                showBanner('success');
                form.reset();
                Object.keys(fieldMap).forEach(id => clearField(id));
                document.getElementById('charCount').textContent = '0';
                lastSubmitTime = Date.now();
                submitCount++;
                sessionStorage.setItem('kts_submits', submitCount);
            } else {
                const json = await response.json().catch(() => ({}));
                const msg  = json.errors
                    ? json.errors.map(e => e.message).join(', ')
                    : 'Something went wrong. Please try again or email us directly.';
                showBanner('error', msg);
            }
        } catch {
            showBanner('error', 'Network error. Please check your connection and try again.');
        } finally {
            setSubmitting(false);
        }
    }

    /* ── INLINE VALIDATION (on blur + input) ───────────────── */

    function attachInlineValidation() {
        Object.keys(fieldMap).forEach(id => {
            const input = document.getElementById(id);
            if (!input) return;

            // Validate on blur (when user leaves field)
            input.addEventListener('blur', () => validateField(id));

            // Clear error on input (once field has been touched)
            input.addEventListener('input', () => {
                if (input.classList.contains('field-invalid')) {
                    validateField(id);
                }
            });
        });
    }

    /* ── CHAR COUNTER ──────────────────────────────────────── */

    function attachCharCounter() {
        const textarea  = document.getElementById('fmessage');
        const counter   = document.getElementById('charCount');
        const countWrap = counter && counter.closest('.char-count');
        if (!textarea || !counter) return;

        textarea.addEventListener('input', () => {
            const len = textarea.value.length;
            counter.textContent = len;
            if (countWrap) {
                countWrap.classList.toggle('char-warn',  len > 1600);
                countWrap.classList.toggle('char-limit', len >= 2000);
            }
        });
    }

    /* ── INIT ──────────────────────────────────────────────── */

    function init() {
        const form = document.getElementById('contactForm');
        if (!form) return;

        form.addEventListener('submit', handleSubmit);
        attachInlineValidation();
        attachCharCounter();

        // Hide banners initially
        hideBanners();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

})();