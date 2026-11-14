import re
import hashlib
from typing import Dict, List, Any, Optional

# Non-UPI email domains to exclude from UPI handle detection
EXCLUDED_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "icloud.com",
    "proton.me", "protonmail.com", "aol.com", "zoho.com", "mail.com",
    "yandex.com", "live.com", "msn.com", "googlemail.com", "me.com"
}

# Known Indian UPI handles (common PSPs and banks)
KNOWN_UPI_HANDLES = {
    "okaxis", "okhdfcbank", "oksbi", "okicici", "paytm", "ybl", "ibl", "axl",
    "upi", "apl", "barodampay", "pingpay", "postbank", "idfcbank", "freecharge",
    "airtel", "kotak", "indus", "federal", "rbl", "yesbank", "pnb", "cnrb",
    "aubank", "jupiteraxis", "goaxl", "sliceaxis", "timeaxis", "waaxis",
    "wahdfcbank", "waicici", "wasbi"
}

# Suspicious URL Shorteners
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "is.gd", "rb.gy", "cutt.ly", "t.co", "rebrand.ly",
    "shorturl.at", "goo.gl", "ow.ly", "buff.ly", "bl.ink", "tiny.cc", "v.gd", "clck.ru"
}

# High-Risk / Scam TLDs and extensions
HIGH_RISK_TLDS = {
    "top", "xyz", "click", "apk", "tk", "ml", "ga", "cf", "gq", "buzz",
    "fit", "rest", "icu", "link", "live", "work", "monster", "cfd", "sbs", "quest", "space", "cc"
}

# Indian TRAI DLT Header Regex: 2 letters (service provider + circle) followed by hyphen and 6 alphanumeric chars
# e.g., AD-HDFCBK, VK-SBIINB, CP-AIRTEL, BP-ICICIB, BZ-KOTAKB, or standalone 6-character alpha headers
DLT_HEADER_REGEX = re.compile(r"^[A-Za-z]{2}-[A-Za-z0-9]{6}$|^[A-Za-z]{6}$")

# Indian 10-digit mobile number pattern
INDIAN_MOBILE_REGEX = re.compile(r"^(?:\+91[\-\s]?)?[6-9]\d{9}$")

# Suspicious Brand Spoofing Tokens inside URLs
SPOOFED_BRAND_KEYWORDS = [
    "sbi", "hdfc", "icici", "axis", "pnb", "bob", "kotak", "canara", "bank",
    "pan", "kyc", "aadhaar", "incometax", "tax-refund", "parivahan", "echallan",
    "challan", "bijli", "electricity", "netflix", "amazon", "indiapost", "post-office",
    "reward", "points-redeem", "cashback", "fast-loan", "instant-loan"
]


def generate_privacy_fingerprint(text: str) -> str:
    """
    Strips all digits, special phone/account numbers, and excessive whitespace,
    then generates a truncated 16-character SHA-256 hash.
    Ensures personal PII (phone numbers, account numbers, amounts) is not retained.
    """
    no_digits = re.sub(r"\d+", "", text.lower())
    normalized = re.sub(r"[^\w\s]", " ", no_digits)
    cleaned = re.sub(r"\s+", " ", normalized).strip()
    full_hash = hashlib.sha256(cleaned.encode("utf-8")).hexdigest()
    return full_hash[:16]


def extract_urls(text: str) -> List[str]:
    """Extract http/https URLs and standalone web links."""
    url_pattern = re.compile(
        r"(https?://[^\s<>\"']+|www\.[^\s<>\"']+|[a-zA-Z0-9\-]+\.(?:top|xyz|click|apk|tk|ml|ga|cf|gq|buzz|icu|live|info|ru|cn|in|com|org|net|co|biz|online|site|mobi|app|co\.in|gov-auth\.com)(?:/[^\s<>\"']*)?)",
        re.IGNORECASE
    )
    matches = url_pattern.findall(text)
    clean_urls = []
    for u in matches:
        u_clean = u.rstrip(".,;!?:)'\"")
        if u_clean and u_clean not in clean_urls:
            clean_urls.append(u_clean)
    return clean_urls


def extract_upi_indicators(text: str) -> Dict[str, Any]:
    """
    Extracts UPI IDs (excluding standard email addresses) and upi://pay deep links.
    """
    upi_ids = []
    deep_links = []
    warnings = []

    # Detect upi:// deep links
    deep_link_pattern = re.compile(r"upi://[^\s<>\"']+", re.IGNORECASE)
    for dl in deep_link_pattern.findall(text):
        deep_links.append(dl)
        warnings.append(
            "CRITICAL: Detected 'upi://' deep link. Scammers use collect intent links to trick victims into entering a UPI PIN."
        )

    # General VPA pattern: identifier@psp
    vpa_pattern = re.compile(r"([a-zA-Z0-9.\-_]{2,100}@[a-zA-Z0-9.\-]{2,50})", re.IGNORECASE)
    for match in vpa_pattern.findall(text):
        parts = match.split("@")
        if len(parts) == 2:
            domain_part = parts[1].lower()
            if domain_part in EXCLUDED_EMAIL_DOMAINS:
                continue
            if any(domain_part.endswith("." + em) for em in EXCLUDED_EMAIL_DOMAINS):
                continue

            if match not in upi_ids:
                upi_ids.append(match)

    # Check for UPI PIN fraud lures (e.g. "Enter PIN to receive money / cashback / refund")
    pin_receive_pattern = re.compile(
        r"(enter\s+(?:your\s+)?(?:upi\s+)?pin\s+(?:to\s+)?(?:receive|credit|claim|get)|pin\s+daal\w*\s+paise|pin\s+enter\s+kar\w*|receive.*pin|scan.*qr.*(?:receive|claim))",
        re.IGNORECASE
    )
    if pin_receive_pattern.search(text):
        warnings.append(
            "HIGH RISK UPI FRAUD: Entering a UPI PIN ALWAYS DEDUCTS money from your bank account! You NEVER need a UPI PIN to receive money, refunds, or cashback."
        )

    return {
        "upi_ids": upi_ids,
        "deep_links": deep_links,
        "warnings": warnings,
        "has_upi_threat": len(warnings) > 0 or len(deep_links) > 0
    }


def inspect_urls_and_malware(urls: List[str]) -> Dict[str, Any]:
    """
    Analyzes URLs for shorteners, high-risk TLDs, APK downloads, and brand spoofing.
    """
    shortened = []
    risky_tlds = []
    apk_links = []
    spoofed_brands = []
    ip_based_urls = []
    findings = []

    for u in urls:
        u_lower = u.lower()

        # Check for APK links
        if ".apk" in u_lower or ("download" in u_lower and ("app" in u_lower or "apk" in u_lower)):
            apk_links.append(u)
            findings.append(f"Malware Vector: URL references direct APK installation payload ({u})")

        # Check for raw IP address in URL
        if re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", u_lower):
            ip_based_urls.append(u)
            findings.append(f"Host Anomaly: Direct numeric IP address URL used instead of verified domain ({u})")

        # Extract hostname
        domain_match = re.search(r"://([^/:\s]+)", u_lower) or re.search(r"^([^/:\s]+)", u_lower)
        if domain_match:
            host = domain_match.group(1).lower()

            # URL Shorteners
            if host in SHORTENER_DOMAINS:
                shortened.append(u)
                findings.append(f"Evasion Detected: URL shortener '{host}' obscures real destination")

            # High-Risk TLDs
            tld = host.split(".")[-1]
            if tld in HIGH_RISK_TLDS:
                risky_tlds.append(u)
                findings.append(f"Abuse-Prone TLD: Hosted on high-risk domain extension '.{tld}' ({host})")

            # Brand keyword spoofing in domain (e.g. sbi-pan-update, hdfc-security, etc.)
            for kw in SPOOFED_BRAND_KEYWORDS:
                if kw in host and not (host.endswith(f".{kw}.com") or host.endswith(f".{kw}.co.in") or host == f"{kw}.com" or host == f"{kw}.co.in"):
                    # Check if domain has suspicious hyphenated combination
                    if ("-" in host or ".xyz" in host or ".top" in host or ".site" in host or "update" in host or "verify" in host or "login" in host or "auth" in host):
                        spoofed_brands.append(u)
                        findings.append(f"Brand Impersonation / Typosquatting: Domain '{host}' masquerades as '{kw}'")
                        break

    return {
        "urls": urls,
        "shortened_urls": shortened,
        "risky_tlds": risky_tlds,
        "apk_links": apk_links,
        "spoofed_brands": spoofed_brands,
        "ip_based_urls": ip_based_urls,
        "findings": findings
    }


def validate_dlt_sender(sender: Optional[str], has_url: bool, has_sensitive_lure: bool) -> Dict[str, Any]:
    """
    Validates Indian Telecom DLT commercial sender headers according to TRAI guidelines.
    Commercial banking, offers, and utility messages from personal 10-digit numbers are illegal UCC / smishing.
    """
    if not sender:
        warning = None
        if has_url or has_sensitive_lure:
            warning = "Sender Header Missing: Alert contains actionable links or commercial claims from an anonymous sender."
        return {
            "provided": False,
            "sender": None,
            "is_valid_dlt": False,
            "is_mobile_number": False,
            "warning": warning
        }

    sender_clean = sender.strip().upper()
    is_mobile = bool(INDIAN_MOBILE_REGEX.match(sender.strip()))
    is_dlt = bool(DLT_HEADER_REGEX.match(sender_clean))

    warning = None
    if is_mobile:
        if has_url:
            warning = (
                f"CRITICAL SENDER ANOMALY: A private 10-digit personal mobile number ({sender}) sent an actionable web link. "
                "Official Indian banks and enterprises are legally prohibited by TRAI from transmitting links via personal mobile numbers."
            )
        elif has_sensitive_lure:
            warning = (
                f"HIGH RISK SENDER ANOMALY: Banking / KYC / Financial / Utility alert was sent from a private 10-digit personal number ({sender}) "
                "instead of a TRAI-registered 6-character commercial DLT header (e.g., AD-HDFCBK, VK-SBIINB)."
            )
        else:
            warning = f"Private Mobile Sender: Sent from a private 10-digit number ({sender})."
    elif not is_dlt:
        warning = f"UNOFFICIAL SENDER HEADER: Header '{sender}' does not adhere to official TRAI commercial DLT syntax (e.g. AD-HDFCBK)."

    return {
        "provided": True,
        "sender": sender.strip(),
        "is_valid_dlt": is_dlt,
        "is_mobile_number": is_mobile,
        "warning": warning
    }


# Regional Indic Script Unicode Ranges (using letter-specific ranges to avoid shared danda 0x0964)
REGIONAL_SCRIPT_RANGES = {
    "Bengali / Assamese": re.compile(r"[\u0980-\u09FF]"),
    "Hindi / Devanagari": re.compile(r"[\u0904-\u0939\u0958-\u0961]"),
    "Punjabi / Gurmukhi": re.compile(r"[\u0A00-\u0A7F]"),
    "Gujarati": re.compile(r"[\u0A80-\u0AFF]"),
    "Odia": re.compile(r"[\u0B00-\u0B7F]"),
    "Tamil": re.compile(r"[\u0B80-\u0BFF]"),
    "Telugu": re.compile(r"[\u0C00-\u0C7F]"),
    "Kannada": re.compile(r"[\u0C80-\u0CFF]"),
    "Malayalam": re.compile(r"[\u0D00-\u0D7F]")
}

# Hinglish & Romanized Indic phonetic smishing vocabulary
HINGLISH_VOCAB_REGEX = re.compile(
    r"\b(?:aapka|aapke|apka|apke|tumhara|tumhari|khata|khate|band|bandh|turant|tatkal|"
    r"bijli|vidyut|veej|biddut|kaat|kat|gul|batti|paise|paisa|taka|panam|dabbu|"
    r"daal\w*|bharo|bhejo|bheje|kamayein|kamao|kamana|rozana|inaam|inam|jeet\w*|"
    r"ghante|karein|kijiye|karo|aaj\s*raat|nikli|bina|thana|girftar|nasha|nasheele|"
    r"gaadi|challan|chalan|suljhao|adhikari|afsar|darj|dastavez|jurmana|rok|nillambit|"
    r"lottery\s*lagi|kbc\s*winner|ghar\s*baithe|paane\s*ke\s*liye|lene\s*ke\s*liye)\b",
    re.IGNORECASE
)


def detect_regional_language(text: str) -> Dict[str, Any]:
    """
    Detects native Indic scripts (Devanagari, Tamil, Telugu, Bengali, Kannada, etc.)
    or Hinglish / Romanized Indic dialect in the message.
    """
    for script_name, regex in REGIONAL_SCRIPT_RANGES.items():
        if regex.search(text):
            return {
                "language": script_name,
                "is_regional": True,
                "is_romanized": False
            }

    if HINGLISH_VOCAB_REGEX.search(text):
        return {
            "language": "Hinglish (Romanized Indic / Hindi)",
            "is_regional": True,
            "is_romanized": True
        }

    return {
        "language": "English",
        "is_regional": False,
        "is_romanized": False
    }


def scan_regional_indic_signatures(text: str) -> Dict[str, Any]:
    """
    Specialized regional language smishing analyzer covering:
    - Hindi / Devanagari (Bank KYC, Bijli Cutoff, UPI PIN, Lottery, Digital Arrest)
    - Hinglish / Romanized Hindi/Urdu smishing
    - Tamil, Telugu, Bengali, Kannada, Gujarati Regional threats
    """
    regional_sigs = []
    categories = []
    base_score = 0

    # 1. Regional Bank / KYC Account Freeze
    reg_bank_patterns = [
        # Devanagari (Hindi, Marathi)
        (r"(?:खाता|अकाउंट|बैंक|एसबीआई|एचडीएफसी|आईसीआईसीआई|पीएनबी|क्रेडिट\s*कार्ड|डेबिट\s*कार्ड|केवाईसी|पैन\s*कार्ड)\s*.*?(?:बंद|निलंबित|ब्लॉक|रोक|अवरुद्ध|अमान्य|फ्रीज|निष्क्रिय|सत्यापित|अपडेट)", "Indic Devanagari Bank Account Freeze / KYC Lure"),
        # Hinglish
        (r"(?:khata|khate|account|card|kyc|pan\s*card)\s*.*?(?:band|bandh|block|rok|nillambit|freeze|kat|deactivat\w*|suspend\w*|update\s*karein|link\s*karein)", "Hinglish Bank Account / KYC Suspension Lure"),
        # Tamil
        (r"(?:வங்கி|கணக்கு|கார்டு|கேஒய்சி).*?(?:முடக்க|பிளாக்|செயலிழக்க|புதுப்பிக்க|இணைக்க)", "Tamil Regional Bank Account Block Smishing"),
        # Telugu
        (r"(?:బ్యాంక్|ఖాతా|కార్డు|కేవైసీ).*?(?:బ్లాక్|నిలిపివే|రద్దు|అప్‌డేట్|వెరిఫై)", "Telugu Regional Bank Account Block Smishing"),
        # Bengali
        (r"(?:ব্যাঙ্ক|অ্যাকাউন্ট|কেওয়াইসি|প্যান).*?(?:ব্লক|বন্ধ|স্থগিত|আপডেট)", "Bengali Regional Bank Account Freeze Lure"),
        # Kannada
        (r"(?:ಬ್ಯಾಂಕ್|ಖಾತೆ|ಕೆವೈಸಿ).*?(?:ನಿರ್ಬಂಧ|ಬ್ಲಾಕ್|ಅಪ್‌ಡೇಟ್)", "Kannada Regional Bank Account Freeze Lure"),
        # Gujarati
        (r"(?:બેંક|ખાતું|કેવાયસી).*?(?:બ્લોક|બંધ|અપડેટ)", "Gujarati Regional Bank Account Freeze Lure")
    ]

    matched_bank = []
    matched_labels = []
    for pat, label in reg_bank_patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            matched_bank.append(m.group(0))
            matched_labels.append(label)

    if matched_bank:
        categories.append("Fake Bank / KYC Scam")
        regional_sigs.append({
            "category": "Fake Bank / KYC Scam",
            "threat_label": matched_labels[0],
            "severity": "CRITICAL",
            "matches": matched_bank,
            "description": "Regional language smishing lure threatening bank account closure / KYC freeze to bypass English spam filters."
        })
        base_score += 55

    # 2. Regional Electricity / Utility Cutoff
    reg_elec_patterns = [
        # Devanagari
        (r"(?:बिजली|विद्युत|पावर|बिल|कनेक्शन)\s*.*?(?:काट|कट|बंद|डिस्कनेक्ट|रात\s*\d+|अधिकारी|कॉल\s*करें)", "Indic Devanagari Electricity Cutoff Threat"),
        # Hinglish
        (r"(?:bijli|vidyut|power|line|batti|veej|biddut)\s*.*?(?:kaat|kat|gul|band|off|cut|aaj\s*raat|officer|afsar|call\s*karein)", "Hinglish Electricity Disconnection Warning"),
        # Tamil
        (r"(?:மின்\s*கட்டணம்|மின்சாரம்|மின்சார).*?(?:துண்டிக்க|இன்றிரவு|செலுத்த|அழைக்கவும்)", "Tamil Regional Electricity Cutoff Threat"),
        # Telugu
        (r"(?:విద్యుత్|కరెంట్|బిల్లు).*?(?:నిలిపివేయ|కట్|ఈ\s*రాత్రి|సంప్రదించండి)", "Telugu Regional Electricity Cutoff Threat"),
        # Bengali
        (r"(?:বিদ্যুৎ\s*বিল|বিদ্যুৎ\s*সংযোগ).*?(?:বিচ্ছিন্ন|কাটা|যোগাযোগ)", "Bengali Regional Electricity Disconnection Threat")
    ]

    matched_elec = []
    matched_elec_labels = []
    for pat, label in reg_elec_patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            matched_elec.append(m.group(0))
            matched_elec_labels.append(label)

    if matched_elec:
        categories.append("Electricity / e-Challan Scam")
        regional_sigs.append({
            "category": "Electricity / e-Challan Scam",
            "threat_label": matched_elec_labels[0],
            "severity": "HIGH",
            "matches": matched_elec,
            "description": "Regional language utility cutoff threat warning power disconnection tonight, coercing victims to call personal numbers."
        })
        base_score += 50

    # 3. Regional UPI PIN Inversion / Money Receive Fraud
    reg_upi_patterns = [
        # Devanagari
        (r"(?:यूपीआई\s*पिन|पिन\s*दर्ज|पैसे\s*प्राप्त|कैशबैक|रिफंड|पैसे\s*पाने).*?(?:पिन|दर्ज|क्लिक)", "Indic Devanagari UPI PIN Deception Lure"),
        # Hinglish
        (r"(?:paise|cashback|refund|inaam|taka|panam|dabbu)\s*.*?(?:paane|lene|pane|milne|credit)\s*.*?(?:pin\s*daal|pin\s*enter|pin\s*bharo|pin\s*karo)", "Hinglish UPI PIN Deduct Fraud"),
        # Tamil
        (r"(?:பணம்\s*பெற|யுபிஐ\s*பின்|பின்னை\s*உள்ளிடவும்)", "Tamil Regional UPI PIN Deception Lure"),
        # Telugu
        (r"(?:డబ్బులు\s*పొందడానికి|యూపీఐ\s*పిన్|పిన్\s*ఎంటర్)", "Telugu Regional UPI PIN Deception Lure"),
        # Bengali
        (r"(?:টাকা\s*পেতে|ইউপিআই\s*পিন\s*দিন)", "Bengali Regional UPI PIN Deception Lure")
    ]

    matched_upi = []
    matched_upi_labels = []
    for pat, label in reg_upi_patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            matched_upi.append(m.group(0))
            matched_upi_labels.append(label)

    if matched_upi:
        categories.append("UPI Collect / Refund Fraud")
        regional_sigs.append({
            "category": "UPI Collect / Refund Fraud",
            "threat_label": matched_upi_labels[0],
            "severity": "CRITICAL",
            "matches": matched_upi,
            "description": "Regional language UPI PIN trick: falsely claims entering UPI PIN receives or claims money/cashback."
        })
        base_score += 55

    # 4. Regional Lottery, KBC & Daily Task Scams
    reg_job_patterns = [
        # Devanagari
        (r"(?:बधाई|लॉटरी|इनाम|रुपये\s*जीते|विजेता|घर\s*बैठे|रोजाना\s*कमाएं|कमाई|लकी\s*ड्रॉ)", "Indic Devanagari Lottery / Job Scam"),
        # Hinglish
        (r"(?:lottery|inaam|kbc|jeet|diwali\s*offer|lakshya|ghar\s*baithe|rozana|daily\s*income)\s*.*?(?:nikli|lagi|won|mili|paayein|kamayein|kamao)", "Hinglish Lottery / Work-From-Home Scam"),
        # Tamil
        (r"(?:பரிசு|லாட்டரி|பணம்\s*வென்றுள்ளீர்கள்|வீட்டிலிருந்தே\s*சம்பாதிக்க)", "Tamil Regional Lottery / Prize Fraud"),
        # Telugu
        (r"(?:లాటరీ|బహుమతి|డబ్బులు\s*గెలుచుకున్నారు|ఇంటి\s*నుండే\s*సంపాదించండి)", "Telugu Regional Lottery / Prize Fraud"),
        # Bengali
        (r"(?:লটারি|পুরস্কার|টাকা\s*জিতেছেন|ঘরে\s*বসে\s*আয়)", "Bengali Regional Lottery / Income Scam")
    ]

    matched_job = []
    matched_job_labels = []
    for pat, label in reg_job_patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            matched_job.append(m.group(0))
            matched_job_labels.append(label)

    if matched_job:
        categories.append("Job / Lottery Scam")
        regional_sigs.append({
            "category": "Job / Lottery Scam",
            "threat_label": matched_job_labels[0],
            "severity": "HIGH",
            "matches": matched_job,
            "description": "Regional language lottery or work-from-home task bait promising unrealistic financial windfalls."
        })
        base_score += 45

    # 5. Regional Law Enforcement / Digital Arrest
    reg_arrest_patterns = [
        # Devanagari
        (r"(?:गिरफ्तार|गिरफ्तारी|वारंट|पुलिस\s*थाना|कस्टम|ड्रग्स|नशीले\s*पदार्थ|पार्सल\s*जब्त|सीबीआई|डिजिटल\s*अरेस्ट)", "Indic Devanagari Digital Arrest Extortion"),
        # Hinglish
        (r"(?:parcel|consignment)\s*.*?(?:nasha|drugs|pakda|customs|police|thaney|arrest|warrant|cbi)", "Hinglish Digital Arrest / Narcotics Extortion")
    ]

    matched_arrest = []
    matched_arrest_labels = []
    for pat, label in reg_arrest_patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            matched_arrest.append(m.group(0))
            matched_arrest_labels.append(label)

    if matched_arrest:
        categories.append("Digital Arrest / TRAI Scam")
        regional_sigs.append({
            "category": "Digital Arrest / TRAI Scam",
            "threat_label": matched_arrest_labels[0],
            "severity": "CRITICAL",
            "matches": matched_arrest,
            "description": "Regional language law enforcement extortion threatening arrest over contraband parcels."
        })
        base_score += 55

    return {
        "signatures_detected": regional_sigs,
        "categories": list(set(categories)),
        "base_score": base_score
    }


def scan_indian_scam_signatures(text: str) -> Dict[str, Any]:
    """
    Comprehensive scanner detecting all Indian English, Hinglish, and Regional Indic smishing:
    1. Regional Indic & Hinglish Multi-dialect signatures
    2. Fake Bank / Net Banking / KYC / Card Freeze Lures
    3. Income Tax / GST / Government Refund Fraud
    4. Instant / Pre-Approved Loan & Limit Enhancement Traps
    5. Reward Points & Cashback Expiry Fraud
    6. Subscription / OTT & Postal Delivery Smishing
    7. Lottery / Lucky Draw / Work-from-Home Task Scams
    8. Fake TRAI / SIM Disconnection & 5G Upgrade Threats
    9. Fake Electricity / Utility Disconnection Warnings
    10. FedEx / Customs / CBI 'Digital Arrest' Extortion
    11. Traffic e-Challan / Parivahan APK Malware
    """
    signatures_detected = []
    categories = []
    base_score = 0

    # 0. Regional Indic & Hinglish dialect evaluation
    regional_res = scan_regional_indic_signatures(text)
    if regional_res["signatures_detected"]:
        signatures_detected.extend(regional_res["signatures_detected"])
        categories.extend(regional_res["categories"])
        base_score = max(base_score, regional_res["base_score"])

    # 1. Fake Bank / Net Banking / KYC / Card Freeze Lures
    bank_patterns = [
        r"(?:\b(?:sbi|hdfc|icici|axis|pnb|bob|kotak|canara|indusind|idfc|rbl|citi|bank)\b|net\s*banking|credit\s*card|debit\s*card|bank\s*a/c|bank\s*account)\s*.*(?:\b(?:blocked|deactivated|suspended|hold|freez\w+|locked|disabled|compromised|restricted|inactive)\b)",
        r"(?:update|verify|link|submit|complete|reactivat\w*|renew\w*)\s+(?:your\s+)?(?:pan\s*card|aadhaar|kyc|pancard|identity|documents?|net\s*banking|debit\s*card)",
        r"(?:avoid|stop|prevent)\s+(?:account\s+)?(?:deactivation|suspension|debit\s*freeze|penalty|closure|blocking)",
        r"(?:click\s+(?:here|link)|visit\s+link|login\s+to\s+verify|verify\s+your\s+account)\s*.*(?:kyc|pan|bank|a/c|account|security|unlock|reactivate)",
        r"dear\s+(?:customer|user).*account.*(?:suspended|blocked|disabled|action\s*required)",
        r"(?:unauthorized|suspicious)\s+(?:transaction|login|activity).*click.*verify"
    ]
    matched_bank = []
    for pat in bank_patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            matched_bank.append(m.group(0))

    if matched_bank:
        categories.append("Fake Bank / KYC Scam")
        signatures_detected.append({
            "category": "Fake Bank / KYC Scam",
            "threat_label": "Fake Bank / Net Banking / KYC Account Freeze Lure",
            "severity": "CRITICAL",
            "matches": matched_bank,
            "description": "Scammer impersonates a bank claiming net banking or card is blocked, directing victim to credential-harvesting phishing portals."
        })
        base_score += 55

    # 2. Income Tax / GST / Government Refund Fraud
    refund_patterns = [
        r"(?:income\s*tax|incometax|it\s*department|itr|gst|pm\s*kisan|pm\s*yojana|sarkari|subsidy|grant)\s*.*(?:refund|approved|credited|claim|pending)",
        r"(?:refund\s*of\s*(?:rs|inr|\u20b9)?\s*\d+[\d,]*\s*(?:has\s*been\s*)?approved)",
        r"(?:tax\s*refund|claim\s*refund|verify\s*account\s*to\s*receive\s*refund)"
    ]
    matched_refund = []
    for pat in refund_patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            matched_refund.append(m.group(0))

    if matched_refund:
        categories.append("Income Tax / Refund Fraud")
        signatures_detected.append({
            "category": "Income Tax / Refund Fraud",
            "threat_label": "Fake Income Tax / Government Refund Phishing",
            "severity": "CRITICAL",
            "matches": matched_refund,
            "description": "Exploits tax return expectations with bogus refund claims to steal banking credentials and OTPs."
        })
        base_score += 50

    # 3. Instant / Pre-Approved Loan & Limit Enhancement Traps
    loan_patterns = [
        r"(?:pre-approved|instant|urgent|fast|paperless|no\s*cibil)\s*(?:loan|credit|cash)",
        r"(?:loan\s*(?:of\s*(?:rs|inr|\u20b9)?\s*\d+[\d,]*\s*)?(?:approved|sanctioned|disburs\w*|eligible|offer))",
        r"(?:credit\s*card\s*limit\s*(?:increase|enhanc\w*|upgrade|doubled))",
        r"(?:apply\s*now|claim\s*loan|disburse\s*now|transfer\s*funds).*link"
    ]
    matched_loan = []
    for pat in loan_patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            matched_loan.append(m.group(0))

    if matched_loan:
        categories.append("Fake Loan / Credit Limit Trap")
        signatures_detected.append({
            "category": "Fake Loan / Credit Limit Trap",
            "threat_label": "Predatory Loan & Credit Card Limit Enhancement Trap",
            "severity": "HIGH",
            "matches": matched_loan,
            "description": "Offers bogus instant loans or credit limit increases to extract upfront processing fees or install lending malware."
        })
        base_score += 45

    # 4. Reward Points & Cashback Expiry Fraud
    reward_patterns = [
        r"(?:reward\s*points?|cash\s*points?|bonus\s*points?|loyalty\s*points?|card\s*points?)\s*.*(?:expir\w*|redeem|worth|claim)",
        r"(?:expir\w*\s*today|redeem\s*cash\s*now|convert\s*points\s*to\s*cash)",
        r"(?:free\s*(?:gift|iphone|voucher|shopping|coupon)|cashback\s*(?:approved|credited|won))"
    ]
    matched_reward = []
    for pat in reward_patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            matched_reward.append(m.group(0))

    if matched_reward:
        categories.append("Reward Points / Cashback Fraud")
        signatures_detected.append({
            "category": "Reward Points / Cashback Fraud",
            "threat_label": "Expiring Reward Points & Cashback Lure",
            "severity": "HIGH",
            "matches": matched_reward,
            "description": "Lures cardholders to redeem imaginary points before they expire, leading to phishing pages that capture CVV and OTP."
        })
        base_score += 45

    # 5. Subscription / OTT & Postal Delivery Smishing
    sub_patterns = [
        r"(?:netflix|prime|amazon|hotstar|spotify|subscription|membership)\s*.*(?:expir\w*|renew\w*|failed|suspended|payment\s*method|closure)",
        r"(?:india\s*post|speed\s*post|courier|parcel|delivery|consignment|bluedart|delhivery)\s*.*(?:pending|undelivered|address|update\s*address|reschedule|failed)"
    ]
    matched_sub = []
    for pat in sub_patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            matched_sub.append(m.group(0))

    if matched_sub:
        categories.append("Subscription / Delivery Smishing")
        signatures_detected.append({
            "category": "Subscription / Delivery Smishing",
            "threat_label": "Subscription Expiry / Postal Delivery Smishing",
            "severity": "HIGH",
            "matches": matched_sub,
            "description": "Impersonates streaming services or postal couriers alleging failed delivery or expired subscription to capture card data."
        })
        base_score += 45

    # 6. Lottery / Lucky Draw / Work-from-Home Task Scams
    lottery_patterns = [
        r"(?:congratulations|lucky\s*draw|lottery|winner|kbc|diwali\s*gift|won\s*(?:rs|inr|\u20b9)?\s*\d+)",
        r"(?:part[-\s]?time\s*job|work\s*from\s*home|daily\s*income|earn\s*(?:rs|inr|\u20b9)?\s*\d+[\d,]*\s*(?:per\s*day|daily))",
        r"(?:youtube\s*like|google\s*review|hotel\s*review|rating\s*task|crypto\s*task|telegram\s*task)"
    ]
    matched_lottery = []
    for pat in lottery_patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            matched_lottery.append(m.group(0))

    if matched_lottery:
        categories.append("Job / Lottery Scam")
        signatures_detected.append({
            "category": "Job / Lottery Scam",
            "threat_label": "Fake Work-From-Home / Lottery Prize Scam",
            "severity": "HIGH",
            "matches": matched_lottery,
            "description": "Entices victims with high daily earnings for rating tasks or fake lottery winnings, leading to deposit-drain traps."
        })
        base_score += 45

    # 7. Fake TRAI / SIM Disconnection & 5G Upgrade Threats
    trai_sim_patterns = [
        r"(?:\btrai\b|\bdot\b|telecom\s+regulatory|department\s+of\s+telecom\w*)\s*.*(?:disconnect\w*|block\w*|deactivat\w*|suspend\w*)",
        r"(?:\bsim\b\s*card|mobile\s*number|phone\s*number)\s*(?:will\s*be\s*)?(?:blocked|disconnected|terminated|suspended)\s*(?:in|within)\s*\d+\s*(?:hrs?|hours?)",
        r"(?:biometric|\bsim\b\s*kyc|re-verification|verification)\s*(?:pending|mandatory|failed)",
        r"(?:upgrade\s*to\s*5g|free\s*5g|5g\s*sim|sim\s*swap|e-sim|send\s*sim\s*to\s*\d+)"
    ]
    matched_trai = []
    for pat in trai_sim_patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            matched_trai.append(m.group(0))

    if matched_trai:
        categories.append("Digital Arrest / TRAI Scam")
        signatures_detected.append({
            "category": "Digital Arrest / TRAI Scam",
            "threat_label": "Fake TRAI / DoT SIM Disconnection & 5G Swap Threat",
            "severity": "CRITICAL",
            "matches": matched_trai,
            "description": "Fabricates telecom authority threatening SIM deactivation or offers fake 5G upgrades to execute SIM-swap fraud."
        })
        base_score += 50

    # 8. Fake Electricity / Utility Disconnection Warnings
    electricity_patterns = [
        r"(?:electricity|power|bijli|gas|water|discom)\s*(?:power|supply|connection|line|bill)?\s*(?:will\s*be\s*)?(?:disconnected|cut\s*off)\s*(?:tonight|today|at\s*\d+(?::\d+)?\s*(?:pm|am))",
        r"(?:previous\s+month|unpaid|pending)\s*(?:bill|electricity\s*bill)\s*(?:was\s*not\s*updated|not\s*paid)",
        r"(?:contact|call|whatsapp)\s*(?:our\s*)?(?:electricity\s*officer|power\s*office|\bje\b|\bsdow\b|executive)\s*(?:at\s*)?(?:\+91[\-\s]?)?[6-9]\d{9}",
        r"(?:bill\s*update|pay\s*bijli\s*bill).*(?:apk|link|immediately)"
    ]
    matched_elec = []
    for pat in electricity_patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            matched_elec.append(m.group(0))

    if matched_elec:
        categories.append("Electricity / e-Challan Scam")
        signatures_detected.append({
            "category": "Electricity / e-Challan Scam",
            "threat_label": "Fake Electricity Power Cutoff Warning",
            "severity": "HIGH",
            "matches": matched_elec,
            "description": "Impersonates state electricity boards claiming power will be cut tonight, luring victims to call personal numbers or download malicious APKs."
        })
        base_score += 50

    # 9. FedEx / Customs & "Digital Arrest" Extortion
    digital_arrest_patterns = [
        r"(?:fedex|dhl|india\s*post|customs|airport\s*cargo)\s*.*(?:parcel|courier|consignment|package).*(?:seized|intercepted|confiscated|illegal|drugs|narcotics|mdma|passports?)",
        r"(?:digital\s*arrest|\bcbi\b|\bed\b|enforcement\s*directorate|narcotics\s*control|\bncb\b|mumbai\s*police|delhi\s*police|cyber\s*crime\s*branch)",
        r"(?:arrest\s*warrant|supreme\s*court\s*order|money\s*laundering|terror\s*funding|interrogation\s*call)",
        r"(?:stay\s+on\s+skype|video\s+call\s+interrogation|do\s+not\s+hang\s+up|clearance\s+certificate)"
    ]
    matched_arrest = []
    for pat in digital_arrest_patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            matched_arrest.append(m.group(0))

    if matched_arrest:
        categories.append("Digital Arrest / TRAI Scam")
        signatures_detected.append({
            "category": "Digital Arrest / TRAI Scam",
            "threat_label": "FedEx / Customs 'Digital Arrest' Extortion",
            "severity": "CRITICAL",
            "matches": matched_arrest,
            "description": "Cyber extortion syndicate impersonating police/customs claiming contraband parcels and threatening 'Digital Arrest'."
        })
        base_score += 55

    # 10. Fake e-Challan / Parivahan APK Malware
    challan_patterns = [
        r"(?:traffic\s*police|echallan|e-challan|challan|parivahan|mparivahan|vahan)\s*.*(?:pending|issued|notice|fine|court)",
        r"(?:pending\s*challan|vehicle\s*number|pay\s*challan)\s*.*(?:click|visit|download|install)",
        r"(?:download|install)\s*(?:parivahan|challan|vahan).*(?:\.apk|app)",
        r"parivahan.*echallan.*pay"
    ]
    matched_challan = []
    for pat in challan_patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            matched_challan.append(m.group(0))

    if matched_challan:
        categories.append("Electricity / e-Challan Scam")
        signatures_detected.append({
            "category": "Electricity / e-Challan Scam",
            "threat_label": "Fake Traffic e-Challan / Parivahan APK Malware",
            "severity": "CRITICAL",
            "matches": matched_challan,
            "description": "Distributes Trojanized fake Parivahan APKs under the pretext of overdue traffic violation challan payment."
        })
        base_score += 50

    return {
        "signatures_detected": signatures_detected,
        "categories": list(set(categories)),
        "base_score": base_score
    }


def evaluate_social_engineering_heuristics(text: str, has_url: bool) -> Dict[str, Any]:
    """
    Evaluates universal psychological manipulation tactics used in spam/phishing:
    - Urgency & time pressure
    - Call to action (links, phone numbers, WhatsApp, verification demands)
    - Coercion & threats
    - Financial bait & greed
    """
    urgency_matches = re.findall(
        r"\b(?:immediately|urgently|within\s*\d+\s*(?:hrs?|hours?|mins?|minutes?)|tonight|today\s*only|last\s*chance|expir\w*\s*today|final\s*(?:notice|warning)|action\s*required|mandatory|without\s*delay|before\s*midnight)\b",
        text,
        re.IGNORECASE
    )

    threat_matches = re.findall(
        r"\b(?:blocked|deactivated|suspended|hold|freez\w+|locked|disabled|penalty|court|police|arrest|legal\s*action|disconnected|terminated|closure)\b",
        text,
        re.IGNORECASE
    )

    bait_matches = re.findall(
        r"\b(?:approved|credited|cashback|refund|won|lottery|reward\s*points?|bonus|free\s*gift|pre-approved|eligible|congratulations)\b",
        text,
        re.IGNORECASE
    )

    cta_matches = re.findall(
        r"(?:click\s+(?:here|link)|visit\s+link|apply\s*now|claim\s*now|redeem\s*now|download\s*(?:apk|app)|call\s*(?:immediately|now)|whatsapp\s*us|update\s*now|verify\s*now|login\s*here)",
        text,
        re.IGNORECASE
    )

    heuristic_score = 0
    factors = []

    if urgency_matches:
        heuristic_score += 20
        factors.append(f"Artificial Urgency: {', '.join(urgency_matches[:2])}")

    if threat_matches:
        heuristic_score += 25
        factors.append(f"Intimidation / Coercion: {', '.join(threat_matches[:2])}")

    if bait_matches:
        heuristic_score += 20
        factors.append(f"Financial Bait: {', '.join(bait_matches[:2])}")

    if cta_matches:
        heuristic_score += 25
        factors.append(f"Manipulative Call-to-Action: {', '.join(cta_matches[:2])}")

    # Combination booster: Urgency/Threat + CTA with a Link is the classic phishing anatomy
    if (urgency_matches or threat_matches or bait_matches) and (cta_matches or has_url):
        heuristic_score += 20
        factors.append("Phishing Signature: Synergistic combination of Urgency/Bait with direct Action Lure")

    return {
        "heuristic_score": min(heuristic_score, 85),
        "factors": factors,
        "is_suspicious": heuristic_score >= 35
    }


def scan_message(message: str, sender: Optional[str] = None) -> Dict[str, Any]:
    """
    Master threat analyzer combining:
    - Privacy-Safe SHA-256 fingerprinting
    - UPI & Deep-Link inspection
    - URL Shortener, Risky TLD, APK malware & Brand typosquatting
    - Regional Indian scam signatures (11 major categories)
    - Social Engineering heuristic NLP vectors
    - TRAI DLT commercial telecom sender header validation
    """
    msg_hash = generate_privacy_fingerprint(message)
    regional_intel = detect_regional_language(message)
    upi_intel = extract_upi_indicators(message)
    urls = extract_urls(message)
    url_intel = inspect_urls_and_malware(urls)
    signatures = scan_indian_scam_signatures(message)

    has_url = len(urls) > 0
    contains_sensitive_lure = (
        len(signatures["signatures_detected"]) > 0 
        or upi_intel["has_upi_threat"]
        or len(url_intel["findings"]) > 0
    )
    dlt_intel = validate_dlt_sender(sender, has_url, contains_sensitive_lure)
    heuristics = evaluate_social_engineering_heuristics(message, has_url)

    # Calculate Composite Risk Score
    score = signatures["base_score"]

    # Incorporate Heuristics
    score = max(score, heuristics["heuristic_score"])

    # UPI Threats
    if upi_intel["warnings"]:
        score = max(score, 75) + 15
        signatures["categories"].append("UPI Collect / Refund Fraud")
    elif upi_intel["deep_links"]:
        score = max(score, 70) + 10

    # URL / Malware Checks
    if url_intel["apk_links"]:
        score = max(score, 85) + 15
    if url_intel["spoofed_brands"]:
        score = max(score, 80) + 15
    if url_intel["ip_based_urls"]:
        score = max(score, 75) + 10
    if url_intel["risky_tlds"]:
        score = max(score, 70) + 15
    if url_intel["shortened_urls"]:
        score = max(score, 65) + 10

    # Sender DLT Rules
    if dlt_intel["is_mobile_number"]:
        if has_url:
            # Illegal in India: personal 10-digit number sending web links is high-probability smishing
            score = max(score, 70) + 15
        elif contains_sensitive_lure or heuristics["is_suspicious"]:
            score = max(score, 60) + 15

    # Check for Legitimate Transactional Bank SMS (Whitelisting check)
    # Legitimate Indian bank alerts: Valid DLT header + debited/credited amount + balance + NO external URLs
    is_legit_bank_alert = False
    if dlt_intel["is_valid_dlt"] and not has_url and not upi_intel["warnings"]:
        legit_tx_pattern = re.search(
            r"(?:debited|credited|avl\s*bal|available\s*balance|spent\s*on|txn\s*of|otp\s*is|secret\s*code)",
            message,
            re.IGNORECASE
        )
        if legit_tx_pattern and not signatures["signatures_detected"]:
            is_legit_bank_alert = True
            score = 5

    # If completely clean, personal, and no threats
    if (
        not signatures["signatures_detected"]
        and not url_intel["findings"]
        and not upi_intel["warnings"]
        and not heuristics["is_suspicious"]
        and not (dlt_intel["is_mobile_number"] and has_url)
    ):
        score = 8 if not has_url else 22

    final_score = max(5, min(score, 99))

    # Determine primary category
    primary_category = "General Phishing / Spam"
    if signatures["categories"]:
        primary_category = signatures["categories"][0]
    elif upi_intel["upi_ids"] or upi_intel["warnings"]:
        primary_category = "UPI Collect / Refund Fraud"
    elif url_intel["apk_links"]:
        primary_category = "Electricity / e-Challan Scam"
    elif url_intel["spoofed_brands"]:
        primary_category = "Fake Bank / KYC Scam"
    elif heuristics["is_suspicious"]:
        primary_category = "Social Engineering / Smishing"
    elif final_score < 25 or is_legit_bank_alert:
        primary_category = "Legitimate / Low Risk"

    return {
        "msg_hash": msg_hash,
        "base_score": final_score,
        "primary_category": primary_category,
        "categories": signatures["categories"],
        "signatures": signatures["signatures_detected"],
        "heuristics": heuristics,
        "regional_intel": regional_intel,
        "upi": upi_intel,
        "urls": url_intel,
        "dlt": dlt_intel
    }
