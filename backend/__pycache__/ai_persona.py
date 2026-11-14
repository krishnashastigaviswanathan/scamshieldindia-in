import json
import logging
import requests
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

OLLAMA_API_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "llama3.2"


def extract_fallback_triggers(message: str, signatures: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    """
    Extracts high-impact quotes and assigns psycho-social manipulation reasons
    when LLM is offline.
    """
    triggers = []
    lower_msg = message.lower()

    # Look for urgency markers
    urgency_phrases = [
        ("immediately", "Creates artificial panic to disable rational skepticism and verification."),
        ("tonight", "Imposes an artificial deadline to force hasty action before offices open."),
        ("within 24 hours", "Weaponizes time pressure to bypass standard due-diligence."),
        ("within 2 hours", "Extreme urgency designed to induce panic and irrational compliance."),
        ("blocked", "Threatens loss of critical financial or utility access to induce fear."),
        ("suspended", "Simulates administrative finality to compel urgent submission."),
        ("arrest", "Instills criminal prosecution dread, isolating the victim psychologically."),
        ("narcotics", "Fabricates severe criminal contraband charges to paralyze critical thinking."),
        ("illegal", "Manipulates fear of police interrogation and legal disgrace."),
        ("enter pin", "Classic deception: entering UPI PIN deducts money instead of receiving it."),
        ("update kyc", "Impersonates regulatory compliance to harvest PII and banking credentials."),
        ("download apk", "Induces user to bypass OS security filters to install remote-access trojans."),
        # Regional Indic & Hinglish Phrasing
        ("turant", "Creates urgent panic in local dialect to compel immediate unverified compliance."),
        ("aaj raat", "Imposes artificial night-time deadline before bank/electricity branches open."),
        ("kaat di jayegi", "Exploits anxiety of sudden basic service deprivation (power/line cutoff)."),
        ("band ho gaya", "Falsely claims bank account is frozen to induce financial panic."),
        ("paise paane", "Exploits greed; confuses user into believing PIN entry receives incoming funds."),
        ("inaam", "Psychological enticement with fictitious lottery winnings."),
        ("rozana", "Baiting victims with unrealistic daily work-from-home earnings."),
        ("निलंबित", "Simulates regulatory suspension in Hindi to trigger compliance."),
        ("काट दी जाएगी", "Threatens immediate service cutoff in Hindi to bypass critical thinking."),
        ("पिन दर्ज करें", "Deceptive UPI claim: entering PIN always debits funds rather than receiving."),
        ("मुடக்கப்பட்டுள்ளது", "Fabricates bank account freeze in Tamil to panic the account holder."),
        ("துண்டிக்கப்படும்", "Threatens electricity disconnection tonight in Tamil to prompt hasty action."),
        ("నిలిపివేయబడుతుంది", "Threatens power / account suspension in Telugu to induce emergency panic."),
        ("ব্লক করা হয়েছে", "Fabricates bank account block in Bengali to harvest KYC credentials.")
    ]

    for phrase, reason in urgency_phrases:
        idx = lower_msg.find(phrase)
        if idx != -1:
            # Capture contextual snippet around phrase
            start = max(0, idx - 15)
            end = min(len(message), idx + len(phrase) + 25)
            snippet = message[start:end].strip()
            # Clean snippet borders
            triggers.append({
                "quote": f"...{snippet}...",
                "manipulation_reason": reason
            })
            if len(triggers) >= 3:
                break

    # If no triggers found from list, pull any matched regex patterns
    if not triggers and signatures:
        for sig in signatures:
            for match in sig.get("matches", [])[:2]:
                triggers.append({
                    "quote": match,
                    "manipulation_reason": f"Matches known deceptive phrasing associated with {sig.get('category')}."
                })

    return triggers


def generate_rule_based_persona(message: str, scanner_results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Context-aware rule-based fallback generating the exact Scam Persona schema
    specifically tailored for Indian threat patterns across all regional languages.
    """
    signatures = scanner_results.get("signatures", [])
    categories = scanner_results.get("categories", [])
    upi = scanner_results.get("upi", {})
    urls = scanner_results.get("urls", {})
    score = scanner_results.get("base_score", 10)
    reg_intel = scanner_results.get("regional_intel", {})
    lang_tag = f" [{reg_intel['language']}]" if reg_intel.get("is_regional") else ""
    regional_warning = " Scammers utilize regional Indian dialects to exploit local trust and bypass English spam filters." if reg_intel.get("is_regional") else ""

    # 1. Bank KYC & Account Lock Lure
    if "Fake Bank / KYC Scam" in categories or any("kyc" in c.lower() or "bank" in c.lower() for c in categories):
        return {
            "archetype": f"The Urgent Bank Compliance Officer{lang_tag}",
            "primary_tactic": f"False Urgency & Account Deactivation Fear{lang_tag}",
            "highlighted_triggers": extract_fallback_triggers(message, signatures) or [
                {"quote": "Account Blocked / Update KYC", "manipulation_reason": "Fabricates imminent account suspension to force credential disclosure on phishing pages."}
            ],
            "recommended_action": f"Do NOT click the link or disclose OTP/passwords.{regional_warning} Official Indian banks never request KYC updates via SMS links. Dial 1930 to report financial fraud, or lodge a complaint on Sanchar Saathi's Chakshu portal.",
            "engine": "PhishGuard Threat Intelligence Heuristics (Offline Fallback)"
        }

    # 2. Income Tax / Government Refund Fraud
    if "Income Tax / Refund Fraud" in categories or "refund" in message.lower() or "income tax" in message.lower() or "itr" in message.lower():
        return {
            "archetype": "The Impersonated Tax Authority Officer",
            "primary_tactic": "Authority Exploitation & Bogus Financial Windfall",
            "highlighted_triggers": extract_fallback_triggers(message, signatures) or [
                {"quote": "Refund approved / Click to claim", "manipulation_reason": "Lures taxpayer to input NetBanking password and debit card credentials under the guise of receiving money."}
            ],
            "recommended_action": "The Income Tax Department directly transfers refunds to pre-validated bank accounts and NEVER requires clicking links to claim refunds. Check status only on eportal.incometax.gov.in.",
            "engine": "PhishGuard Threat Intelligence Heuristics (Offline Fallback)"
        }

    # 3. Predatory Loan & Credit Limit Enhancement Trap
    if "Fake Loan / Credit Limit Trap" in categories or "loan" in message.lower() or "credit limit" in message.lower():
        return {
            "archetype": "The Predatory Instant Loan Operator",
            "primary_tactic": "Financial Need Exploitation & Advance-Fee Lure",
            "highlighted_triggers": extract_fallback_triggers(message, signatures) or [
                {"quote": "Pre-approved loan without CIBIL / Click to claim", "manipulation_reason": "Preys on urgent cash needs to extort upfront processing fees or install unauthorized lending spyware."}
            ],
            "recommended_action": "Never install unknown lending apps or transfer advance processing fees. Verify all loan products through RBI-registered NBFCs and banks.",
            "engine": "PhishGuard Threat Intelligence Heuristics (Offline Fallback)"
        }

    # 4. Reward Points & Cashback Fraud
    if "Reward Points / Cashback Fraud" in categories or "reward" in message.lower() or "points" in message.lower():
        return {
            "archetype": "The Deceptive Card Rewards Representative",
            "primary_tactic": "Loss Aversion & Expiring Benefit Panic",
            "highlighted_triggers": extract_fallback_triggers(message, signatures) or [
                {"quote": "Points expiring today / Redeem cash now", "manipulation_reason": "Creates artificial FOMO (fear of missing out) to trick victims into entering card CVV and OTP."}
            ],
            "recommended_action": "Credit card reward points are redeemed exclusively inside official banking apps. Banks never send direct SMS links to redeem points for cash. Report to 1930.",
            "engine": "PhishGuard Threat Intelligence Heuristics (Offline Fallback)"
        }

    # 5. Subscription / Courier Delivery Smishing
    if "Subscription / Delivery Smishing" in categories or any(k in message.lower() for k in ["netflix", "courier", "parcel", "speed post", "india post", "delivery", "subscription"]):
        return {
            "archetype": "The Fraudulent Courier / Service Dispatcher",
            "primary_tactic": "Urgency & Service Disruption / Delivery Delay Panic",
            "highlighted_triggers": extract_fallback_triggers(message, signatures) or [
                {"quote": "Package undelivered / Update address immediately", "manipulation_reason": "Drives victim to a clone portal requiring a small fee payment that secretly captures credit card credentials."}
            ],
            "recommended_action": "India Post and legitimate couriers never require updating delivery addresses via unverified third-party web links. Track consignments only on indiapost.gov.in.",
            "engine": "PhishGuard Threat Intelligence Heuristics (Offline Fallback)"
        }

    # 6. Digital Arrest / FedEx / Law Enforcement
    if "Digital Arrest / TRAI Scam" in categories and any(k in message.lower() for k in ["arrest", "fedex", "customs", "police", "cbi", "narcotics"]):
        return {
            "archetype": "The Intimidating Law Enforcement Official",
            "primary_tactic": "Fear, Coercion & Digital Arrest Extortion",
            "highlighted_triggers": extract_fallback_triggers(message, signatures) or [
                {"quote": "Customs Parcel Seized / Warrant", "manipulation_reason": "Exploits dread of criminal prosecution to psychologically corner the victim."}
            ],
            "recommended_action": "Hang up immediately. Indian Police, CBI, ED, and Customs NEVER conduct 'Digital Arrest' or interrogation over video calls. Report immediately to cybercrime.gov.in or call 1930.",
            "engine": "PhishGuard Threat Intelligence Heuristics (Offline Fallback)"
        }

    # 7. Electricity / Utility Scam
    if "Electricity / e-Challan Scam" in categories and any(k in message.lower() for k in ["electricity", "power", "bijli", "discom", "bill"]):
        return {
            "archetype": "The Deceptive Utility Billing Officer",
            "primary_tactic": "Imminent Blackout Panic & Service Cutoff Pressure",
            "highlighted_triggers": extract_fallback_triggers(message, signatures) or [
                {"quote": "Power disconnected tonight", "manipulation_reason": "Creates artificial panic to prevent the user from cross-checking their official discom account."}
            ],
            "recommended_action": "State electricity boards never instruct customers to call personal mobile numbers or download apps. Pay electricity bills only via your official DISCOM web portal.",
            "engine": "PhishGuard Threat Intelligence Heuristics (Offline Fallback)"
        }

    # 8. Fake e-Challan / Parivahan APK Malware
    if "Electricity / e-Challan Scam" in categories or urls.get("apk_links") or any(k in message.lower() for k in ["challan", "parivahan"]):
        return {
            "archetype": "The Bogus Traffic Enforcement Officer",
            "primary_tactic": "Legal Penalties Avoidance & Spyware Delivery",
            "highlighted_triggers": extract_fallback_triggers(message, signatures) or [
                {"quote": "Traffic Challan Pending / Download APK", "manipulation_reason": "Lures user to install a malicious APK trojan that intercepts incoming SMS and OTPs."}
            ],
            "recommended_action": "Never download or install APK files received via SMS. Verify and pay legitimate traffic violations only on the Ministry's official echallan.parivahan.gov.in portal.",
            "engine": "PhishGuard Threat Intelligence Heuristics (Offline Fallback)"
        }

    # 9. TRAI / SIM Disconnection & 5G Swap
    if "Digital Arrest / TRAI Scam" in categories or "trai" in message.lower() or "sim card" in message.lower() or "5g" in message.lower():
        return {
            "archetype": "The Telecom Regulatory Impersonator",
            "primary_tactic": "Authority Exploitation & Sudden Disconnection Panic",
            "highlighted_triggers": extract_fallback_triggers(message, signatures) or [
                {"quote": "SIM Disconnection in 2 hours", "manipulation_reason": "Threatens abrupt loss of digital connectivity to prompt rash compliance."}
            ],
            "recommended_action": "TRAI and DoT never issue SMS threats to disconnect individual SIM cards. Forward suspicious messages to DoT's Chakshu portal at sancharsaathi.gov.in.",
            "engine": "PhishGuard Threat Intelligence Heuristics (Offline Fallback)"
        }

    # 10. UPI Collect Scam
    if upi.get("warnings") or upi.get("has_upi_threat") or "upi" in message.lower() or "pin" in message.lower():
        return {
            "archetype": "The Fraudulent Buyer / Cashback Agent",
            "primary_tactic": "Financial Confusion & UPI PIN Reversal Trap",
            "highlighted_triggers": extract_fallback_triggers(message, signatures) or [
                {"quote": "Enter UPI PIN to receive money", "manipulation_reason": "Exploits user misunderstanding of UPI architecture; PIN entry always debits funds."}
            ],
            "recommended_action": "NEVER enter your UPI PIN to receive money or refunds. If you approved a fraudulent request, immediately call the National Cybercrime Helpline 1930 and freeze your UPI account via your banking app.",
            "engine": "PhishGuard Threat Intelligence Heuristics (Offline Fallback)"
        }

    # 11. Job / Telegram Task Scam
    if "Job / Lottery Scam" in categories or any(k in message.lower() for k in ["job", "earn", "telegram", "lottery", "winner", "lucky draw", "kbc"]):
        return {
            "archetype": "The Deceptive Recruiter / Wealth Distributor",
            "primary_tactic": "Greed, False Prosperity & Advance-Fee Trap",
            "highlighted_triggers": extract_fallback_triggers(message, signatures) or [
                {"quote": "Daily income for simple tasks", "manipulation_reason": "Baiting victims with easy money before requiring escalating security deposits."}
            ],
            "recommended_action": "Legitimate employers never recruit or pay for review tasks over Telegram or WhatsApp. Report the fraud to cybercrime.gov.in and block the sender.",
            "engine": "PhishGuard Threat Intelligence Heuristics (Offline Fallback)"
        }

    # 12. Generic Smishing & Social Engineering
    if score >= 50 or scanner_results.get("heuristics", {}).get("is_suspicious"):
        return {
            "archetype": "The Opportunistic Social Engineering Spammer",
            "primary_tactic": "Deceptive Call-to-Action & Unregistered Commercial Smishing",
            "highlighted_triggers": extract_fallback_triggers(message, signatures) or [
                {"quote": "Actionable link / Urgency lure", "manipulation_reason": "Pressures victim to interact with unverified links or contacts."}
            ],
            "recommended_action": "Exercise high caution before engaging. If suspicious, report the sender to Sanchar Saathi (Chakshu portal) or call the Cybercrime Helpline at 1930.",
            "engine": "PhishGuard Threat Intelligence Heuristics (Offline Fallback)"
        }

    # 8. Legitimate / Low Risk
    if score < 30:
        return {
            "archetype": "Legitimate Sender / Routine Communication",
            "primary_tactic": "Informational / Standard Transactional Notice",
            "highlighted_triggers": [],
            "recommended_action": "This communication does not exhibit typical phishing or social engineering patterns. Remain vigilant and never share passwords or banking OTPs with anyone.",
            "engine": "PhishGuard Threat Intelligence Heuristics (Offline Fallback)"
        }

    # Default Generic
    return {
        "archetype": "The Unknown Deceptive Social Engineer",
        "primary_tactic": "Urgency & Evasion Strategy",
        "highlighted_triggers": extract_fallback_triggers(message, signatures),
        "recommended_action": "Exercise high caution before engaging. If suspicious, report the sender to Sanchar Saathi (Chakshu portal) or call the Cybercrime Helpline at 1930.",
        "engine": "PhishGuard Threat Intelligence Heuristics (Offline Fallback)"
    }


def analyze_scam_persona(message: str, scanner_results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Invokes local Ollama llama3.2 to reverse-engineer the attacker's social engineering playbook.
    Falls back gracefully to high-accuracy rule-based persona engine if Ollama is unreachable.
    """
    system_prompt = (
        "You are an elite Indian cyber-intelligence analyst specializing in UPI scams, "
        "DLT phishing, and social engineering reverse-engineering. Analyze the suspicious message "
        "and return ONLY valid JSON matching this exact schema:\n"
        "{\n"
        '  "archetype": "The scammer fake disguise (e.g. The Urgent Bank Compliance Officer, The Intimidating Law Enforcement Official, The Fake Reward Distributor, or Legitimate Sender)",\n'
        '  "primary_tactic": "Core psychological hook (e.g. Fear & Authority, False Urgency, Greed & Enticement, etc.)",\n'
        '  "highlighted_triggers": [\n'
        '    {"quote": "exact short quote from message", "manipulation_reason": "why this specific phrase manipulates the victim"}\n'
        "  ],\n"
        '  "recommended_action": "1-sentence actionable advice tailored for India, referencing either 1930 National Cybercrime Helpline or Sanchar Saathi / Chakshu portal."\n'
        "}"
    )

    user_prompt = f"Message to analyze:\n\"\"\"{message}\"\"\"\n\nPre-screened threat indicators: {json.dumps(scanner_results.get('categories', []))}"

    try:
        response = requests.post(
            OLLAMA_API_URL,
            json={
                "model": MODEL_NAME,
                "prompt": f"{system_prompt}\n\n{user_prompt}",
                "format": "json",
                "stream": False,
                "options": {
                    "temperature": 0.2
                }
            },
            timeout=(0.4, 1.2)
        )

        if response.status_code == 200:
            data = response.json()
            raw_text = data.get("response", "").strip()
            parsed = json.loads(raw_text)

            # Validate expected fields
            if (
                isinstance(parsed, dict)
                and "archetype" in parsed
                and "primary_tactic" in parsed
                and "recommended_action" in parsed
            ):
                triggers = parsed.get("highlighted_triggers", [])
                if not isinstance(triggers, list):
                    triggers = []

                return {
                    "archetype": str(parsed.get("archetype")),
                    "primary_tactic": str(parsed.get("primary_tactic")),
                    "highlighted_triggers": triggers,
                    "recommended_action": str(parsed.get("recommended_action")),
                    "engine": f"Local Ollama ({MODEL_NAME})"
                }
    except Exception as e:
        logger.info(f"Ollama local API offline or failed ({str(e)}). Switching to intelligent rule-based persona engine.")

    # Fallback
    return generate_rule_based_persona(message, scanner_results)
