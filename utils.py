import re

# --- MASTER SCAM DICTIONARY ---
SCAM_KEYWORDS = {
    "Financial": ["kyc", "pan card", "block", "suspend", "debit card", "credit card", "reward points", "redeem"],
    "Urgency": ["immediately", "urgent", "24 hours", "today only", "legal action", "police", "arrest", "cbi", "illegal"],
    "Tech": ["apk", "teamviewer", "anydesk", "quicksupport", "screen share"],
    "Utilities": ["electricity", "power", "bill", "disconnect", "connection"],
    "Money": ["lottery", "winner", "refund", "cashback", "prize", "upi", "pay"],
    
    # NEW CATEGORY: CATCH HACKERS (Fixes Test 5)
    "Adversarial": ["ignore all", "previous instructions", "system prompt", "programming", "openai", "gemini", "language model"]
}

# --- REGEX PATTERNS ---
PATTERNS = {
    # Matches: example@upi, name@okhdfc
    "upi": r'[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}',
    
    # Matches: 9-18 digit numbers (common for Indian accounts)
    "bank_account": r'\b[0-9]{9,18}\b',
    
    # Matches: Standard URLs (http/https)
    "link": r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+',
    
    # Matches: Indian mobile numbers (+91 optional, starts with 6-9)
    "phone": r'(?:\+91[\-\s]?)?[6789]\d{9}'
}

def detect_scam_keywords(text: str) -> tuple[bool, str]:
    """
    Scans text for keywords.
    Returns: (is_scam: bool, category: str)
    """
    text_lower = text.lower()
    
    for category, keywords in SCAM_KEYWORDS.items():
        if any(word in text_lower for word in keywords):
            return True, category
            
    return False, "Safe"

def extract_regex_data(text: str) -> dict:
    return {
        "upiIds": re.findall(PATTERNS["upi"], text),
        "bankAccounts": re.findall(PATTERNS["bank_account"], text),
        "phishingLinks": re.findall(PATTERNS["link"], text),
        "phoneNumbers": re.findall(PATTERNS["phone"], text)
    }