from schemas import IncomingRequest, AgentResponse, EngagementMetrics, IntelligenceData, FinalCallbackPayload
import utils
import agent
import requests 
from datetime import datetime, timezone

# GUVI Callback Endpoint (As per your earlier code)
CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

def parse_timestamp(ts_string: str) -> datetime:
    """
    Parses ISO 8601 timestamps (e.g., '2026-01-21T10:15:30Z') securely.
    Handles the 'Z' timezone indicator manually for Python <3.11 compatibility.
    """
    try:
        # 1. Handle 'Z' for UTC
        if ts_string.endswith('Z'):
            ts_string = ts_string[:-1] + '+00:00'
            
        # 2. Parse ISO format
        dt = datetime.fromisoformat(ts_string)
        
        # 3. Ensure it is timezone-aware (UTC default if missing)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
            
        return dt
    except Exception:
        # Safety net: If timestamp is malformed, return current UTC time
        # This prevents the API from crashing during a demo
        return datetime.now(timezone.utc)

# CHANGE: Input type hint changed to 'dict' to match main.py
async def process_incoming_message(payload: dict) -> tuple[AgentResponse, FinalCallbackPayload | None]:
    """
    Core Logic: Detect -> Engage -> Extract -> Measure -> Report
    """
    
    # --- FIX: SAFE DICTIONARY ACCESS ---
    # We use ["key"] instead of .key because main.py sends a dictionary now
    
    # 1. Get Message Object safely
    msg_data = payload.get("message", {})
    if isinstance(msg_data, str): # Handle edge case where it might be a string
        current_text = msg_data
        current_timestamp = datetime.now(timezone.utc).isoformat()
    else:
        current_text = msg_data.get("text", "")
        current_timestamp = msg_data.get("timestamp", datetime.now(timezone.utc).isoformat())

    # 2. Get History & Session
    history = payload.get("conversationHistory", [])
    session_id = payload.get("sessionId", "unknown_session")
    
    # --- STEP 1: SCAM DETECTION ---
    is_scam = False
    scam_category = "None"
    
    # If history exists, we are already deep in conversation -> Assume Scam
    if len(history) > 0:
        is_scam = True
        scam_category = "Ongoing Interaction"
    else:
        # First message: Check keywords strictly (Dictionary Match)
        is_scam, scam_category = utils.detect_scam_keywords(current_text)

    # --- STEP 2: PASSIVE MODE (Safe User) ---
    if not is_scam:
        # COMPLIANCE UPDATE: status must be "success" per rules
        return AgentResponse(
            status="success",  
            scamDetected=False,
            engagementMetrics=EngagementMetrics(engagementDurationSeconds=0, totalMessagesExchanged=0),
            extractedIntelligence=IntelligenceData(),
            agentNotes="Status: Monitoring. No scam detected.", 
            reply=None
        ), None

    # --- STEP 3: ACTIVATE AGENT (The Persona) ---
    # This calls Google Gemini 2.5 Flash
    # Note: agent.get_agent_response likely expects history as list of dicts, which is what we have.
    ai_result = agent.get_agent_response(history, current_text)
    
    # --- STEP 4: INTELLIGENCE EXTRACTION (Hybrid) ---
    # A. Regex Extraction (The Sniper) - fast & accurate
    regex_data = utils.extract_regex_data(current_text)
    
    # B. AI Extraction - gets context/intent keywords
    final_intel = IntelligenceData(
        bankAccounts=regex_data["bankAccounts"],
        upiIds=regex_data["upiIds"],
        phishingLinks=regex_data["phishingLinks"],
        phoneNumbers=regex_data["phoneNumbers"],
        suspiciousKeywords=ai_result.get("suspicious_keywords", [])
    )

    # --- STEP 5: METRICS CALCULATION (Real-Time) ---
    total_messages = len(history) + 1
    duration = 0
    
    if len(history) > 0:
        # Robust Time Calculation
        # FIX: Access history item as dict (item["timestamp"]) not object (item.timestamp)
        first_msg = history[0]
        first_ts_str = first_msg.get("timestamp") if isinstance(first_msg, dict) else getattr(first_msg, "timestamp", str(datetime.now()))
        
        first_msg_ts = parse_timestamp(first_ts_str)
        current_msg_ts = parse_timestamp(current_timestamp)
        
        # Calculate difference in seconds
        delta = current_msg_ts - first_msg_ts
        duration = int(delta.total_seconds())
    else:
        # First message just arrived
        duration = 0

    # --- STEP 6: CONSTRUCT RESPONSE ---
    response_obj = AgentResponse(
        status="success", # COMPLIANCE: Always "success" for the evaluator
        scamDetected=True,
        engagementMetrics=EngagementMetrics(
            engagementDurationSeconds=duration, 
            totalMessagesExchanged=total_messages
        ),
        extractedIntelligence=final_intel,
        # We store the *real* internal status in the notes
        agentNotes=f"Status: Active. Category: {scam_category}. {ai_result.get('agent_notes', '')}",
        reply=ai_result.get("reply")
    )

    # --- STEP 7: DECIDE TO "SNITCH" (Callback Logic) ---
    callback_payload = None
    
    # Condition 1: We found critical financial info (Bank/UPI/Phone)
    found_critical_info = (
        len(final_intel.bankAccounts) > 0 or 
        len(final_intel.upiIds) > 0 or
        len(final_intel.phoneNumbers) > 0
    )
    
    # Condition 2: Conversation is getting long (stall success)
    long_engagement = total_messages > 10
    
    # Only fire callback if we found something NEW or hit the limit
    if found_critical_info or long_engagement:
        callback_payload = FinalCallbackPayload(
            sessionId=session_id,
            scamDetected=True,
            totalMessagesExchanged=total_messages,
            extractedIntelligence=final_intel,
            agentNotes=response_obj.agentNotes
        )

    return response_obj, callback_payload


def send_callback_background(payload: FinalCallbackPayload):
    """
    The 'Snitch' function. 
    Runs in the background so it doesn't slow down the user response.
    """
    try:
        # Convert Pydantic model to dict
        data = payload.dict()
        intel = data['extractedIntelligence']
        
        print(f"\n [CALLBACK TRIGGERED] Reporting Session: {data['sessionId']}")
        
        # IMPROVED LOGGING: Shows exactly what was found
        print(f"    Intel Report:")
        print(f"      - Bank Accounts: {len(intel['bankAccounts'])} found")
        print(f"      - UPI IDs:       {len(intel['upiIds'])} found")
        print(f"      - Phone Numbers: {len(intel['phoneNumbers'])} found")
        print(f"      - Keywords:      {len(intel['suspiciousKeywords'])} found")
        
        # Send Real Request 
        response = requests.post(CALLBACK_URL, json=data, timeout=5)
        if response.status_code == 200:
            print("    Report Sent Successfully")
        else:
            print(f"    Report Failed: {response.status_code}")
        
    except Exception as e:
        print(f" Callback Failed: {e}")