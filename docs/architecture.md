                ┌─────────────────┐
                │   Incoming POST │
                │    /webhook     │
                └────────┬────────┘
                         ▼
          ┌──────────────────────────┐
          │   Session Manager        │
          │   • turn_count           │
          │   • extracted_intel      │
          │   • pending_callback_task│
          └────────────┬─────────────┘
                       ▼
    ┌───────────────────────────────────┐
    │      Step 0: Injection Check      │
    │   (if malicious → neutral reply)  │
    └────────────────┬──────────────────┘
                     ▼
    ┌───────────────────────────────────┐
    │       Three‑Tier Detection        │
    │  ┌─────────────┐                  │
    │  │  Keywords   │ → fast pass      │
    │  ├─────────────┤                  │
    │  │   Regex     │ → pattern match  │
    │  ├─────────────┤                  │
    │  │    NLP      │ → intent analysis│
    │  └─────────────┘                  │
    └────────────────┬──────────────────┘
                     ▼
          ┌─────────────────────┐
          │  Scam?              │
          │  └─ Yes → Activate  │
          │     Agent "Alex"    │
          └──────────┬──────────┘
                     ▼
    ┌───────────────────────────────────┐
    │  Intelligence Extraction          │
    │  • regex_data (immediate)         │
    │  • NLP entities (fallback)        │
    │  → stored in session              │
    └────────────────┬──────────────────┘
                     ▼
    ┌───────────────────────────────────┐
    │  Final Output Decision            │
    │  if scam & (has_intel OR turn≥10):│
    │    • build final_output           │
    │    • cancel previous callback     │
    │    • schedule new callback (10s)  │
    └────────────────┬──────────────────┘
                     ▼
    ┌───────────────────────────────────┐
    │  Dual‑Mode Delivery               │
    │  ┌──────────────┐ ┌──────────────┐│
    │  │ Push (Mode A)│ │ Pull (Mode B)││
    │  │ if CALLBACK_ │ │ GET /final/  ││
    │  │ URL set      │ │ {sessionId}  ││
    │  └──────────────┘ └──────────────┘│
    └───────────────────────────────────┘