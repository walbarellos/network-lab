"""UI styling and CSS themes."""

DARK_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Rajdhani:wght@400;500;600;700&family=Share+Tech+Mono&family=Exo+2:wght@300;400;600;700&display=swap');

:root {
    --bg-primary:    #070B14;
    --bg-secondary:  #0D1526;
    --bg-card:       #111B2E;
    --bg-elevated:   #162038;
    --border:        #1E3A5F;
    --border-bright: #2A5080;
    --cyan:          #00D4FF;
    --cyan-dim:      #007BA8;
    --amber:         #FFB800;
    --amber-dim:     #7A5800;
    --green:         #00FF87;
    --green-dim:     #007A42;
    --red:           #FF1744;
    --red-dim:       #7A0020;
    --orange:        #FF6D00;
    --text-primary:  #E0EAF5;
    --text-secondary: #7A96B8;
    --text-dim:      #3D5A7A;
    --font-display:  'Rajdhani', sans-serif;
    --font-mono:     'Share Tech Mono', monospace;
    --font-body:     'Exo 2', sans-serif;
    --scan-duration: 2s;
}

.stApp {
    background: var(--bg-primary) !important;
    font-family: var(--font-body) !important;
    color: var(--text-primary) !important;
}

.stApp::before {
    content: '';
    position: fixed; top:0; left:0; width:100%; height:100%;
    background-image:
        linear-gradient(rgba(0,212,255,0.03) 1px, transparent 1px),
        linear-gradient(90deg, rgba(0,212,255,0.03) 1px, transparent 1px);
    background-size: 40px 40px;
    pointer-events: none; z-index: 0;
    animation: gridPulse 8s ease-in-out infinite;
}
@keyframes gridPulse {
    0%, 100% { opacity: 0.6; }
    50%       { opacity: 1; }
}

h1, h2, h3 {
    font-family: var(--font-display) !important;
    letter-spacing: 0.05em !important;
    text-transform: uppercase !important;
}
h1 { color: var(--cyan) !important; font-size: 2rem !important; font-weight: 700 !important; }
h2 { color: var(--text-primary) !important; font-size: 1.3rem !important; font-weight: 600 !important; border-bottom: 1px solid var(--border) !important; padding-bottom: 6px !important; margin-top: 1.5rem !important; }
h3 { color: var(--cyan-dim) !important; font-size: 1.1rem !important; font-weight: 500 !important; }

[data-testid="stSidebar"] {
    background: var(--bg-secondary) !important;
    border-right: 1px solid var(--border) !important;
}
[data-testid="stSidebar"] * { color: var(--text-primary) !important; }

[data-testid="stMetric"] {
    background: var(--bg-card) !important;
    border: 1px solid var(--border) !important;
    border-radius: 6px !important;
    padding: 14px 18px !important;
    position: relative !important;
    overflow: hidden !important;
}
[data-testid="stMetric"]::before {
    content: ''; position: absolute; top:0; left:0;
    width: 3px; height: 100%;
    background: linear-gradient(180deg, var(--cyan), var(--cyan-dim));
}
[data-testid="stMetricLabel"] > div {
    font-family: var(--font-display) !important;
    font-size: 0.75rem !important;
    letter-spacing: 0.1em !important;
    text-transform: uppercase !important;
    color: var(--text-secondary) !important;
}
[data-testid="stMetricValue"] > div {
    font-family: var(--font-display) !important;
    font-size: 2rem !important;
    font-weight: 700 !important;
    color: var(--cyan) !important;
    line-height: 1.1 !important;
}

.stButton > button {
    background: transparent !important;
    border: 1px solid var(--cyan-dim) !important;
    color: var(--cyan) !important;
    font-family: var(--font-display) !important;
    font-weight: 600 !important;
    letter-spacing: 0.08em !important;
    text-transform: uppercase !important;
    border-radius: 4px !important;
    transition: all 0.2s ease !important;
}
.stButton > button:hover {
    background: rgba(0,212,255,0.1) !important;
    border-color: var(--cyan) !important;
    box-shadow: 0 0 15px rgba(0,212,255,0.2) !important;
    transform: translateY(-1px) !important;
}
.stButton > button[kind="primary"] {
    background: linear-gradient(135deg, #003A5C, #005A8A) !important;
    border-color: var(--cyan) !important;
    box-shadow: 0 0 20px rgba(0,212,255,0.15) !important;
}

.stTextInput > div > div > input,
.stTextArea > div > div > textarea,
.stSelectbox > div > div,
.stMultiSelect > div > div {
    background: var(--bg-elevated) !important;
    border: 1px solid var(--border) !important;
    border-radius: 4px !important;
    color: var(--text-primary) !important;
    font-family: var(--font-mono) !important;
}
.stTextInput > div > div > input:focus,
.stTextArea > div > div > textarea:focus {
    border-color: var(--cyan) !important;
    box-shadow: 0 0 8px rgba(0,212,255,0.15) !important;
}

.stDataFrame {
    border: 1px solid var(--border) !important;
    border-radius: 6px !important;
    overflow: hidden !important;
}
.stDataFrame thead th {
    background: var(--bg-elevated) !important;
    color: var(--cyan) !important;
    font-family: var(--font-display) !important;
    font-size: 0.8rem !important;
    letter-spacing: 0.1em !important;
    text-transform: uppercase !important;
    border-bottom: 1px solid var(--border-bright) !important;
}
.stDataFrame tbody tr:hover { background: rgba(0,212,255,0.05) !important; }
.stDataFrame tbody td {
    font-family: var(--font-mono) !important;
    font-size: 0.82rem !important;
    color: var(--text-primary) !important;
    border-bottom: 1px solid rgba(30,58,95,0.5) !important;
}

.nw-scan-pulse {
    display: inline-block;
    width: 8px; height: 8px;
    background: var(--green);
    border-radius: 50%;
    animation: pulse 1.5s ease-in-out infinite;
    margin-right: 6px;
}
@keyframes pulse {
    0%, 100% { opacity: 1; transform: scale(1); }
    50% { opacity: 0.5; transform: scale(0.8); }
}
</style>
"""


def get_themed_css(theme: str = "cyan") -> str:
    """Get CSS with custom theme accent color."""
    colors = {
        "cyan": ("#00D4FF", "#007BA8"),
        "amber": ("#FFB800", "#7A5800"),
        "green": ("#00FF87", "#007A42"),
        "red": ("#FF1744", "#7A0020"),
    }
    primary, dim = colors.get(theme, colors["cyan"])
    return DARK_CSS.replace("var(--cyan)", primary).replace("var(--cyan-dim)", dim)
