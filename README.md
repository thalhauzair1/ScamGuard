# ScamGuard

A Chrome extension that detects tech support scam websites and warns users with a clear, actionable banner. ScamGuard uses **two-layer detection** combining keyword analysis, popup/modal detection, suspicious domain checks, and advanced domain reputation analysis to help protect users from common online scams.

## Features

### **Layer 1: Content-Based Detection**
- **Keyword-based scam detection** (high/medium risk phrases)
- **Suspicious popup/modal detection**
- **Suspicious TLD (domain extension) detection**
- **Toll-free phone number detection**
- **Trusted/educational domain whitelisting**
- **Scoring system with severity-based warning banner**

### **Layer 2: Domain Reputation Analysis** 🆕
- **Domain pattern analysis** - Detects suspicious words in domain names
- **Brand typosquatting detection** - Identifies fake brand domains
- **Domain age indicators** - Flags newly registered domains
- **URL structure analysis** - Checks for suspicious paths and parameters
- **Character pattern detection** - Identifies suspicious character sequences
- **Cross-layer correlation** - Combines content and domain analysis for higher accuracy

### **Enhanced User Experience**
- **Modern, professional UI** with smooth animations
- **Efficient, debounced DOM monitoring**
- **Easy to dismiss warning**
- **Auto-hide for low-risk warnings**
- **Detailed popup with comprehensive analysis**

## Installation
1. Clone or download this repository:
   ```
   git clone https://github.com/thalhauzair1/ScamGuard.git
   ```
2. Open Chrome and go to `chrome://extensions/`
3. Enable **Developer mode** (top right)
4. Click **Load unpacked** and select the ScamGuard directory (the folder containing `manifest.json`)

## Usage
- Browse the web as usual.
- If you visit a page with scam indicators, a modern warning banner will appear at the top.
- Click **Dismiss Warning** to close the banner or **Trust This Site** to whitelist it.
- Trusted sites (Google, Wikipedia, etc.) and educational/discussion pages are not flagged.
- Open the extension popup to see detailed analysis of both content and domain reputation.

## Testing

### Basic Scam Detection
- Use the included `test_scam.html` file:
  1. Open `test_scam.html` in Chrome (drag and drop or use `Ctrl+O`)
  2. You should see a warning banner appear, flagging the page as a scam.

### Second Layer Domain Analysis
- Use the included `test_domain_scam.html` file:
  1. Open `test_domain_scam.html` in Chrome
  2. This demonstrates the enhanced domain reputation analysis
  3. The combination of suspicious content AND suspicious domain should trigger a high-confidence warning.

- Try visiting trusted sites (e.g., google.com) to confirm no warning appears.

## How It Works

### **Two-Layer Detection System**

**Layer 1: Content Analysis**
- Scans visible text for scammy keywords and phone numbers
- Detects suspicious popups/modals
- Flags uncommon/high-risk domain extensions
- Skips trusted and educational/discussion sites
- Assigns a content-based score

**Layer 2: Domain Reputation Analysis**
- Analyzes domain name for suspicious patterns (support, virus, fix, etc.)
- Detects brand typosquatting (fake microsoft, apple, etc.)
- Identifies newly registered domains (2024, new, temp, etc.)
- Checks URL structure for suspicious parameters and paths
- Detects suspicious character patterns (excessive numbers, special chars)
- Assigns a domain reputation score

**Cross-Layer Correlation**
- Combines both scores with weighted multipliers
- Provides significant bonus for multi-layer detection
- Reduces false positives through correlation analysis

### **Scoring System**
- **Content Score**: Based on keywords, popups, phone numbers, TLD
- **Domain Score**: Based on patterns, typosquatting, age, URL structure
- **Cross-Layer Bonus**: Additional points when both layers detect issues
- **Final Score**: Weighted combination determining warning severity

## Advanced Features

### **Domain Reputation Patterns Detected**
- Suspicious words: support, help, fix, virus, malware, secure
- Brand names: microsoft, apple, google, facebook, amazon
- New domain indicators: 2024, new, temp, fresh, latest
- Suspicious structures: support-, -fix, microsoft-, -virus
- Character patterns: excessive numbers, special characters

### **URL Analysis**
- Suspicious parameters: support, help, fix, virus, malware
- Suspicious paths: support, help, assist, fix, repair
- File extensions: .exe, .zip, .rar, .scr, .bat, .cmd
- Excessive URL depth (common in scam sites)

### **Smart Thresholds**
- Dynamic thresholds based on domain reputation
- Lower thresholds for suspicious TLDs
- Higher thresholds for trusted-looking domains
- Cross-layer correlation bonuses

## Contributing
Pull requests and suggestions are welcome! For major changes, please open an issue first to discuss what you would like to change.

## License
MIT 