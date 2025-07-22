# ScamGuard

A Chrome extension that detects tech support scam websites and warns users with a clear, actionable banner. ScamGuard uses keyword analysis, popup/modal detection, suspicious domain checks, and more to help protect users from common online scams.

## Features
- **Keyword-based scam detection** (high/medium risk phrases)
- **Suspicious popup/modal detection**
- **Suspicious TLD (domain extension) detection**
- **Toll-free phone number detection**
- **Trusted/educational domain whitelisting**
- **Scoring system with severity-based warning banner**
- **Efficient, debounced DOM monitoring**
- **Easy to dismiss warning**

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
- If you visit a page with scam indicators, a warning banner will appear at the top.
- Click **Close Warning** to dismiss the banner.
- Trusted sites (Google, Wikipedia, etc.) and educational/discussion pages are not flagged.

## Testing
- Use the included `scam-test.html` file:
  1. Open `scam-test.html` in Chrome (drag and drop or use `Ctrl+O`)
  2. You should see a warning banner appear, flagging the page as a scam.
- Try visiting trusted sites (e.g., google.com) to confirm no warning appears.

## How It Works
- Scans visible text for scammy keywords and phone numbers
- Detects suspicious popups/modals
- Flags uncommon/high-risk domain extensions
- Skips trusted and educational/discussion sites
- Assigns a score and displays a warning if the score is high

## Contributing
Pull requests and suggestions are welcome! For major changes, please open an issue first to discuss what you would like to change.

## License
MIT 