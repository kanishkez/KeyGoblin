# KeyGoblin

A comprehensive security auditing tool for detecting exposed API keys, tokens, and endpoints in web applications. This scanner performs deep inspection of client-side assets, network traffic, and runtime behavior to identify potential security vulnerabilities.

## Overview

API Security Scanner performs automated reconnaissance on web applications to identify:

- Exposed API keys and authentication tokens
- Hardcoded secrets in JavaScript files
- API endpoints and their usage patterns
- Suspicious HTTP headers that may leak sensitive information
- Runtime API calls made by client-side code

The scanner uses browser automation to simulate real user sessions, capturing both static assets and dynamic runtime behavior.

## Key Features

### Multi-Layer Detection

- **Static Analysis**: Scans HTML, JavaScript, and external resources
- **Network Monitoring**: Captures all HTTP requests and responses
- **Runtime Instrumentation**: Hooks fetch, XMLHttpRequest, WebSocket, and beacon APIs
- **AST Parsing**: Optional tree-sitter integration for accurate JavaScript analysis
- **Source Map Inspection**: Examines source maps for development-time secrets

### Pattern Recognition

Detects common secret formats including:

- HuggingFace tokens (hf_*)
- OpenAI API keys (sk-*)
- Google API keys (AIza*)
- Mapbox tokens (pk.*)
- JWT tokens
- Bearer tokens
- Generic API key patterns
- Firebase configuration
- AWS credentials

### Intelligent Filtering

- Context-aware validation to reduce false positives
- Minified code noise reduction
- CDN header filtering
- Configurable crawling depth for multi-page applications

## Installation

### Prerequisites

- Python 3.7 or higher
- pip package manager

### Required Dependencies

```bash
pip install playwright
python -m playwright install chromium
```

### Optional Dependencies

For enhanced JavaScript parsing with AST analysis:

```bash
pip install tree-sitter
```

If tree-sitter is installed, you must build a language library:

```bash
# Create build directory
mkdir -p build

# Clone tree-sitter-javascript
git clone https://github.com/tree-sitter/tree-sitter-javascript vendor/tree-sitter-javascript

# Build the library (requires a C compiler)
python -c "from tree_sitter import Language; Language.build_library('build/my-languages.so', ['vendor/tree-sitter-javascript'])"
```

Note: AST parsing is optional. The scanner will fall back to regex-based extraction if tree-sitter is unavailable.

## Usage

### Basic Scan

```bash
python cli.py https://example.com
```

### Output Formats

Human-readable report (default):

```bash
python cli.py https://example.com
```

JSON output for automation:

```bash
python cli.py https://example.com --json
```

### Advanced Options

```bash
python cli.py https://example.com \
  --depth 2 \           # Crawl depth for internal links (default: 1)
  --timeout 90000 \     # Page load timeout in milliseconds (default: 60000)
  --headful \           # Run browser in visible mode for debugging
  --no-js               # Skip external JavaScript file downloads
```

### Example Output

```
API SECURITY SCAN REPORT
======================================================================

API KEYS FOUND
----------------------------------------------------------------------
Google API Key: AIzaSyC1234567890abcdefghijklmnop
HuggingFace Token: hf_AbCdEfGhIjKlMnOpQrStUvWxYz1234567890
JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

API ENDPOINTS
----------------------------------------------------------------------
https://api.example.com
https://maps.googleapis.com
https://api-inference.huggingface.co

SUSPICIOUS HEADERS
----------------------------------------------------------------------
x-api-key → https://api.example.com/data
authorization → https://backend.example.com/user

======================================================================
Done.
```

## Architecture

### Scanner Components

1. **Network Interceptor**: Monitors all HTTP requests and responses through Playwright's network events
2. **JavaScript Analyzer**: Downloads and parses external scripts, including source maps
3. **Window Inspector**: Extracts and analyzes global JavaScript variables
4. **Runtime Hooks**: Instruments browser APIs to capture dynamic API calls
5. **Pattern Matcher**: Applies regex and AST-based detection patterns

### Scanning Process

1. Launch headless Chromium browser
2. Install runtime API hooks (fetch, XHR, WebSocket)
3. Navigate to target URL
4. Crawl internal links up to specified depth
5. For each page:
   - Capture network traffic
   - Extract inline and external scripts
   - Dump window globals
   - Collect runtime evidence
6. Apply pattern matching to all collected data
7. Generate findings report

## Security Considerations

### Responsible Use

This tool is intended for:

- Security audits of applications you own or have permission to test
- Penetration testing engagements with proper authorization
- Compliance verification and security assessments

**Do not use this tool against applications without explicit authorization.**



## Configuration

### Customizing Patterns

Edit `scanner.py` to add custom detection patterns in the `STRICT_PATTERNS` dictionary:

```python
STRICT_PATTERNS = {
    "custom_api_key": re.compile(r"\bcustom_[A-Za-z0-9]{32}\b"),
    # Add your patterns here
}
```

### Adjusting Scan Scope

Modify these constants in `scanner.py`:

- `API_PATH_INDICATORS`: Add custom API path patterns
- `COMMON_API_DOMAINS`: Add known API domains
- `CONTEXT_KEYWORDS`: Add keywords that indicate secrets


## Contributing

Contributions are welcome. Please ensure:

- Code follows existing style conventions
- New patterns are tested against false positive scenarios
- Performance impact is minimized for large-scale scans


## Disclaimer

The authors and contributors are not responsible for misuse of this tool. Always obtain proper authorization before scanning any application you do not own.
