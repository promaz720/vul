# 🔒 Website Vulnerability Scanner for HackerOne

A comprehensive web vulnerability scanner built with Python Streamlit that automatically detects security issues and generates HackerOne-ready reports.

## Features

### 🔍 Comprehensive Scanning
- **Multiple Vulnerability Types**: XSS, SQL Injection, CSRF, Broken Authentication, Security Misconfiguration, Sensitive Data Exposure, Broken Access Control
- **Technology Detection**: Identifies frameworks like WordPress, React, jQuery, Bootstrap, etc.
- **Security Headers Check**: Validates essential security headers (CSP, HSTS, X-Frame-Options, etc.)
- **Website Crawling**: Automatically discovers and scans multiple pages

### 📊 HackerOne Integration
- **Structured Reports**: Generates properly formatted reports for HackerOne submission
- **CVSS Scoring**: Includes Common Vulnerability Scoring System ratings
- **Detailed Remediation**: Provides specific fix recommendations
- **Export Functionality**: Download reports in Markdown format

### 🎯 Vulnerability Detection
- **Cross-Site Scripting (XSS)**: Detects forms without CSRF protection
- **SQL Injection**: Identifies potentially vulnerable input fields
- **Security Headers**: Checks for missing essential security headers
- **Information Disclosure**: Finds exposed email addresses and sensitive data
- **Authentication Issues**: Detects weak password policies
- **Access Control**: Identifies admin pages without proper authentication

## Installation

1. **Clone or download the project files**
   ```bash
   # Ensure you have the files: requirements.txt, vulnerability_scanner.py, README.md
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**
   ```bash
   streamlit run vulnerability_scanner.py
   ```

4. **Open your browser**
   Navigate to `http://localhost:8501` to access the web interface.

## Usage

### Basic Scanning
1. Enter the target website URL (e.g., `https://example.com`)
2. Configure scan settings in the sidebar:
   - Max Pages to Scan (1-50)
   - Enable/disable form scanning
   - Enable/disable security header checks
3. Click "🚀 Start Scan" to begin the analysis

### Understanding Results
- **High Severity**: Critical vulnerabilities requiring immediate attention
- **Medium Severity**: Important issues that should be addressed
- **Low Severity**: Minor issues and best practice recommendations
- **Info**: Informational findings about the website

### Exporting Reports
- All findings are automatically formatted for HackerOne submission
- Download reports as Markdown files with timestamps
- Reports include detailed descriptions, CVSS scores, and remediation steps

## HackerOne Report Format

The generated reports include:

```markdown
# Website Security Assessment - X findings

## Summary
Comprehensive security scan completed with the following findings:
- High severity: X
- Medium severity: X
- Low severity: X
- Informational: X

## Findings

### Vulnerability Title
- **Category:** Category Name
- **Severity:** HIGH
- **CVSS Score:** X.X

**Description:**
Detailed description of the vulnerability...

**Remediation:**
Specific steps to fix the issue...

## General Recommendations
- Implement proper input validation and sanitization
- Use prepared statements for database queries
- Implement CSRF protection on all forms
- ...
```

## Dependencies

- **streamlit**: Web interface framework
- **requests**: HTTP requests for website scanning
- **beautifulsoup4**: HTML parsing and analysis
- **selenium**: Advanced web scraping (optional)
- **lxml**: Fast XML/HTML parsing
- **python-dotenv**: Environment variable management

## Configuration

### Scan Settings
- **Max Pages**: Control how many pages to scan (default: 10)
- **Timeout**: Request timeout in seconds (default: 10)
- **User Agent**: Browser identification string

### Detection Modules
- Form analysis for CSRF protection
- Input field analysis for injection vulnerabilities
- Header validation for security best practices
- Content analysis for information disclosure

## Limitations

- **Passive Scanning**: Only analyzes visible content and forms
- **No Authentication**: Cannot scan protected areas without credentials
- **Rate Limiting**: Respects website response times
- **JavaScript Dependent**: May miss dynamically loaded content

## Security Considerations

- **Legal Usage**: Only scan websites you own or have permission to test
- **Rate Limiting**: The scanner includes delays to avoid overwhelming servers
- **Responsible Disclosure**: Use findings for legitimate security research only

## Contributing

To extend the scanner:

1. Add new vulnerability checks in the `WebsiteVulnerabilityScanner` class
2. Update the `check_*` methods for specific vulnerability types
3. Add corresponding remediation advice
4. Test thoroughly before deployment

## License

This tool is provided for educational and authorized security testing purposes only. Users are responsible for complying with applicable laws and obtaining proper permissions before scanning any website.

## Support

For issues or questions:
1. Check the troubleshooting section
2. Review the code comments for implementation details
3. Ensure all dependencies are properly installed

---

**⚠️ Disclaimer**: This tool should only be used on websites you own or have explicit permission to test. Unauthorized scanning may violate terms of service or applicable laws.
