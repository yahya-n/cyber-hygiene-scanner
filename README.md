# Cyber Hygiene Scanner

A web-based cybersecurity assessment tool designed to help small businesses and website owners evaluate common website security weaknesses and understand practical security improvements.

The project is built with Python and Flask, with dependencies for HTTP requests, HTML parsing, PDF report generation, background task processing, Redis, and environment-based configuration.

> **Disclaimer:** This tool is intended for authorized security assessments, educational use, and defensive security research. Only scan websites that you own or have explicit permission to assess.

---

## Overview

Small businesses often operate websites without dedicated cybersecurity teams. Misconfigured security headers, weak security practices, and publicly exposed information can increase a website's security risks.

**Cyber Hygiene Scanner** aims to simplify the initial website security assessment process by providing a centralized interface for analyzing a website and presenting security-related findings in an understandable format.

### Project Objectives

- Assess common website security hygiene practices.
- Identify potential security configuration weaknesses.
- Present findings in a structured format.
- Provide practical security recommendations.
- Support security assessment scoring.
- Generate PDF-based assessment reports.
- Improve cybersecurity awareness among small businesses and developers.

---

## Features

### Website Security Assessment

Analyze a website URL and evaluate selected security-related properties.

### HTTP and HTML Analysis

Use HTTP requests and HTML parsing to inspect publicly accessible website information.

### Security Findings

Present identified issues in a structured format to help users understand potential weaknesses.

### Security Recommendations

Provide practical recommendations for improving a website's security posture.

### Security Score

Summarize assessment results through a security score or rating system where supported by the implementation.

### PDF Reports

Generate downloadable security assessment reports using ReportLab.

### Background Task Support

The project includes Celery and Redis dependencies for background task processing, allowing time-consuming operations to be handled asynchronously when configured.

### Web Interface

The application is built with Flask and can be accessed through a browser.

---

## Technology Stack

| Technology | Purpose |
|------------|---------|
| Python | Application development |
| Flask | Web application framework |
| Requests | HTTP requests and website analysis |
| BeautifulSoup4 | HTML parsing |
| ReportLab | PDF report generation |
| Celery | Background task processing |
| Redis | Task queue and result backend support |
| python-dotenv | Environment variable management |

---

## Project Structure

```text
cyber-hygiene-scanner/
│
├── app/
│   └── ...                    # Flask application package
│
├── run.py                     # Application entry point
├── requirements.txt           # Python dependencies
├── .gitignore                 # Git ignore rules
└── README.md                  # Project documentation
```

> The internal structure of the `app/` package may change as development continues.

---

## Requirements

Before running the project, ensure the following are installed:

- Python 3.9 or later
- pip
- Git

Optional, depending on the background-processing configuration:

- Redis
- Celery

---

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/yahya-n/cyber-hygiene-scanner.git
```

### 2. Navigate to the Project Directory

```bash
cd cyber-hygiene-scanner
```

### 3. Create a Virtual Environment

#### Windows

```bash
python -m venv venv
venv\Scripts\activate
```

#### Linux / macOS

```bash
python3 -m venv venv
source venv/bin/activate
```

### 4. Install Dependencies

```bash
pip install -r requirements.txt
```

---

## Configuration

The application uses environment variables where required.

Create a `.env` file in the project root if the application requires environment-based configuration:

```env
FLASK_ENV=development
FLASK_DEBUG=True
SECRET_KEY=replace-with-a-secure-random-value

# Add project-specific API keys or service configuration here.
# Do not commit real secrets to GitHub.
```

> Use the variable names expected by the application code. The example above is a configuration template and should be adjusted according to the implementation.

---

## Running the Application

Start the Flask development server with:

```bash
python run.py
```

The application is configured to run on:

```text
http://127.0.0.1:5000
```

Open the application in a browser:

```text
http://localhost:5000
```

---

## Usage

### 1. Open the Web Application

Launch the application in your browser.

### 2. Enter a Website URL

Provide the URL of a website you own or are authorized to assess.

Example:

```text
https://example.com
```

### 3. Start the Assessment

Submit the URL through the application's scanning interface.

### 4. Review the Results

Review the available findings, security checks, and recommendations.

### 5. Generate a Report

If PDF reporting is enabled in the current implementation, generate a report containing the assessment results.

---

## Assessment Workflow

```text
User enters an authorized website URL
                │
                ▼
        Flask Web Interface
                │
                ▼
       URL Validation & Request
                │
                ▼
       Website Security Checks
                │
                ▼
       HTTP / HTML Analysis
                │
                ▼
       Findings & Risk Evaluation
                │
                ▼
       Security Score Calculation
                │
                ▼
       Results Dashboard / Report
                │
                ▼
          PDF Export
```

---

## Security Checks

The scanner is intended to support checks related to common website security hygiene practices.

Depending on the current implementation, checks may include:

- HTTPS availability
- HTTP security headers
- SSL/TLS-related configuration indicators
- Content Security Policy
- Strict-Transport-Security
- X-Content-Type-Options
- X-Frame-Options
- Referrer-Policy
- Cookie security attributes
- Publicly accessible website information
- Basic HTML and response analysis

> **Important:** The exact checks, scoring rules, and integrations depend on the current application code. A check should only be considered implemented when it is present and functioning in the scanner.

---

## Security Score

The project may use a security score to summarize assessment results.

A typical scoring model can consider:

- Number of detected issues
- Severity of findings
- Presence or absence of recommended security controls
- Configuration weaknesses
- Overall security hygiene

### Example Severity Categories

| Severity | Description |
|----------|-------------|
| Critical | A serious issue requiring immediate investigation |
| High | A significant security weakness |
| Medium | A security issue that should be addressed |
| Low | A minor weakness or improvement opportunity |
| Informational | Useful security-related information |

> Severity classifications should reflect the actual scoring logic implemented in the project.

---

## PDF Report Generation

The project includes ReportLab for generating PDF reports.

A report may contain:

- Target website
- Assessment date
- Security score
- Detected findings
- Severity classifications
- Technical observations
- Recommended remediation steps

### Report Workflow

```text
Assessment Results
        │
        ▼
Report Data Preparation
        │
        ▼
PDF Generation
        │
        ▼
Downloadable Security Report
```

---

## Background Tasks

Celery and Redis are included in the project's dependencies to support background processing.

Background tasks can be useful for:

- Long-running website assessments
- PDF report generation
- Scheduled security checks
- Processing multiple assessment tasks
- Avoiding long-running operations in the web request

### Redis

Redis may be used as a message broker or result backend for Celery.

A local Redis instance may be required if background task functionality is enabled.

> The exact Celery configuration and worker commands depend on the implementation inside the `app/` package.

---

## Development

### Run the Application

```bash
python run.py
```

### Install New Dependencies

After installing a new Python package, update the dependency file:

```bash
pip freeze > requirements.txt
```

Review the generated file before committing changes.

### Recommended Development Practices

- Use a virtual environment.
- Keep secrets in environment variables.
- Do not commit `.env` files containing credentials.
- Validate user-provided URLs.
- Handle network timeouts and connection failures.
- Avoid scanning unauthorized targets.
- Keep dependencies updated.
- Log errors without exposing sensitive information.
- Test security checks against controlled environments.

---

## Responsible Use

This project is intended for:

- Website owners
- Small businesses
- Developers
- Cybersecurity students
- Security researchers
- Authorized penetration testers
- Defensive security teams

### Do Not Use This Tool To:

- Scan websites without permission.
- Attempt unauthorized exploitation.
- Disrupt services.
- Bypass authentication.
- Access private information.
- Conduct denial-of-service activity.
- Evade security monitoring.
- Perform attacks against third-party systems.

Only assess systems for which you have explicit authorization.

---

## Limitations

A website hygiene scanner is not a replacement for a complete security audit.

Potential limitations include:

- Public-facing checks cannot identify every vulnerability.
- Automated results may contain false positives or false negatives.
- The scanner may not detect application-logic vulnerabilities.
- Authentication-protected functionality may not be assessed.
- Results depend on network connectivity and website availability.
- Security scores are only as reliable as the checks and scoring logic behind them.
- A passing scan does not guarantee that a website is secure.

For high-risk systems, combine automated scanning with manual testing, code review, configuration review, and professional security assessment.

---

## Troubleshooting

### Application Does Not Start

Verify that dependencies are installed:

```bash
pip install -r requirements.txt
```

Confirm that the virtual environment is activated and that Python is available:

```bash
python --version
```

### Port Already in Use

The default application port is `5000`.

Stop the process using that port or modify the port configuration in `run.py`.

### Website Cannot Be Scanned

Check that:

- The URL is correctly formatted.
- The target website is reachable.
- Your internet connection is working.
- The website is not blocking the request.
- The scanner's timeout settings are appropriate.

### PDF Report Is Not Generated

Check that:

- ReportLab is installed.
- The application has permission to create files.
- The report-generation function is correctly configured.
- Any required output directory exists.

### Background Tasks Are Not Running

If background processing is enabled:

- Confirm that Redis is running.
- Confirm that Celery is configured correctly.
- Start the appropriate Celery worker.
- Check application and worker logs for errors.

---

## Future Improvements

Potential future improvements include:

- Expanded security-header analysis
- SSL/TLS configuration checks
- Improved vulnerability classification
- More detailed security scoring
- Enhanced PDF reports
- Scheduled website assessments
- Email notifications
- Dashboard-based assessment history
- Multi-website monitoring
- Improved error handling
- Authentication and user accounts
- Database-backed scan history
- Docker support
- Automated testing
- CI/CD integration
- Export to additional report formats

---

## Contributing

Contributions are welcome.

### Contribution Workflow

1. Fork the repository.
2. Create a feature branch.

```bash
git checkout -b feature/your-feature-name
```

3. Make your changes.
4. Test the application.
5. Commit your changes.

```bash
git add .
git commit -m "Add your feature description"
```

6. Push the branch.

```bash
git push origin feature/your-feature-name
```

7. Open a pull request.

### Contribution Guidelines

- Keep changes focused.
- Follow the existing project structure.
- Write clear commit messages.
- Avoid committing secrets.
- Test security-related changes carefully.
- Update documentation when functionality changes.

---

## License

No license has currently been specified for this repository.

Until a license is added, the project should not be assumed to be available for unrestricted redistribution, modification, or commercial use.

---

## Author

**Abdul Kuddoos Yahya**

- GitHub: [yahya-n](https://github.com/yahya-n)
- Portfolio: [yahya-dev.me](https://yahya-dev.me)

---

## Project Status

This project is under development.

Features, security checks, scoring logic, and integrations may change as development continues.

---

## Disclaimer

This software is provided for educational and defensive cybersecurity purposes. The author is not responsible for misuse, unauthorized scanning, damage, data loss, or legal consequences resulting from the use of this tool.

Always obtain explicit authorization before assessing a website or system.
