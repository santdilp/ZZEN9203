```markdown
# IoT Security Assessment Tool Project

## Project Goal
To build a Python-based security assessment tool that scans consumer IoT devices. The tool will retrieve known vulnerabilities from CVE dataset, perform dictionary credentials check, and generate a risk score based on the results. The tool aims to help home users to evaluate their connected IoT devices security posture and take corrective actions.

## Project Description
IoT devices are common in most homes and often consumers lack implementing best practices, making them easy target for attack. Often outdated firmware, vulnerable libraries, and easy to guess password are contributing factors.

This project aims to include a step-by-step guide to run an assessment tool which will:
1. Discover Devices (nmap or scapy)
2. Check for vulnerabilities (nvdlib or other library) 
3. Credentials Check (Controlled on owned devices)
4. Score and generate report

## Project Schedule

### Week 1: Research
1. Study IoT security vulnerabilities
2. Create a dictionary for credentials
3. Review nvdlib or other api on how to query NIST database

### Week 2: Device Discovery Test
1. Test nmap or/and scapy to discover devices
2. Validate inventory and report learnings

### Week 3: Check for Vulnerabilities
1. Learn how to collect banner / firmware information using Python
2. Implement CVE lookup
3. Use GenAI to assess criticality (optional)

### Week 4: Credential Checks
1. Setup one device with password from the dictionary
2. Validate login pages /login or /admin
3. Attempt login and report learnings

### Week 5: Scoring and Report
1. Build a database of devices
2. Include findings from CVE lookup and Credentials check
3. Include remediation, time permitted use GenAI to create a user friend remediation steps

### Week 6
Conclude my analysis and submit the report

## Project Deliverables/Outcomes
A working prototype (python based) tool along with a comprehensive report that will include development and implementation details, along with my learnings.

### Security Review Tool (Python based)
- Python Executable Script
- Readme.md
- Html report

### Comprehensive Report
- Introduction
- Implementation Details  
- Findings
- Learnings
- Conclusion
```
