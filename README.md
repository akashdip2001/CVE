# CVE Analysis Repository

A comprehensive repository for tracking and analyzing Common Vulnerabilities and Exposures (CVEs) from 2000 to present. This repository serves as a knowledge base for security researchers, developers, and IT professionals to stay updated with the latest vulnerabilities in the tech world.

## 📚 Repository Structure

Each year folder contains:
- **CVE entries** organized by severity (CVSS score 10.0 to 1.0)
- **README.md** with indexed CVE list
- **Service/Software tags** for easy categorization
- **Public documentation links** for further research
- **Mermaid diagrams** showing vulnerability relationships and impact

## 📊 Severity Ratings

CVEs are categorized using CVSS (Common Vulnerability Scoring System) scores:

| Score Range | Severity | Color Code |
|-------------|----------|------------|
| 9.0 - 10.0  | 🔴 Critical | Red |
| 7.0 - 8.9   | 🟠 High | Orange |
| 4.0 - 6.9   | 🟡 Medium | Yellow |
| 0.1 - 3.9   | 🟢 Low | Green |

## 📁 Year Coverage

```
CVE/
├── 2000/
├── 2001/
├── ...
├── 2023/
└── 2024/
```

## 🔍 Quick Navigation

- [2024 CVEs](./2024/) - Latest vulnerabilities
- [2023 CVEs](./2023/) - Previous year
- [2022 CVEs](./2022/)
- [2021 CVEs](./2021/)
- [2020 CVEs](./2020/)

## 🏷️ Common Tags

- `Web Framework` - React, Angular, Vue, etc.
- `Backend` - Node.js, Django, Spring, etc.
- `Database` - MySQL, PostgreSQL, MongoDB, etc.
- `Operating System` - Linux, Windows, macOS
- `Cloud` - AWS, Azure, GCP
- `Container` - Docker, Kubernetes
- `Security Tools` - OpenSSL, Apache, Nginx

## 📖 How to Use This Repository

1. **Browse by Year**: Navigate to specific year folders
2. **Search by Severity**: Look for critical vulnerabilities first
3. **Filter by Technology**: Use tags to find relevant CVEs
4. **Study Diagrams**: Understand attack vectors through Mermaid diagrams
5. **Follow Links**: Deep dive with official CVE documentation

## 🤝 Contributing

To add new CVEs:
1. Place in appropriate year folder
2. Update the year's README.md
3. Include CVSS score, affected software, and documentation links
4. Add Mermaid diagram if applicable

## 📚 Resources

- [NVD - National Vulnerability Database](https://nvd.nist.gov/)
- [CVE.org](https://cve.org/)
- [MITRE CVE List](https://cve.mitre.org/)
- [FIRST CVSS Calculator](https://www.first.org/cvss/calculator/3.1)

## ⚠️ Disclaimer

This repository is for educational and research purposes only. Information is compiled from public sources. Always verify CVE details from official sources before taking action.

---

**Last Updated**: 2024
**Maintainer**: akashdip2001
