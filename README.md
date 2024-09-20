
# lostsub

lostsub is a fast and effective tool designed for discovering valid subdomains for websites. It performs passive subdomain enumeration by collecting data from various sources.


## Features

- **Fast and Powerful:** Quickly gathers subdomain data from various APIs.
- **Advanced Retry Mechanism:** Automatically retries commands in case of any errors.
- **Modular Architecture:** Easily extensible with support for different data sources.
- **Comprehensive Support:** Customizable through various command-line flags.


## Screenshots

![App Screenshot](https://raw.githubusercontent.com/EN5R/SubCortex/refs/heads/main/src/SubCortex.png)

## Videos
[https://github.com/EN5R/SubCortex/blob/main/src/SubCortex.mp4
](https://github-production-user-asset-6210df.s3.amazonaws.com/104204586/369095286-75a71664-da4b-4862-bb0a-281f7b009943.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAVCODYLSA53PQK4ZA%2F20240919%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20240919T165323Z&X-Amz-Expires=300&X-Amz-Signature=b47e2d945524b3372ea73c7a3da1c6e65c4b643516dfe0fbf94c48322c599a03&X-Amz-SignedHeaders=host)

## Usage

You can view the usage instructions with the following command:

```bash
  python3 lostsub.py -h
```

## Examples

To collect subdomains:

```bash
  python3 lostsub.py -d example.com
```
## Installation

lostsub can be easily installed along with its required libraries as follows:

```bash
  pip3 install -r requirements.txt
```
    
## Running

You can run lostsub with the following command:

```bash
  python3 lostsub.py -d example.com
```

## Important Note

Before running the Python file or if you encounter the "Your VirusTotal API key is missing." error, please edit the `lostsub.py` file by following these steps:

1. Open the `lostsub.py` file.
2. Locate the following line:
   ```python
   VT_API_KEY = 'your_virustotal_api_key_here' 
   ```
3. Replace 'your_virustotal_api_key_here' with your actual [**VirusTotal API KEY**](https://www.virustotal.com/gui/my-apikey)
4. Save the file and try running the program again.


## About the Project

SubCortex collects its resources through APIs. Key sources used for gathering subdomains include:

- **CRTsh:** crt.sh searches Certificate Transparency logs to find subdomains.

- **SecurityTrails:** SecurityTrails provides subdomain information through its comprehensive domain and DNS records database.

- **VirusTotal:** VirusTotal discovers subdomains by aggregating data from various domain records and sources.

- **Wayback Machine:** Wayback Machine identifies subdomains by crawling and archiving historical snapshots of web pages and their subdomains.

- *etc..*

SubCortex gathers its resources from subdomain tools, in addition to APIs. Key sources necessary for collecting subdomains include:

- [**TraceNinja:**](https://github.com/mohdh34m/TraceNinja) TraceNinja is a subdomain enumeration tool. *(required)*

- [**Subfinder:**](https://github.com/projectdiscovery/subfinder) Discovers subdomains from passive sources. *(required)*

- [**Assetfinder:**](https://github.com/tomnomnom/assetfinder) Finds subdomains for a specified domain. *(required)*


## 🔗 Links
[![portfolio](https://img.shields.io/badge/my_portfolio-000?style=for-the-badge&logo=ko-fi&logoColor=white)](https://github.com/0xlipon)

## Conclusion

Feel free to modify or add any information as needed! If there's anything more you'd like to include, just let me know!
