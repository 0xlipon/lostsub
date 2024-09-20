
# lostsub

lostsub is a fast and effective tool designed for discovering valid subdomains for websites. It performs passive subdomain enumeration by collecting data from various sources.


## Features

- **Fast and Powerful:** Quickly gathers subdomain data from various APIs.
- **Advanced Retry Mechanism:** Automatically retries commands in case of any errors.
- **Modular Architecture:** Easily extensible with support for different data sources.
- **Comprehensive Support:** Customizable through various command-line flags.


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


## Required Tools

print(f"[**Dnsbruter:**](https://github.com/RevoltSecurities/Dnsbruter) Dnsbruter is a DNS brute-forcing tool. *(required)*")
print(f"[**Subdominator:**](https://github.com/RevoltSecurities/Subdominator) Subdominator is a subdomain enumeration tool. *(required)*")
print(f"[**Subfinder:**](https://github.com/projectdiscovery/subfinder) Subfinder is a tool for discovering subdomains. *(required)*")
print(f"[**Assetfinder:**](https://github.com/tomnomnom/assetfinder) Assetfinder helps find assets associated with a domain. *(required)*")
print(f"[**Chaos:**](https://github.com/projectdiscovery/chaos) Chaos is a tool for managing subdomain data. *(required)*")
print(f"[**Findomain:**](https://github.com/Findomain/Findomain) Findomain is a subdomain discovery tool. *(required)*")
print(f"[**Sublist3r:**](https://github.com/aboehme/Sublist3r) Sublist3r is a fast subdomain enumeration tool. *(required)*")
print(f"[**TraceNinja:**](https://github.com/mohdh34m/TraceNinja) TraceNinja is a subdomain enumeration tool. *(required)*")
print(f"[**JQ:**](https://stedolan.github.io/jq/) JQ is a lightweight and flexible command-line JSON processor. *(optional)*")
print(f"[**Anew:**](https://github.com/tomnomnom/anew) Anew is a tool for deduplicating results. *(optional)*")


## 🔗 Links
[![portfolio](https://img.shields.io/badge/my_portfolio-000?style=for-the-badge&logo=ko-fi&logoColor=white)](https://github.com/0xlipon)

## Conclusion

Feel free to modify or add any information as needed! If there's anything more you'd like to include, just let me know!
