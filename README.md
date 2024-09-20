
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

If you encounter "Your VirusTotal API key is missing," edit the lostsub.py file as follows:

1. Open the `lostsub.py` file.
2. Locate the following line:
   ```python
   VT_API_KEY = 'your_virustotal_api_key_here' 
   ```
3. Replace 'your_virustotal_api_key_here' with your actual [**VirusTotal API KEY**](https://www.virustotal.com/gui/my-apikey)
4. Save the file and try running the program again.


## Required Tools

- [**Dnsbruter:**](https://github.com/RevoltSecurities/Dnsbruter) DNS brute-forcing tool. *(required)*
- [**Subdominator:**](https://github.com/RevoltSecurities/Subdominator) Subdomain enumeration tool. *(required)*
- [**Subfinder:**](https://github.com/projectdiscovery/subfinder) Discovers subdomains from passive sources. *(required)*
- [**Assetfinder:**](https://github.com/tomnomnom/assetfinder) Finds subdomains for a specified domain. *(required)*
- [**Chaos:**](https://github.com/projectdiscovery/chaos) Manages subdomain data. *(required)*
- [**Findomain:**](https://github.com/Findomain/Findomain) Subdomain discovery tool. *(required)*
- [**Sublist3r:**](https://github.com/aboehme/Sublist3r) Fast subdomain enumeration tool. *(required)*
- [**TraceNinja:**](https://github.com/mohdh34m/TraceNinja) Subdomain enumeration tool. *(required)*
- [**JQ:**](https://stedolan.github.io/jq/) Lightweight command-line JSON processor. *(optional)*
- [**Anew:**](https://github.com/tomnomnom/anew) Tool for deduplicating results. *(optional)*


## 🙏 Support on KoFi:
[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/0xlipon)

## Conclusion

Feel free to modify or add any information as needed! If there's anything more you'd like to include, just let me know!
