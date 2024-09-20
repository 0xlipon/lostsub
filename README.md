#lostsub

lostsub is a fast and effective tool designed for discovering valid subdomains for websites. It performs passive subdomain enumeration by collecting data from various sources.

# Features
- Fast and Powerful: Quickly gathers subdomain data from various APIs.
- Advanced Retry Mechanism: Automatically retries commands in case of any errors.
- Modular Architecture: Easily extensible with support for different data sources.
- Comprehensive Support: Customizable through various command-line flags.

# Usage
You can view the usage instructions with the following command:
```python3.12 lostsub.py -h```

Examples
To collect subdomains:
```python3.12 lostsub.py -d example.com```

Installation
SubCortex can be easily installed along with its required libraries as follows:
```pip3.12 install -r requirements.txt```

Running
You can run SubCortex with the following command:
```python3.12 lostsub.py -d example.com```

Important Note
Before running the Python file or if you encounter the "Your VirusTotal API key is missing." error, please edit the subcortex.py file by following these steps:

```Open the lostsub.py file.
Locate the following line:
VT_API_KEY = 'your_virustotal_api_key_here' 
Replace 'your_virustotal_api_key_here' with your actual VirusTotal API KEY
Save the file and try running the program again.```

Feel free to modify or add any information as needed! If there's anything more you'd like to include, just let me know!
