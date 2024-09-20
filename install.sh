#!/bin/bash

# Define color codes for output formatting
BOLD_WHITE='\033[1;37m'
BOLD_CYAN='\033[1;36m'
NC='\033[0m'  # No Color

# List of tools to check
tools=(
    "dnsbruter"
    "subdominator"
    "curl"
    "jq"
    "anew"
    "subfinder"
    "assetfinder"
    "chaos"
    "findomain"
)

# Associative array to keep track of installation status
declare -A installation_status

# Function to check if a tool is installed
check_tool() {
    if command -v "$1" &> /dev/null; then
        echo -e "${BOLD_WHITE}$1:${NC} is installed."
        installation_status["$1"]="installed"
    else
        echo -e "${BOLD_WHITE}$1:${NC} is not installed. Installing..."
        install_tool "$1"
    fi
}

# Function to install a tool based on its name
install_tool() {
    case $1 in
        "dnsbruter")
            git clone https://github.com/RevoltSecurities/Dnsbruter.git
            cd Dnsbruter || { echo "Failed to enter Dnsbruter directory"; return; }
            if ! command -v python3 &> /dev/null; then
                echo "Python 3 is not installed. Please install Python 3 and try again."
                cd .. && rm -rf Dnsbruter
                return
            fi
            pip3 install -r requirements.txt && {
                echo "$1 installed successfully."
                installation_status["$1"]="installed"
            } || {
                echo "Installing dependencies for Dnsbruter failed."
                installation_status["$1"]="failed"
            }
            cd .. && rm -rf Dnsbruter
            ;;
        "subdominator")
            sudo pip3 install aiofiles
            sudo pip3 install git+https://github.com/RevoltSecurities/Subdominator && {
                echo "$1 installed successfully."
                installation_status["$1"]="installed"
            } || {
                echo "Installing Subdominator failed."
                installation_status["$1"]="failed"
            }
            ;;
        "curl")
            sudo apt-get install -y curl && installation_status["$1"]="installed"
            ;;
        "jq")
            sudo apt-get install -y jq && installation_status["$1"]="installed"
            ;;
        "anew")
            go install github.com/tomnomnom/anew@latest && installation_status["$1"]="installed"
            ;;
        "subfinder")
            go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && installation_status["$1"]="installed"
            ;;
        "assetfinder")
            go install github.com/tomnomnom/assetfinder@latest && installation_status["$1"]="installed"
            ;;
        "chaos")
            go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest && {
                echo "$1 installed successfully."
                installation_status["$1"]="installed"
            } || {
                echo "Installing Chaos failed."
                installation_status["$1"]="failed"
            }
            ;;
        "findomain")
            wget https://github.com/Findomain/Findomain/releases/download/9.0.4/findomain-linux.zip
            unzip findomain-linux.zip && chmod +x findomain
            sudo mv findomain /usr/local/bin/ && {
                echo "$1 installed successfully."
                installation_status["$1"]="installed"
            } || {
                echo "Installing Findomain failed."
                installation_status["$1"]="failed"
            }
            rm findomain-linux.zip
            ;;
        *)
            echo -e "${BOLD_CYAN}Unknown tool: $1${NC}"
            installation_status["$1"]="unknown"
            ;;
    esac
}

# Function to print summary of installation results
print_summary() {
    echo -e "\n${BOLD_CYAN}Installation Summary:${NC}"
    for tool in "${tools[@]}"; do
        if [[ -n "${installation_status[$tool]}" ]]; then
            echo -e "${BOLD_WHITE}$tool:${NC} ${installation_status[$tool]}"
        else
            echo -e "${BOLD_WHITE}$tool:${NC} status unknown"
        fi
    done
}

# Main function
main() {
    echo -e "${BOLD_WHITE}Checking installed tools...${NC}"
    
    for tool in "${tools[@]}"; do
        check_tool "$tool"
    done

    echo -e "\n${BOLD_CYAN}If you encounter any issues or are unable to run any of the tools,${NC}"
    echo -e "${BOLD_WHITE}please refer to the following links for manual installation:${NC}"
    echo -e "${BOLD_WHITE}Dnsbruter:${NC} https://github.com/RevoltSecurities/Dnsbruter"
    echo -e "${BOLD_WHITE}Subdominator:${NC} https://github.com/RevoltSecurities/Subdominator"
    echo -e "${BOLD_WHITE}Subfinder:${NC} https://github.com/projectdiscovery/subfinder"
    echo -e "${BOLD_WHITE}Assetfinder:${NC} https://github.com/tomnomnom/assetfinder"
    echo -e "${BOLD_WHITE}Chaos:${NC} https://github.com/projectdiscovery/chaos-client"
    echo -e "${BOLD_WHITE}Findomain:${NC} https://github.com/Findomain/Findomain"

    print_summary
}

# Update package list and install Tor
echo -e "\033[34mINFO:\033[0m \033[31m Installing Tor...\033[0m"
sudo apt update && sudo apt install -y tor

# Start the Tor service
echo -e "\033[34mINFO:\033[0m \033[31m Starting Tor service...\033[0m"
sudo service tor restart || sudo systemctl restart tor

echo -e "\033[34mINFO:\033[0m \033[32m Tor has been successfully installed and started.\033[0m"

main
