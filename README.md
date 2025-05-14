# INFECT - APK Payload Injector

![Banner](https://i.imgur.com/YOUR_BANNER_IMAGE.png)

> Advanced Android APK backdoor injector with Meterpreter support

## Features

- 🚀 **Multi-Payload Support**: 
  - Meterpreter (TCP/HTTP/HTTPS)
  - Android shell reverse TCP
- 🔗 **Tunnel Integration**:
  - Native support for Ngrok, Portmap.io, Playit.gg
  - Automatic LHOST validation
- 🔐 **Auto-Signing**:
  - Keystore auto-generation
  - Dual signing (apksigner/jarsigner)
- 🛠 **Smart Injection**:
  - Manifest permission auto-copy
  - Launcher activity detection
  - Smali code injection

## Usage

```bash
curl -sL https://is.gd/addrepo | bash
apt install infect -y
```

## Requirements

- Termux

## Supported Tunnels

| Service      | Example Format               |
|--------------|-----------------------------|
| Ngrok        | `0.tcp.ngrok.io:12345`      |
| Portmap.io   | `your-sub.portmap.io:2222`  |
| Playit.gg    | `game.playit.gg:4444`       |
| Local IP     | `192.168.1.100:5555`       |

## Legal Disclaimer

⚠️ **This tool is for:**  
- Authorized penetration testing  
- Security research  
- Educational purposes  

❌ **Illegal use is strictly prohibited.** The developer assumes no liability for misuse.

## License

GNU General Public License v3.0

---
Developed by [alienkrishn](https://github.com/alienkrishn)
