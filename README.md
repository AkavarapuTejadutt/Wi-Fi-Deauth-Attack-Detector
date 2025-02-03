

# **Wi-Fi Deauth Attack Detector**

## **Overview**
The **Wi-Fi Deauthentication Attack Detector** is a Python-based tool designed to monitor Wi-Fi networks for deauthentication attacks. These attacks can be used to disconnect devices from a network, often as part of a larger denial-of-service (DoS) attack. This tool listens to Wi-Fi traffic and detects when deauthentication frames are sent, which is a sign of an ongoing attack. The tool logs all detected attacks and prints alerts to the console in real-time.

**Features:**
- Real-time detection of deauthentication frames in Wi-Fi traffic.
- Logs detected attacks with timestamps.
- Customizable Wi-Fi network interface input.
- Lightweight and easy to use.

## **Installation**

### Prerequisites
To run the **Wi-Fi Deauth Attack Detector**, ensure that you have the following installed:

- Python 3.6 or higher
- Scapy library (used for packet sniffing and analysis)

### Installation Steps

1. **Install Python 3** (if not already installed).  
   - On Linux (Ubuntu/Debian):  
     ```bash
     sudo apt-get update
     sudo apt-get install python3 python3-pip
     ```
   - On macOS:  
     ```bash
     brew install python
     ```
   - On Windows, download and install from the official Python website: https://www.python.org/downloads/

2. **Install dependencies**:
   Install the required `scapy` library by running the following command in your terminal:
   ```bash
   pip install scapy
   ```

### Run the Script
Once all dependencies are installed, you can run the script directly. Here's how to execute it:

1. Download or clone the repository to your local machine.
2. Open a terminal/command prompt and navigate to the project directory.
3. Run the script with the following command:
   ```bash
   python3 deauth_attack_detector.py
   ```

## **Usage**

When you run the script, it will prompt you to input your Wi-Fi interface (e.g., `wlan0` or `wlan1` on Linux, `en0` on macOS). The script will then begin monitoring your network traffic for deauthentication attacks.

### Example Output:

```bash
Enter your Wi-Fi Interface (e.g., wlan0) > wlan0
[*] Monitoring Wi-Fi network for Deauthentication attacks... Press Ctrl+C to stop.
[⚠] ALERT: Deauthentication Packet Detected! Count: 1
[2025-02-03 12:30:01] ALERT: Deauthentication Attack Detected! Count: 1
[⚠] ALERT: Deauthentication Packet Detected! Count: 2
```

### Log File:
All detected deauthentication attacks are logged in a file named `deauth_attack_log.txt`. This log file will store the count and timestamp for each detected attack. Here's an example log entry:

```
[2025-02-03 12:30:01] ALERT: Deauthentication Attack Detected! Count: 1
```

You can check the log file for a record of attacks after running the tool.

## **Troubleshooting**

1. **Error: No Wi-Fi interface found**
   - Make sure your Wi-Fi adapter supports monitor mode. You might need to enable monitor mode on your Wi-Fi interface using tools like `airmon-ng` (on Linux).
   
2. **Permission Denied Error**
   - On Linux/macOS, you might need to run the script with elevated permissions (e.g., `sudo`) to access the network interface.
   - Example:  
     ```bash
     sudo python3 deauth_attack_detector.py
     ```

3. **No Deauth packets detected**
   - Ensure that your network has deauthentication packets being sent. This tool works only when there is ongoing deauthentication activity on the network. Try running the tool on a busy network or simulate an attack.

## **Future Enhancements**
- **Email Alerts:** Add functionality to send email notifications when an attack is detected.
- **GUI Interface:** Develop a graphical user interface (GUI) for easier monitoring.
- **Advanced Analysis:** Implement analysis for different types of Wi-Fi attacks beyond deauthentication.
- **Support for Multiple Interfaces:** Extend the script to support multiple Wi-Fi interfaces for broader monitoring.

## **License**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---
