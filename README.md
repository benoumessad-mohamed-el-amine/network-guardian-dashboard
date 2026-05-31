# Network Guardian IDS Dashboard - Full Stack Application

A comprehensive Network Intrusion Detection System (NIDS) dashboard built with a Django backend and a React/TypeScript/Vite frontend. It includes a real-time Scapy-based packet sniffer, dynamic WiFi sniffing interface selection, and a Hierarchical Machine Learning composite classifier (routing anomalies through DDoS, Portscan, Brute Force, and Syn Flood).

---

## 🏗️ Project Structure

```
network-guardian-dashboard/
├── back/                    # Django Backend
│   ├── manage.py
│   ├── requirements.txt
│   ├── db.sqlite3
│   ├── demo/                # Django project settings
│   │   ├── settings.py      # REST Framework & CORS config
│   │   ├── urls.py
│   └── myapp/               # Main application
│       ├── models.py        # TrafficLog, Alert, AuditLog
│       ├── views.py         # API endpoints
│       ├── sniffer_manager.py # Threaded sniffer control
│       ├── processing/      # IDS ML & feature extraction
│       │   ├── extractor.py # Real-time flow tracker
│       │   ├── model_wrappers.py # Hierarchical composite model
│       │   ├── model_factory.py
│       │   └── service.py   # Analysis & alert storage
│       └── tests/
│
└── front/                   # React + Vite Frontend
    ├── src/
    │   ├── components/      # React components (EngineStatus selector, Charts, Tables)
    │   ├── context/         # Auth and Monitoring contexts
    │   ├── routes/          # Navigation views (Alerts, Logs, Settings)
    │   └── main.tsx
    ├── package.json
    ├── vite.config.ts
    └── tsconfig.json
```

---

## 🚀 Running the Project on Linux

### 1. Django Backend Setup
Open a terminal and run the following commands:
```bash
# Navigate to backend folder
cd back

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run migrations
python manage.py migrate

# Seed initial admin user and data (optional)
python manage.py loaddata initial_data.json  # If available, or run standard seeding

# Start the development server
python manage.py runserver
```
The API is now running at `http://127.0.0.1:8000/`.

> [!IMPORTANT]
> **Packet Sniffing Privileges on Linux:**
> Sniffing live packets (including WiFi sniffing) requires access to raw sockets. You must run the sniffer command or the Django server with root privileges:
> ```bash
> # Run sniffer CLI on wlan0 interface
> sudo venv/bin/python manage.py sniff --interface wlan0
> ```

### 2. Frontend React Setup
Open a second terminal window:
```bash
# Navigate to frontend folder
cd front

# Install dependencies
npm install

# Run Vite dev server
npm run dev
```
The React dashboard is now running at `http://localhost:5173/`.

---

## 🚀 Running the Project on Windows

### 1. Django Backend Setup
Open PowerShell or Command Prompt:
```cmd
:: Navigate to backend folder
cd back

:: Create virtual environment
python -m venv venv

:: Activate virtual environment
:: In CMD:
venv\Scripts\activate.bat
:: In PowerShell:
.\venv\Scripts\Activate.ps1

:: Install dependencies
pip install -r requirements.txt

:: Run migrations
python manage.py migrate

:: Start the development server
python manage.py runserver
```
The API is now running at `http://127.0.0.1:8000/`.

> [!IMPORTANT]
> **Packet Sniffing Privileges on Windows:**
> To capture live traffic on Windows, you must install **Npcap** or **WinPcap** (ensure you check the box to "Install Npcap with WinPcap compatibility mode").
> Open your terminal as **Administrator**, activate the virtual environment, and run:
> ```cmd
> python manage.py sniff --interface any
> ```

### 2. Frontend React Setup
Open a new terminal window:
```cmd
:: Navigate to frontend folder
cd front

:: Install dependencies
npm install

:: Run Vite dev server
npm run dev
```
The React dashboard is now running at `http://localhost:5173/`.

---

## 🛡️ Machine Learning Pipeline Integration

The backend is configured to use a dynamic loader for the hierarchical models:
1. **Tier-1 Binary Filter:** Decides if traffic is `normal` or an `anomaly` (`binary_anomaly_rf.pkl`).
2. **Tier-2 Attack Classifiers:** Anomalies are routed to specialized models in parallel:
   - **DDoS** (`ddos_rf.pkl`)
   - **Portscan** (`portscan_rf.pkl`)
   - **Syn Flood** (`synflood_rf.pkl`)
   - **Brute Force** (`bruteforce_rf.pkl`)
3. If no Tier-2 classifier is positive, it registers as an **Unknown Threat** and alerts the user to check network configuration.

*Note: If the `.pkl` files are not placed in `back/myapp/processing/models/`, the server automatically falls back to a MockModel so you can develop without ML requirements.*

---

## ⚙️ Configuration & Environment

- **CORS Allowed Origins:** Managed in `back/demo/settings.py`.
- **API URL Configuration:** Managed in `front/src/context/auth-context.tsx` or using a `.env` file containing `VITE_API_URL=http://localhost:8000`.
