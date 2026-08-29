# V2Leafy

V2Leafy contains two independent applications:

```text
V2Leafy/
├── .devcontainer/       # Root Codespaces configuration
│   ├── Dockerfile
│   └── devcontainer.json
├── railway.json          # Root Railway build/deploy configuration
├── Procfile              # Root Railway process command
├── requirements.txt      # Root Railway dependency entrypoint
├── G2Leafy/              # G2Leafy application code only
│   ├── main.py
│   └── index.html
├── R2Leafy/              # R2Leafy application code only
│   ├── main.py
│   ├── index.html
│   └── requirements.txt
├── assets/               # Shared assets
├── configs.txt
└── LICENSE
```

## Codespaces / G2Leafy

Open the repository root in GitHub Codespaces. Codespaces automatically uses `.devcontainer/devcontainer.json`, builds `.devcontainer/Dockerfile`, and starts `G2Leafy/main.py`. The dashboard uses port 8080 and the VLESS endpoint uses port 443.

Manual start:

```bash
cd V2Leafy/G2Leafy
python3 main.py
```

## Railway / R2Leafy

Deploy the repository root to Railway. Railway reads `railway.json`, installs dependencies through the root `requirements.txt`, starts `python R2Leafy/main.py`, and checks `/health`. Railway supplies `PORT`; configure a strong `SECRET_KEY` variable. The R2Leafy application code remains under `R2Leafy/`.

## Both / Cloudflare Relay

Each panel has its own independent relay implementation embedded directly in its single `main.py` backend. Open **Both / Relay**, create a Cloudflare API token using the provided link, enter the Railway HTTPS origin and token, then select **Generate Relay**.

The token is used only during provisioning. It is not stored, returned by the API, put in panel state, or written to logs. The generated Worker supports HTTP and WebSocket forwarding with a bounded upstream handshake timeout.

Only use this with domains and traffic you own or are authorized to operate. Cloudflare and hosting-provider limits and terms still apply.

Shared assets and repository-level metadata live only at the V2Leafy root. The original `G2Leafy-main` and `R2Leafy-main` folders remain unchanged.
