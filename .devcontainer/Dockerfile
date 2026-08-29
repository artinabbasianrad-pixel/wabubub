FROM debian:bookworm-slim

LABEL maintainer="G2rayXCodeLeafy" \
      description="V2Leafy G2Leafy Codespace"

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    TERM=xterm-256color \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        bash curl wget unzip ca-certificates sudo openssl uuid-runtime tmux tzdata \
        qrencode jq vnstat bc net-tools gnupg libcap2-bin iproute2 \
        procps psmisc locales python3 python3-venv \
    && sed -i 's/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen \
    && locale-gen \
    && curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
        | dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg \
    && chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
        > /etc/apt/sources.list.d/github-cli.list \
    && apt-get update && apt-get install -y --no-install-recommends gh \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    case "$(dpkg --print-architecture)" in \
        amd64) XR="Xray-linux-64.zip" ;; \
        arm64) XR="Xray-linux-arm64-v8a.zip" ;; \
        *) XR="Xray-linux-64.zip" ;; \
    esac; \
    wget -qO /tmp/xray.zip "https://github.com/XTLS/Xray-core/releases/latest/download/${XR}" \
    && unzip -q /tmp/xray.zip -d /tmp/xray-dir \
    && mv /tmp/xray-dir/xray /usr/local/bin/xray \
    && mv /tmp/xray-dir/*.dat /usr/local/bin/ \
    && chmod +x /usr/local/bin/xray \
    && setcap 'cap_net_bind_service=+ep' /usr/local/bin/xray \
    && rm -rf /tmp/xray.zip /tmp/xray-dir

EXPOSE 443 8080
