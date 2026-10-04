# Oracle runtime: original RCT1 (Win32, 2000) under 32-bit Wine, headless via Xvfb.
FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN dpkg --add-architecture i386 && apt-get update && apt-get install -y --no-install-recommends \
      wine wine32 wine64 libwine libwine:i386 \
      xvfb xauth xdotool x11-utils imagemagick \
      p7zip-full ca-certificates procps python3 \
    && rm -rf /var/lib/apt/lists/*
RUN useradd -m -u 1000 rct
USER rct
ENV WINEARCH=win32 WINEPREFIX=/home/rct/.wine WINEDEBUG=-all DISPLAY=:99
# Initialize a pristine 32-bit prefix at build time so runs start from identical state.
RUN (Xvfb :99 -screen 0 1024x768x24 & sleep 2; wineboot -i; wineserver -w) 2>/dev/null
WORKDIR /work
