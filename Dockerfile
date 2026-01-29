# [Stage 1] The Builder: Compiles the C# App
# UPDATE: Using .NET 9.0 SDK
FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src

# Copy the C# Project file
COPY SnifferAvalonia/SnifferAvalonia.csproj ./SnifferAvalonia/
WORKDIR /src/SnifferAvalonia
RUN dotnet restore

# Copy the rest of the source code
COPY SnifferAvalonia/ .
# Publish for Linux
RUN dotnet publish -c Release -o /app/publish --no-restore

# [Stage 2] The Runner: Creates the Final Image
# UPDATE: Using .NET 9.0 SDK for the runtime environment
FROM mcr.microsoft.com/dotnet/sdk:9.0 AS final
WORKDIR /app

# 1. Install System Dependencies (Python, Scapy Support, GUI Support)
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    libpcap0.8 \
    libice6 \
    libsm6 \
    libfontconfig1 \
    libx11-6 \
    && rm -rf /var/lib/apt/lists/*

# 2. Install Scapy
RUN pip3 install scapy --break-system-packages

# 3. Copy the Compiled C# App from Stage 1
COPY --from=build /app/publish .

# 4. Copy the Python Engine Script
COPY SnifferAvalonia/sniffer_gui.py .

# 5. Define the Entrypoint
ENTRYPOINT ["dotnet", "SnifferAvalonia.dll"]