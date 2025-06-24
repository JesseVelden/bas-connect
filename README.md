# BAS-Connect: SSH DevSpace Tunnel CLI

A utility tool for creating secure SSH tunnels to Business Application Studio (BAS) Dev Spaces, allowing direct SSH access to your development environment.

## Description

This tool automates the process of establishing an SSH connection to your Business Application Studio dev space. It handles:

- **Automatic Authentication**: Opens a browser window for authentication towards the BAS landscape
- **Dev Space Auto-Start**: Starts your dev space if it's not running
- **SSH Configuration**: Automatically sets up your local SSH config
- **Connection Resilience**: Automatically reconnects if the connection is lost

Once running, you can connect to your dev space using standard SSH commands and tools like VS Code Remote SSH.

## Prerequisites

- Node.js (v22 or later)
- The BAS landscape URL (e.g., https://xxx.eu20cf.applicationstudio.cloud.sap) and an already created dev space ID (e.g., ws-xxxx)
## Usage

You can simply run the script without any arguments, and it will prompt you for the necessary information:

```shell script
npx bas-connect
```

### Command Line Arguments

For faster usage, the script accepts also the following command-line parameters:

| Argument         | Short | Description                                     | Example                                                         |
|------------------|-------|-------------------------------------------------|-----------------------------------------------------------------|
| `--landscapeUrl` | `-u`  | Your BAS landscape URL                          | `--landscapeUrl https://xxx.eu20cf.applicationstudio.cloud.sap` |
| `--devspaceId`   | `-d`  | Your dev space ID                               | `--devspaceId ws-xxxx`                                          |
| `--sshPort`      | `-p`  | Local SSH port to use (default: 22222)          | `--sshPort 22222`                                               |
|                  | `-L`  | Forward extra ports. Can be used multiple times | `-L 4004:4004` (local:remote)                                                |   

**Example with command line arguments:**
```shell script
npx bas-connect --landscapeUrl https://xxx.eu20cf.applicationstudio.cloud.sap --devspaceId ws-xxxx --sshPort 22222
npx bas-connect -u https://xxx.eu20cf.applicationstudio.cloud.sap -d ws-xxxx -p 22222
```

### Environment Variables
You can also set the following environment variables in a `.env` file to avoid entering them every time:
```shell
BAS_LANDSCAPE_URL=https://xxx.eu20cf.applicationstudio.cloud.sap
BAS_DEVSPACE_ID=ws-xxxx
```

## Connecting to your dev space

Once the tunnel is established, you will see the connection details in the terminal.  

The script will keep running to maintain the tunnel. Press `CTRL+C` to stop the tunnel when you're finished.

## Troubleshooting

**Connection Issues:**
- Ensure you have an active internet connection
- Verify your dev space exists and is accessible **(only two dev spaces can be active at a time)**
- Check that the local port is not already in use

**Authentication Issues:**
- If authentication fails, try clearing browser cookies and try again

## Contributing
This script is based on the VS Code Extensions but adapted to provide fixed SSH ports and a more streamlined CLI experience
with the ability to automatically start the dev space and reconnect if the connection is lost.

You can run the `dev` script with arguments like this `npm run dev -- -- -l xxx.com -d ws-xxxx` the double `--` are needed to
first pass it to te npm run script and then again to ts-node

Contributions are welcome! 

## Disclaimer
This is an unofficial tool and is not affiliated with, endorsed, or sponsored by SAP SE or its affiliates. It is provided "as-is" without any warranty. Use at your own discretion and risk.
