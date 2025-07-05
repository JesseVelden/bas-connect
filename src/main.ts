import 'dotenv/config';

import {
	BaseStream,
	ObjectDisposedError,
	SshAlgorithms,
	SshClientSession,
	SshDisconnectReason,
	SshProtocolExtensionNames,
	SshSessionConfiguration,
} from '@microsoft/dev-tunnels-ssh';
import { PortForwardingService } from '@microsoft/dev-tunnels-ssh-tcp';
import { core, devspace, remotessh } from '@sap/bas-sdk';
import findCacheDirectory from 'find-cache-directory';
import * as fs from 'fs';
import * as http from 'http';
import open from 'open';
import * as os from 'os';
import * as path from 'path';
import prompts from 'prompts';
import { parse, stringify } from 'ssh-config';
import { URL } from 'url';

const isDebugMode = process.env.DEBUG === 'true' || process.env.DEBUG === '1';
const getCurrentTime = () => {
	return new Date().toLocaleTimeString(undefined, {
		hour: '2-digit',
		minute: '2-digit',
	});
};

const logger = {
	info: (message: string) => console.log(`${getCurrentTime()}  INFO - ${message}`),
	error: (message: string, error?: unknown) => console.error(`${getCurrentTime()} ERROR - ${message}`, error || ''),
	debug: (message: string) => isDebugMode && console.log(`${getCurrentTime()} DEBUG - ${message}`),
	warn: (message: string) => console.warn(`${getCurrentTime()}  WARN - ${message}`),
};

const SSHD_SOCKET_PORT = 33765; // Standard SSHD port in the dev space, for BAS Remote Access.
const LOCAL_JWT_REDIRECT_PORT = 55532; // Port for the local HTTP server for retrieving the JWT callback redirect.

let landscapeUrl = process.env.BAS_LANDSCAPE_URL || ''; // e.g. 'https://xxx.eu20cf.applicationstudio.cloud.sap'
if (landscapeUrl) {
	try {
		landscapeUrl = `https://${new URL(landscapeUrl).hostname}`;
	} catch (_e) {
		logger.error('Invalid BAS Landscape URL. Aborting');
		process.exit(1);
	}
}
let devspaceId = process.env.BAS_DEVSPACE_ID || ''; // e.g. 'ws-xxxx'
let fixedSshPort = process.env.BAS_SSH_PORT ? parseInt(process.env.BAS_SSH_PORT, 10) : 22222; // The preferred local SSH-port
if (process.env.BAS_SSH_PORT && (isNaN(fixedSshPort) || fixedSshPort <= 0 || fixedSshPort >= 65536)) {
	logger.warn(
		`Invalid SSH port '${process.env.BAS_SSH_PORT}' provided via environment variable. Using default: 22222.`,
	);
	fixedSshPort = 22222;
}

const MAX_RECONNECT_ATTEMPTS = 10;
const RECONNECT_DELAY_MS = 10_000;

let currentJwt = ''; // Global for reconnects
let currentDevSpaceWsUrl = ''; // wsUrl for reconnects, e.g. 'wss://port33765--workspaces-ws-xxx.eu20cf.applicationstudio.cloud.sap:443'
const portForwards: { localPort: number; remotePort: number }[] = [];

class WebSocketClientStream extends BaseStream {
	public constructor(private readonly websocket: WebSocket) {
		super();

		this.websocket.addEventListener('message', (event) => {
			if (event.data instanceof ArrayBuffer) {
				this.onData(Buffer.from(event.data));
			} else {
				this.onData(event.data);
			}
		});

		this.websocket.addEventListener('close', (event) => {
			if (event.code === 1000) {
				this.onEnd();
			} else {
				const error = new Error(event.reason || `WebSocket closed with code ${event.code}`);
				(error as any).code = event.code;
				this.onError(error);
			}
		});

		this.websocket.addEventListener('error', (event) => {
			this.onError((event as any).error || new Error('WebSocket error'));
		});
	}

	public async write(data: Buffer): Promise<void> {
		if (this.disposed) {
			throw new ObjectDisposedError(this);
		}
		if (!data) {
			throw new TypeError('Data is required.');
		}
		this.websocket.send(data);
		return Promise.resolve();
	}

	public async close(error?: Error): Promise<void> {
		if (this.disposed && !error) {
			return Promise.resolve();
		}

		if (!error) {
			this.websocket.close(1000, 'Normal Closure');
		} else {
			// Use a specific error code if available, otherwise a generic one.
			const code = (error as any).code && (error as any).code > 1000 ? (error as any).code : 1011;
			this.websocket.close(code, error.message);
		}
		this.disposed = true;
		this.closedEmitter.fire({ error });
		return Promise.resolve();
	}

	public dispose(): void {
		if (!this.disposed) {
			this.websocket.close();
		}
		super.dispose();
	}
}

// --- Authentication using a local HTTP login server for retrieving the JWT as a callback ---
async function retrieveJwtInteractive(targetLandscapeUrl: string): Promise<string> {
	return new Promise((resolve, reject) => {
		const server = http.createServer(async (req, res) => {
			res.setHeader('Access-Control-Allow-Origin', '*');
			res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
			res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

			if (req.method === 'OPTIONS') {
				res.writeHead(204); // No content
				res.end();
				return;
			}

			const requestUrl = new URL(req.url || '', `http://localhost:${LOCAL_JWT_REDIRECT_PORT}`);
			if (requestUrl.pathname === '/ext-login') {
				let body = '';
				req.on('data', (chunk) => {
					body += chunk.toString();
				});

				req.on('end', () => {
					try {
						const jsonBody = JSON.parse(body);
						const jwt = jsonBody.jwt;

						if (jwt) {
							logger.debug('JWT retrieved.');
							res.writeHead(200, { 'Content-Type': 'text/plain' });
							res.end('Login success! You can close this window now.');
							server.close(() => {
								logger.debug('Local login HTTP server closed.');
								resolve(jwt);
							});
						} else {
							const errMessage = 'Could not find JWT in the request body.';
							logger.error(errMessage);
							res.writeHead(400, { 'Content-Type': 'text/plain' });
							res.end(errMessage);
							reject(new Error(errMessage));
						}
					} catch (error) {
						const errMessage = 'Error in processing the JSON body.';
						logger.error(errMessage, error);
						res.writeHead(400, { 'Content-Type': 'text/plain' });
						res.end(errMessage);
						reject(new Error(errMessage));
					}
				});
			} else {
				res.writeHead(404);
				res.end();
			}
		});

		server.listen(LOCAL_JWT_REDIRECT_PORT, async () => {
			logger.debug(`Local login HTTP server started on port ${LOCAL_JWT_REDIRECT_PORT}.`);

			const loginUrl = core.getExtLoginPath(targetLandscapeUrl);
			logger.info(`Open the following URL in your browser to log in: ${loginUrl}`);
			try {
				await open(loginUrl);
			} catch (err) {
				logger.error('Could not open browser', err);
				reject(err);
				server.close();
			}
		});

		server.on('error', (err) => {
			logger.error('Error at local login HTTP server.', err);
			reject(err);
		});
	});
}

// --- Dev Space info functions ---
async function getDevSpaceDetails(
	targetLandscapeUrl: string,
	jwt: string,
	targetDevspaceId: string,
): Promise<devspace.DevspaceInfo> {
	logger.debug(`Retrieving dev space details for ${targetDevspaceId}...`);
	try {
		const devspaces = await devspace.getDevSpaces(targetLandscapeUrl, jwt);
		const targetDevSpace = devspaces.find((ds) => ds.id === targetDevspaceId);

		if (!targetDevSpace) {
			throw new Error(`Dev Space with ID ${targetDevspaceId} not found in landscape ${targetLandscapeUrl}.`);
		}
		logger.debug(`Found dev space: ${targetDevSpace.id}, Status: ${targetDevSpace.status}`);
		return targetDevSpace;
	} catch (error) {
		logger.error(`Error retrieving Dev Space details for ${targetDevspaceId}`);
		throw error;
	}
}

async function ensureDevSpaceRunning(
	targetLandscapeUrl: string,
	jwt: string,
	devSpace: devspace.DevspaceInfo,
): Promise<devspace.DevspaceInfo> {
	// The VS code extension kinda does the same
	let currentDevSpace = devSpace;
	if (currentDevSpace.status !== devspace.DevSpaceStatus.RUNNING) {
		logger.info(`Dev space ${currentDevSpace.id} is not ${devspace.DevSpaceStatus.RUNNING}, we are booting it up...`);
		await devspace.updateDevSpace(targetLandscapeUrl, jwt, currentDevSpace.id, {
			Suspended: false,
			WorkspaceDisplayName: currentDevSpace.devspaceDisplayName,
		});

		let attempts = 0;
		const maxAttempts = 30; // 5 minutes (30 * 10 seconds)
		while (currentDevSpace.status !== devspace.DevSpaceStatus.RUNNING && attempts < maxAttempts) {
			await new Promise((resolve) => setTimeout(resolve, 10_000));
			currentDevSpace = await getDevSpaceDetails(targetLandscapeUrl, jwt, currentDevSpace.id);
			logger.info(`Current Dev Space status ${currentDevSpace.id}: ${currentDevSpace.status} (attempt ${++attempts})`);
		}

		if (currentDevSpace.status !== devspace.DevSpaceStatus.RUNNING) {
			throw new Error(
				`Could not start Dev space ${currentDevSpace.id} within time limit. Current status: ${currentDevSpace.status}`,
			);
		}
		logger.info(`Dev space ${currentDevSpace.id} is now ${devspace.DevSpaceStatus.RUNNING}.`);
	}
	if (!currentDevSpace.url) {
		throw new Error(`Dev space ${currentDevSpace.id} is RUNNING, but for some reason does not have an URL.`);
	}
	logger.debug(`Dev space ${currentDevSpace.id} url: ${currentDevSpace.url}`);
	return currentDevSpace;
}

// --- SSH Setup

function getSshConfigFilePath(): string {
	// In VS Code we get the SSH config file path from the settings, but here we use the default path.
	return path.join(os.homedir(), '.ssh', 'config');
}

function getSshConfigFolderPath(): string {
	return path.parse(getSshConfigFilePath()).dir;
}

async function getPK(targetLandscapeUrl: string, jwt: string, wsId: string): Promise<string> {
	logger.debug(`Retrieving SSH Private Key for ${wsId}...`);
	return remotessh.getKey(targetLandscapeUrl, jwt, wsId);
}

function savePK(pk: string, wsUrl: string): string {
	const sshFolderPath: string = getSshConfigFolderPath();
	if (!fs.existsSync(sshFolderPath)) {
		fs.mkdirSync(sshFolderPath, { recursive: true });
	}
	// Use the hostname of the wsUrl for the file name to make sure it is unique
	const keyFileName = `${new URL(wsUrl).hostname}.key`;
	const fileName: string = path.join(sshFolderPath, keyFileName);

	if (fs.existsSync(fileName)) {
		logger.debug(`Existing PK file ${fileName} will be removed.`);
		fs.unlinkSync(fileName);
	}
	fs.writeFileSync(fileName, `${pk}\n`, { mode: '0400', flag: 'w' });
	logger.debug(`Private key saved in: ${fileName}`);
	return fileName;
}

function updateSSHConfigFile(
	sshKeyFilePath: string,
	targetLandscapeUrl: string,
	wsId: string,
	localSshPort: number,
): string {
	const sectionName = `${new URL(targetLandscapeUrl).hostname}.${wsId}`;
	const sshConfigFile = getSshConfigFilePath();

	const newSection = parse(`Host ${sectionName}
  HostName 127.0.0.1
  Port ${localSshPort}
  IdentityFile ${sshKeyFilePath}
  User user
  NoHostAuthenticationForLocalhost yes
  StrictHostKeyChecking no
  UserKnownHostsFile /dev/null
`);

	if (fs.existsSync(sshConfigFile)) {
		const configData = fs.readFileSync(sshConfigFile, 'utf-8');
		const configArray = parse(configData);
		configArray.remove({ Host: sectionName });
		configArray.push(...newSection);
		fs.writeFileSync(sshConfigFile, stringify(configArray));
	} else {
		fs.writeFileSync(sshConfigFile, stringify(newSection));
	}

	logger.debug(`SSH config updated in ${sshConfigFile} for host ${sectionName} on port ${localSshPort}.`);
	return sectionName;
}

// SSH Tunnel Client
const sessionMap: Map<string, SshClientSession> = new Map();
let activeSshSession: SshClientSession | null = null;
let activePortForwardingService: PortForwardingService | null = null;
let reconnectAttempts = 0;
let reconnecting = false;
async function handleSshSessionClosed(opts: { devSpaceWsUrl: string; localSshPort: number; jwt: string }) {
	if (reconnecting) return;
	reconnecting = true;
	activeSshSession = null;

	while (reconnectAttempts < MAX_RECONNECT_ATTEMPTS) {
		reconnectAttempts++;
		logger.info(`Attempting to reconnect SSH tunnel (attempt ${reconnectAttempts}/${MAX_RECONNECT_ATTEMPTS})...`);
		if (activePortForwardingService) {
			logger.debug(`Stopping port forwarder on port ${fixedSshPort}...`);
			try {
				activePortForwardingService.dispose();
				logger.debug(`Port forwarder on port ${fixedSshPort} successfully stopped.`);
			} catch (disposeError) {
				logger.error(`Error stopping port forwarder on port ${fixedSshPort}:`, disposeError);
			}
			activePortForwardingService = null;
		}
		if (!currentJwt || !currentDevSpaceWsUrl) {
			logger.error('Cannot reconnect: JWT or DevSpace WebSocket URL is missing. Aborting retries.');
			reconnecting = false;
			return; // Exit the handler; no further retries for this event.
		}

		try {
			activeSshSession = await setupSshTunnel({
				devSpaceWsUrl: currentDevSpaceWsUrl,
				localSshPort: opts.localSshPort,
				jwt: currentJwt,
			});
			logger.info('SSH Tunnel successfully reconnected.');
			reconnectAttempts = 0;
			reconnecting = false;
			return;
		} catch (e) {
			logger.error(`Error reconnecting SSH tunnel (attempt ${reconnectAttempts}/${MAX_RECONNECT_ATTEMPTS})`);
			const error = e as Error;

			if (error.message?.includes('Received network error or non-101 status code.')) {
				try {
					let devSpaceInfo = await getDevSpaceDetails(landscapeUrl, currentJwt, devspaceId);
					devSpaceInfo = await ensureDevSpaceRunning(landscapeUrl, currentJwt, devSpaceInfo);
					continue;
				} catch (devSpaceError: any) {
					if (devSpaceError?.code === 'ENOTFOUND' || devSpaceError?.message?.includes('getaddrinfo ENOTFOUND')) {
						logger.warn('Please check your internet connection! It seems the server could not be reached.');
					} else if (devSpaceError?.response?.status === 401) {
						logger.warn('Authentication token is expired or invalid, retrieving a new one...');
						try {
							currentJwt = await retrieveJwtInteractive(landscapeUrl);
							logger.info('New authentication token retrieved successfully.');
							continue;
						} catch (authError) {
							logger.error('Failed to retrieve a new token. Aborting reconnect.', authError);
							break;
						}
					}
				}
			} else {
				logger.error(error.toString());
			}

			logger.info(
				`Waiting ${RECONNECT_DELAY_MS / 1000} seconds before next reconnect attempt (${
					reconnectAttempts + 1
				}/${MAX_RECONNECT_ATTEMPTS})...`,
			);
			await new Promise((resolve) => setTimeout(resolve, RECONNECT_DELAY_MS));
		}
	}

	logger.error('Maximum reconnect attempts reached! Closing SSH session and cleaning up.');
	reconnecting = false;
	await cleanup(true);
}

async function setupSshTunnel(opts: {
	devSpaceWsUrl: string; // e.g. wss://ws-xxxx....
	localSshPort: number;
	jwt: string;
}): Promise<SshClientSession> {
	const serverUri = opts.devSpaceWsUrl;
	const remoteSshPort = 2222;

	const existingSession = sessionMap.get(serverUri);

	if (existingSession) {
		logger.debug(`Closing existing SSH session for ${serverUri}`);
		await existingSession.close(SshDisconnectReason.byApplication);
		sessionMap.delete(serverUri);
	}

	const config = new SshSessionConfiguration();
	config.keyExchangeAlgorithms.push(SshAlgorithms.keyExchange.ecdhNistp521Sha512);
	config.publicKeyAlgorithms.push(SshAlgorithms.publicKey.ecdsaSha2Nistp521);
	config.publicKeyAlgorithms.push(SshAlgorithms.publicKey.rsa2048);
	config.encryptionAlgorithms.push(SshAlgorithms.encryption.aes256Gcm);
	config.protocolExtensions.push(SshProtocolExtensionNames.sessionReconnect);
	config.protocolExtensions.push(SshProtocolExtensionNames.sessionLatency);
	config.addService(PortForwardingService);

	return new Promise<SshClientSession>((resolve, reject) => {
		// https://undici.nodejs.org/#/docs/api/WebSocket.md
		const ws = new WebSocket(serverUri, {
			protocols: ['ssh'],
			headers: {
				Authorization: `Bearer ${opts.jwt}`,
			},
		});

		ws.binaryType = 'arraybuffer';

		ws.addEventListener('open', async () => {
			try {
				logger.info(`SSH Tunnel: WebSocket connected!`);
				const stream = new WebSocketClientStream(ws);
				const session = new SshClientSession(config);

				session.onAuthenticating((e) => {
					// The VS Code extension doesn't do client authentication here, only the WebSocket authentication (JWT) used
					e.authenticationPromise = Promise.resolve({});
				});

				session.onClosed((event) => {
					if (event?.reason !== SshDisconnectReason.byApplication) {
						logger.info(`SSH Tunnel: Session closed for ${serverUri}. Reason: ${event.reason}, Error: ${event.error}`);
						setImmediate(() => handleSshSessionClosed(opts));
					} else {
						logger.info(`SSH Tunnel: Session closed for ${serverUri}.`);
					}
				});

				session.onDisconnected(() => {
					logger.info(`SSH Tunnel: Session disconnected for ${serverUri}`);
					setImmediate(() => handleSshSessionClosed(opts));
				});

				await session.connect(stream);
				await session.authenticateClient({ username: 'user', publicKeys: [] }); // PK auth is done server-side
				logger.debug('SSH Tunnel: Client authenticated.');

				activePortForwardingService = session.activateService(PortForwardingService);

				await activePortForwardingService.forwardToRemotePort(
					'127.0.0.1', // Listen address on local machine
					opts.localSshPort,
					'127.0.0.1', // Target address in remote (dev space)
					remoteSshPort,
				);
				logger.info(`SSH Tunnel: Port forwarding active! Local ${opts.localSshPort} -> Remote ${remoteSshPort}`);

				for (const forward of portForwards) {
					logger.info(`Setting up Port Forward: Local ${forward.localPort} -> Remote ${forward.remotePort}`);
					await activePortForwardingService.forwardToRemotePort(
						'127.0.0.1',
						forward.localPort,
						'127.0.0.1',
						forward.remotePort,
					);
				}

				sessionMap.set(serverUri, session);
				activeSshSession = session;
				resolve(session);
			} catch (err) {
				logger.error('SSH Tunnel: Error during connection, authentication, or port forwarding.', err);
				reject(err);
			}
		});

		ws.addEventListener('error', (event) => {
			logger.error(`SSH Tunnel: WebSocket connectFailed for ${serverUri}`);
			logger.debug(event.error);
			reject(event.error);
		});
	});
}

let isCleaningUp = false;
const cleanup = async (isErrorExit = false) => {
	if (isCleaningUp) return;
	isCleaningUp = true;

	logger.info('Stopping and cleaning up...');
	if (activeSshSession && !activeSshSession.isClosed) {
		logger.debug('Closing active SSH session...');
		activeSshSession.onClosed(() => logger.debug('SSH session closed.'));
		await activeSshSession.close(SshDisconnectReason.byApplication).catch((err) => {
			logger.error('Error while closing SSH session', err);
		});
	}
	activeSshSession = null;

	if (currentDevSpaceWsUrl) {
		const sessionInMap = sessionMap.get(currentDevSpaceWsUrl);
		if (sessionInMap && !sessionInMap.isClosed) {
			await sessionInMap.close(SshDisconnectReason.byApplication).catch((err) => {
				logger.error(`Error while closing SSH session for ${currentDevSpaceWsUrl}:`, err);
			});
		}
		sessionMap.delete(currentDevSpaceWsUrl);
	}

	logger.info(isErrorExit ? 'Process ended because of an error.' : 'Process ended.');
	process.exit(isErrorExit ? 1 : 0);
};

function getCacheFilePath(): string | undefined {
	const cacheDir = findCacheDirectory({ name: 'bas-connect' });
	if (!cacheDir) return undefined;
	return path.join(cacheDir, 'cache.json');
}

async function checkForNewVersion() {
	const cacheFile = getCacheFilePath();
	const cacheDuration = 24 * 60 * 60 * 1000; // 24 hours
	if (cacheFile) {
		try {
			if (fs.existsSync(cacheFile)) {
				const cacheContent = fs.readFileSync(cacheFile, 'utf-8');
				const cache = JSON.parse(cacheContent);
				const lastChecked = new Date(cache.lastChecked).getTime();
				if (Date.now() - lastChecked < cacheDuration) {
					logger.debug('Version check skipped; last check was less than 24 hours ago.');
					return;
				}
			}
		} catch (error) {
			logger.debug(`Could not read version check cache file: ${error}`);
		}
	}

	try {
		const { default: pkg } = await import('../package.json');
		const currentVersion = pkg.version;

		logger.debug(`Checking for new version of ${pkg.name} on npmjs.com...`);
		const response = await fetch(`https://registry.npmjs.org/${pkg.name}/latest`);
		if (!response.ok) {
			logger.debug(`Failed to check for new version: ${response.statusText}`);
			return;
		}

		const { version: latestVersion } = await response.json() as { version: string };
		if (cacheFile) {
			try {
				const cacheDir = path.dirname(cacheFile);
				if (!fs.existsSync(cacheDir)) fs.mkdirSync(cacheDir, { recursive: true });
				fs.writeFileSync(cacheFile, JSON.stringify({ lastChecked: new Date().toISOString() }));
			} catch (error) {
				logger.debug(`Failed to write to version check cache file: ${error}`);
			}
		}

		if (currentVersion !== latestVersion) {
			logger.info(`A new version of ${pkg.name} is available (${latestVersion}). Please update by running: npm i -g ${pkg.name}`);
		}
	} catch (error) {
		logger.debug(`Error checking for new version: ${error}`);
	}
}


async function main() {
	try {
		await checkForNewVersion();

		const args = process.argv.slice(2); // Skip 'node' and script path
		for (let i = 0; i < args.length; i++) {
			const arg = args[i];
			const value = args[i + 1];

			if ((arg === '--landscapeUrl' || arg === '-u') && value !== undefined) {
				if (value) {
					try {
						landscapeUrl = `https://${new URL(value).hostname}`;
					} catch {
						logger.error(`Invalid Landscape URL '${value}' provided via command line argument. Aborting.`);
						return cleanup(true);
					}
				}
				i++;
				logger.info(`Landscape URL set from command line argument: ${landscapeUrl}`);
			} else if ((arg === '--devspaceId' || arg === '-d') && value !== undefined) {
				devspaceId = value;
				i++;
				logger.info(`DevSpace ID set from command line argument: ${devspaceId}`);
			} else if ((arg === '--sshPort' || arg === '-p') && value !== undefined) {
				const port = parseInt(value, 10);
				if (!isNaN(port) && port > 0 && port < 65536) {
					fixedSshPort = port;
					logger.info(`SSH Port set from command line argument: ${fixedSshPort}`);
				} else {
					logger.warn(
						`Invalid SSH port '${value}' provided via command line argument. Using current value: ${fixedSshPort}.`,
					);
				}
				i++;
			} else if (arg === '-L' && value !== undefined) {
				const [localPortStr, remotePortStr] = value.split(':');
				const localPort = parseInt(localPortStr, 10);
				const remotePort = parseInt(remotePortStr, 10);
				if (!isNaN(localPort) && !isNaN(remotePort) && localPort > 0 && localPort < 65536 && remotePort > 0 && remotePort < 65536) {
					portForwards.push({ localPort: localPort, remotePort: remotePort });
					logger.debug(`Port forwarding added: Local ${localPort} -> Remote ${remotePort}`);
				} else {
					logger.warn(
						`Invalid port-forward rule "-p ${value}". It must be in "localPort:remotePort" format, with ports between 1 and 65535.`,
					);
				}
				i++;
			}
		}

		if (!landscapeUrl) {
			const response = await prompts({
				type: 'text',
				name: 'value',
				message: 'Enter Landscape URL (e.g., https://xxx.eu20cf.applicationstudio.cloud.sap):',
				validate: (value) => {
					try {
						new URL(value);
						return true;
					} catch {
						return 'Invalid URL.';
					}
				},
			});
			landscapeUrl = `https://${new URL(response.value).hostname}`;
		}

		if (!devspaceId) {
			const response = await prompts({
				type: 'text',
				name: 'value',
				message: 'Enter Dev Space ID (e.g., ws-xxxx):',
				validate: (val) => (val?.trim() !== '' ? true : 'Dev Space ID cannot be empty.'),
			});
			devspaceId = response.value.trim();
		}

		currentJwt = await retrieveJwtInteractive(landscapeUrl);
		logger.debug('Retrieved JWT successfully.');

		let devSpace = await getDevSpaceDetails(landscapeUrl, currentJwt, devspaceId);
		devSpace = await ensureDevSpaceRunning(landscapeUrl, currentJwt, devSpace);

		if (!devSpace.url) {
			logger.error(`Cannot setup SSH tunnel: url not available for dev space ${devspaceId}.`);
			return cleanup(true);
		}

		// SSH Setup
		const pk = await getPK(landscapeUrl, currentJwt, devSpace.id);
		const sshKeyFilePath = savePK(pk, devSpace.url);

		const sshHostAlias = updateSSHConfigFile(sshKeyFilePath, landscapeUrl, devSpace.id, fixedSshPort);

		logger.info(`Setting up SSH tunnel on local port ${fixedSshPort}...`);

		currentDevSpaceWsUrl = `wss://port${SSHD_SOCKET_PORT}-${new URL(devSpace.url).hostname}:443`;
		activeSshSession = await setupSshTunnel({
			devSpaceWsUrl: currentDevSpaceWsUrl,
			localSshPort: fixedSshPort,
			jwt: currentJwt,
		});

		logger.info('------------------------------------------------------------');
		logger.info('Setup complete!');
		logger.info('You can now connect to your dev space via SSH:');
		logger.info(`ssh ${sshHostAlias}`);
		logger.info('Or configure your SSH client to directly use 127.0.0.1:' + fixedSshPort + ' with the key ' + sshKeyFilePath);
		logger.info('The SSH tunnel will remain active as long as this script is running.');
		logger.info('Press CTRL+C to stop the script and the tunnel.');
		logger.info('------------------------------------------------------------');

		process.stdin.resume(); // Keep this node process running

		process.on('SIGINT', () => cleanup(false)); // CTRL+C
		process.on('SIGTERM', () => cleanup(false)); // Terminate

		process.on('uncaughtException', (error: unknown) => {
			if ((error as any)?.code === 'ECONNRESET') return; // ignore socket reset on Windows
			throw error; // re-throw anything else
		});
	} catch (error: any) {
		logger.error(error.toString());
		process.exit(1);
	}
}

main();
