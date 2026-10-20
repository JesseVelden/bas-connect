import 'dotenv/config';

import * as fs from 'fs';
import * as http from 'http';
import * as os from 'os';
import * as path from 'path';
import { URL } from 'url';

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
import open from 'open';
import prompts from 'prompts';
import { parse, stringify } from 'ssh-config';
import WebSocket from 'ws';

const isDebugMode = process.env.DEBUG === 'true' || process.env.DEBUG === '1';
const getCurrentTime = () => {
	return new Date().toLocaleTimeString(undefined, {
		hour: '2-digit',
		minute: '2-digit',
	});
};

const logger = {
	info: (message: string) => console.log(`${getCurrentTime()} - ${message}`),
	error: (message: string, error?: unknown) => {
		if (error instanceof Error) {
			console.error(`${getCurrentTime()} ERROR: ${message}\n${error.stack ?? error.message}`);
		} else if (error !== undefined) {
			console.error(`${getCurrentTime()} ERROR: ${message}`, error);
		} else {
			console.error(`${getCurrentTime()} ERROR: ${message}`);
		}
	},
	debug: (message: string) => isDebugMode && console.log(`${getCurrentTime()} DEBUG: ${message}`),
	warn: (message: string) => console.warn(`${getCurrentTime()} WARN: ${message}`),
};

function getErrorMessage(error: unknown): string {
	return error instanceof Error ? error.message : String(error);
}

function hasErrorCode(error: unknown, code: string): boolean {
	return typeof error === 'object' && error !== null && 'code' in error && error.code === code;
}

function hasResponseStatus(error: unknown, status: number): boolean {
	if (typeof error !== 'object' || error === null || !('response' in error)) return false;
	const response = error.response;
	return typeof response === 'object' && response !== null && 'status' in response && response.status === status;
}

class WebSocketCloseError extends Error {
	public constructor(
		message: string,
		public readonly code: number,
	) {
		super(message);
	}
}

const SSHD_SOCKET_PORT = 33765; // Standard SSHD port in the dev space, for BAS Remote Access.
const LOCAL_JWT_REDIRECT_PORT = 55532; // Port for the local HTTP server for retrieving the JWT callback redirect.

let landscapeUrl = process.env.BAS_LANDSCAPE_URL || ''; // e.g. 'https://xxx.eu20cf.applicationstudio.cloud.sap'
if (landscapeUrl) {
	try {
		landscapeUrl = `https://${new URL(landscapeUrl).hostname}`;
	} catch {
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
const SESSION_CLOSE_TIMEOUT_MS = 5_000;
const WS_CONNECT_TIMEOUT_MS = 15_000;
const DEV_SPACE_STATUS_POLL_INTERVAL_MS = 10_000;
const DEV_SPACE_STATUS_TIMEOUT_MS = 5 * 60 * 1000;
const DEV_SPACE_HEALTH_CHECK_INTERVAL_MS = 60_000;
const KEEP_ALIVE_FAILURES_BEFORE_RECONNECT = 2;

let currentJwt = ''; // Global for reconnects
let currentDevSpaceWsUrl = ''; // wsUrl for reconnects, e.g. 'wss://port33765--workspaces-ws-xxx.eu20cf.applicationstudio.cloud.sap:443'
const portForwards: { localPort: number; remotePort: number }[] = [];

class WebSocketClientStream extends BaseStream {
	private readonly handleMessage = (event: WebSocket.MessageEvent) => {
		if (this.disposed) return;
		if (typeof event.data === 'string') {
			this.onData(Buffer.from(event.data));
		} else if (event.data instanceof ArrayBuffer) {
			this.onData(Buffer.from(event.data));
		} else if (Buffer.isBuffer(event.data)) {
			this.onData(event.data);
		} else {
			this.onData(Buffer.concat(event.data));
		}
	};

	private readonly handleClose = (event: WebSocket.CloseEvent) => {
		if (this.disposed) return;
		if (event.code === 1000) {
			this.onEnd();
		} else {
			const error = new WebSocketCloseError(
				event.reason || `WebSocket closed with code ${event.code}`,
				event.code,
			);
			this.onError(error);
		}
	};

	private readonly handleError = (event: WebSocket.ErrorEvent) => {
		if (!this.disposed) this.onError(new Error(event.message || 'WebSocket error'));
	};

	public constructor(private readonly websocket: WebSocket) {
		super();

		this.websocket.addEventListener('message', this.handleMessage);
		this.websocket.addEventListener('close', this.handleClose);
		this.websocket.addEventListener('error', this.handleError);
	}

	private removeEventListeners(): void {
		this.websocket.removeEventListener('message', this.handleMessage);
		this.websocket.removeEventListener('close', this.handleClose);
		this.websocket.removeEventListener('error', this.handleError);
	}

	private terminateWebSocket(): void {
		if (this.websocket.readyState !== WebSocket.CLOSED) this.websocket.terminate();
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
		if (this.disposed) return;

		this.removeEventListeners();
		this.terminateWebSocket();
		const closeError = error || new ObjectDisposedError(this);
		this.disposed = true;
		this.onError(closeError);
		this.closedEmitter.fire({ error: closeError });
		return Promise.resolve();
	}

	public dispose(): void {
		if (!this.disposed) {
			this.removeEventListeners();
			this.terminateWebSocket();
		}
		super.dispose();
	}
}

// --- Authentication using a local HTTP login server for retrieving the JWT as a callback ---
async function retrieveJwtInteractive(targetLandscapeUrl: string): Promise<string> {
	const jwt = await new Promise<string>((resolve, reject) => {
		const server = http.createServer((req, res) => {
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
				req.on('data', (chunk: unknown) => {
					body += Buffer.isBuffer(chunk) ? chunk.toString() : String(chunk);
				});

				req.on('end', () => {
					try {
						const jsonBody: unknown = JSON.parse(body);
						const jwt =
							typeof jsonBody === 'object' &&
							jsonBody !== null &&
							'jwt' in jsonBody &&
							typeof jsonBody.jwt === 'string'
								? jsonBody.jwt
								: undefined;

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

		const handleServerListening = async (): Promise<void> => {
			logger.debug(`Local login HTTP server started on port ${LOCAL_JWT_REDIRECT_PORT}.`);

			const loginUrl = core.getExtLoginPath(targetLandscapeUrl);
			logger.info(`Open the following URL in your browser to log in: ${loginUrl}`);
			try {
				await open(loginUrl);
			} catch (err) {
				logger.error('Could not open browser', err);
				reject(err instanceof Error ? err : new Error(String(err)));
				server.close();
			}
		};

		server.listen(LOCAL_JWT_REDIRECT_PORT, () => {
			void handleServerListening();
		});

		server.on('error', (err) => {
			logger.error('Error at local login HTTP server.', err);
			reject(err);
		});
	});
	return jwt;
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
		logger.info(
			`Dev space ${currentDevSpace.id} is not ${devspace.DevSpaceStatus.RUNNING}, we are booting it up...`,
		);
		if (currentDevSpace.status === devspace.DevSpaceStatus.STOPPING) {
			currentDevSpace = await waitForDevSpaceStatus(
				targetLandscapeUrl,
				jwt,
				currentDevSpace.id,
				devspace.DevSpaceStatus.STOPPED,
			);
		}
		if (currentDevSpace.status !== devspace.DevSpaceStatus.STARTING) {
			await devspace.updateDevSpace(targetLandscapeUrl, jwt, currentDevSpace.id, {
				Suspended: false,
				WorkspaceDisplayName: currentDevSpace.devspaceDisplayName,
			});
		}

		currentDevSpace = await waitForDevSpaceStatus(
			targetLandscapeUrl,
			jwt,
			currentDevSpace.id,
			devspace.DevSpaceStatus.RUNNING,
		);
		logger.info(`Dev space ${currentDevSpace.id} is now ${devspace.DevSpaceStatus.RUNNING}.`);
	}
	if (!currentDevSpace.url) {
		throw new Error(`Dev space ${currentDevSpace.id} is RUNNING, but for some reason does not have an URL.`);
	}
	logger.debug(`Dev space ${currentDevSpace.id} url: ${currentDevSpace.url}`);
	return currentDevSpace;
}

async function waitForDevSpaceStatus(
	targetLandscapeUrl: string,
	jwt: string,
	devSpaceId: string,
	expectedStatus: devspace.DevSpaceStatus,
): Promise<devspace.DevspaceInfo> {
	const maxAttempts = Math.ceil(DEV_SPACE_STATUS_TIMEOUT_MS / DEV_SPACE_STATUS_POLL_INTERVAL_MS);
	let currentDevSpace = await getDevSpaceDetails(targetLandscapeUrl, jwt, devSpaceId);
	let attempts = 0;

	while (currentDevSpace.status !== expectedStatus && attempts < maxAttempts) {
		await new Promise((resolve) => setTimeout(resolve, DEV_SPACE_STATUS_POLL_INTERVAL_MS));
		currentDevSpace = await getDevSpaceDetails(targetLandscapeUrl, jwt, devSpaceId);
		logger.info(
			`Current Dev Space status ${currentDevSpace.id}: ${currentDevSpace.status} (attempt ${++attempts})`,
		);
	}

	if (currentDevSpace.status !== expectedStatus) {
		throw new Error(
			`Dev space ${devSpaceId} did not reach ${expectedStatus} within ${DEV_SPACE_STATUS_TIMEOUT_MS / 60_000} minutes. Current status: ${currentDevSpace.status}`,
		);
	}

	return currentDevSpace;
}

async function restartDevSpace(
	targetLandscapeUrl: string,
	jwt: string,
	devSpaceId: string,
): Promise<devspace.DevspaceInfo> {
	let currentDevSpace = await getDevSpaceDetails(targetLandscapeUrl, jwt, devSpaceId);
	logger.warn(`Restarting Dev Space ${devSpaceId} to recover the WebSocket connection...`);

	if (currentDevSpace.status !== devspace.DevSpaceStatus.STOPPED) {
		await devspace.updateDevSpace(targetLandscapeUrl, jwt, devSpaceId, {
			Suspended: true,
			WorkspaceDisplayName: currentDevSpace.devspaceDisplayName,
		});
		currentDevSpace = await waitForDevSpaceStatus(
			targetLandscapeUrl,
			jwt,
			devSpaceId,
			devspace.DevSpaceStatus.STOPPED,
		);
	}

	await devspace.updateDevSpace(targetLandscapeUrl, jwt, devSpaceId, {
		Suspended: false,
		WorkspaceDisplayName: currentDevSpace.devspaceDisplayName,
	});
	return waitForDevSpaceStatus(targetLandscapeUrl, jwt, devSpaceId, devspace.DevSpaceStatus.RUNNING);
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
let reconnectScheduled = false;
let isCleaningUp = false;
let devSpaceHealthCheckTimer: ReturnType<typeof setInterval> | undefined;
let devSpaceHealthCheckInProgress = false;
const sessionsBeingClosed = new WeakSet<SshClientSession>();
const KEEP_ALIVE_INTERVAL_MS = 60 * 1000; // 1 minute

function isWebSocket503Error(error: unknown): boolean {
	const message = error instanceof Error ? error.message : String(error);
	return /\b503\b/.test(message);
}

function getDevSpaceWsUrl(devSpaceUrl: string): string {
	return `wss://port${SSHD_SOCKET_PORT}-${new URL(devSpaceUrl).hostname}:443`;
}

function stopPortForwarder(): void {
	if (!activePortForwardingService) return;

	const portForwardingService = activePortForwardingService;
	activePortForwardingService = null;
	logger.debug(`Stopping port forwarder on port ${fixedSshPort}...`);
	try {
		portForwardingService.dispose();
		logger.debug(`Port forwarder on port ${fixedSshPort} successfully stopped.`);
	} catch (disposeError) {
		logger.error(`Error stopping port forwarder on port ${fixedSshPort}:`, disposeError);
	}
}

async function closeSshSession(session: SshClientSession, description: string): Promise<void> {
	if (session.isClosed) return;
	sessionsBeingClosed.add(session);

	let timeout: ReturnType<typeof setTimeout> | undefined;
	try {
		await Promise.race([
			session.close(SshDisconnectReason.byApplication),
			new Promise<never>((_, reject) => {
				timeout = setTimeout(() => {
					reject(new Error(`SSH session did not close within ${SESSION_CLOSE_TIMEOUT_MS / 1000} seconds.`));
				}, SESSION_CLOSE_TIMEOUT_MS);
			}),
		]);
	} catch (closeError) {
		logger.error(`Error while closing ${description}:`, closeError);
	} finally {
		if (timeout) clearTimeout(timeout);

		if (!session.isClosed) {
			logger.warn(`${description} did not close gracefully. Forcefully disposing the SSH session and WebSocket.`);
			try {
				session.dispose();
			} catch (disposeError) {
				logger.error(`Error while forcefully disposing ${description}:`, disposeError);
			}
		}
	}
}

async function handleSshSessionClosed(opts: { devSpaceWsUrl: string; localSshPort: number; jwt: string }) {
	if (reconnecting || isCleaningUp) return;
	reconnecting = true;
	const staleSessions = new Set(sessionMap.values());
	if (activeSshSession) staleSessions.add(activeSshSession);
	sessionMap.clear();
	activeSshSession = null;
	for (const staleSession of staleSessions) {
		await closeSshSession(staleSession, `stale SSH session for ${opts.devSpaceWsUrl}`);
	}

	while (reconnectAttempts < MAX_RECONNECT_ATTEMPTS - 1) {
		if (isCleaningUp) {
			reconnecting = false;
			return;
		}
		reconnectAttempts++;
		logger.info(`Attempting to reconnect SSH tunnel (attempt ${reconnectAttempts}/${MAX_RECONNECT_ATTEMPTS})...`);
		stopPortForwarder();
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
			const errorMessage = getErrorMessage(e);

			if (isWebSocket503Error(e)) {
				try {
					const devSpaceInfo = await restartDevSpace(landscapeUrl, currentJwt, devspaceId);
					if (!devSpaceInfo.url) {
						logger.error(`Dev space ${devSpaceInfo.id} restarted but does not have an URL.`);
					} else {
						currentDevSpaceWsUrl = getDevSpaceWsUrl(devSpaceInfo.url);
						logger.info('Dev Space restarted after the WebSocket server returned HTTP 503.');
						continue;
					}
				} catch (devSpaceError) {
					logger.error(
						'Could not restart the Dev Space after the WebSocket server returned HTTP 503.',
						devSpaceError,
					);
				}
			} else if (
				errorMessage.includes('Received network error or non-101 status code.') ||
				errorMessage.includes('getaddrinfo ENOTFOUND') ||
				errorMessage.includes('404') ||
				errorMessage.includes('401')
			) {
				try {
					let devSpaceInfo = await getDevSpaceDetails(landscapeUrl, currentJwt, devspaceId);
					devSpaceInfo = await ensureDevSpaceRunning(landscapeUrl, currentJwt, devSpaceInfo);
					continue;
				} catch (devSpaceError: unknown) {
					const devSpaceErrorMessage = getErrorMessage(devSpaceError);
					if (
						hasErrorCode(devSpaceError, 'ENOTFOUND') ||
						devSpaceErrorMessage.includes('getaddrinfo ENOTFOUND')
					) {
						logger.warn('Please check your internet connection! It seems the server could not be reached.');
					} else if (hasResponseStatus(devSpaceError, 401)) {
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
				logger.error(errorMessage);
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

function requestSshReconnect(reason: string): void {
	if (reconnecting || reconnectScheduled || isCleaningUp || !currentJwt || !currentDevSpaceWsUrl) return;

	reconnectScheduled = true;
	logger.warn(reason);
	setImmediate(() => {
		reconnectScheduled = false;
		void handleSshSessionClosed({
			devSpaceWsUrl: currentDevSpaceWsUrl,
			localSshPort: fixedSshPort,
			jwt: currentJwt,
		});
	});
}

function stopDevSpaceHealthCheck(): void {
	if (devSpaceHealthCheckTimer) {
		clearInterval(devSpaceHealthCheckTimer);
		devSpaceHealthCheckTimer = undefined;
	}
}

function startDevSpaceHealthCheck(): void {
	stopDevSpaceHealthCheck();

	const checkDevSpaceHealth = async (): Promise<void> => {
		if (isCleaningUp || reconnecting || devSpaceHealthCheckInProgress) return;
		devSpaceHealthCheckInProgress = true;

		try {
			const devSpaceInfo = await getDevSpaceDetails(landscapeUrl, currentJwt, devspaceId);
			if (devSpaceInfo.status === devspace.DevSpaceStatus.RUNNING) return;

			logger.warn(
				`Dev Space ${devSpaceInfo.id} is ${devSpaceInfo.status} while the tunnel is active; starting it again...`,
			);
			const runningDevSpace = await ensureDevSpaceRunning(landscapeUrl, currentJwt, devSpaceInfo);
			if (!runningDevSpace.url) {
				throw new Error(`Dev space ${runningDevSpace.id} is running but does not have an URL.`);
			}

			currentDevSpaceWsUrl = getDevSpaceWsUrl(runningDevSpace.url);
			requestSshReconnect(`Dev Space ${runningDevSpace.id} is running again; reconnecting the SSH tunnel.`);
		} catch (error) {
			logger.error('Dev Space health check failed; it will be retried.', error);
		} finally {
			devSpaceHealthCheckInProgress = false;
		}
	};

	devSpaceHealthCheckTimer = setInterval(() => {
		void checkDevSpaceHealth();
	}, DEV_SPACE_HEALTH_CHECK_INTERVAL_MS);
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
		sessionMap.delete(serverUri);
		await closeSshSession(existingSession, `existing SSH session for ${serverUri}`);
	}

	const config = new SshSessionConfiguration();
	config.keyExchangeAlgorithms.push(SshAlgorithms.keyExchange.ecdhNistp521Sha512);
	config.publicKeyAlgorithms.push(SshAlgorithms.publicKey.ecdsaSha2Nistp521);
	config.publicKeyAlgorithms.push(SshAlgorithms.publicKey.rsa2048);
	config.encryptionAlgorithms.push(SshAlgorithms.encryption.aes256Gcm);
	config.protocolExtensions.push(SshProtocolExtensionNames.sessionReconnect);
	config.protocolExtensions.push(SshProtocolExtensionNames.sessionLatency);
	config.addService(PortForwardingService);
	config.keepAliveTimeoutInSeconds = KEEP_ALIVE_INTERVAL_MS / 1000;

	return new Promise<SshClientSession>((resolve, reject) => {
		// // https://undici.nodejs.org/#/docs/api/WebSocket.md
		// Undici, which contains the native Node.js WebSocket implementation, is currently still unstable/ buggy in Node.js v24.11.1.
		// That is why we use the ws package instead.

		// const ws = new WebSocket(serverUri, {
		// 	protocols: ['ssh'],
		// 	headers: {
		// 		Authorization: `Bearer ${opts.jwt}`,
		// 	},
		// });

		const ws = new WebSocket(serverUri, ['ssh'], {
			headers: {
				Authorization: `Bearer ${opts.jwt}`,
			},
			handshakeTimeout: WS_CONNECT_TIMEOUT_MS,
		});

		ws.binaryType = 'arraybuffer';

		const handleWebSocketOpen = async (): Promise<void> => {
			let session: SshClientSession | undefined;
			try {
				logger.info(`SSH Tunnel: WebSocket connected!`);
				const stream = new WebSocketClientStream(ws);
				session = new SshClientSession(config);

				session.onKeepAliveFailed((failureCount) => {
					if (failureCount >= KEEP_ALIVE_FAILURES_BEFORE_RECONNECT) {
						requestSshReconnect(
							`SSH keep-alive failed ${failureCount} times for ${serverUri}; reconnecting the tunnel.`,
						);
					}
				});

				session.onAuthenticating((e) => {
					// The VS Code extension doesn't do client authentication here, only the WebSocket authentication (JWT) used
					e.authenticationPromise = Promise.resolve({});
				});

				session.onClosed((event) => {
					if (!session || sessionsBeingClosed.has(session) || isCleaningUp) return;
					if (event?.reason !== SshDisconnectReason.byApplication) {
						logger.info(
							`SSH Tunnel: Session closed for ${serverUri}. Reason: ${event.reason}, Error: ${event.error}`,
						);
						setImmediate(() => {
							void handleSshSessionClosed(opts);
						});
					} else {
						logger.info(`SSH Tunnel: Session closed for ${serverUri}.`);
					}
				});

				session.onDisconnected(() => {
					if (!session || sessionsBeingClosed.has(session) || isCleaningUp) return;
					logger.info(`SSH Tunnel: Session disconnected for ${serverUri}`);
					setImmediate(() => {
						void handleSshSessionClosed(opts);
					});
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
				logger.info(
					`SSH Tunnel: Port forwarding active! Local ${opts.localSshPort} -> Remote ${remoteSshPort}`,
				);

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
				if (session) {
					sessionsBeingClosed.add(session);
					try {
						session.dispose();
					} catch (disposeError) {
						logger.error('SSH Tunnel: Error disposing failed session.', disposeError);
					}
				}
				ws.terminate();
				logger.error('SSH Tunnel: Error during connection, authentication, or port forwarding.', err);
				reject(err instanceof Error ? err : new Error(String(err)));
			}
		};

		ws.addEventListener('open', () => {
			void handleWebSocketOpen();
		});

		ws.addEventListener('error', (event) => {
			const err = new Error(event.message || `WebSocket error event: ${event.type}`);

			const errorMessage = err.message || '';
			if (isWebSocket503Error(err)) {
				logger.debug(
					`SSH Tunnel: WebSocket connection failed with 503 for ${serverUri} (will restart workspace)`,
				);
			} else if (errorMessage.includes('404') || errorMessage.includes('Unexpected server response: 404')) {
				logger.debug(`SSH Tunnel: WebSocket connection failed with 404 for ${serverUri} (will retry)`);
			} else {
				logger.error(`SSH Tunnel: WebSocket connectFailed for ${serverUri}`, err);
				logger.debug(err.stack || err.toString());
			}

			reject(err);
		});
	});
}

async function cleanup(isErrorExit = false): Promise<void> {
	if (isCleaningUp) return;
	isCleaningUp = true;
	stopDevSpaceHealthCheck();

	logger.info('Stopping and cleaning up...');
	stopPortForwarder();
	if (activeSshSession && !activeSshSession.isClosed) {
		logger.debug('Closing active SSH session...');
		const session = activeSshSession;
		activeSshSession = null;
		session.onClosed(() => {
			logger.debug('SSH session closed.');
		});
		await closeSshSession(session, 'active SSH session');
	}
	activeSshSession = null;

	if (currentDevSpaceWsUrl) {
		const sessionInMap = sessionMap.get(currentDevSpaceWsUrl);
		sessionMap.delete(currentDevSpaceWsUrl);
		if (sessionInMap && !sessionInMap.isClosed) {
			await closeSshSession(sessionInMap, `SSH session for ${currentDevSpaceWsUrl}`);
		}
	}

	logger.info(isErrorExit ? 'Process ended because of an error.' : 'Process ended.');
	process.exit(isErrorExit ? 1 : 0);
}

function getCacheFilePath(): string | undefined {
	const cacheDir = findCacheDirectory({ name: 'bas-connect' });
	if (!cacheDir) return undefined;
	return path.join(cacheDir, 'cache.json');
}

function isRunningViaNpx(): boolean {
	const userAgent = process.env.npm_config_user_agent ?? '';
	const execPath = process.env.npm_execpath ?? '';

	return (
		userAgent.includes(' npx/') || userAgent.startsWith('npx/') || /(^|[\\/])npx(?:-cli)?(?:\.js)?$/i.test(execPath)
	);
}

async function checkForNewVersion() {
	const cacheFile = getCacheFilePath();
	const cacheDuration = 24 * 60 * 60 * 1000; // 24 hours
	if (cacheFile) {
		try {
			if (fs.existsSync(cacheFile)) {
				const cacheContent = fs.readFileSync(cacheFile, 'utf-8');
				const cache: unknown = JSON.parse(cacheContent);
				if (
					typeof cache === 'object' &&
					cache !== null &&
					'lastChecked' in cache &&
					typeof cache.lastChecked === 'string'
				) {
					const lastChecked = new Date(cache.lastChecked).getTime();
					if (Date.now() - lastChecked < cacheDuration) {
						logger.debug('Version check skipped; last check was less than 24 hours ago.');
						return;
					}
				}
			}
		} catch (error) {
			logger.debug(`Could not read version check cache file: ${getErrorMessage(error)}`);
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

		const latestPayload: unknown = await response.json();
		const latestVersion =
			typeof latestPayload === 'object' &&
			latestPayload !== null &&
			'version' in latestPayload &&
			typeof latestPayload.version === 'string'
				? latestPayload.version
				: undefined;
		if (!latestVersion) return;
		if (cacheFile) {
			try {
				const cacheDir = path.dirname(cacheFile);
				if (!fs.existsSync(cacheDir)) fs.mkdirSync(cacheDir, { recursive: true });
				fs.writeFileSync(cacheFile, JSON.stringify({ lastChecked: new Date().toISOString() }));
			} catch (error) {
				logger.debug(`Failed to write to version check cache file: ${getErrorMessage(error)}`);
			}
		}

		if (currentVersion !== latestVersion) {
			logger.info(
				`A new version of ${pkg.name} is available (${latestVersion}). Please update by running: npm i -g ${pkg.name}`,
			);
		}
	} catch (error) {
		logger.debug(`Error checking for new version: ${getErrorMessage(error)}`);
	}
}

async function main() {
	try {
		if (!isRunningViaNpx()) await checkForNewVersion();

		const args: string[] = process.argv.slice(2); // Skip 'node' and script path
		for (let i = 0; i < args.length; i++) {
			const arg: string | undefined = args[i];
			const value: string | undefined = args[i + 1];

			if ((arg === '--landscapeUrl' || arg === '-u') && value !== undefined) {
				if (value) {
					try {
						landscapeUrl = `https://${new URL(value).hostname}`;
					} catch {
						logger.error(`Invalid Landscape URL '${value}' provided via command line argument. Aborting.`);
						await cleanup(true);
						return;
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
				if (
					!isNaN(localPort) &&
					!isNaN(remotePort) &&
					localPort > 0 &&
					localPort < 65536 &&
					remotePort > 0 &&
					remotePort < 65536
				) {
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
			const response = await prompts<'value'>({
				type: 'text',
				name: 'value',
				message: 'Enter Landscape URL (e.g., https://xxx.eu20cf.applicationstudio.cloud.sap):',
				validate: (value: unknown) => {
					if (typeof value !== 'string') return 'Invalid URL.';
					try {
						new URL(value);
						return true;
					} catch {
						return 'Invalid URL.';
					}
				},
			});
			const value: unknown = response.value;
			if (typeof value !== 'string') throw new Error('Landscape URL prompt was cancelled.');
			landscapeUrl = `https://${new URL(value).hostname}`;
		}

		if (!devspaceId) {
			const response = await prompts<'value'>({
				type: 'text',
				name: 'value',
				message: 'Enter Dev Space ID (e.g., ws-xxxx):',
				validate: (val: unknown) =>
					typeof val === 'string' && val.trim() !== '' ? true : 'Dev Space ID cannot be empty.',
			});
			const value: unknown = response.value;
			if (typeof value !== 'string') throw new Error('Dev Space ID prompt was cancelled.');
			devspaceId = value.trim();
		}

		currentJwt = await retrieveJwtInteractive(landscapeUrl);
		logger.debug('Retrieved JWT successfully.');

		let devSpace = await getDevSpaceDetails(landscapeUrl, currentJwt, devspaceId);
		devSpace = await ensureDevSpaceRunning(landscapeUrl, currentJwt, devSpace);

		if (!devSpace.url) {
			logger.error(`Cannot setup SSH tunnel: url not available for dev space ${devspaceId}.`);
			await cleanup(true);
			return;
		}

		// SSH Setup
		const pk = await getPK(landscapeUrl, currentJwt, devSpace.id);
		const sshKeyFilePath = savePK(pk, devSpace.url);

		const sshHostAlias = updateSSHConfigFile(sshKeyFilePath, landscapeUrl, devSpace.id, fixedSshPort);

		logger.info(`Setting up SSH tunnel on local port ${fixedSshPort}...`);

		currentDevSpaceWsUrl = getDevSpaceWsUrl(devSpace.url);
		try {
			activeSshSession = await setupSshTunnel({
				devSpaceWsUrl: currentDevSpaceWsUrl,
				localSshPort: fixedSshPort,
				jwt: currentJwt,
			});
		} catch (error) {
			if (!isWebSocket503Error(error)) throw error;

			const restartedDevSpace = await restartDevSpace(landscapeUrl, currentJwt, devSpace.id);
			if (!restartedDevSpace.url) {
				throw new Error(`Dev space ${restartedDevSpace.id} restarted but does not have an URL.`, {
					cause: error,
				});
			}
			currentDevSpaceWsUrl = getDevSpaceWsUrl(restartedDevSpace.url);
			logger.info('Dev Space restarted after the WebSocket server returned HTTP 503.');
			activeSshSession = await setupSshTunnel({
				devSpaceWsUrl: currentDevSpaceWsUrl,
				localSshPort: fixedSshPort,
				jwt: currentJwt,
			});
		}
		startDevSpaceHealthCheck();

		logger.info('------------------------------------------------------------');
		logger.info('Setup complete!');
		logger.info('You can now connect to your dev space via SSH:');
		logger.info(`ssh ${sshHostAlias}`);
		logger.info(
			'Or configure your SSH client to directly use 127.0.0.1:' +
				fixedSshPort +
				' with the key ' +
				sshKeyFilePath,
		);
		logger.info('The SSH tunnel will remain active as long as this script is running.');
		logger.info('Press CTRL+C to stop the script and the tunnel.');
		logger.info('------------------------------------------------------------');

		process.stdin.resume(); // Keep this node process running

		process.on('SIGINT', () => {
			void cleanup(false);
		}); // CTRL+C
		process.on('SIGTERM', () => {
			void cleanup(false);
		}); // Terminate

		process.on('uncaughtException', (error: unknown) => {
			if (hasErrorCode(error, 'ECONNRESET')) return; // ignore socket reset on Windows
			throw error; // re-throw anything else
		});
	} catch (error: unknown) {
		logger.error(getErrorMessage(error));
		process.exit(1);
	}
}

void main();
