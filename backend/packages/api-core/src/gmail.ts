import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { google } from "googleapis";

export const GMAIL_SEND_SCOPE = "https://www.googleapis.com/auth/gmail.send";
const identityScopes = ["openid", "email"];
const oauthCallbackPaths = {
  cepalco: "/oauth/gmail/callback",
  water: "/oauth/gmail/callback",
} as const;
type UtilityPortal = keyof typeof oauthCallbackPaths;

export function configuredGmailSender(portal: UtilityPortal): string {
  const variable = portal === "cepalco" ? "CEPALCO_GMAIL_SENDER_EMAIL" : "WATER_GMAIL_SENDER_EMAIL";
  const email = requiredEnvironment(variable).toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new Error(`${variable} must be a valid email address.`);
  return email;
}

function requiredEnvironment(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is not configured on the server.`);
  return value;
}

export function gmailRedirectUri(portal: UtilityPortal): string {
  const variable = portal === "cepalco" ? "GMAIL_CEPALCO_REDIRECT_URI" : "GMAIL_WATER_REDIRECT_URI";
  const defaultPort = portal === "cepalco" ? 4102 : 4103;
  const uri = process.env[variable]?.trim() || `http://localhost:${defaultPort}${oauthCallbackPaths[portal]}`;
  let parsed: URL;
  try {
    parsed = new URL(uri);
  } catch {
    throw new Error(`${variable} must be a valid absolute URL.`);
  }
  if (parsed.protocol !== "https:" && !(process.env.NODE_ENV !== "production" && parsed.protocol === "http:" && ["localhost", "127.0.0.1"].includes(parsed.hostname))) {
    throw new Error(`${variable} must use HTTPS outside local development.`);
  }
  return parsed.toString();
}

function createOAuthClient(portal: UtilityPortal) {
  return new google.auth.OAuth2(
    requiredEnvironment("GMAIL_OAUTH_CLIENT_ID"),
    requiredEnvironment("GMAIL_OAUTH_CLIENT_SECRET"),
    gmailRedirectUri(portal),
  );
}

export function createGmailAuthorizationUrl(portal: UtilityPortal, state: string): string {
  return createOAuthClient(portal).generateAuthUrl({
    access_type: "offline",
    prompt: "consent",
    scope: [GMAIL_SEND_SCOPE, ...identityScopes],
    state,
  });
}

export async function exchangeGmailAuthorizationCode(portal: UtilityPortal, code: string) {
  const oauthClient = createOAuthClient(portal);
  const { tokens } = await oauthClient.getToken(code);
  if (!tokens.access_token) throw new Error("Google did not return an access token.");
  oauthClient.setCredentials(tokens);
  const identity = await google.oauth2({ version: "v2", auth: oauthClient }).userinfo.get();
  const email = identity.data.email?.trim().toLowerCase();
  if (!email || !identity.data.verified_email) throw new Error("Google did not verify the connected Gmail address.");
  return { email, refreshToken: tokens.refresh_token ?? null };
}

function tokenEncryptionKey(): Buffer {
  const encoded = requiredEnvironment("GMAIL_TOKEN_ENCRYPTION_KEY");
  const key = Buffer.from(encoded, "base64");
  if (key.length !== 32 || key.toString("base64") !== encoded) {
    throw new Error("GMAIL_TOKEN_ENCRYPTION_KEY must be a base64-encoded 32-byte key.");
  }
  return key;
}

export function assertGmailTokenEncryptionConfigured(): void {
  tokenEncryptionKey();
}

export function encryptRefreshToken(token: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", tokenEncryptionKey(), iv);
  const encrypted = Buffer.concat([cipher.update(token, "utf8"), cipher.final()]);
  return [iv, cipher.getAuthTag(), encrypted].map(part => part.toString("base64url")).join(".");
}

export function decryptRefreshToken(value: string): string {
  const [encodedIv, encodedTag, encodedEncrypted, ...extra] = value.split(".");
  if (!encodedIv || !encodedTag || !encodedEncrypted || extra.length) throw new Error("Stored Gmail authorization is invalid.");
  try {
    const decipher = createDecipheriv("aes-256-gcm", tokenEncryptionKey(), Buffer.from(encodedIv, "base64url"));
    decipher.setAuthTag(Buffer.from(encodedTag, "base64url"));
    return Buffer.concat([
      decipher.update(Buffer.from(encodedEncrypted, "base64url")),
      decipher.final(),
    ]).toString("utf8");
  } catch {
    throw new Error("Stored Gmail authorization cannot be decrypted. Reconnect the Gmail account.");
  }
}

export function createRawEmail(recipient: string, subject: string, body: string): string {
  if (!/^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(recipient) || /[\r\n]/.test(recipient)) {
    throw new Error("Recipient email address is invalid.");
  }
  const encodedSubject = `=?UTF-8?B?${Buffer.from(subject, "utf8").toString("base64")}?=`;
  const message = [
    `To: ${recipient}`,
    `Subject: ${encodedSubject}`,
    "MIME-Version: 1.0",
    "Content-Type: text/plain; charset=UTF-8",
    "Content-Transfer-Encoding: base64",
    "",
    Buffer.from(body, "utf8").toString("base64"),
  ].join("\r\n");
  return Buffer.from(message, "utf8").toString("base64url");
}

export async function sendGmailMessage(
  portal: UtilityPortal,
  refreshToken: string,
  recipient: string,
  subject: string,
  body: string,
): Promise<void> {
  const auth = createOAuthClient(portal);
  auth.setCredentials({ refresh_token: refreshToken });
  const gmail = google.gmail({ version: "v1", auth });
  await gmail.users.messages.send({
    userId: "me",
    requestBody: { raw: createRawEmail(recipient, subject, body) },
  });
}

export function safeGmailError(error: unknown): string {
  const message = error instanceof Error ? error.message : "";
  if (/invalid_grant|revoked|expired/i.test(message)) {
    return "Gmail authorization expired or was revoked. Reconnect the Gmail account.";
  }
  if (/rate.?limit|quota|too many requests/i.test(message)) {
    return "Gmail sending limit reached. Retry delivery later.";
  }
  return "Gmail could not send this message. Check the connected account and recipient address.";
}
