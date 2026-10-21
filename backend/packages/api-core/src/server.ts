import cors from "cors";
import express, { type NextFunction, type Request, type Response } from "express";
import { createHash, randomBytes, randomInt } from "node:crypto";
import { database, findActorForToken, hashPassword, issueSession, seedDemoAccounts, verifyPassword, type Actor } from "./database.js";
import {
  assertGmailTokenEncryptionConfigured,
  configuredGmailSender,
  createGmailAuthorizationUrl,
  decryptRefreshToken,
  encryptRefreshToken,
  exchangeGmailAuthorizationCode,
  parseGmailImageAttachment,
  safeGmailError,
  sendGmailMessage,
} from "./gmail.js";

type Portal = "resident" | "cepalco" | "water";
type Locals = { actor?: Actor };
type Row = Record<string, unknown>;
const utilities: Record<Exclude<Portal, "resident">, string> = { cepalco: "CEPALCO", water: "Water District" };

function required(value: unknown, name: string): string {
  if (typeof value !== "string" || value.trim().length === 0) throw new Error(`${name} is required.`);
  return value.trim();
}

// ADDED: Validate optional map coordinates from the advisory publishing form.
function optionalCoordinate(value: unknown, name: string, minimum: number, maximum: number): number | null {
  if (value === undefined || value === null || value === "") return null;
  const coordinate = typeof value === "number"
    ? value
    : typeof value === "string" && value.trim() !== ""
      ? Number(value)
      : Number.NaN;
  if (!Number.isFinite(coordinate) || coordinate < minimum || coordinate > maximum) {
    throw new Error(`${name} must be a valid number between ${minimum} and ${maximum}.`);
  }
  return coordinate;
}


function publicActor(actor: Actor) {
  return {
    id: actor.id,
    name: actor.name,
    email: actor.email,
    role: actor.role,
    utility: actor.utility,
    phoneNumber: actor.phone_number ?? "",
    address: actor.address ?? "",
    barangay: actor.barangay ?? "",
    district: actor.district ?? "",
    city: actor.city ?? "",
    postalCode: actor.postal_code ?? "",
    profileImage: actor.profile_image ?? null,
    smsAlerts: Boolean(actor.sms_alerts),
    maintenanceAlerts: Boolean(actor.notify_maintenance),
    emailDigest: Boolean(actor.notify_email_digest),
    immediateEmailAlerts: Boolean(actor.immediate_email_alerts),
  };
}

function decorateRows<T extends Row>(rows: T[]): T[] {
  return rows.map(row => {
    const decorated: Row = { ...row };
    for (const [key, value] of Object.entries(row)) {
      const outputKey = key.replace(/_([a-z])/g, (_, letter: string) => letter.toUpperCase());
      decorated[outputKey] = value;
    }
    return decorated as T;
  });
}

export function createApi(portal: Portal) {
  seedDemoAccounts();
  const app = express();
  app.disable("x-powered-by");
  const configuredOrigins = process.env.CORS_ORIGIN?.split(",").map(origin => origin.trim()).filter(Boolean);
  app.use(cors({
    origin: (origin, callback) => {
      const localDevelopmentOrigin = process.env.NODE_ENV !== "production" && /^http:\/\/(?:localhost|127\.0\.0\.1):\d+$/.test(origin || "");
      if (!origin || (configuredOrigins ? configuredOrigins.includes(origin) : localDevelopmentOrigin)) return callback(null, true);
      return callback(new Error("Origin is not allowed by CORS."));
    },
    allowedHeaders: ["Content-Type", "Authorization"],
  }));
  app.use(express.json({ limit: "2mb" }));
  app.get("/health", (_req, res) => res.json({ ok: true, portal, service: "CivicAlert API" }));
  app.get("/content", (_req, res) => {
    const rows = database.prepare("SELECT content_key, content_value FROM ui_copy ORDER BY content_key").all() as Array<{ content_key: string; content_value: string }>;
    const settings = database.prepare("SELECT settings_json FROM portal_settings WHERE portal = ?").get(portal) as { settings_json: string } | undefined;
    if (!settings) return res.status(500).json({ error: `Portal content for ${portal} is unavailable.` });
    return res.json({ copy: Object.fromEntries(rows.map(row => [row.content_key, row.content_value])), settings: JSON.parse(settings.settings_json) });
  });
  if (portal === "resident") {
    app.get("/auth/me", authenticate("resident"), (_req, res: Response<unknown, Locals>) => res.json({ actor: publicActor(res.locals.actor!) }));
  } else {
    app.get("/auth/me", requireUtility(utilities[portal]), (_req, res: Response<unknown, Locals>) => res.json({ actor: publicActor(res.locals.actor!) }));
    app.get("/email/gmail/status", requireUtility(utilities[portal]), (_req, res) => {
      const connection = database.prepare("SELECT sender_email, connected_at FROM gmail_connections WHERE utility = ?")
        .get(utilities[portal]) as { sender_email: string; connected_at: string } | undefined;
      return res.json({ connected: Boolean(connection), senderEmail: connection?.sender_email ?? null, connectedAt: connection?.connected_at ?? null });
    });
    app.post("/email/gmail/connect", requireUtility(utilities[portal]), (req, res: Response<unknown, Locals>) => {
      const state = randomBytes(32).toString("base64url");
      const userId = res.locals.actor!.id;
      try {
        assertGmailTokenEncryptionConfigured();
        configuredGmailSender(portal);
        const authorizationUrl = createGmailAuthorizationUrl(portal, state);
        database.prepare("DELETE FROM gmail_oauth_states WHERE expires_at < ?").run(Date.now());
        database.prepare("INSERT INTO gmail_oauth_states (state_hash, user_id, utility, expires_at) VALUES (?, ?, ?, ?)")
          .run(createHash("sha256").update(state).digest("hex"), userId, utilities[portal], Date.now() + 5 * 60 * 1000);
        return res.json({ authorizationUrl });
      } catch (error) {
        return res.status(503).json({ error: error instanceof Error ? error.message : "Gmail OAuth is not configured on the server." });
      }
    });
    app.get("/oauth/gmail/callback", async (req, res) => {
      const frontend = gmailFrontendUrl(portal);
      const state = typeof req.query.state === "string" ? req.query.state : "";
      const stateHash = createHash("sha256").update(state).digest("hex");
      const oauthState = state ? database.prepare(`
        SELECT oauth_states.user_id, oauth_states.utility, oauth_states.expires_at
        FROM gmail_oauth_states AS oauth_states
        JOIN users ON users.id = oauth_states.user_id
        WHERE oauth_states.state_hash = ? AND users.role = 'admin' AND users.utility = oauth_states.utility
      `)
        .get(stateHash) as { user_id: number; utility: string; expires_at: number } | undefined : undefined;
      if (!oauthState || oauthState.expires_at < Date.now() || oauthState.utility !== utilities[portal]) {
        return res.redirect(gmailFrontendRedirect(frontend, portal, "error"));
      }
      database.prepare("DELETE FROM gmail_oauth_states WHERE state_hash = ?").run(stateHash);
      if (typeof req.query.error === "string" || typeof req.query.code !== "string") {
        return res.redirect(gmailFrontendRedirect(frontend, portal, "error"));
      }
      try {
        const connected = await exchangeGmailAuthorizationCode(portal, req.query.code);
        if (connected.email !== configuredGmailSender(portal)) {
          throw new Error("The authorized Google account does not match the configured official utility address.");
        }
        const existing = database.prepare("SELECT encrypted_refresh_token FROM gmail_connections WHERE utility = ?")
          .get(utilities[portal]) as { encrypted_refresh_token: string } | undefined;
        const refreshToken = connected.refreshToken
          ? encryptRefreshToken(connected.refreshToken)
          : existing?.encrypted_refresh_token;
        if (!refreshToken) throw new Error("Google did not issue a refresh token. Reconnect and approve offline access.");
        database.prepare(`
          INSERT INTO gmail_connections (utility, sender_email, encrypted_refresh_token, connected_by)
          VALUES (?, ?, ?, ?)
          ON CONFLICT(utility) DO UPDATE SET
            sender_email = excluded.sender_email,
            encrypted_refresh_token = excluded.encrypted_refresh_token,
            connected_by = excluded.connected_by,
            connected_at = CURRENT_TIMESTAMP
        `).run(utilities[portal], connected.email, refreshToken, oauthState.user_id);
        return res.redirect(gmailFrontendRedirect(frontend, portal, "connected"));
      } catch (error) {
        console.error(`[${portal}-api] Gmail account connection failed: ${safeGmailError(error)}`);
        return res.redirect(gmailFrontendRedirect(frontend, portal, "error"));
      }
    });
  }
  app.post("/auth/login", (req, res) => {
    try {
      const email = required(req.body?.email, "Email").toLowerCase();
      const password = required(req.body?.password, "Password");
      const expectedRole = portal === "resident" ? "resident" : "admin";
      const user = database.prepare("SELECT id, name, email, password_hash, role, utility, phone_number, address, barangay, district, city, postal_code, profile_image, sms_alerts, notify_maintenance, notify_email_digest, immediate_email_alerts, terms_accepted_at FROM users WHERE email = ? AND role = ? AND (utility IS ? OR utility = ?)").get(
        email, expectedRole, portal === "resident" ? null : utilities[portal], portal === "resident" ? "" : utilities[portal],
      ) as (Actor & { password_hash: string }) | undefined;
      if (!user || !verifyPassword(password, user.password_hash)) return res.status(401).json({ error: "Email or password is incorrect." });
      const { password_hash: _secret, ...actor } = user;
      return res.json({ token: issueSession(user.id), actor: publicActor(actor) });
    } catch (error) {
      return res.status(400).json({ error: error instanceof Error ? error.message : "Invalid sign-in request." });
    }
  });

  if (portal === "resident") {
    app.patch("/auth/profile", authenticate("resident"), (req, res: Response<unknown, Locals>) => {
      try {
        const name = required(req.body?.name, "Full name");
        const email = required(req.body?.email, "Email").toLowerCase();
        const phoneNumber = typeof req.body?.phoneNumber === "string" ? req.body.phoneNumber.trim() : "";
        const address = typeof req.body?.address === "string" ? req.body.address.trim() : "";
        const barangay = typeof req.body?.barangay === "string" ? req.body.barangay.trim() : "";
        const district = typeof req.body?.district === "string" ? req.body.district.trim() : "";
        const city = typeof req.body?.city === "string" ? req.body.city.trim() : "";
        const postalCode = typeof req.body?.postalCode === "string" ? req.body.postalCode.trim() : "";
        const smsAlerts = typeof req.body?.smsAlerts === "boolean" ? Number(req.body.smsAlerts) : res.locals.actor!.sms_alerts ?? 1;
        const maintenanceAlerts = typeof req.body?.maintenanceAlerts === "boolean" ? Number(req.body.maintenanceAlerts) : res.locals.actor!.notify_maintenance ?? 1;
        const emailDigest = typeof req.body?.emailDigest === "boolean" ? Number(req.body.emailDigest) : res.locals.actor!.notify_email_digest ?? 1;
        const immediateEmailAlerts = typeof req.body?.immediateEmailAlerts === "boolean" ? Number(req.body.immediateEmailAlerts) : res.locals.actor!.immediate_email_alerts ?? 0;
        const profileImage = req.body?.profileImage;
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: "Enter a valid email address." });
        if (phoneNumber.length > 40 || address.length > 240 || barangay.length > 100 || district.length > 80 || city.length > 100 || postalCode.length > 20 || name.length > 120) {
          return res.status(400).json({ error: "One or more profile fields are too long." });
        }
        if (profileImage !== null && profileImage !== undefined &&
            (typeof profileImage !== "string" || profileImage.length > 1_500_000 ||
             !/^data:image\/(?:jpeg|png|webp);base64,[A-Za-z0-9+/]+={0,2}$/.test(profileImage))) {
          return res.status(400).json({ error: "Choose a JPEG, PNG, or WebP profile image under 1 MB." });
        }
        const imageToSave = profileImage === undefined ? res.locals.actor!.profile_image ?? null : profileImage;
        const result = database.prepare(`
          UPDATE users SET name = ?, email = ?, phone_number = ?, address = ?, barangay = ?, district = ?, city = ?, postal_code = ?, profile_image = ?, sms_alerts = ?, notify_maintenance = ?, notify_email_digest = ?, immediate_email_alerts = ?
          WHERE id = ? AND role = 'resident'
        `).run(name, email, phoneNumber, address, barangay, district, city, postalCode, imageToSave, smsAlerts, maintenanceAlerts, emailDigest, immediateEmailAlerts, res.locals.actor!.id);
        if (!Number(result.changes)) return res.status(404).json({ error: "Resident account not found." });
        const actor = database.prepare("SELECT id, name, email, role, utility, phone_number, address, barangay, district, city, postal_code, profile_image, sms_alerts, notify_maintenance, notify_email_digest, immediate_email_alerts, terms_accepted_at FROM users WHERE id = ?").get(res.locals.actor!.id) as Actor;
        return res.json({ actor: publicActor(actor) });
      } catch (error) {
        if (error instanceof Error && error.message.includes("UNIQUE constraint")) return res.status(409).json({ error: "An account with this email already exists." });
        return res.status(400).json({ error: error instanceof Error ? error.message : "Could not update resident profile." });
      }
    });
    app.post("/auth/password", authenticate("resident"), (req, res: Response<unknown, Locals>) => {
      try {
        const currentPassword = required(req.body?.currentPassword, "Current password");
        const newPassword = required(req.body?.newPassword, "New password");
        if (newPassword.length < 8) return res.status(400).json({ error: "New password must be at least 8 characters." });
        const user = database.prepare("SELECT password_hash FROM users WHERE id = ? AND role = 'resident'").get(res.locals.actor!.id) as { password_hash: string } | undefined;
        if (!user || !verifyPassword(currentPassword, user.password_hash)) return res.status(401).json({ error: "Current password is incorrect." });
        if (verifyPassword(newPassword, user.password_hash)) return res.status(400).json({ error: "Choose a password you have not used before." });
        database.prepare("UPDATE users SET password_hash = ? WHERE id = ?").run(hashPassword(newPassword), res.locals.actor!.id);
        return res.json({ ok: true });
      } catch (error) {
        return res.status(400).json({ error: error instanceof Error ? error.message : "Could not change password." });
      }
    });
    app.post("/auth/register", (req, res) => {
      try {
        const name = required(req.body?.name, "Name");
        const email = required(req.body?.email, "Email").toLowerCase();
        const password = required(req.body?.password, "Password");
        const phoneNumber = required(req.body?.phoneNumber, "Mobile telephone");
        const address = required(req.body?.address, "Street address");
        const barangay = required(req.body?.barangay, "Barangay");
        const district = required(req.body?.district, "District");
        const city = required(req.body?.city, "City");
        const postalCode = required(req.body?.postalCode, "Postal code");
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: "Enter a valid email address." });
        if (password.length < 8) return res.status(400).json({ error: "Password must be at least 8 characters." });
        if (name.length > 120 || phoneNumber.length > 40 || address.length > 240 || barangay.length > 100 || district.length > 80 || city.length > 100 || postalCode.length > 20) {
          return res.status(400).json({ error: "One or more registration fields are too long." });
        }
        if (req.body?.termsAccepted !== true) return res.status(400).json({ error: "Please accept the resident terms and privacy policy." });
        const smsAlerts = req.body?.smsAlerts === false ? 0 : 1;
        const immediateEmailAlerts = req.body?.immediateEmailAlerts === true ? 1 : 0;
        const id = Number(database.prepare(`
          INSERT INTO users (name, email, password_hash, role, utility, phone_number, address, barangay, district, city, postal_code, sms_alerts, immediate_email_alerts, terms_accepted_at)
          VALUES (?, ?, ?, 'resident', NULL, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        `).run(name, email, hashPassword(password), phoneNumber, address, barangay, district, city, postalCode, smsAlerts, immediateEmailAlerts).lastInsertRowid);
        const actor: Actor = { id, name, email, role: "resident", utility: null, phone_number: phoneNumber, address, barangay, district, city, postal_code: postalCode, sms_alerts: smsAlerts, immediate_email_alerts: immediateEmailAlerts, notify_maintenance: 1, notify_email_digest: 1 };
        return res.status(201).json({ token: issueSession(id), actor: publicActor(actor) });
      } catch (error) {
        if (error instanceof Error && error.message.includes("UNIQUE constraint")) return res.status(409).json({ error: "An account with this email already exists." });
        return res.status(400).json({ error: error instanceof Error ? error.message : "Could not create account." });
      }
    });
    app.get("/advisories", (_req, res) => res.json(decorateRows(database.prepare("SELECT id, reference, title, utility, type, area, status, details, created_at, latitude, longitude FROM advisories ORDER BY id DESC").all() as Row[])));
    app.get("/work-orders", (_req, res) => {
      const rows = database.prepare("SELECT id, reference, title, utility, area, status, starts_at, ends_at FROM work_orders ORDER BY starts_at").all() as Row[];
      return res.json(decorateRows(rows));
    });
    app.post("/reports", authenticate("resident"), (req, res: Response<unknown, Locals>) => {
      try {
        const utility = required(req.body?.utility, "Utility");
        if (!["CEPALCO", "Water District"].includes(utility)) return res.status(400).json({ error: "Choose a valid utility." });
        const title = required(req.body?.issue, "Issue");
        const area = required(req.body?.area, "Service area");
        const details = typeof req.body?.details === "string" ? req.body.details.trim() : "";
        const reference = `CAS-R-${Date.now().toString(36).toUpperCase()}${randomInt(10, 99)}`;
        const id = Number(database.prepare("INSERT INTO reports (reference, user_id, title, utility, area, details) VALUES (?, ?, ?, ?, ?, ?)").run(reference, res.locals.actor!.id, title, utility, area, details).lastInsertRowid);
        return res.status(201).json({ id, reference, title, utility, area, details, status: "Received" });
      } catch (error) { return res.status(400).json({ error: error instanceof Error ? error.message : "Could not submit report." }); }
    });
    app.get("/reports/mine", authenticate("resident"), (_req, res: Response<unknown, Locals>) => {
      const rows = database.prepare("SELECT id, reference, title, utility, area, status, created_at FROM reports WHERE user_id = ? ORDER BY id DESC").all(res.locals.actor!.id) as Row[];
      return res.json(decorateRows(rows));
    });
  } else {
    const utility = utilities[portal];
    app.get("/advisories", requireUtility(utility), (_req, res) => {
      const rows = database.prepare("SELECT id, reference, title, utility, type, area, status, details, created_at, latitude, longitude FROM advisories WHERE utility = ? ORDER BY id DESC").all(utility) as Row[];
      return res.json(decorateRows(rows));
    });
    app.post("/advisories", requireUtility(utility), async (req, res) => {
      try {
        const title = required(req.body?.title, "Advisory title");
        const area = required(req.body?.area, "Affected service area");
        const details = required(req.body?.details, "Public update");
        const type = typeof req.body?.type === "string" ? req.body.type : "Service disruption";

        // ADDED: Validate the optional Google Maps location. A pin must include both coordinates.
        const latitude = optionalCoordinate(req.body?.latitude, "Latitude", -90, 90);
        const longitude = optionalCoordinate(req.body?.longitude, "Longitude", -180, 180);
        if ((latitude === null) !== (longitude === null)) {
          throw new Error("Select a map location so both latitude and longitude are provided.");
        }

        // ADDED: Validate the optional announcement image before saving the advisory.
        // The frontend will submit it as a data URL (JPEG, PNG, or WebP).
        const validatedImage = parseGmailImageAttachment(req.body?.imageDataUrl ?? null);
        const imageDataUrl = validatedImage
          ? `data:${validatedImage.mimeType};base64,${validatedImage.content.toString("base64")}`
          : null;

        const reference = `${portal === "water" ? "WD" : "CE"}-${Date.now().toString(36).toUpperCase()}`;

        // ADDED: Save the validated image with the advisory so failed email deliveries can retry with it.
        const id = Number(database.prepare(`
          INSERT INTO advisories
            (reference, title, utility, type, area, details, image_data_url, latitude, longitude)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(reference, title, utility, type, area, details, imageDataUrl, latitude, longitude).lastInsertRowid);

        // ADDED: Pass the optional image through to the Gmail delivery function.
        const emailDelivery = await deliverAdvisoryEmails(
          portal, utility, id, reference, title, area, details, imageDataUrl,
        );
        return res.status(201).json({ id, reference, title, utility, type, area, status: "Monitoring", details, latitude, longitude, emailDelivery });
      } catch (error) { return res.status(400).json({ error: error instanceof Error ? error.message : "Could not publish advisory." }); }
    });
    app.get("/advisories/:id/email-delivery", requireUtility(utility), (req, res) => {
      const advisory = database.prepare("SELECT id FROM advisories WHERE id = ? AND utility = ?")
        .get(Number(req.params.id), utility) as { id: number } | undefined;
      if (!advisory) return res.status(404).json({ error: "Advisory not found." });
      const rows = database.prepare(`
        SELECT deliveries.status, deliveries.error_message, deliveries.attempt_count, deliveries.sent_at,
          users.name AS recipient_name
        FROM email_deliveries AS deliveries
        JOIN users ON users.id = deliveries.resident_id
        WHERE deliveries.advisory_id = ?
        ORDER BY deliveries.id
      `).all(advisory.id) as Array<{ status: "pending" | "sent" | "failed"; error_message: string | null; attempt_count: number; sent_at: string | null; recipient_name: string }>;
      return res.json(summarizeEmailDeliveries(rows));
    });
    app.post("/advisories/:id/email-delivery/retry", requireUtility(utility), async (req, res) => {
      // ADDED: Fetch the saved image too, so retrying a failed email preserves its attachment.
      const advisory = database.prepare(`
        SELECT id, reference, title, area, details, image_data_url
        FROM advisories WHERE id = ? AND utility = ?
      `).get(Number(req.params.id), utility) as {
        id: number;
        reference: string;
        title: string;
        area: string;
        details: string;
        image_data_url: string | null;
      } | undefined;
      if (!advisory) return res.status(404).json({ error: "Advisory not found." });
      try {
        // ADDED: Pass the originally saved image before the `failedOnly` flag.
        const emailDelivery = await deliverAdvisoryEmails(
          portal,
          utility,
          advisory.id,
          advisory.reference,
          advisory.title,
          advisory.area,
          advisory.details,
          advisory.image_data_url,
          true,
        );
        return res.json(emailDelivery);
      } catch (error) {
        return res.status(500).json({ error: error instanceof Error ? error.message : "Could not retry email delivery." });
      }
    });
    app.patch("/advisories/:id/status", requireUtility(utility), (req, res) => {
      const status = req.body?.status;
      if (!["Monitoring", "Under investigation", "Crew dispatched", "Resolved"].includes(status)) return res.status(400).json({ error: "Unsupported advisory status." });
      const result = database.prepare("UPDATE advisories SET status = ? WHERE id = ? AND utility = ?").run(status, Number(req.params.id), utility);
      return Number(result.changes) ? res.json({ ok: true }) : res.status(404).json({ error: "Advisory not found." });
    });
    app.get("/work-orders", requireUtility(utility), (_req, res) => {
      const rows = database.prepare("SELECT id, reference, title, utility, area, status, starts_at, ends_at FROM work_orders WHERE utility = ? ORDER BY starts_at").all(utility) as Row[];
      return res.json(decorateRows(rows));
    });
    app.post("/work-orders", requireUtility(utility), (req, res) => {
      try {
        const title = required(req.body?.title, "Work order title");
        const area = required(req.body?.area, "Affected service area");
        const startsAt = required(req.body?.startsAt, "Start time");
        const endsAt = required(req.body?.endsAt, "End time");
        const description = typeof req.body?.description === "string" ? req.body.description.trim() : "";
        if (Number.isNaN(Date.parse(startsAt)) || Number.isNaN(Date.parse(endsAt)) || Date.parse(endsAt) <= Date.parse(startsAt)) return res.status(400).json({ error: "End time must be later than start time." });
        const reference = `${portal === "water" ? "WD" : "CE"}-WO-${Date.now().toString(36).toUpperCase()}`;
        const id = Number(database.prepare("INSERT INTO work_orders (reference, title, utility, area, description, starts_at, ends_at) VALUES (?, ?, ?, ?, ?, ?, ?)").run(reference, title, utility, area, description, startsAt, endsAt).lastInsertRowid);
        return res.status(201).json({ id, reference, title, utility, area, description, startsAt, endsAt, status: "Scheduled" });
      } catch (error) { return res.status(400).json({ error: error instanceof Error ? error.message : "Could not create work order." }); }
    });
    app.get("/reports", requireUtility(utility), (_req, res) => {
      const rows = database.prepare("SELECT id, reference, title, utility, area, status, created_at FROM reports WHERE utility = ? ORDER BY id DESC").all(utility) as Row[];
      return res.json(decorateRows(rows));
    });
    app.patch("/reports/:id/status", requireUtility(utility), (req, res) => {
      const status = req.body?.status;
      if (!["Received", "Under investigation", "Crew dispatched", "Resolved"].includes(status)) return res.status(400).json({ error: "Unsupported report status." });
      const result = database.prepare("UPDATE reports SET status = ? WHERE id = ? AND utility = ?").run(status, Number(req.params.id), utility);
      return Number(result.changes) ? res.json({ ok: true }) : res.status(404).json({ error: "Report not found." });
    });
    if (portal === "water") {
      app.get("/network", requireUtility(utility), (_req, res) => {
        const rows = database.prepare("SELECT district, area, pressure_psi, reservoir_percent, recorded_at FROM network_readings WHERE utility = ? ORDER BY id").all(utility) as Row[];
        return res.json(decorateRows(rows));
      });
    }
  }

  app.use((error: unknown, _req: Request, res: Response, _next: NextFunction) => {
    console.error(`[${portal}-api]`, error);
    res.status(500).json({ error: "An unexpected server error occurred." });
  });
  return app;
}

function authenticate(expectedRole: Actor["role"]) {
  return (req: Request, res: Response<unknown, Locals>, next: NextFunction) => {
    const authorization = req.header("authorization");
    const token = authorization?.startsWith("Bearer ") ? authorization.slice(7) : "";
    const actor = token ? findActorForToken(token) : undefined;
    if (!actor || actor.role !== expectedRole) return res.status(401).json({ error: "Please sign in to continue." });
    res.locals.actor = actor;
    next();
  };
}

function requireUtility(utility: string) {
  return (req: Request, res: Response<unknown, Locals>, next: NextFunction) => {
    const authorization = req.header("authorization");
    const token = authorization?.startsWith("Bearer ") ? authorization.slice(7) : "";
    const actor = token ? findActorForToken(token) : undefined;
    if (!actor || actor.role !== "admin" || actor.utility !== utility) return res.status(401).json({ error: "A matching utility administrator must sign in." });
    res.locals.actor = actor;
    next();
  };
}

function gmailFrontendUrl(portal: Exclude<Portal, "resident">): URL {
  const variable = portal === "cepalco" ? "CEPALCO_FRONTEND_URL" : "WATER_FRONTEND_URL";
  const defaultPort = portal === "cepalco" ? 5174 : 5175;
  const configuredUrl = process.env[variable]?.trim() || `http://localhost:${defaultPort}`;
  const frontend = new URL(configuredUrl);
  if (frontend.protocol !== "https:" && !(process.env.NODE_ENV !== "production" && frontend.protocol === "http:" && ["localhost", "127.0.0.1"].includes(frontend.hostname))) {
    throw new Error(`${variable} must use HTTPS outside local development.`);
  }
  return frontend;
}

function gmailFrontendRedirect(frontend: URL, portal: Exclude<Portal, "resident">, result: "connected" | "error"): string {
  frontend.search = "";
  frontend.hash = "";
  frontend.searchParams.set("portal", portal);
  frontend.searchParams.set("view", "portal");
  frontend.searchParams.set("page", "publish");
  frontend.searchParams.set("gmail", result);
  return frontend.toString();
}

type EmailDeliveryRow = {
  status: "pending" | "sent" | "failed";
  error_message: string | null;
  attempt_count: number;
  sent_at: string | null;
  recipient_name: string;
};

function summarizeEmailDeliveries(rows: EmailDeliveryRow[]) {
  const sent = rows.filter(row => row.status === "sent").length;
  const failed = rows.filter(row => row.status === "failed").length;
  const pending = rows.filter(row => row.status === "pending").length;
  const status = rows.length === 0
    ? "no_recipients"
    : pending > 0
      ? "pending"
      : failed === 0
        ? "sent"
        : sent > 0
          ? "partial"
          : "failed";
  const errors = new Map<string, number>();
  for (const row of rows) {
    if (row.error_message) errors.set(row.error_message, (errors.get(row.error_message) ?? 0) + 1);
  }
  return {
    status,
    attempted: sent + failed,
    sent,
    failed,
    pending,
    errors: [...errors].map(([message, count]) => ({ message, count })),
    deliveries: rows.map(row => ({
      status: row.status,
      error: row.error_message,
      attempts: row.attempt_count,
      sentAt: row.sent_at,
      recipientName: row.recipient_name,
    })),
  };
}

async function deliverAdvisoryEmails(
  portal: Exclude<Portal, "resident">,
  utility: string,
  advisoryId: number,
  reference: string,
  title: string,
  area: string,
  details: string,
  // ADDED: Optional image data URL saved with the advisory; null keeps text-only emails working.
  imageDataUrl: string | null = null,
  failedOnly = false,
) {
  const recipients = failedOnly
    ? database.prepare(`
        SELECT users.id, users.name, users.email FROM email_deliveries
        JOIN users ON users.id = email_deliveries.resident_id
        WHERE email_deliveries.advisory_id = ? AND email_deliveries.status = 'failed'
          AND users.role = 'resident' AND users.immediate_email_alerts = 1
        ORDER BY users.id
      `).all(advisoryId) as Array<{ id: number; name: string; email: string }>
    : database.prepare(`
        SELECT id, name, email FROM users
        WHERE role = 'resident' AND immediate_email_alerts = 1
        ORDER BY id
      `).all() as Array<{ id: number; name: string; email: string }>;
  if (failedOnly) {
    database.prepare(`
      UPDATE email_deliveries SET status = 'pending', error_message = NULL
      WHERE advisory_id = ? AND status = 'failed' AND resident_id IN (
        SELECT id FROM users WHERE role = 'resident' AND immediate_email_alerts = 1
      )
    `).run(advisoryId);
  } else {
    for (const resident of recipients) {
      database.prepare(`
        INSERT OR IGNORE INTO email_deliveries (advisory_id, resident_id, status)
        VALUES (?, ?, 'pending')
      `).run(advisoryId, resident.id);
    }
  }
  if (recipients.length === 0) return summarizeEmailDeliveries([]);

  const connection = database.prepare("SELECT encrypted_refresh_token FROM gmail_connections WHERE utility = ?")
    .get(utility) as { encrypted_refresh_token: string } | undefined;
  let refreshToken: string | null = null;
  let connectionError: string | null = null;
  if (!connection) {
    connectionError = "No Gmail sending account is connected for this utility.";
  } else {
    try {
      refreshToken = decryptRefreshToken(connection.encrypted_refresh_token);
    } catch (error) {
      connectionError = error instanceof Error ? error.message : "Reconnect the Gmail sending account.";
    }
  }

  for (const recipient of recipients) {
    const update = database.prepare(`
      UPDATE email_deliveries
      SET status = ?, error_message = ?, attempt_count = attempt_count + 1,
        sent_at = CASE WHEN ? = 'sent' THEN CURRENT_TIMESTAMP ELSE NULL END
      WHERE advisory_id = ? AND resident_id = ?
    `);
    if (!refreshToken) {
      update.run("failed", connectionError, "failed", advisoryId, recipient.id);
      continue;
    }
    try {
      await sendGmailMessage(
        portal,
        refreshToken,
        recipient.email,
        `${utility} advisory: ${title}`,
        `${title}\n\n${area}\n\n${details}\n\nReference: ${reference}`,
        // ADDED: Gmail creates a multipart email when this optional image data URL is present.
        imageDataUrl,
      );
      update.run("sent", null, "sent", advisoryId, recipient.id);
    } catch (error) {
      update.run("failed", safeGmailError(error), "failed", advisoryId, recipient.id);
    }
  }

  const rows = database.prepare(`
    SELECT deliveries.status, deliveries.error_message, deliveries.attempt_count,
      deliveries.sent_at, users.name AS recipient_name
    FROM email_deliveries AS deliveries
    JOIN users ON users.id = deliveries.resident_id
    WHERE deliveries.advisory_id = ?
    ORDER BY deliveries.id
  `).all(advisoryId) as EmailDeliveryRow[];
  return summarizeEmailDeliveries(rows);
}
