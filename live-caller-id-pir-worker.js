import { Container, getContainer } from "@cloudflare/containers"

const LIVE_CALLER_ID_TOKEN_PATH = "/live-caller-id/token"
const USER_TOKEN_SIGNING_SECRET = "LIVE_CALLER_ID_USER_TOKEN_SIGNING_SECRET"
const EXPECTED_BUNDLE_ID = "com.almorantino.callshield"
const EXPECTED_EXTENSION_ID = "com.almorantino.callshield.CallShieldLiveCallerID"
const TOKEN_TIER = "tier1"
const TOKEN_TTL_SECONDS = 90 * 24 * 60 * 60

const ALLOWED_PATHS = new Set([
  "/config",
  "/key",
  "/queries",
  "/.well-known/private-token-issuer-directory",
  "/issue",
  "/token-key-for-user-token",
])

export class LiveCallerIDPIRContainer extends Container {
  defaultPort = 8080
  requiredPorts = [8080]
  sleepAfter = "5m"
}

function bytesToBase64(bytes) {
  let binary = ""
  for (const byte of bytes) {
    binary += String.fromCharCode(byte)
  }
  return btoa(binary)
}

function base64URLFromBytes(bytes) {
  return bytesToBase64(bytes).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "")
}

function base64URLFromString(value) {
  return base64URLFromBytes(new TextEncoder().encode(value))
}

function base64FromString(value) {
  return bytesToBase64(new TextEncoder().encode(value))
}

async function signTokenPayload(secret, signingInput) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  )
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(signingInput))
  return base64URLFromBytes(new Uint8Array(signature))
}

function jsonError(message, status) {
  return Response.json({ error: message }, { status })
}

function readRequiredString(body, key) {
  const value = body?.[key]
  return typeof value === "string" ? value.trim() : ""
}

async function handleLiveCallerIDToken(request, env) {
  if (request.method !== "POST") {
    return jsonError("method not allowed", 405)
  }

  const secret = env[USER_TOKEN_SIGNING_SECRET]
  if (!secret) {
    return jsonError("token issuer not configured", 503)
  }

  let body
  try {
    body = await request.json()
  } catch {
    return jsonError("invalid json", 400)
  }

  const installID = readRequiredString(body, "install_id")
  const bundleID = readRequiredString(body, "bundle_id")
  const extensionID = readRequiredString(body, "extension_id")
  if (!installID || installID.length > 128) {
    return jsonError("invalid install_id", 400)
  }
  if (bundleID !== EXPECTED_BUNDLE_ID || extensionID !== EXPECTED_EXTENSION_ID) {
    return jsonError("invalid app identity", 403)
  }

  const issuedAt = Math.floor(Date.now() / 1000)
  const expiresAt = issuedAt + TOKEN_TTL_SECONDS
  const payload = {
    v: 1,
    tier: TOKEN_TIER,
    install_id: installID,
    bundle_id: bundleID,
    extension_id: extensionID,
    iat: issuedAt,
    exp: expiresAt,
  }
  const payloadSegment = base64URLFromString(JSON.stringify(payload))
  const signingInput = `v1.${payloadSegment}`
  const signatureSegment = await signTokenPayload(secret, signingInput)
  const token = `${signingInput}.${signatureSegment}`

  return Response.json({
    token_base64: base64FromString(token),
    expires_at: new Date(expiresAt * 1000).toISOString(),
    tier: TOKEN_TIER,
  })
}

function containerStartOptions(env) {
  const secret = env[USER_TOKEN_SIGNING_SECRET]
  return secret
    ? {
        envVars: {
          [USER_TOKEN_SIGNING_SECRET]: secret,
        },
      }
    : undefined
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url)

    if (url.pathname === "/" || url.pathname === "/health") {
      return Response.json({
        ok: true,
        service: "callshield-live-caller-id-pir",
      })
    }

    if (url.pathname === LIVE_CALLER_ID_TOKEN_PATH) {
      return handleLiveCallerIDToken(request, env)
    }

    if (!ALLOWED_PATHS.has(url.pathname)) {
      return Response.json({ error: "not found" }, { status: 404 })
    }

    const container = getContainer(env.LIVE_CALLER_ID_PIR, "primary")
    await container.startAndWaitForPorts({
      ports: 8080,
      cancellationOptions: {
        instanceGetTimeoutMS: 30_000,
        portReadyTimeoutMS: 120_000,
        waitInterval: 1_000,
      },
      startOptions: containerStartOptions(env),
    })
    return container.fetch(request)
  },
}
