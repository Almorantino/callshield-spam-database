import { Container, getContainer } from "@cloudflare/containers"

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

export default {
  async fetch(request, env) {
    const url = new URL(request.url)

    if (url.pathname === "/" || url.pathname === "/health") {
      return Response.json({
        ok: true,
        service: "callshield-live-caller-id-pir",
      })
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
    })
    return container.fetch(request)
  },
}
