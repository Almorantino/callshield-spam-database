const JSON_HEADERS = { "Content-Type": "application/json" }
const EXTERNAL_FETCH_TIMEOUT_MS = 1500
const OPENAI_FETCH_TIMEOUT_MS = 1500
const OPENAI_FETCH_TIMEOUT_MIN_MS = 500
const OPENAI_FETCH_TIMEOUT_MAX_MS = 2500
const APPLE_APP_SITE_ASSOCIATION = {
  messagefilter: {
    apps: [
      "65CU34K4S6.com.almorantino.callshield",
      "65CU34K4S6.com.almorantino.callshield.CallShieldMessageFilter",
    ],
  },
  classificationreport: {
    apps: [
      "65CU34K4S6.com.almorantino.callshield",
      "65CU34K4S6.com.almorantino.callshield.CallShieldReportingExtension",
    ],
  },
}

function jsonResponse(payload, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: JSON_HEADERS,
  })
}

function healthResponse() {
  return jsonResponse({
    ok: true,
    service: "callshield-report",
    worker_version: "v4",
  })
}

function appleAppSiteAssociationResponse() {
  return new Response(JSON.stringify(APPLE_APP_SITE_ASSOCIATION), {
    status: 200,
    headers: JSON_HEADERS,
  })
}

function liveCallerIDToken(env) {
  return String(env?.LIVE_CALLER_ID_TOKEN || "").trim() || "callshield-dev-token"
}

function normalizeNumber(value) {
  const digits = String(value || "").replace(/\D+/g, "")
  if (!digits) return ""
  if (digits.startsWith("33") && digits.length === 11) return digits
  if (digits.startsWith("0") && digits.length === 10) return `33${digits.slice(1)}`
  return digits
}

function extractPrefix(number) {
  if (!number) return ""
  return number.slice(0, 6)
}

function normalizeText(value) {
  return String(value || "")
    .replace(/\s+/g, " ")
    .trim()
}

function canonicalCategory(value) {
  const category = String(value || "unknown").trim().toLowerCase()
  if (["fraud", "scam", "arnaque", "fraude", "phishing"].includes(category)) return "fraud"
  if (["telemarketing", "demarchage", "démarchage"].includes(category)) return "telemarketing"
  if (["spam"].includes(category)) return "spam"
  if (["safe", "allow", "pas_spam"].includes(category)) return "safe"
  return "unknown"
}

function buildResponse(label, category, confidence) {
  return {
    match: true,
    label,
    category,
    confidence,
  }
}

function emptyResponse() {
  return {
    match: false,
    label: null,
    category: null,
    confidence: 0,
  }
}

function clampScore(value) {
  const score = Number(value)
  if (!Number.isFinite(score)) return 0
  return Math.max(0, Math.min(100, Math.round(score)))
}

function riskLevelFromScore(score) {
  if (score <= 24) return "low"
  if (score <= 49) return "medium"
  if (score <= 74) return "high"
  return "critical"
}

function actionFromScore(score, category = "unknown") {
  if (category === "fraud") {
    if (score <= 49) return "warn"
    return "block"
  }

  if (category === "spam") {
    return "warn"
  }

  if (category === "telemarketing") {
    return score >= 35 ? "warn" : "allow"
  }

  if (category === "unknown") {
    return score >= 35 ? "warn" : "allow"
  }

  return "allow"
}

function confidenceFromScore(score) {
  return Math.max(0.05, Math.min(0.99, Number((score / 100).toFixed(2))))
}

function uniqueReasonCodes(values) {
  return [...new Set((values || []).filter(Boolean))]
}

async function fetchWithTimeout(resource, options = {}, timeoutMs = EXTERNAL_FETCH_TIMEOUT_MS) {
  const controller = new AbortController()
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs)

  try {
    return await fetch(resource, {
      ...options,
      signal: controller.signal,
    })
  } finally {
    clearTimeout(timeoutId)
  }
}

function openAIFetchTimeoutMs(env) {
  const configured = Number(env?.OPENAI_FETCH_TIMEOUT_MS)
  if (!Number.isFinite(configured)) return OPENAI_FETCH_TIMEOUT_MS
  return Math.max(
    OPENAI_FETCH_TIMEOUT_MIN_MS,
    Math.min(OPENAI_FETCH_TIMEOUT_MAX_MS, Math.round(configured))
  )
}


function hasTrustedDomainMatch(domains = [], trustContext = null) {
  if (!trustContext) return false

  const normalizedDomains = [...new Set((domains || []).map(normalizeDomainValue).filter(Boolean))]
  if (normalizedDomains.length === 0) return false

  const matchedDomains = new Set(
    (Array.isArray(trustContext.matchedDomains) ? trustContext.matchedDomains : [])
      .map(normalizeDomainValue)
      .filter(Boolean)
  )
  const matchedRootDomains = new Set(
    (Array.isArray(trustContext.matchedRootDomains) ? trustContext.matchedRootDomains : [])
      .map(normalizeDomainValue)
      .filter(Boolean)
  )

  return normalizedDomains.some((domain) =>
    matchedDomains.has(domain) || matchedRootDomains.has(rootDomainFromHost(domain))
  )
}

function isDomainTrusted(domain, trustContext = null) {
  if (isDomainKnownFraud(domain, trustContext)) return false
  return hasTrustedDomainMatch([domain], trustContext)
}

function areDomainsTrusted(domains = [], trustContext = null) {
  const normalizedDomains = [...new Set((domains || []).map(normalizeDomainValue).filter(Boolean))]
  if (normalizedDomains.length === 0) return false
  return normalizedDomains.every((domain) => isDomainTrusted(domain, trustContext))
}

function normalizeBrandComparable(value) {
  return String(value || "")
    .toLowerCase()
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/[^a-z0-9]/g, "")
}

function parseOfficialDomains(value) {
  if (Array.isArray(value)) {
    return [...new Set(value.map(normalizeDomainValue).filter(Boolean))]
  }

  const raw = String(value || "").trim()
  if (!raw) return []

  let values = []
  if (raw.startsWith("[")) {
    try {
      const parsed = JSON.parse(raw)
      if (Array.isArray(parsed)) {
        values = parsed
      }
    } catch {
      values = raw
        .replace(/^\[/, "")
        .replace(/\]$/, "")
        .split(",")
    }
  } else {
    values = raw.split(",")
  }

  return [...new Set(values
    .map((item) => String(item || "").trim().replace(/^['"]|['"]$/g, ""))
    .map(normalizeDomainValue)
    .filter(Boolean))]
}

function buildBrandRegistryContext(rows = [], text = "") {
  const normalizedText = normalizeBrandComparable(text)
  const brands = []
  const mentionedBrands = []

  for (const row of rows || []) {
    const brandKey = String(row?.brand_key || "").trim().toLowerCase()
    const normalizedBrandKey = normalizeBrandComparable(brandKey)
    if (!brandKey || !normalizedBrandKey) continue

    const officialDomains = parseOfficialDomains(row?.official_domains)
    const officialRootDomains = [...new Set(officialDomains.map(rootDomainFromHost).filter(Boolean))]
    const brand = {
      brandKey,
      normalizedBrandKey,
      officialDomains,
      officialRootDomains,
    }
    brands.push(brand)

    if (normalizedText.includes(normalizedBrandKey)) {
      mentionedBrands.push(brand)
    }
  }

  return {
    hasData: brands.length > 0,
    brands,
    mentionedBrands,
    mentionedBrandKeys: mentionedBrands.map((brand) => brand.brandKey),
  }
}

function isBrandRegistryContextUsable(brandContext) {
  return Boolean(brandContext?.hasData && Array.isArray(brandContext.mentionedBrands))
}

function isDomainOfficialForBrand(domain, brand) {
  const normalizedDomain = normalizeDomainValue(domain)
  if (!normalizedDomain || !brand) return false

  const officialDomains = new Set((brand.officialDomains || []).map(normalizeDomainValue).filter(Boolean))
  const officialRootDomains = new Set((brand.officialRootDomains || []).map(normalizeDomainValue).filter(Boolean))
  const root = rootDomainFromHost(normalizedDomain)

  return officialDomains.has(normalizedDomain) || officialRootDomains.has(root)
}

function areDomainsOfficialForMentionedBrand(domains = [], brandContext = null) {
  if (!isBrandRegistryContextUsable(brandContext) || brandContext.mentionedBrands.length === 0) return false

  const normalizedDomains = [...new Set((domains || []).map(normalizeDomainValue).filter(Boolean))]
  if (normalizedDomains.length === 0) return false

  return normalizedDomains.every((domain) =>
    brandContext.mentionedBrands.some((brand) => isDomainOfficialForBrand(domain, brand))
  )
}

async function lookupBrandRegistry(env, text = "", domains = []) {
  const normalizedDomains = [...new Set((domains || []).map(normalizeDomainValue).filter(Boolean))]
  if (!env?.DB || normalizedDomains.length === 0) {
    return buildBrandRegistryContext([], text)
  }

  try {
    const rows = await env.DB.prepare(`
      SELECT brand_key, official_domains
      FROM brand_registry
    `).all()
    const results = Array.isArray(rows?.results) ? rows.results : []
    return buildBrandRegistryContext(results, text)
  } catch (error) {
    console.error("brand_registry_lookup_failed", error)
    return buildBrandRegistryContext([], text)
  }
}

function adjustHeuristicForOfficialBrandDomains(heuristic, domains = [], brandContext = null) {
  if (!areDomainsOfficialForMentionedBrand(domains, brandContext)) return heuristic

  const reasonCodes = Array.isArray(heuristic?.reasonCodes) ? heuristic.reasonCodes : []
  let score = Number(heuristic?.score || 0)
  let removedScore = 0
  const filteredReasons = reasonCodes.filter((code) => {
    if (code === "SPOOFING") {
      removedScore += 20
      return false
    }
    if (code === "BRAND_SPOOF") {
      removedScore += 35
      return false
    }
    return true
  })

  if (filteredReasons.length === reasonCodes.length) return heuristic

  return {
    score: clampScore(score - removedScore),
    reasonCodes: uniqueReasonCodes(filteredReasons),
  }
}

function analyzeBrandRegistrySpoof(text, domains = [], domainsTrusted = false, brandContext = null) {
  if (domainsTrusted || !isBrandRegistryContextUsable(brandContext) || brandContext.mentionedBrands.length === 0) {
    return { score: 0, reasons: [] }
  }

  const normalizedDomains = [...new Set((domains || []).map(normalizeDomainValue).filter(Boolean))]
  if (normalizedDomains.length === 0) return { score: 0, reasons: [] }

  const hasUnofficialBrandDomain = normalizedDomains.some((domain) =>
    !brandContext.mentionedBrands.some((brand) => isDomainOfficialForBrand(domain, brand))
  )

  if (!hasUnofficialBrandDomain) return { score: 0, reasons: [] }

  return { score: 35, reasons: ["BRAND_SPOOF"] }
}

function isDomainKnownFraud(domain, trustContext = null) {
  if (!trustContext) return false

  const normalizedDomain = normalizeDomainValue(domain)
  if (!normalizedDomain) return false

  const fraudDomains = new Set(
    (Array.isArray(trustContext.fraudDomains) ? trustContext.fraudDomains : [])
      .map(normalizeDomainValue)
      .filter(Boolean)
  )
  const fraudRootDomains = new Set(
    (Array.isArray(trustContext.fraudRootDomains) ? trustContext.fraudRootDomains : [])
      .map(normalizeDomainValue)
      .filter(Boolean)
  )

  return fraudDomains.has(normalizedDomain) || fraudRootDomains.has(rootDomainFromHost(normalizedDomain))
}

const DOMAIN_TOKEN_PATTERN = /\b(?:[a-z0-9-]+\.)+(?:fr|com|net|org|info|biz|eu|co|xyz|top|click|ru|cn|tk|ml|ga)\b(?:\/[^\s]*)?/gi

function containsUrl(text) {
  return /(https?:\/\/|www\.|\b(?:[a-z0-9-]+\.)+(?:fr|com|net|org|info|biz|eu|co|xyz|top|click|ru|cn|tk|ml|ga)\b)/i.test(text)
}

function containsShortener(text) {
  return /\b(bit\.ly|t\.co|tinyurl\.com|goo\.gl|ow\.ly|buff\.ly|cutt\.ly|tiny\.cc|rebrand\.ly)\b/i.test(text)
}

function containsUrgency(text) {
  return /\b(urgent|urgence|immédiatement|immediatement|dernier rappel|final notice|immédiat|immediat|sous 24h|sous 48h|action requise|compte suspendu|suspendu)\b/i.test(text)
}

function containsSpoofing(text, domains = [], domainsTrustedInput = null, brandContext = null) {
  const lower = String(text || "").toLowerCase()

  const domainsTrusted = domainsTrustedInput === true
  if (domainsTrusted) return false

  const actionPattern = /\b(confirmez?|validez?|v[ée]rifiez?|mettez?\s+[àa]\s+jour|paiement|payer|login|identifiant|mot de passe|code secret|iban|cb|carte bancaire|identit[ée]|informations?)\b/i
  const urgencyPattern = /\b(urgent|urgence|immédiatement|immediatement|dernier rappel|final notice|immédiat|immediat|sous 24h|sous 48h|action requise|compte suspendu|suspendu)\b/i

  const hasSuspiciousContext =
    actionPattern.test(lower) ||
    urgencyPattern.test(lower) ||
    /\b(colis|livraison|suivi)\b/i.test(lower)

  if (
    hasSuspiciousContext &&
    isBrandRegistryContextUsable(brandContext) &&
    brandContext.mentionedBrands.length > 0
  ) {
    return !areDomainsOfficialForMentionedBrand(domains, brandContext)
  }

  const knownBrands = ["amazon", "paypal", "google", "apple", "vinted", "laposte", "orange", "sfr", "free", "bouygues"]

  for (const brand of knownBrands) {
    if (!lower.includes(brand)) continue

    if (hasSuspiciousContext) {
      return true
    }
  }

  return false
}

function containsOTP(text) {
  const value = String(text || "")
  return /\b(code|otp)\b/i.test(value) ||
    (/\b(validation|vérification|verification|sécurité|securite)\b/i.test(value) && /\b\d{4,8}\b/.test(value))
}

function containsSuspiciousPattern(text) {
  return /[€$]\s*\d|\d\s*€|cliquez|cliquer|confirmez?|validez?|v[ée]rifiez?|mettre à jour|mettre a jour|amende|pénalité|penalite|sur votre compte|promo|promotion|offre|répondez stop|repondez stop|désinscrire|desinscrire|suspension|compte suspendu|identité|identite|informations?/i.test(text)
}


function isLikelyTrackingMessage(text) {
  return /\b(colis|livraison|suivi|tracking|expédié|expedie|acheminement)\b/i.test(text)
}

function isLikelyOtpOnly(text) {
  return /\b(code|otp|verification|vérification)\b/i.test(text)
    && !containsUrl(text)
    && !containsUrgency(text)
}

function isTrustedOtpUrlMessage(text, domains = [], trustContext = null) {
  if (!containsOTP(text) || !containsUrl(text)) return false
  if (containsShortener(text)) return false

  const messageDomains = domains?.length ? domains : collectMessageDomains(text)
  return areDomainsTrusted(messageDomains, trustContext)
}

function extractUrls(text) {
  const matches = String(text || "").match(/https?:\/\/[^\s]+|www\.[^\s]+|\b(?:[a-z0-9-]+\.)+(?:fr|com|net|org|info|biz|eu|co|xyz|top|click|ru|cn|tk|ml|ga)\b(?:\/[^\s]*)?/gi) || []
  const urlsByDomain = new Map()

  for (const match of matches) {
    const value = String(match || "").replace(/[),.;:!?]+$/g, "")
    const domain = extractDomain(value)
    if (!domain) continue
    if (!urlsByDomain.has(domain) || /^https?:\/\//i.test(value) || /^www\./i.test(value)) {
      urlsByDomain.set(domain, value)
    }
  }

  return [...urlsByDomain.values()]
}

function hasTooManyDashes(url) {
  return (url.match(/-/g) || []).length >= 3
}

function isIpUrl(url) {
  return /https?:\/\/\d{1,3}(\.\d{1,3}){3}/i.test(url)
}

function extractDomain(url) {
  try {
    const clean = String(url || "").replace(/^https?:\/\//i, "").replace(/^www\./i, "")
    return clean.split("/")[0].replace(/[),.;:!?]+$/g, "").toLowerCase()
  } catch {
    return ""
  }
}

function isHighRiskTLD(domain) {
  return /\.(xyz|top|click|info|biz|ru|cn|tk|ml|ga)$/i.test(domain)
}

function hasSuspiciousKeywords(domain) {
  return /(secure|login|verify|account|update|confirm|bank|wallet)/i.test(domain)
}

function looksLikeBrandSpoof(domain, text) {
  if (!domain) return false
  const brands = ["amazon", "paypal", "google", "apple", "vinted", "laposte"]
  for (const brand of brands) {
    if (text.includes(brand) && domain.includes(brand) === false) {
      if (domain.includes(brand.substring(0, 3))) return true
    }
  }
  return false
}

function analyzeUrls(text, trustContext = null) {
  const urls = extractUrls(text)
  if (!urls || urls.length === 0) {
    return { score: 0, reasons: [] }
  }

  let score = 0
  const reasons = []

  for (const url of urls) {
    const domain = extractDomain(url)
    if (!domain) continue

    const isTrusted = isDomainTrusted(domain, trustContext)
    if (isTrusted) continue

    if (isIpUrl(url)) {
      score += 40
      reasons.push("IP_URL")
    }

    if (hasTooManyDashes(url)) {
      score += 15
      reasons.push("DASH_DOMAIN")
    }

    if (isHighRiskTLD(domain)) {
      score += 25
      reasons.push("RISKY_TLD")
    }

    if (hasSuspiciousKeywords(domain)) {
      score += 15
      reasons.push("SUSPICIOUS_DOMAIN")
    }

    if (looksLikeBrandSpoof(domain, text)) {
      score += 35
      reasons.push("BRAND_SPOOF")
    }
  }

  return {
    score,
    reasons,
  }
}

function analyzeDomainReputation(domains = [], trustContext = null) {
  const normalizedDomains = [...new Set((domains || []).map(normalizeDomainValue).filter(Boolean))]
  if (normalizedDomains.length === 0) {
    return { score: 0, reasons: [] }
  }

  if (normalizedDomains.some((domain) => isDomainKnownFraud(domain, trustContext))) {
    return { score: 50, reasons: ["KNOWN_MALICIOUS_DOMAIN"] }
  }

  return { score: 0, reasons: [] }
}
function normalizeDomainValue(domain) {
  return String(domain || "")
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/^www\./, "")
    .replace(/\/.*$/, "")
}

function rootDomainFromHost(domain) {
  const value = normalizeDomainValue(domain)
  if (!value) return ""
  const parts = value.split(".").filter(Boolean)
  if (parts.length <= 2) return value
  return parts.slice(-2).join(".")
}

function normalizeBusinessNameValue(value) {
  return String(value || "")
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, " ")
    .trim()
    .replace(/\s+/g, " ")
}

function businessNameCandidatesFromMessage(text) {
  const normalized = normalizeBusinessNameValue(text)
  if (!normalized) return []

  const words = normalized
    .split(" ")
    .filter((word) => word.length >= 2 && !/^\d+$/.test(word))
    .slice(0, 60)
  const candidates = new Set()

  for (let start = 0; start < words.length; start += 1) {
    for (let size = 1; size <= 4 && start + size <= words.length; size += 1) {
      const phrase = words.slice(start, start + size).join(" ")
      if (phrase.length >= 3) candidates.add(phrase)
      const compact = phrase.replace(/\s+/g, "")
      if (compact.length >= 4) candidates.add(compact)
    }
  }

  return [...candidates].slice(0, 80)
}

function phoneNumberEvidenceCandidates(number) {
  const normalized = normalizeNumber(number)
  if (!normalized) return []
  return [...new Set([normalized, `+${normalized}`])]
}

async function lookupTrustedDomains(env, domains = []) {
  const normalizedDomains = [...new Set((domains || []).map(normalizeDomainValue).filter(Boolean))]
  if (normalizedDomains.length === 0) {
    return {
      matchedDomains: [],
      matchedRootDomains: [],
      brandKeys: [],
      fraudDomains: [],
      fraudRootDomains: [],
      maxTrustScore: 0,
      trustLevel: "low",
    }
  }

  try {
    const roots = [...new Set(normalizedDomains.map(rootDomainFromHost).filter(Boolean))]
    const domainPlaceholders = normalizedDomains.map(() => "?").join(",")
    const rootPlaceholders = roots.map(() => "?").join(",")

    const whereParts = []
    const bindValues = []

    if (normalizedDomains.length > 0) {
      whereParts.push(`domain IN (${domainPlaceholders})`)
      bindValues.push(...normalizedDomains)
    }

    if (roots.length > 0) {
      whereParts.push(`root_domain IN (${rootPlaceholders})`)
      bindValues.push(...roots)
    }

    const query = `
      SELECT domain, root_domain, brand_key, trust_score, trust_level, status
      FROM trusted_domains
      WHERE status IN ('active', 'fraud')
        AND (${whereParts.join(" OR ")})
    `

    const statement = env.DB.prepare(query).bind(...bindValues)
    const rows = await statement.all()
    const results = Array.isArray(rows?.results) ? rows.results : []

    const matchedDomains = []
    const matchedRootDomains = []
    const brandKeys = []
    const fraudDomains = []
    const fraudRootDomains = []
    let maxTrustScore = 0
    let trustLevel = "low"
    const trustedTrustLevels = new Set(["verified", "high"])

    for (const row of results) {
      const status = String(row?.status || "").toLowerCase()
      if (status === "fraud") {
        if (row?.domain) fraudDomains.push(String(row.domain))
        if (row?.root_domain) fraudRootDomains.push(String(row.root_domain))
        continue
      }

      const rowTrustScore = Number(row?.trust_score || 0)
      const rowTrustLevel = String(row?.trust_level || "").toLowerCase()
      if (rowTrustScore < 80 && !trustedTrustLevels.has(rowTrustLevel)) {
        continue
      }

      if (row?.domain) matchedDomains.push(String(row.domain))
      if (row?.root_domain) matchedRootDomains.push(String(row.root_domain))
      if (row?.brand_key) brandKeys.push(String(row.brand_key))
      if (rowTrustScore > maxTrustScore) {
        maxTrustScore = rowTrustScore
      }
      if (rowTrustLevel === "verified") {
        trustLevel = "verified"
      } else if (trustLevel !== "verified" && rowTrustLevel === "high") {
        trustLevel = "high"
      } else if (trustLevel === "low" && rowTrustLevel === "medium") {
        trustLevel = "medium"
      }
    }

    return {
      matchedDomains: [...new Set(matchedDomains)],
      matchedRootDomains: [...new Set(matchedRootDomains)],
      brandKeys: [...new Set(brandKeys)],
      fraudDomains: [...new Set(fraudDomains)],
      fraudRootDomains: [...new Set(fraudRootDomains)],
      maxTrustScore,
      trustLevel,
    }
  } catch (error) {
    console.error("trusted_domains_lookup_failed", error)
    return {
      matchedDomains: [],
      matchedRootDomains: [],
      brandKeys: [],
      fraudDomains: [],
      fraudRootDomains: [],
      maxTrustScore: 0,
      trustLevel: "low",
    }
  }
}

function isTransactionalLegitMessage(text) {
  return /\b(facture|prélevé|preleve|montant|échéance|echeance|relevé|releve|document disponible|colis expédié|colis expedie|suivi disponible|commande expédiée|commande expediee|commande|orders|livraison prévue|livraison prevue|paiement validé|paiement valide|activité validée|activite validee|rendez-vous confirmé|rendez-vous confirme|abonnement|confirmation)\b/i.test(
    String(text || "")
  )
}

async function checkDomainAgeRisk(env, text) {
  if (!env.DOMAIN_CHECK_API_KEY || !env.DOMAIN_API_USER) return { score: 0, reasons: [] }

  const urls = extractUrls(text)
  let score = 0
  const reasons = []

  for (const url of urls) {
    const host = extractDomain(url)
    if (!host) continue

    try {
      const res = await fetchWithTimeout("https://neutrinoapi.net/domain-lookup", {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "User-ID": env.DOMAIN_API_USER,
          "API-Key": env.DOMAIN_CHECK_API_KEY,
        },
        body: `host=${encodeURIComponent(host)}`,
      })

      if (!res.ok) continue

      const data = await res.json()
      const age = Number(data?.age || 0)

      if (age > 0 && age < 30) {
        score += 40
        reasons.push("NEW_DOMAIN")
      } else if (age >= 30 && age < 90) {
        score += 20
        reasons.push("RECENT_DOMAIN")
      }

      if (data?.nefarious === true) {
        score += 50
        reasons.push("KNOWN_MALICIOUS_DOMAIN")
      }
    } catch {}
  }

  return { score, reasons }
}

async function checkPhoneReputation(env, number) {
  if (!number) {
    return { score: 0, reasons: [] }
  }

  if (!env.REPUTATION_API_KEY) {
    return { score: 0, reasons: [] }
  }

  try {
    const res = await fetchWithTimeout("https://api-service.verirouteintel.io/api/v1/cnam", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${env.REPUTATION_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        phone_number: number,
        include_spam_check: true,
      }),
    })

    if (!res.ok) return { score: 0, reasons: [] }

    const data = await res.json()
    let score = 0
    const reasons = []

    if (data?.spam === true) {
      score += 50
      reasons.push("KNOWN_SPAM_NUMBER")
    }

    if (data?.fraud === true) {
      score += 70
      reasons.push("KNOWN_FRAUD_NUMBER")
    }

    if (typeof data?.reputation_score === "number") {
      if (data.reputation_score < 30) {
        score += 40
        reasons.push("BAD_REPUTATION")
      } else if (data.reputation_score < 60) {
        score += 20
        reasons.push("MEDIUM_REPUTATION")
      }
    }

    return { score, reasons }
  } catch {
    return { score: 0, reasons: [] }
  }
}

async function checkCarrierRisk(env, number) {
  if (!number) {
    return { score: 0, reasons: [] }
  }

  if (String(env?.CARRIER_LOOKUP_ENABLED || "").trim() !== "true") {
    return { score: 0, reasons: [] }
  }

  try {
    const res = await fetchWithTimeout(`https://messageproviderlookup.com/api?number=${encodeURIComponent(number)}`)
    if (!res.ok) return { score: 0, reasons: [] }

    const data = await res.json()

    let score = 0
    const reasons = []

    if (data?.spam === true) {
      score += 30
      reasons.push("CARRIER_FLAGGED_SPAM")
    }

    if (typeof data?.provider === "string" && data.provider.toLowerCase().includes("voip")) {
      score += 15
      reasons.push("VOIP_NUMBER")
    }

    return { score, reasons }
  } catch {
    return { score: 0, reasons: [] }
  }
}

async function fetchGlobalThreatGraph(env, number, normalizedMessage) {
  if (!env.THREAT_GRAPH_URL) {
    return { score: 0, reasons: [] }
  }

  try {
    const res = await fetchWithTimeout(env.THREAT_GRAPH_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${env.THREAT_GRAPH_KEY || ""}`,
      },
      body: JSON.stringify({
        number,
        message_hash: normalizedMessage,
      }),
    })

    if (!res.ok) return { score: 0, reasons: [] }

    const data = await res.json()
    let score = 0
    const reasons = []

    if (data?.is_global_scam === true) {
      score += 60
      reasons.push("GLOBAL_SCAM_DETECTED")
    }

    if (typeof data?.threat_score === "number") {
      if (data.threat_score > 80) {
        score += 50
        reasons.push("HIGH_THREAT_GRAPH")
      } else if (data.threat_score > 50) {
        score += 30
        reasons.push("MEDIUM_THREAT_GRAPH")
      }
    }

    return { score, reasons }
  } catch {
    return { score: 0, reasons: [] }
  }
}

async function buildLocalThreatGraph(env, number, normalizedMessage) {
  try {
    const row = await env.DB.prepare(`
      SELECT COUNT(*) as count
      FROM sms_analysis_dataset
      WHERE number_e164 = ?1
         OR normalized_message = ?2
    `)
      .bind(number, normalizedMessage)
      .first()

    const count = row?.count || 0
    let score = 0
    const reasons = []

    if (count > 30) {
      score += 35
      reasons.push("LOCAL_GRAPH_HIGH")
    } else if (count > 10) {
      score += 20
      reasons.push("LOCAL_GRAPH_MEDIUM")
    }

    return { score, reasons }
  } catch {
    return { score: 0, reasons: [] }
  }
}

function localThreatGraphFromCount(count) {
  const total = Number(count || 0)
  let score = 0
  const reasons = []

  if (total > 30) {
    score += 35
    reasons.push("LOCAL_GRAPH_HIGH")
  } else if (total > 10) {
    score += 20
    reasons.push("LOCAL_GRAPH_MEDIUM")
  }

  return { score, reasons }
}

async function analyzeLocalFrequencySignals(env, number, normalizedMessage) {
  try {
    const [numberRow, messageRow, feedbackRow, feedbackEventRow] = await Promise.all([
      number
        ? env.DB.prepare(`
          SELECT COUNT(*) as count
          FROM sms_analysis_dataset
          WHERE number_e164 = ?1
        `)
          .bind(number)
          .first()
        : Promise.resolve({ count: 0 }),
      env.DB.prepare(`
        SELECT COUNT(*) as count,
               COUNT(DISTINCT number_e164) as distinct_numbers
        FROM sms_analysis_dataset
        WHERE normalized_message = ?1
      `)
        .bind(normalizedMessage)
        .first(),
      number
        ? env.DB.prepare(`
          SELECT
            SUM(CASE WHEN user_feedback = 'confirmed_scam' THEN 1 ELSE 0 END) as scam_count,
            SUM(CASE WHEN user_feedback = 'confirmed_safe' THEN 1 ELSE 0 END) as safe_count
          FROM sms_analysis_dataset
          WHERE number_e164 = ?1
             OR normalized_message = ?2
        `)
          .bind(number, normalizedMessage)
          .first()
        : env.DB.prepare(`
          SELECT
            SUM(CASE WHEN user_feedback = 'confirmed_scam' THEN 1 ELSE 0 END) as scam_count,
            SUM(CASE WHEN user_feedback = 'confirmed_safe' THEN 1 ELSE 0 END) as safe_count
          FROM sms_analysis_dataset
          WHERE normalized_message = ?1
        `)
          .bind(normalizedMessage)
          .first(),
      number
        ? env.DB.prepare(`
          SELECT
            SUM(CASE WHEN primary_category = 'fraud' OR user_disposition = 'reported_scam' THEN 1 ELSE 0 END) as scam_count,
            SUM(CASE WHEN primary_category = 'safe' OR user_disposition = 'marked_safe' THEN 1 ELSE 0 END) as safe_count
          FROM feedback_events
          WHERE number_e164 = ?1
            AND validation_status = 'accepted'
        `)
          .bind(number)
          .first()
        : Promise.resolve({ scam_count: 0, safe_count: 0 }),
    ])

    const numberCount = Number(numberRow?.count || 0)
    const messageCount = Number(messageRow?.count || 0)
    const distinctNumbers = Number(messageRow?.distinct_numbers || 0)
    const scamCount = Number(feedbackRow?.scam_count || 0)
    const safeCount = Number(feedbackRow?.safe_count || 0)
    const feedbackEventScamCount = Number(feedbackEventRow?.scam_count || 0)
    const feedbackEventSafeCount = Number(feedbackEventRow?.safe_count || 0)
    const confirmedScamCount = Math.max(scamCount, feedbackEventScamCount)
    const confirmedSafeCount = Math.max(safeCount, feedbackEventSafeCount)

    let score = 0
    const reasons = []

    if (numberCount >= 3) {
      score += 10
      reasons.push("REPEAT_NUMBER")
    }
    if (numberCount >= 8) {
      score += 15
      reasons.push("HIGH_REPEAT_NUMBER")
    }

    if (messageCount >= 3) {
      score += 10
      reasons.push("REPEAT_MESSAGE")
    }
    if (messageCount >= 8) {
      score += 15
      reasons.push("HIGH_REPEAT_MESSAGE")
    }

    if (distinctNumbers >= 3) {
      score += 18
      reasons.push("MULTI_NUMBER_SAME_MESSAGE")
    }
    if (distinctNumbers >= 8) {
      score += 22
      reasons.push("CAMPAIGN_PATTERN_CONFIRMED")
    }

    if (confirmedScamCount >= 2 && confirmedScamCount > confirmedSafeCount) {
      score += 30
      reasons.push("USER_CONFIRMED_SCAM")
    }

    if (confirmedSafeCount >= 2 && confirmedSafeCount > confirmedScamCount) {
      score -= 25
      reasons.push("USER_CONFIRMED_SAFE")
    }

    return { score, reasons, numberCount, messageCount, distinctNumbers }
  } catch {
    return { score: 0, reasons: [], numberCount: 0, messageCount: 0, distinctNumbers: 0 }
  }
}

async function analyzeFeedbackEntitySignals(env, domains = []) {
  const normalizedDomains = [...new Set((domains || []).map(normalizeDomainValue).filter(Boolean))]
  if (!env?.DB || normalizedDomains.length === 0) {
    return { score: 0, reasons: [] }
  }

  try {
    const roots = [...new Set(normalizedDomains.map(rootDomainFromHost).filter(Boolean))]
    const whereParts = []
    const bindValues = []

    if (normalizedDomains.length > 0) {
      whereParts.push(`(entity_type = 'domain' AND entity_value IN (${normalizedDomains.map(() => "?").join(",")}))`)
      bindValues.push(...normalizedDomains)
    }

    if (roots.length > 0) {
      whereParts.push(`(entity_type = 'root_domain' AND entity_value IN (${roots.map(() => "?").join(",")}))`)
      bindValues.push(...roots)
    }

    if (whereParts.length === 0) return { score: 0, reasons: [] }

    const rows = await env.DB.prepare(`
      SELECT
        fraud_count,
        spam_count,
        telemarketing_count,
        safe_count,
        source_count,
        controversy_score
      FROM feedback_entity_aggregates
      WHERE ${whereParts.join(" OR ")}
    `)
      .bind(...bindValues)
      .all()

    const results = Array.isArray(rows?.results) ? rows.results : []
    let fraudCount = 0
    let spamCount = 0
    let telemarketingCount = 0
    let safeCount = 0
    let sourceCount = 0
    let controversyScore = 0

    for (const row of results) {
      fraudCount = Math.max(fraudCount, Number(row?.fraud_count || 0))
      spamCount = Math.max(spamCount, Number(row?.spam_count || 0))
      telemarketingCount = Math.max(telemarketingCount, Number(row?.telemarketing_count || 0))
      safeCount = Math.max(safeCount, Number(row?.safe_count || 0))
      sourceCount = Math.max(sourceCount, Number(row?.source_count || 0))
      controversyScore = Math.max(controversyScore, Number(row?.controversy_score || 0))
    }

    const positiveCount = fraudCount + spamCount + telemarketingCount
    if (fraudCount >= 2 && safeCount === 0 && controversyScore === 0) {
      return { score: 20, reasons: ["USER_CONFIRMED_SCAM"] }
    }

    if (safeCount >= 2 && positiveCount === 0 && sourceCount >= 2) {
      return { score: -25, reasons: ["USER_CONFIRMED_SAFE"] }
    }

    return { score: 0, reasons: [] }
  } catch (error) {
    console.error("feedback_entity_aggregate_lookup_failed", error)
    return { score: 0, reasons: [] }
  }
}

async function analyzeFeedbackNumberSignals(env, number = "") {
  const normalizedNumber = normalizeNumber(number)
  if (!env?.DB || !normalizedNumber) {
    return { score: 0, reasons: [] }
  }

  try {
    const rows = await env.DB.prepare(`
      SELECT
        fraud_count,
        spam_count,
        telemarketing_count,
        safe_count,
        source_count,
        controversy_score
      FROM feedback_entity_aggregates
      WHERE entity_type = 'number'
        AND entity_value = ?1
    `)
      .bind(normalizedNumber)
      .all()

    const results = Array.isArray(rows?.results) ? rows.results : []
    let fraudCount = 0
    let spamCount = 0
    let telemarketingCount = 0
    let safeCount = 0
    let sourceCount = 0
    let controversyScore = 0

    for (const row of results) {
      fraudCount = Math.max(fraudCount, Number(row?.fraud_count || 0))
      spamCount = Math.max(spamCount, Number(row?.spam_count || 0))
      telemarketingCount = Math.max(telemarketingCount, Number(row?.telemarketing_count || 0))
      safeCount = Math.max(safeCount, Number(row?.safe_count || 0))
      sourceCount = Math.max(sourceCount, Number(row?.source_count || 0))
      controversyScore = Math.max(controversyScore, Number(row?.controversy_score || 0))
    }

    const positiveCount = fraudCount + spamCount + telemarketingCount
    if (fraudCount >= 2 && safeCount === 0 && controversyScore === 0) {
      return { score: 20, reasons: ["USER_CONFIRMED_SCAM"] }
    }

    if (spamCount + telemarketingCount >= 3 && safeCount === 0 && controversyScore === 0) {
      return { score: 15, reasons: ["KNOWN_SPAM_NUMBER"] }
    }

    if (safeCount >= 2 && positiveCount === 0 && sourceCount >= 2) {
      return { score: -25, reasons: ["USER_CONFIRMED_SAFE"] }
    }

    return { score: 0, reasons: [] }
  } catch (error) {
    console.error("feedback_number_aggregate_lookup_failed", error)
    return { score: 0, reasons: [] }
  }
}

async function analyzeLiveLookupNumberSignals(env, number = "") {
  const normalizedNumber = normalizeNumber(number)
  if (!env?.DB || !normalizedNumber) {
    return { score: 0, reasons: [] }
  }

  try {
    const row = await env.DB.prepare(`
      SELECT category, confidence, risk_level
      FROM live_lookup
      WHERE number_e164 = ?1
      LIMIT 1
    `)
      .bind(normalizedNumber)
      .first()

    if (!row) return { score: 0, reasons: [] }

    const category = canonicalCategory(row.category)
    const riskLevel = Number(row.risk_level || 0)
    const confidence = Number(row.confidence || 0)
    const hasUsableConfidence = confidence <= 0 || confidence >= 0.7

    if (category === "fraud" && riskLevel >= 70 && hasUsableConfidence) {
      return { score: 35, reasons: ["KNOWN_FRAUD_NUMBER"] }
    }

    if (category === "spam" && riskLevel >= 60 && hasUsableConfidence) {
      return { score: 35, reasons: ["KNOWN_SPAM_NUMBER"] }
    }

    if (category === "telemarketing" && riskLevel >= 60 && hasUsableConfidence) {
      return { score: 35, reasons: ["TELEMARKETING_PATTERN"] }
    }

    return { score: 0, reasons: [] }
  } catch (error) {
    console.error("live_lookup_number_signal_failed", error)
    return { score: 0, reasons: [] }
  }
}

async function analyzeExternalUrlEvidenceSignals(env, domains = []) {
  const normalizedDomains = [...new Set((domains || []).map(normalizeDomainValue).filter(Boolean))].slice(0, 10)
  if (!env?.DB || normalizedDomains.length === 0) {
    return { score: 0, reasons: [] }
  }

  try {
    const roots = [...new Set(normalizedDomains.map(rootDomainFromHost).filter(Boolean))].slice(0, 10)
    const whereParts = []
    const bindValues = []

    if (normalizedDomains.length > 0) {
      whereParts.push(`(entity_type = 'domain' AND entity_value IN (${normalizedDomains.map(() => "?").join(",")}))`)
      bindValues.push(...normalizedDomains)
    }

    if (roots.length > 0) {
      whereParts.push(`(entity_type = 'root_domain' AND entity_value IN (${roots.map(() => "?").join(",")}))`)
      bindValues.push(...roots)
    }

    if (whereParts.length === 0) return { score: 0, reasons: [] }

    const rows = await env.DB.prepare(`
      SELECT
        entity_type,
        entity_value,
        phishing_count,
        malware_count,
        smishing_count,
        official_ioc_count,
        source_count,
        evidence_count,
        max_confidence
      FROM external_url_evidence_aggregates
      WHERE ${whereParts.join(" OR ")}
    `)
      .bind(...bindValues)
      .all()

    const results = Array.isArray(rows?.results) ? rows.results : []
    let score = 0

    for (const row of results) {
      const entityType = String(row?.entity_type || "")
      const phishingCount = Number(row?.phishing_count || 0)
      const malwareCount = Number(row?.malware_count || 0)
      const smishingCount = Number(row?.smishing_count || 0)
      const officialIocCount = Number(row?.official_ioc_count || 0)
      const sourceCount = Number(row?.source_count || 0)
      const evidenceCount = Number(row?.evidence_count || 0)
      const maxConfidence = Number(row?.max_confidence || 0)
      const riskCount = phishingCount + malwareCount + smishingCount + officialIocCount
      if (riskCount <= 0) continue

      if (entityType === "domain") {
        if ((malwareCount > 0 || officialIocCount > 0) && maxConfidence >= 0.7) {
          score = Math.max(score, 15)
        } else if (sourceCount >= 2 && maxConfidence >= 0.6) {
          score = Math.max(score, 15)
        } else if (smishingCount > 0 && evidenceCount >= 2) {
          score = Math.max(score, 10)
        } else if (maxConfidence >= 0.55) {
          score = Math.max(score, 5)
        }
      } else if (
        entityType === "root_domain" &&
        evidenceCount >= 3 &&
        riskCount >= 3 &&
        maxConfidence >= 0.55
      ) {
        score = Math.max(score, 5)
      }
    }

    return score > 0
      ? { score, reasons: ["BAD_REPUTATION"] }
      : { score: 0, reasons: [] }
  } catch (error) {
    console.error("external_url_evidence_lookup_failed", error)
    return { score: 0, reasons: [] }
  }
}

function hasBusinessReputationScenario(text) {
  return /\b(assurance|mutuelle|sant[ée]|energie|énergie|electricit[ée]|gaz|prime|remboursement|aide|ch[èe]que|contrat|abonnement|mensualit[ée]|pr[ée]l[èe]vement|sepa|iban|rib|coordonn[ée]es bancaires|d[ée]marchage|conseiller|vente directe|rappel commercial|fournisseur|[ée]conomiseur|economiseur)\b/i.test(
    String(text || "")
  )
}

async function analyzeBusinessReputationSignals(env, domains = [], number = "", message = "") {
  if (!env?.DB || !hasBusinessReputationScenario(message)) {
    return { score: 0, reasons: [] }
  }

  const normalizedDomains = [...new Set((domains || []).map(normalizeDomainValue).filter(Boolean))].slice(0, 10)
  const roots = [...new Set(normalizedDomains.map(rootDomainFromHost).filter(Boolean))].slice(0, 10)
  const phoneNumbers = phoneNumberEvidenceCandidates(number).slice(0, 4)
  const companyNameCandidates = businessNameCandidatesFromMessage(message)

  if (
    normalizedDomains.length === 0 &&
    roots.length === 0 &&
    phoneNumbers.length === 0 &&
    companyNameCandidates.length === 0
  ) {
    return { score: 0, reasons: [] }
  }

  try {
    const whereParts = []
    const bindValues = []

    if (normalizedDomains.length > 0) {
      whereParts.push(`(entity_type = 'domain' AND entity_value IN (${normalizedDomains.map(() => "?").join(",")}))`)
      bindValues.push(...normalizedDomains)
    }

    if (roots.length > 0) {
      whereParts.push(`(entity_type = 'root_domain' AND entity_value IN (${roots.map(() => "?").join(",")}))`)
      bindValues.push(...roots)
    }

    if (phoneNumbers.length > 0) {
      whereParts.push(`(entity_type = 'phone_number' AND entity_value IN (${phoneNumbers.map(() => "?").join(",")}))`)
      bindValues.push(...phoneNumbers)
    }

    if (companyNameCandidates.length > 0) {
      whereParts.push(`(entity_type = 'company_name' AND entity_value IN (${companyNameCandidates.map(() => "?").join(",")}))`)
      bindValues.push(...companyNameCandidates)
    }

    if (whereParts.length === 0) return { score: 0, reasons: [] }

    const rows = await env.DB.prepare(`
      SELECT
        entity_type,
        status,
        consumer_evidence_count,
        contested_evidence_count,
        max_confidence
      FROM business_reputation_evidence_aggregates
      WHERE ${whereParts.join(" OR ")}
    `)
      .bind(...bindValues)
      .all()

    const results = Array.isArray(rows?.results) ? rows.results : []
    let score = 0

    for (const row of results) {
      const status = String(row?.status || "").toLowerCase()
      if (status !== "evidence_confirmed") continue

      const entityType = String(row?.entity_type || "")
      const consumerEvidenceCount = Number(row?.consumer_evidence_count || 0)
      const contestedEvidenceCount = Number(row?.contested_evidence_count || 0)
      const maxConfidence = Number(row?.max_confidence || 0)
      if (consumerEvidenceCount <= 0 || maxConfidence < 0.6) continue

      let rowScore = 0
      if (entityType === "phone_number" && consumerEvidenceCount >= 1) {
        rowScore = 15
      } else if (
        ["domain", "root_domain", "company", "company_name"].includes(entityType) &&
        consumerEvidenceCount >= 2
      ) {
        rowScore = 20
      }

      if (contestedEvidenceCount >= consumerEvidenceCount) {
        rowScore = Math.min(rowScore, 10)
      }

      score = Math.max(score, rowScore)
    }

    return score > 0
      ? { score: Math.min(score, 20), reasons: ["KNOWN_BAD_ACTOR"] }
      : { score: 0, reasons: [] }
  } catch (error) {
    console.error("business_reputation_lookup_failed", error)
    return { score: 0, reasons: [] }
  }
}

function suppressSafeFeedbackEntityForCriticalReasons(signal, reasonCodes = []) {
  const reasons = Array.isArray(signal?.reasons) ? signal.reasons : []
  if (!reasons.includes("USER_CONFIRMED_SAFE")) return signal || { score: 0, reasons: [] }
  if (!hasFraudCriticalReason(reasonCodes)) return signal

  return { score: 0, reasons: [] }
}

function correlateSignals(signals) {
  let score = 0
  const reasons = []

  const {
    hasUrl,
    spoof,
    urgency,
    cluster,
    reputation,
  } = signals

  if (hasUrl && spoof && urgency) {
    score += 40
    reasons.push("STRONG_CORRELATED_SCAM")
  }

  if (cluster && hasUrl) {
    score += 30
    reasons.push("CAMPAIGN_WITH_LINK")
  }

  if (reputation && spoof) {
    score += 35
    reasons.push("KNOWN_BAD_ACTOR")
  }

  return { score, reasons }
}

function analyzeMessagePatterns(text) {
  let score = 0
  const reasons = []

  if (/\b(gagne|gratuit|offert|récompense|reward|bonus|0\.?01|€0)/i.test(text)) {
    score += 20
    reasons.push("MONEY_TRAP")
  }

  if (/\b(cliquez|click|accédez|voir ici|lien ci-dessous)\b/i.test(text)) {
    score += 15
    reasons.push("CLICK_INCITATION")
  }

  if (/\b(service client|support|assistance|centre sécurité|security team)\b/i.test(text)) {
    score += 20
    reasons.push("FAKE_AUTHORITY")
  }

  if (/\b(amende|pénalité|paiement requis|frais|taxe)\b/i.test(text)) {
    score += 25
    reasons.push("PAYMENT_PRESSURE")
  }

  if (/\b(compte suspendu|bloqué|désactivé|limité)\b/i.test(text)) {
    score += 25
    reasons.push("ACCOUNT_THREAT")
  }

  if (/\b(colis bloqué|frais de livraison|livraison échouée|reprogrammer)\b/i.test(text)) {
    score += 30
    reasons.push("DELIVERY_SCAM")
  }

  if (/\b(job|emploi|recrutement|gagnez \d+€\/jour)\b/i.test(text)) {
    score += 25
    reasons.push("JOB_SCAM")
  }

  return { score, reasons }
}

function analyzeStructure(text) {
  let score = 0
  const reasons = []

  if (text.length < 60 && containsUrl(text)) {
    score += 20
    reasons.push("SHORT_WITH_LINK")
  }

  if ((text.match(/\d/g) || []).length > 6) {
    score += 10
    reasons.push("NUMERIC_HEAVY")
  }

  if (text === text.toLowerCase() && text.length > 20) {
    score += 5
    reasons.push("LOW_QUALITY_TEXT")
  }

  return { score, reasons }
}

function collectMessageDomains(text) {
  const urls = extractUrls(text)
  const domainsFromUrls = urls.map((url) => extractDomain(url)).filter(Boolean)
  const nakedDomains = (String(text || "").match(DOMAIN_TOKEN_PATTERN) || [])
    .map((value) => extractDomain(value))
    .filter(Boolean)

  return [...new Set([...domainsFromUrls, ...nakedDomains])]
}

function hasIdentityRequest(text) {
  return /\b(confirmez?|validez?|v[ée]rifiez?|v[ée]rifi[ée]e|verifiee|mettez?\s+[àa]\s+jour|mise\s+[àa]\s+jour|renseignez|compl[ée]tez|compl[ée]t[ée]e|completee|requise?|doit\s+[eê]tre|doit\s+etre)\b/i.test(text)
    && /\b(informations?|identit[ée]|compte|profil|acc[eè]s|coordonn[ée]es|paiement|iban|cb|carte bancaire|mot de passe|password|identifiant|login)\b/i.test(text)
}

function requiresAIReviewForLowScore(message, reasonCodes = []) {
  const reasons = Array.isArray(reasonCodes) ? reasonCodes : []
  return hasIdentityRequest(message) ||
    hasAccountThreat(message) ||
    reasons.some((code) => [
      "DELIVERY_SCAM",
      "PAYMENT_PRESSURE",
      "ACCOUNT_THREAT",
      "PHISHING_INTENT",
      "FAKE_AUTHORITY",
      "JOB_SCAM",
      "KNOWN_SPAM_NUMBER",
      "KNOWN_BAD_ACTOR",
      "USER_CONFIRMED_SCAM",
    ].includes(code))
}

function hasAccountThreat(text) {
  return /\b(suspension|suspendu|bloqu[ée]|d[ée]sactiv[ée]|limit[ée]|restriction|restreint)\b/i.test(text)
}

function hasTelemarketingContent(text) {
  return /\b(offre|promo|promotion|gratuit|rappel|0800|devis|contactez[- ]nous|rappelez[- ]nous|service commercial|conseiller|internet|fibre|mobile|forfait|assurance|energie|énergie|travaux|isolation|solaire)\b/i.test(text)
}

function hasFraudCriticalReason(reasonCodes = []) {
  return [
    "OTP_SCAM",
    "IP_URL",
    "BRAND_SPOOF",
    "KNOWN_MALICIOUS_DOMAIN",
    "RISKY_TLD",
    "SUSPICIOUS_DOMAIN",
    "KNOWN_FRAUD_NUMBER",
    "GLOBAL_SCAM_DETECTED",
    "STRONG_CORRELATED_SCAM",
    "FAKE_TRACKING_LINK",
  ].some((code) => reasonCodes.includes(code))
}


function filterDatasetReasonsForTrusted(reasonCodes = []) {
  const blocked = new Set([
    "REPEAT_NUMBER",
    "HIGH_REPEAT_NUMBER",
    "REPEAT_MESSAGE",
    "HIGH_REPEAT_MESSAGE",
    "MULTI_NUMBER_SAME_MESSAGE",
    "CAMPAIGN_PATTERN_CONFIRMED",
    "SPREAD_CAMPAIGN",
    "MULTI_NUMBER_CAMPAIGN",
    "LOCAL_GRAPH_HIGH",
    "LOCAL_GRAPH_MEDIUM",
    "CLUSTER_HIGH_RISK",
    "CLUSTER_MEDIUM_RISK",
    "CLUSTER_LOW_RISK",
    "CAMPAIGN_WITH_LINK",
  ])

  return reasonCodes.filter((code) => !blocked.has(code))
}

function runHeuristic(message) {
  const text = normalizeText(message).toLowerCase()
  let score = 0
  const reasonCodes = []

  const domains = collectMessageDomains(text)
  const trustContext = null
  const domainsTrusted = areDomainsTrusted(domains, trustContext)

  const hasUrl = containsUrl(text)
  const hasUrgency = containsUrgency(text)
  const hasSpoof = containsSpoofing(text, domains, domainsTrusted)
  const hasShortener = containsShortener(text)
  const hasPattern = containsSuspiciousPattern(text)
  const hasPhishingKeywords = /\b(confirmer|valider|vérifier|verification|vérification|informations|identité|identite)\b/i.test(text)
  const hasAccountKeywords = /\b(suspension|suspendu|bloqué|bloque|désactivé|desactive|limité|limite|éviter la suspension)\b/i.test(text)
  const hasTelemarketing = /\b(offre|promo|gratuit|rappel|0800)\b/i.test(text)

  // const legitService = domainsTrusted
  const tracking = isLikelyTrackingMessage(text)
  const hasOTP = containsOTP(text)
  const otpOnly = hasOTP && !hasUrl && !hasUrgency

  if (hasUrl) {
    if (domainsTrusted) {
      score -= 5
      reasonCodes.push("URL_TRUSTED")
    } else {
      score += 30
      reasonCodes.push("URL")
    }
  }

    if (hasUrgency) {
    score += 25
    reasonCodes.push("URGENCY")
  }

  if (
    hasUrgency &&
    hasPhishingKeywords
  ) {
    score += 40
    reasonCodes.push("PHISHING_INTENT")
  }

  if (
    hasPhishingKeywords &&
    hasAccountKeywords
  ) {
    score += 45
    reasonCodes.push("PHISHING_INTENT")
  }

  if (
    hasAccountKeywords &&
    (hasUrgency || hasPhishingKeywords)
  ) {
    score += 35
    reasonCodes.push("ACCOUNT_THREAT")
  }

  if (hasSpoof) {
    score += 20
    reasonCodes.push("SPOOFING")
  }


  if (hasShortener) {
    score += 15
    reasonCodes.push("SHORTENER")
  }

  if (hasPattern) {
    score += 10
    reasonCodes.push("SUSPICIOUS_PATTERN")
  }

  if (hasTelemarketing) {
    score += 25
    reasonCodes.push("TELEMARKETING_PATTERN")
  }

  if (hasOTP && hasUrl) {
    score = Math.max(score, 95)
    reasonCodes.push("OTP_SCAM")
  }

  if (!domainsTrusted) {
    const urlAnalysis = analyzeUrls(text, trustContext)
    if (urlAnalysis.score > 0) {
      score += urlAnalysis.score
      reasonCodes.push(...urlAnalysis.reasons)
    }
  }

  const patternAnalysis = analyzeMessagePatterns(text)
  score += patternAnalysis.score
  reasonCodes.push(...patternAnalysis.reasons)

  const structureAnalysis = analyzeStructure(text)
  score += structureAnalysis.score
  reasonCodes.push(...structureAnalysis.reasons)

  if (domainsTrusted && !hasUrl && !hasUrgency) {
    score -= 30
  }

  if (tracking && domainsTrusted && score < 40) {
    score -= 20
  }

  if (tracking && hasUrl && domainsTrusted && !hasShortener && !hasUrgency) {
    score = Math.max(0, score - 25)
    reasonCodes.push("LEGIT_TRACKING_PATTERN")
  }

  if (otpOnly) {
    score = Math.max(0, score - 40)
    reasonCodes.push("OTP_ONLY")
  }

  score = clampScore(score)

  return {
    score,
    reasonCodes: uniqueReasonCodes(reasonCodes),
  }
}

function hardRuleDecision(message, precomputedDomains = null, precomputedTrustContext = null) {
  const text = normalizeText(message).toLowerCase()
  const hasUrl = containsUrl(text)
  const hasOTP = containsOTP(text)
  const trustedOtpUrl = isTrustedOtpUrlMessage(text, precomputedDomains, precomputedTrustContext)

  if (hasOTP && hasUrl && !trustedOtpUrl) {
    return {
      matched: true,
      score: 95,
      category: "fraud",
      decision_source: "heuristic",
      reason_codes: ["OTP_SCAM", "URL"],
      explanation: "Code de validation avec lien détecté.",
    }
  }

  return { matched: false }
}

async function sha256Hex(input) {
  const data = new TextEncoder().encode(String(input || ""))
  const digest = await crypto.subtle.digest("SHA-256", data)
  const bytes = [...new Uint8Array(digest)]
  return bytes.map((b) => b.toString(16).padStart(2, "0")).join("")
}

async function lookupLive(env, number) {
  const row = await env.DB.prepare(`
    SELECT label, category, confidence
    FROM live_lookup
    WHERE number_e164 = ?1
    LIMIT 1
  `)
    .bind(number)
    .first()

  if (!row) return null

  return buildResponse(
    row.label,
    canonicalCategory(row.category),
    row.confidence || 0.9
  )
}

async function fallbackFeedback(env, number) {
  const row = await env.DB.prepare(`
    SELECT primary_category
    FROM feedback_events
    WHERE number_e164 = ?1
    ORDER BY created_at DESC
    LIMIT 1
  `)
    .bind(number)
    .first()

  if (!row) return null

  const category = canonicalCategory(row.primary_category)

  if (category === "fraud") return buildResponse("Fraude probable", "fraud", 0.95)
  if (category === "spam") return buildResponse("Spam probable", "spam", 0.9)
  if (category === "telemarketing") return buildResponse("Démarchage probable", "telemarketing", 0.85)

  return null
}

async function fallbackReports(env, number) {
  try {
    const smsReportColumns = await getTableColumns(env, "sms_reports")
    if (!smsReportColumns.has("category")) return null

    const row = await env.DB.prepare(`
      SELECT category
      FROM sms_reports
      WHERE number_e164 = ?1
      ORDER BY created_at DESC
      LIMIT 1
    `)
      .bind(number)
      .first()

    if (!row) return null

    const category = canonicalCategory(row.category)

    if (category === "fraud") return buildResponse("Fraude probable", "fraud", 0.9)
    if (category === "spam") return buildResponse("Spam probable", "spam", 0.85)
    if (category === "telemarketing") return buildResponse("Démarchage probable", "telemarketing", 0.8)
  } catch (error) {
    console.error("fallback_reports_lookup_failed", error)
  }

  return null
}

async function analyzeNumberCluster(env, number) {
  if (!number) return { score: 0, reasons: [] }

  const prefix = extractPrefix(number)

  try {
    const row = await env.DB.prepare(`
      SELECT COUNT(*) as count
      FROM sms_analysis_dataset
      WHERE number_e164 LIKE ?1
    `)
      .bind(`${prefix}%`)
      .first()

    const count = row?.count || 0
    let score = 0
    const reasons = []

    if (count > 50) {
      score += 40
      reasons.push("CLUSTER_HIGH_RISK")
    } else if (count > 20) {
      score += 25
      reasons.push("CLUSTER_MEDIUM_RISK")
    } else if (count > 10) {
      score += 15
      reasons.push("CLUSTER_LOW_RISK")
    }

    if (count > 50 && count < 200) {
      score -= 10
    }

    return { score, reasons }
  } catch {
    return { score: 0, reasons: [] }
  }
}

function campaignPatternFromDistinctNumbers(distinctNumbers) {
  const unique = Number(distinctNumbers || 0)
  let score = 0
  const reasons = []

  if (unique > 20) {
    score += 40
    reasons.push("MULTI_NUMBER_CAMPAIGN")
  } else if (unique > 10) {
    score += 25
    reasons.push("SPREAD_CAMPAIGN")
  }

  return { score, reasons }
}

async function analyzeCampaignPattern(env, normalizedMessage) {
  try {
    const row = await env.DB.prepare(`
      SELECT COUNT(DISTINCT number_e164) as unique_numbers
      FROM sms_analysis_dataset
      WHERE normalized_message = ?1
    `)
      .bind(normalizedMessage)
      .first()

    return campaignPatternFromDistinctNumbers(row?.unique_numbers)
  } catch {
    return { score: 0, reasons: [] }
  }
}

function compactAIAnalysisContext(context = null) {
  if (!context || typeof context !== "object" || Array.isArray(context)) return null

  const signals = context.signals && typeof context.signals === "object" && !Array.isArray(context.signals)
    ? context.signals
    : {}

  return {
    heuristic_score: clampScore(context.heuristic_score),
    reason_codes: uniqueReasonCodes(Array.isArray(context.reason_codes) ? context.reason_codes : []).slice(0, 20),
    domains: uniqueReasonCodes(Array.isArray(context.domains) ? context.domains.map(normalizeDomainValue).filter(Boolean) : []).slice(0, 10),
    trusted_domains: uniqueReasonCodes(Array.isArray(context.trusted_domains) ? context.trusted_domains.map(normalizeDomainValue).filter(Boolean) : []).slice(0, 10),
    trust_level: String(context.trust_level || "low").trim().toLowerCase() || "low",
    signals: {
      has_url: Boolean(signals.has_url),
      has_urgency: Boolean(signals.has_urgency),
      has_shortener: Boolean(signals.has_shortener),
      has_spoof: Boolean(signals.has_spoof),
      has_identity: Boolean(signals.has_identity),
      has_account_threat: Boolean(signals.has_account_threat),
      has_telemarketing: Boolean(signals.has_telemarketing),
    },
  }
}

const AI_FRAUD_REASON_CODES = new Set([
  "OTP_SCAM",
  "BRAND_SPOOF",
  "PHISHING_INTENT",
  "PAYMENT_PRESSURE",
  "ACCOUNT_THREAT",
  "FAKE_AUTHORITY",
  "FAKE_TRACKING_LINK",
  "JOB_SCAM",
  "KNOWN_MALICIOUS_DOMAIN",
  "RISKY_TLD",
  "SUSPICIOUS_DOMAIN",
  "IP_URL",
])

function hasAIFraudReason(reasonCodes = []) {
  return Array.isArray(reasonCodes) && reasonCodes.some((code) => AI_FRAUD_REASON_CODES.has(code))
}

function normalizeOpenAIAnalysisResult(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null

  const reason_codes = uniqueReasonCodes(Array.isArray(value.reason_codes) ? value.reason_codes : [])
  const hasFraudReason = hasAIFraudReason(reason_codes)
  const hasTelemarketingReason = reason_codes.includes("TELEMARKETING_PATTERN")
  const scamFlag = value.is_scam === true
  let score = clampScore(value.score)
  let category = canonicalCategory(value.category)

  if (category === "safe" || category === "unknown") {
    if (hasTelemarketingReason && !hasFraudReason) {
      category = "telemarketing"
    } else if (scamFlag || hasFraudReason) {
      category = "fraud"
    } else if (score >= 70) {
      category = "spam"
    }
  }

  if (category === "fraud") {
    score = Math.max(score, 50)
  } else if (category === "spam") {
    score = Math.max(score, 50)
  } else if (category === "telemarketing") {
    score = Math.max(score, 35)
  }

  return {
    is_scam: category === "fraud" || (category === "spam" && score >= 50),
    score,
    category,
    reason_codes,
    explanation: String(value.explanation || "").slice(0, 300),
  }
}

function logOpenAIAnalysis({
  model,
  timeoutMs,
  outcome,
  status = null,
  durationMs = 0,
}) {
  console.log("openai_analysis", JSON.stringify({
    model: String(model || ""),
    timeout_ms: Math.max(0, Number(timeoutMs || 0)),
    outcome: String(outcome || "unknown"),
    status: status === null || status === undefined ? null : Number(status),
    duration_ms: Math.max(0, Number(durationMs || 0)),
  }))
}

function supportsOpenAIReasoning(model) {
  const normalized = String(model || "").trim().toLowerCase()
  return normalized.startsWith("gpt-5") || /^o\d/.test(normalized)
}

async function callOpenAI(env, message, number, analysisContext = null) {
  if (!env.OPENAI_API_KEY) return null

  const context = compactAIAnalysisContext(analysisContext)
  const model = env.OPENAI_MODEL || "gpt-5-mini"
  const timeoutMs = openAIFetchTimeoutMs(env)
  const startedAt = Date.now()

  try {
    const response = await fetchWithTimeout("https://api.openai.com/v1/responses", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${env.OPENAI_API_KEY}`,
      },
      body: JSON.stringify({
        model,
        max_output_tokens: 120,
        ...(supportsOpenAIReasoning(model) ? { reasoning: { effort: "minimal" } } : {}),
        input: [
          {
            role: "system",
            content: [
              {
                type: "input_text",
                text: [
                  "Tu es un moteur antifraude SMS pour CallShield.",
                  "Réponds uniquement en JSON strict.",
                  "Pas de texte hors JSON.",
                  "",
                  "{",
                  '  "is_scam": boolean,',
                  '  "score": integer,',
                  '  "category": "fraud|spam|telemarketing|safe|unknown",',
                  '  "reason_codes": string[],',
                  '  "explanation": string',
                  "}",
                  "",
                  "Règles :",
                  "- score entre 0 et 100",
                  "- explanation courte",
                  "- pas de phrases longues",
                  "- fraud = phishing ou usurpation",
                  "- spam = contenu indésirable",
                  "- telemarketing = démarchage",
                  "- utilise context comme signaux Worker, pas comme vérité absolue",
                  "- ne classe safe avec DELIVERY_SCAM, PAYMENT_PRESSURE, ACCOUNT_THREAT ou PHISHING_INTENT que si le SMS est clairement bénin",
                  "- si domaine trusted et aucun signal critique, tends vers safe",
                ].join("\n"),
              },
            ],
          },
          {
            role: "user",
            content: [
              {
                type: "input_text",
                text: JSON.stringify({
                  message,
                  number: number || "",
                  context,
                }),
              },
            ],
          },
        ],
        text: {
          format: {
            type: "json_schema",
            name: "callshield_sms_analysis",
            strict: true,
            schema: {
              type: "object",
              additionalProperties: false,
              properties: {
                is_scam: { type: "boolean" },
                score: { type: "integer" },
                category: {
                  type: "string",
                  enum: ["fraud", "spam", "telemarketing", "safe", "unknown"],
                },
                reason_codes: {
                  type: "array",
                  items: { type: "string" },
                },
                explanation: { type: "string" },
              },
              required: ["is_scam", "score", "category", "reason_codes", "explanation"],
            },
          },
        },
      }),
    }, timeoutMs)

    if (!response.ok) {
      logOpenAIAnalysis({
        model,
        timeoutMs,
        outcome: "http_error",
        status: response.status,
        durationMs: Date.now() - startedAt,
      })
      return null
    }

    const data = await response.json()

    let raw = typeof data?.output_text === "string" ? data.output_text.trim() : ""

    if (!raw && Array.isArray(data?.output)) {
      for (const item of data.output) {
        const contents = Array.isArray(item?.content) ? item.content : []
        for (const c of contents) {
          if (c?.json && typeof c.json === "object" && !Array.isArray(c.json)) {
            const normalized = normalizeOpenAIAnalysisResult(c.json)
            logOpenAIAnalysis({
              model,
              timeoutMs,
              outcome: normalized ? "success" : "invalid_json_object",
              status: response.status,
              durationMs: Date.now() - startedAt,
            })
            return normalized
          }
          const text = typeof c?.text === "string" ? c.text.trim() : ""
          if (text) {
            raw = text
          }
        }
      }
    }

    if (!raw) {
      logOpenAIAnalysis({
        model,
        timeoutMs,
        outcome: "empty_output",
        status: response.status,
        durationMs: Date.now() - startedAt,
      })
      return null
    }

    const parsed = JSON.parse(raw)

    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      logOpenAIAnalysis({
        model,
        timeoutMs,
        outcome: "invalid_json_root",
        status: response.status,
        durationMs: Date.now() - startedAt,
      })
      return null
    }

    const normalized = normalizeOpenAIAnalysisResult(parsed)
    logOpenAIAnalysis({
      model,
      timeoutMs,
      outcome: normalized ? "success" : "invalid_json_object",
      status: response.status,
      durationMs: Date.now() - startedAt,
    })
    return normalized
  } catch {
    logOpenAIAnalysis({
      model,
      timeoutMs,
      outcome: "error",
      status: null,
      durationMs: Date.now() - startedAt,
    })
    return null
  }
}

function buildCanonicalAnalysis({
  sourceMessage,
  heuristicScore,
  aiScore,
  finalScore,
  category,
  action,
  confidence,
  riskLevel,
  decisionSource,
  reasonCodes,
  explanation,
  model,
  modelVersion,
  trustContext = null,
  precomputedDomains = null,
  precomputedTrustContext = null,
  precomputedBrandContext = null,
}) {
  const rawText = String(sourceMessage || "")
  const normalizedText = rawText.toLowerCase()

  const urls = extractUrls(rawText)
  const domains = precomputedDomains || collectMessageDomains(rawText)
  const effectiveTrustContext = trustContext || precomputedTrustContext

  const trustedDomains = domains.filter((domain) => isDomainTrusted(domain, effectiveTrustContext))
  const domainsTrusted = areDomainsTrusted(domains, effectiveTrustContext)

  const hasFraudTrustSignal =
    category === "fraud" ||
    reasonCodes.includes("KNOWN_MALICIOUS_DOMAIN") ||
    reasonCodes.includes("RISKY_TLD") ||
    reasonCodes.includes("SUSPICIOUS_DOMAIN") ||
    reasonCodes.includes("BRAND_SPOOF") ||
    reasonCodes.includes("IP_URL")

  const trustScore = hasFraudTrustSignal
    ? 0
    : (Number(effectiveTrustContext?.maxTrustScore || 0) || (trustedDomains.length > 0 ? 100 : 0))
  const trustLevel = hasFraudTrustSignal
    ? "low"
    : (effectiveTrustContext?.trustLevel || (trustedDomains.length > 0 ? "high" : "low"))
  const numericDensity = (rawText.match(/\d/g) || []).length

  // Cache repeated signal checks
  const hasUrl = containsUrl(rawText)
  const hasShortener = containsShortener(rawText)
  const hasUrgency = containsUrgency(rawText)
  const hasOTP = containsOTP(rawText)
  const hasTracking = isLikelyTrackingMessage(rawText)
  const hasIdentity = /\b(identité|identite|iban|cb|carte bancaire|password|mot de passe|login|identifiant)\b/i.test(rawText)
  const hasSpoof = domainsTrusted
    ? false
    : (reasonCodes.includes("BRAND_SPOOF") || containsSpoofing(rawText, domains, domainsTrusted, precomputedBrandContext))

  return {
    schema_version: "v4",

    input: {
      channel: "sms",
      input_id: null,
      timestamp: Date.now(),
      raw: rawText,
      normalized: normalizedText,
      language: "unknown",
      hash: null,
    },

    entities: {
      domains,
      urls,
      phones: [],
      ips: [],
      brands: [],
      emails: [],
      amounts: [],
      keywords: [],
    },

    signals: {
      has_url: hasUrl,
      has_shortener: hasShortener,
      urgency: hasUrgency ? 1 : 0,
      spoofing: hasSpoof ? 1 : 0,
      phishing_intent: reasonCodes.includes("PHISHING_INTENT") ? 1 : 0,
      financial_pressure: reasonCodes.includes("PAYMENT_PRESSURE") ? 1 : 0,
      identity_request: hasIdentity ? 1 : 0,
      otp_pattern: hasOTP ? 1 : 0,
      tracking_pattern: hasTracking ? 1 : 0,
      telemarketing_pattern: reasonCodes.includes("TELEMARKETING_PATTERN") ? 1 : 0,
      low_quality_text: reasonCodes.includes("LOW_QUALITY_TEXT") ? 1 : 0,
      numeric_density: numericDensity,
    },

    trust: {
      domain_score: trustScore,
      brand_score: effectiveTrustContext?.brandKeys?.length ? 100 : 0,
      sender_score: 0,
      number_score: 0,
      global_trust_score: trustScore,
      trust_level: trustLevel,
    },

    graph: {
      campaign_score: reasonCodes.includes("MULTI_NUMBER_CAMPAIGN") || reasonCodes.includes("SPREAD_CAMPAIGN") ? 1 : 0,
      cluster_score: reasonCodes.includes("CLUSTER_HIGH_RISK") || reasonCodes.includes("CLUSTER_MEDIUM_RISK") || reasonCodes.includes("CLUSTER_LOW_RISK") ? 1 : 0,
      repetition_score: reasonCodes.includes("REPEAT_NUMBER") || reasonCodes.includes("HIGH_REPEAT_NUMBER") || reasonCodes.includes("REPEAT_MESSAGE") || reasonCodes.includes("HIGH_REPEAT_MESSAGE") ? 1 : 0,
      cross_channel_hits: 0,
      linked_objects: [],
    },

    features: {
      heuristic_score: heuristicScore,
      ai_score: aiScore,
      trust_score: trustScore,
      graph_score: 0,
      final_score: finalScore,
    },

    decision: {
      is_scam: category === "fraud" || (category === "spam" && finalScore >= 50),
      category,
      action,
      confidence,
      risk_level: riskLevel,
      decision_source: decisionSource,
      reason_codes: reasonCodes,
      explanation: String(explanation || "").slice(0, 500),
    },

    learning: {
      should_store: true,
      should_update_trust: true,
      should_update_graph: true,
      should_trigger_cluster: false,
      feedback_weight: 0,
      requires_review: false,
    },

    meta: {
      processing_time_ms: 0,
      model_version: modelVersion,
      worker_version: "v4",
      cache_hit: false,
      model,
    },
  }
}

function getAnalysisScore(result) {
  return Number(result?.features?.final_score ?? 0)
}

function getAnalysisDecision(result) {
  return result?.decision || {}
}

function getAnalysisMeta(result) {
  return result?.meta || {}
}

function finalizeCanonicalAnalysisResult(result, {
  inputHash = null,
  modelVersion = null,
  processingTimeMs = 0,
} = {}) {
  if (!result || typeof result !== "object") return result

  return {
    ...result,
    input: {
      ...(result.input || {}),
      input_id: inputHash,
      hash: inputHash,
    },
    meta: {
      ...(result.meta || {}),
      processing_time_ms: processingTimeMs,
      model_version: modelVersion || result?.meta?.model_version || "v1",
    },
  }
}

function logSMSAnalyzePath({
  path,
  number,
  result,
  startedAt,
  usedAI = false,
  usedDomainAge = false,
  appleFastBudget = false,
  d1ReadsEstimate = 0,
}) {
  const decision = getAnalysisDecision(result)
  const finalScore = getAnalysisScore(result)

  console.log("sms_analyze_path", JSON.stringify({
    path,
    number: number || null,
    score: finalScore,
    final_score: finalScore,
    action: decision.action,
    category: decision.category,
    risk_level: decision.risk_level,
    decision_source: decision.decision_source,
    processing_time_ms: Date.now() - startedAt,
    used_ai: Boolean(usedAI),
    used_domain_age: Boolean(usedDomainAge),
    apple_fast_budget: Boolean(appleFastBudget),
    d1_reads_estimate: Math.max(0, Number(d1ReadsEstimate || 0)),
  }))
}

async function buildFinalAnalysis(env, {
  heuristicScore,
  heuristicReasons,
  aiResult,
  decisionSource,
  explanation,
  sourceMessage,
  precomputedDomains = null,
  precomputedTrustContext = null,
  precomputedBrandContext = null,
}) {
  const aiScore = aiResult ? clampScore(aiResult.score) : null
  const aiReasons = Array.isArray(aiResult?.reason_codes) ? aiResult.reason_codes : []

  const allowedReasonCodes = new Set([
    "URL",
    "URGENCY",
    "SPOOFING",
    "OTP_SCAM",
    "RISKY_TLD",
    "SUSPICIOUS_DOMAIN",
    "BRAND_SPOOF",
    "CLICK_INCITATION",
    "PAYMENT_PRESSURE",
    "ACCOUNT_THREAT",
    "DELIVERY_SCAM",
    "JOB_SCAM",
    "LEGIT_TRACKING_PATTERN",
    "FAKE_TRACKING_LINK",
    "FAKE_AUTHORITY",
    "HIGH_THREAT_GRAPH",
    "MEDIUM_THREAT_GRAPH",
    "OTP_ONLY",
    "KNOWN_FRAUD_NUMBER",
    "KNOWN_SPAM_NUMBER",
    "GLOBAL_SCAM_DETECTED",
    "REPEAT_NUMBER",
    "HIGH_REPEAT_NUMBER",
    "REPEAT_MESSAGE",
    "HIGH_REPEAT_MESSAGE",
    "MULTI_NUMBER_SAME_MESSAGE",
    "CAMPAIGN_PATTERN_CONFIRMED",
    "USER_CONFIRMED_SCAM",
    "USER_CONFIRMED_SAFE",
    "SHORT_WITH_LINK",
    "LOW_QUALITY_TEXT",
    "NUMERIC_HEAVY",
    "MONEY_TRAP",
    "SHORTENER",
    "SUSPICIOUS_PATTERN",
    "PHISHING_INTENT",
    "TELEMARKETING_PATTERN",
    "LOCAL_GRAPH_HIGH",
    "LOCAL_GRAPH_MEDIUM",
    "CLUSTER_HIGH_RISK",
    "CLUSTER_MEDIUM_RISK",
    "CLUSTER_LOW_RISK",
    "SPREAD_CAMPAIGN",
    "MULTI_NUMBER_CAMPAIGN",
    "CARRIER_FLAGGED_SPAM",
    "VOIP_NUMBER",
    "BAD_REPUTATION",
    "MEDIUM_REPUTATION",
    "KNOWN_MALICIOUS_DOMAIN",
    "NEW_DOMAIN",
    "RECENT_DOMAIN",
    "STRONG_CORRELATED_SCAM",
    "CAMPAIGN_WITH_LINK",
    "KNOWN_BAD_ACTOR",
    "IP_URL",
    "DASH_DOMAIN",
    "URL_TRUSTED",
    "TRUSTED_DOMAIN",
  ])

  const originalText = String(sourceMessage || "").trim()
  const hasUrl = heuristicReasons.includes("URL") || containsUrl(originalText)
  const hasTracking = heuristicReasons.includes("LEGIT_TRACKING_PATTERN") || isLikelyTrackingMessage(originalText)
  const hasSensitiveKeyword = /\b(mot de passe|password|identifiant|login|carte bancaire|cb|iban|code secret|confirmez immédiatement|validez immédiatement)\b/i.test(originalText)
  let finalScore = heuristicScore
  const reason_codes_raw = uniqueReasonCodes([...heuristicReasons, ...aiReasons]).filter((code) =>
    allowedReasonCodes.has(code)
  )

  const allDomains = precomputedDomains || collectMessageDomains(originalText)
  const trustContext = precomputedTrustContext || await lookupTrustedDomains(env, allDomains)

  const trustedDomains = allDomains.filter((domain) => isDomainTrusted(domain, trustContext))
  const domainsTrusted = areDomainsTrusted(allDomains, trustContext)
  // NOTE: keep logic identical but ensure no duplicate legacy helpers remain referenced
  const trustScore = Number(trustContext?.maxTrustScore || 0) || (trustedDomains.length > 0 ? 100 : 0)

  const hasTrustedDomain = trustedDomains.length > 0
  const hasTransactionalPattern = isTransactionalLegitMessage(originalText)
  const trustedTransactional = domainsTrusted && hasTransactionalPattern && !hasFraudCriticalReason(reason_codes_raw)

  const hasKnownFraud = reason_codes_raw.includes("KNOWN_FRAUD_NUMBER")
  const hasKnownSpamNumber = reason_codes_raw.includes("KNOWN_SPAM_NUMBER")
  const hasGlobalScam = reason_codes_raw.includes("GLOBAL_SCAM_DETECTED")
  const aiCategory = aiResult?.category
    ? canonicalCategory(aiResult.category)
    : "unknown"
  const aiIndicatesRisk =
    aiResult?.is_scam === true ||
    (aiScore !== null && aiScore >= 50 && ["fraud", "spam", "telemarketing"].includes(aiCategory)) ||
    hasAIFraudReason(aiReasons)

  const hasCriticalFraudSignal =
    hasKnownFraud ||
    hasGlobalScam ||
    reason_codes_raw.includes("OTP_SCAM") ||
    reason_codes_raw.includes("IP_URL") ||
    reason_codes_raw.includes("BRAND_SPOOF") ||
    reason_codes_raw.includes("KNOWN_MALICIOUS_DOMAIN") ||
    reason_codes_raw.includes("RISKY_TLD") ||
    reason_codes_raw.includes("SUSPICIOUS_DOMAIN") ||
    reason_codes_raw.includes("STRONG_CORRELATED_SCAM") ||
    reason_codes_raw.includes("FAKE_TRACKING_LINK") ||
    hasSensitiveKeyword


  let reason_codes = trustedTransactional
    ? uniqueReasonCodes(filterDatasetReasonsForTrusted(reason_codes_raw).concat("TRUSTED_DOMAIN"))
    : reason_codes_raw


  if (domainsTrusted && !hasCriticalFraudSignal) {
    reason_codes = uniqueReasonCodes(
      reason_codes.filter((code) => code !== "SPOOFING").concat("TRUSTED_DOMAIN")
    )
    finalScore = Math.min(finalScore, 8)

    if (hasTransactionalPattern) {
      finalScore = Math.min(finalScore, 3)
    }

    // HARD OVERRIDE: trusted + tracking + no fraud signal => force SAFE
    if (
      hasTracking &&
      domainsTrusted &&
      !hasCriticalFraudSignal
    ) {
      finalScore = 0
    }
  }

  if (trustedTransactional && !hasCriticalFraudSignal) {
    return buildCanonicalAnalysis({
      sourceMessage: originalText,
      heuristicScore,
      aiScore,
      finalScore: 2,
      category: "safe",
      action: "allow",
      confidence: 0.98,
      riskLevel: "low",
      decisionSource: "trusted_override",
      reasonCodes: ["TRUSTED_DOMAIN"],
      explanation: "Trusted transactional domain detected.",
      model: "heuristic",
      modelVersion: "v1",
      trustContext,
      precomputedDomains: allDomains,
      precomputedTrustContext: trustContext,
      precomputedBrandContext,
    })
  }

  if (aiScore !== null && !(domainsTrusted && hasTransactionalPattern)) {
    if (heuristicScore >= 90) {
      finalScore = heuristicScore
    } else if (heuristicScore <= 15) {
      finalScore = aiIndicatesRisk && (!domainsTrusted || hasCriticalFraudSignal)
        ? clampScore((aiScore * 0.65) + (heuristicScore * 0.35))
        : Math.min(finalScore, heuristicScore)
    } else {
      finalScore = clampScore((aiScore * 0.65) + (heuristicScore * 0.35))
    }
  }

  const hasSensitiveWorkerReason = reason_codes.some((code) => [
    "PAYMENT_PRESSURE",
    "ACCOUNT_THREAT",
    "PHISHING_INTENT",
    "FAKE_AUTHORITY",
    "DELIVERY_SCAM",
    "JOB_SCAM",
    "BAD_REPUTATION",
    "KNOWN_BAD_ACTOR",
  ].includes(code)) || hasAccountThreat(originalText)
  const aiUnavailableOrLowSafe =
    aiScore === null ||
    (
      aiScore < 35 &&
      (aiCategory === "safe" || aiCategory === "unknown") &&
      aiResult?.is_scam !== true
    )

  if (
    aiUnavailableOrLowSafe &&
    hasSensitiveWorkerReason &&
    !trustedTransactional &&
    !(domainsTrusted && !hasCriticalFraudSignal)
  ) {
    finalScore = Math.max(finalScore, 35)
  }

  const hasFakeTracking =
    hasUrl &&
    hasTracking &&
    !domainsTrusted

  if (hasFakeTracking) {
    finalScore = Math.max(finalScore, 70)
  }

  // Remove any duplicate isTransactionalLegitMessage call: already cached in hasTransactionalPattern
  // (no additional call to isTransactionalLegitMessage should be present here)
  if (trustedTransactional && !hasCriticalFraudSignal) {
    finalScore = Math.min(finalScore, 5)
  }

  if (hasKnownSpamNumber) {
    finalScore = hasCriticalFraudSignal
      ? Math.max(finalScore, 75)
      : 69
  }

  const knownFraudCompanionRisk =
    reason_codes.some((code) => [
      "OTP_SCAM",
      "IP_URL",
      "BRAND_SPOOF",
      "KNOWN_MALICIOUS_DOMAIN",
      "RISKY_TLD",
      "SUSPICIOUS_DOMAIN",
      "STRONG_CORRELATED_SCAM",
      "FAKE_TRACKING_LINK",
      "PAYMENT_PRESSURE",
      "ACCOUNT_THREAT",
      "PHISHING_INTENT",
      "FAKE_AUTHORITY",
      "DELIVERY_SCAM",
      "JOB_SCAM",
      "KNOWN_BAD_ACTOR",
      "USER_CONFIRMED_SCAM",
      "BAD_REPUTATION",
      "HIGH_THREAT_GRAPH",
      "MULTI_NUMBER_CAMPAIGN",
    ].includes(code))

  const weakKnownFraudNumberSignal =
    hasKnownFraud &&
    !hasGlobalScam &&
    aiScore === null &&
    heuristicScore <= 55 &&
    !knownFraudCompanionRisk

  if (hasGlobalScam || (hasKnownFraud && !weakKnownFraudNumberSignal)) {
    finalScore = Math.max(finalScore, 90)
  } else if (weakKnownFraudNumberSignal) {
    finalScore = Math.max(finalScore, 35)
  }

  const hasTelemarketingSignals =
    reason_codes.includes("TELEMARKETING_PATTERN") &&
    !reason_codes.includes("OTP_SCAM") &&
    !reason_codes.includes("KNOWN_FRAUD_NUMBER") &&
    !reason_codes.includes("GLOBAL_SCAM_DETECTED") &&
    !reason_codes.includes("HIGH_THREAT_GRAPH") &&
    !reason_codes.includes("KNOWN_MALICIOUS_DOMAIN") &&
    !reason_codes.includes("IP_URL") &&
    !reason_codes.includes("BRAND_SPOOF") &&
    !reason_codes.includes("FAKE_TRACKING_LINK") &&
    !reason_codes.includes("PHISHING_INTENT") &&
    !reason_codes.includes("ACCOUNT_THREAT") &&
    !reason_codes.includes("STRONG_CORRELATED_SCAM") &&
    !reason_codes.includes("CAMPAIGN_WITH_LINK") &&
    !reason_codes.includes("KNOWN_BAD_ACTOR") &&
    !reason_codes.includes("USER_CONFIRMED_SCAM") &&
    !reason_codes.includes("SUSPICIOUS_DOMAIN") &&
    !reason_codes.includes("RISKY_TLD")

  if (hasTelemarketingSignals) {
    finalScore = Math.min(finalScore, 59)
  }

  finalScore = clampScore(finalScore)

  let category = aiCategory

  if (trustedTransactional && !hasCriticalFraudSignal) {
    category = "safe"
  } else if (hasTelemarketingSignals) {
    category = "telemarketing"
  } else if (hasKnownSpamNumber && !hasCriticalFraudSignal) {
    category = "spam"
  } else if (domainsTrusted && !hasCriticalFraudSignal && finalScore <= 15) {
    category = "safe"
  } else if (finalScore >= 70) {
    category = "fraud"
  } else if (finalScore >= 50) {
    if (category === "safe" || category === "unknown") {
      category = "spam"
    }
  } else if (finalScore >= 35 && reason_codes.includes("TELEMARKETING_PATTERN")) {
    category = "telemarketing"
  } else if (finalScore >= 35 && (category === "safe" || category === "unknown")) {
    category = "unknown"
  } else if (category === "unknown") {
    category = "safe"
  }

  const risk_level = riskLevelFromScore(finalScore)
  const action = actionFromScore(finalScore, category)

  if (
    !hasKnownFraud &&
    !hasGlobalScam &&
    category === "safe" &&
    finalScore < 40 &&
    !reason_codes.includes("KNOWN_MALICIOUS_DOMAIN")
  ) {
    return buildCanonicalAnalysis({
      sourceMessage: originalText,
      heuristicScore,
      aiScore,
      finalScore,
      category,
      action: "allow",
      confidence: aiScore !== null ? Math.max(0.6, aiScore / 100) : confidenceFromScore(finalScore),
      riskLevel: "low",
      decisionSource,
      reasonCodes: reason_codes,
      explanation: String(explanation || "").slice(0, 500),
      model: aiScore !== null ? "openai" : "heuristic",
      modelVersion: "v1",
      trustContext,
      precomputedDomains: allDomains,
      precomputedTrustContext: trustContext,
      precomputedBrandContext,
    })
  }

  return buildCanonicalAnalysis({
    sourceMessage: originalText,
    heuristicScore,
    aiScore,
    finalScore,
    category,
    action,
    confidence: aiScore !== null ? Math.max(0.6, aiScore / 100) : confidenceFromScore(finalScore),
    riskLevel: risk_level,
    decisionSource,
    reasonCodes: reason_codes,
    explanation: String(explanation || "").slice(0, 500),
    model: aiScore !== null ? "openai" : "heuristic",
    modelVersion: "v1",
    trustContext,
    precomputedDomains: allDomains,
    precomputedTrustContext: trustContext,
    precomputedBrandContext,
  })
}

async function logSMSAnalysis(env, row) {
  try {
    await env.DB.prepare(`
      INSERT INTO sms_ai_logs (
        input_hash,
        number_e164,
        message,
        heuristic_score,
        ai_score,
        final_score,
        risk_level,
        action,
        category,
        decision_source,
        model,
        model_version,
        reason_codes,
        explanation,
        created_at
      ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, unixepoch())
    `)
      .bind(
        row.input_hash,
        row.number_e164,
        row.message,
        row.heuristic_score,
        row.ai_score,
        row.final_score,
        row.risk_level,
        row.action,
        row.category,
        row.decision_source,
        row.model,
        row.model_version,
        row.reason_codes,
        row.explanation
      )
      .run()
  } catch (error) {
    console.error("sms_ai_logs_insert_failed", error)
  }
}

async function upsertSMSAnalysisDataset(env, row) {
  try {
    await env.DB.prepare(`
      INSERT INTO sms_analysis_dataset (
        input_hash,
        number_e164,
        message,
        normalized_message,
        heuristic_score,
        ai_score,
        final_score,
        risk_level,
        action,
        category,
        decision_source,
        model,
        model_version,
        reason_codes_json,
        explanation,
        user_feedback,
        reviewed_label,
        created_at,
        updated_at
      ) VALUES (
        ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, unixepoch(), unixepoch()
      )
      ON CONFLICT(input_hash) DO UPDATE SET
        number_e164 = excluded.number_e164,
        message = excluded.message,
        normalized_message = excluded.normalized_message,
        heuristic_score = excluded.heuristic_score,
        ai_score = excluded.ai_score,
        final_score = excluded.final_score,
        risk_level = excluded.risk_level,
        action = excluded.action,
        category = excluded.category,
        decision_source = excluded.decision_source,
        model = excluded.model,
        model_version = excluded.model_version,
        reason_codes_json = excluded.reason_codes_json,
        explanation = excluded.explanation,
        updated_at = unixepoch()
    `)
      .bind(
        row.input_hash,
        row.number_e164,
        row.message,
        row.normalized_message,
        row.heuristic_score,
        row.ai_score,
        row.final_score,
        row.risk_level,
        row.action,
        row.category,
        row.decision_source,
        row.model,
        row.model_version,
        row.reason_codes_json,
        row.explanation,
        row.user_feedback ?? null,
        row.reviewed_label ?? null
      )
      .run()
  } catch (error) {
    console.error("sms_analysis_dataset_upsert_failed", error)
  }
}

async function persistSMSAnalysis(env, row) {
  await logSMSAnalysis(env, {
    input_hash: row.input_hash,
    number_e164: row.number_e164,
    message: row.message,
    heuristic_score: row.heuristic_score,
    ai_score: row.ai_score,
    final_score: row.final_score,
    risk_level: row.risk_level,
    action: row.action,
    category: row.category,
    decision_source: row.decision_source,
    model: row.model,
    model_version: row.model_version,
    reason_codes: row.reason_codes_json,
    explanation: row.explanation,
  })

  await upsertSMSAnalysisDataset(env, row)
}

function scheduleSMSAnalysisPersistence(ctx, env, row) {
  const task = persistSMSAnalysis(env, row)
  if (ctx && typeof ctx.waitUntil === "function") {
    ctx.waitUntil(task)
    return Promise.resolve()
  }

  return task
}

function reviewedLabelFromFeedback(userFeedback) {
  switch (String(userFeedback || "").trim().toLowerCase()) {
    case "confirmed_scam":
      return "fraud"
    case "confirmed_safe":
      return "safe"
    case "wrong_detection":
      return "unknown"
    default:
      return null
  }
}

async function getTableColumns(env, tableName) {
  try {
    const rows = await env.DB.prepare(`PRAGMA table_info(${tableName})`).all()
    const results = Array.isArray(rows?.results) ? rows.results : []
    return new Set(results.map((row) => String(row?.name || "").trim()).filter(Boolean))
  } catch (error) {
    console.error("table_columns_lookup_failed", tableName, error)
    return new Set()
  }
}

let smsReportsSchemaReadyPromise = null

async function ensureSMSReportsSchema(env) {
  if (smsReportsSchemaReadyPromise) {
    return smsReportsSchemaReadyPromise
  }

  smsReportsSchemaReadyPromise = (async () => {
    const existingColumns = await getTableColumns(env, "sms_reports")
    let shouldRetrySchema = existingColumns.size === 0
    const requiredColumns = [
      ["normalized_message", "TEXT"],
      ["input_hash", "TEXT"],
      ["source_url", "TEXT"],
      ["urls_json", "TEXT"],
      ["domains_json", "TEXT"],
    ]

    for (const [name, sqlType] of requiredColumns) {
      if (existingColumns.has(name)) continue
      try {
        await env.DB.prepare(`ALTER TABLE sms_reports ADD COLUMN ${name} ${sqlType}`).run()
        existingColumns.add(name)
      } catch (error) {
        console.error("sms_reports_alter_failed", name, error)
        shouldRetrySchema = true
      }
    }

    if (shouldRetrySchema) {
      smsReportsSchemaReadyPromise = null
    }

    return existingColumns
  })()

  return smsReportsSchemaReadyPromise
}

function aggregateTimestampSeconds(value) {
  const timestamp = Number(value)
  const fallback = Date.now()
  const normalized = Number.isFinite(timestamp) && timestamp > 0 ? timestamp : fallback
  return Math.floor(normalized > 100000000000 ? normalized / 1000 : normalized)
}

function feedbackAggregateDeltas(category) {
  const primaryCategory = canonicalCategory(category)
  const deltas = {
    fraud: 0,
    spam: 0,
    telemarketing: 0,
    safe: 0,
    unknown: 0,
    positiveWeight: 0,
    negativeWeight: 0,
  }

  switch (primaryCategory) {
    case "fraud":
      deltas.fraud = 1
      deltas.positiveWeight = 3
      break
    case "spam":
      deltas.spam = 1
      deltas.positiveWeight = 1.5
      break
    case "telemarketing":
      deltas.telemarketing = 1
      deltas.positiveWeight = 2
      break
    case "safe":
      deltas.safe = 1
      deltas.negativeWeight = 3
      break
    default:
      deltas.unknown = 1
      break
  }

  return deltas
}

function isFeedbackAggregateSourceAllowed({ source = "", sourceContext = "", reportSurface = "" } = {}) {
  const parts = [source, sourceContext, reportSurface]
    .map((value) => String(value || "").trim().toLowerCase())
    .filter(Boolean)

  if (parts.length === 0) return true

  const blockedExactSources = new Set([
    "worker_post_deploy_test",
    "internal_test_batch",
    "delta_fix_test",
    "ultimate_test",
    "brain_test",
    "v2plus_test",
    "export_test",
    "stress_test",
  ])
  if (parts.some((part) => blockedExactSources.has(part))) return false

  return !/(^|[_:\-\s])(test|debug|fixture|mock|validation|stress)([_:\-\s]|$)/.test(parts.join(" "))
}

function normalizeFeedbackSourceDimension(value, fallback = "") {
  const normalized = String(value || fallback || "").trim().toLowerCase()
  return normalized.slice(0, 128)
}

function feedbackSourceAggregateKey({ source = "", sourceContext = "", platform = "", reportSurface = "", channel = "" } = {}) {
  const normalizedSource = normalizeFeedbackSourceDimension(source, "unknown")
  const normalizedSourceContext = normalizeFeedbackSourceDimension(sourceContext)
  const normalizedPlatform = normalizeFeedbackSourceDimension(platform)
  const normalizedReportSurface = normalizeFeedbackSourceDimension(reportSurface)
  const normalizedChannel = normalizeFeedbackSourceDimension(channel)
  return [
    normalizedSource || "unknown",
    normalizedSourceContext,
    normalizedPlatform,
    normalizedReportSurface,
    normalizedChannel,
  ].join("|")
}

async function persistFeedbackSourceAggregate(env, {
  source = "",
  sourceContext = "",
  platform = "",
  reportSurface = "",
  channel = "",
  category = "unknown",
  timestamp = Date.now(),
  validationStatus = "accepted",
} = {}) {
  if (!env?.DB) return false

  const normalizedSource = normalizeFeedbackSourceDimension(source, "unknown") || "unknown"
  const normalizedSourceContext = normalizeFeedbackSourceDimension(sourceContext)
  const normalizedPlatform = normalizeFeedbackSourceDimension(platform)
  const normalizedReportSurface = normalizeFeedbackSourceDimension(reportSurface)
  const normalizedChannel = normalizeFeedbackSourceDimension(channel)
  const sourceKey = feedbackSourceAggregateKey({
    source: normalizedSource,
    sourceContext: normalizedSourceContext,
    platform: normalizedPlatform,
    reportSurface: normalizedReportSurface,
    channel: normalizedChannel,
  })
  const deltas = feedbackAggregateDeltas(category)
  const seenAt = aggregateTimestampSeconds(timestamp)
  const updatedAt = Math.floor(Date.now() / 1000)
  const status = String(validationStatus || "").trim().toLowerCase()
  const acceptedCount = status === "accepted" ? 1 : 0
  const rejectedCount = status && status !== "accepted" ? 1 : 0
  const testEventCount = isFeedbackAggregateSourceAllowed({
    source: normalizedSource,
    sourceContext: normalizedSourceContext,
    reportSurface: normalizedReportSurface,
  }) ? 0 : 1

  try {
    const result = await env.DB.prepare(`
      INSERT INTO feedback_source_aggregates (
        source_key,
        source,
        source_context,
        platform,
        report_surface,
        channel,
        event_count,
        accepted_count,
        rejected_count,
        fraud_count,
        spam_count,
        telemarketing_count,
        safe_count,
        unknown_count,
        positive_weight,
        negative_weight,
        test_event_count,
        first_seen,
        last_seen,
        updated_at
      ) VALUES (
        ?1, ?2, ?3, ?4, ?5, ?6, 1, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?17, ?18
      )
      ON CONFLICT(source_key) DO UPDATE SET
        event_count = event_count + excluded.event_count,
        accepted_count = accepted_count + excluded.accepted_count,
        rejected_count = rejected_count + excluded.rejected_count,
        fraud_count = fraud_count + excluded.fraud_count,
        spam_count = spam_count + excluded.spam_count,
        telemarketing_count = telemarketing_count + excluded.telemarketing_count,
        safe_count = safe_count + excluded.safe_count,
        unknown_count = unknown_count + excluded.unknown_count,
        positive_weight = positive_weight + excluded.positive_weight,
        negative_weight = negative_weight + excluded.negative_weight,
        test_event_count = test_event_count + excluded.test_event_count,
        first_seen = CASE
          WHEN first_seen IS NULL OR excluded.first_seen < first_seen THEN excluded.first_seen
          ELSE first_seen
        END,
        last_seen = CASE
          WHEN last_seen IS NULL OR excluded.last_seen > last_seen THEN excluded.last_seen
          ELSE last_seen
        END,
        updated_at = excluded.updated_at
    `)
      .bind(
        sourceKey,
        normalizedSource,
        normalizedSourceContext,
        normalizedPlatform,
        normalizedReportSurface,
        normalizedChannel,
        acceptedCount,
        rejectedCount,
        deltas.fraud,
        deltas.spam,
        deltas.telemarketing,
        deltas.safe,
        deltas.unknown,
        deltas.positiveWeight,
        deltas.negativeWeight,
        testEventCount,
        seenAt,
        updatedAt
      )
      .run()

    return Number(result?.meta?.changes || 0) > 0
  } catch (error) {
    console.error("feedback_source_aggregate_upsert_failed", error)
    return false
  }
}

function feedbackEntitiesFromInputs({ number = "", message = "", sourceUrl = "" } = {}) {
  const entities = []
  const seen = new Set()
  const addEntity = (entityType, entityValue) => {
    const value = entityType === "number" ? normalizeNumber(entityValue) : normalizeDomainValue(entityValue)
    if (!value) return

    const key = `${entityType}:${value}`
    if (seen.has(key)) return
    seen.add(key)
    entities.push({ entityType, entityValue: value })
  }

  addEntity("number", number)

  const domains = collectMessageDomains(`${message || ""} ${sourceUrl || ""}`)
  for (const domain of domains) {
    const normalizedDomain = normalizeDomainValue(domain)
    if (!normalizedDomain) continue

    addEntity("domain", normalizedDomain)
    addEntity("root_domain", rootDomainFromHost(normalizedDomain))
  }

  return entities
}

async function persistFeedbackEntityAggregate(env, entity, category, timestamp) {
  if (!env?.DB || !entity?.entityType || !entity?.entityValue) return false

  const deltas = feedbackAggregateDeltas(category)
  const seenAt = aggregateTimestampSeconds(timestamp)
  const updatedAt = Math.floor(Date.now() / 1000)

  try {
    const result = await env.DB.prepare(`
      INSERT INTO feedback_entity_aggregates (
        entity_type,
        entity_value,
        fraud_count,
        spam_count,
        telemarketing_count,
        safe_count,
        unknown_count,
        positive_weight,
        negative_weight,
        source_count,
        controversy_score,
        first_seen,
        last_seen,
        updated_at
      ) VALUES (
        ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 1, 0, ?10, ?10, ?11
      )
      ON CONFLICT(entity_type, entity_value) DO UPDATE SET
        fraud_count = fraud_count + excluded.fraud_count,
        spam_count = spam_count + excluded.spam_count,
        telemarketing_count = telemarketing_count + excluded.telemarketing_count,
        safe_count = safe_count + excluded.safe_count,
        unknown_count = unknown_count + excluded.unknown_count,
        positive_weight = positive_weight + excluded.positive_weight,
        negative_weight = negative_weight + excluded.negative_weight,
        source_count = source_count + excluded.source_count,
        controversy_score = controversy_score + CASE
          WHEN excluded.safe_count > 0 AND (fraud_count + spam_count + telemarketing_count) > 0 THEN 1
          WHEN (excluded.fraud_count + excluded.spam_count + excluded.telemarketing_count) > 0 AND safe_count > 0 THEN 1
          ELSE 0
        END,
        first_seen = CASE
          WHEN first_seen IS NULL OR excluded.first_seen < first_seen THEN excluded.first_seen
          ELSE first_seen
        END,
        last_seen = CASE
          WHEN last_seen IS NULL OR excluded.last_seen > last_seen THEN excluded.last_seen
          ELSE last_seen
        END,
        updated_at = excluded.updated_at
    `)
      .bind(
        entity.entityType,
        entity.entityValue,
        deltas.fraud,
        deltas.spam,
        deltas.telemarketing,
        deltas.safe,
        deltas.unknown,
        deltas.positiveWeight,
        deltas.negativeWeight,
        seenAt,
        updatedAt
      )
      .run()

    return Number(result?.meta?.changes || 0) > 0
  } catch (error) {
    console.error("feedback_entity_aggregate_upsert_failed", error)
    return false
  }
}

async function markFeedbackEntityAggregateEvent(env, dedupeKey, entity, category, timestamp) {
  const normalizedDedupeKey = String(dedupeKey || "").trim()
  if (!env?.DB || !normalizedDedupeKey || !entity?.entityType || !entity?.entityValue) return true

  try {
    const result = await env.DB.prepare(`
      INSERT OR IGNORE INTO feedback_entity_aggregate_events (
        dedupe_key,
        entity_type,
        entity_value,
        category,
        created_at
      ) VALUES (?1, ?2, ?3, ?4, ?5)
    `)
      .bind(
        normalizedDedupeKey,
        entity.entityType,
        entity.entityValue,
        canonicalCategory(category),
        aggregateTimestampSeconds(timestamp)
      )
      .run()

    return Number(result?.meta?.changes || 0) > 0
  } catch (error) {
    console.error("feedback_entity_aggregate_event_mark_failed", error)
    return true
  }
}

async function persistFeedbackEntityAggregates(env, {
  number = "",
  message = "",
  sourceUrl = "",
  category = "unknown",
  timestamp = Date.now(),
  dedupeKey = "",
  source = "",
  sourceContext = "",
  reportSurface = "",
} = {}) {
  if (!isFeedbackAggregateSourceAllowed({ source, sourceContext, reportSurface })) return

  const entities = feedbackEntitiesFromInputs({ number, message, sourceUrl })
  for (const entity of entities) {
    const shouldAggregate = await markFeedbackEntityAggregateEvent(env, dedupeKey, entity, category, timestamp)
    if (!shouldAggregate) continue

    await persistFeedbackEntityAggregate(env, entity, category, timestamp)
  }
}

function feedbackCategoryFromNativeReport(body) {
  const rawCategory = String(
    body?.primary_category ||
    body?.primaryCategory ||
    body?.category ||
    body?.report_category ||
    body?.reportCategory ||
    body?.type ||
    ""
  ).trim()

  return rawCategory ? canonicalCategory(rawCategory) : "spam"
}

function feedbackEventPayloadFromUserFeedback(userFeedback) {
  switch (String(userFeedback || "").trim().toLowerCase()) {
    case "confirmed_scam":
      return {
        primaryCategory: "fraud",
        secondaryCategory: null,
        userDisposition: "reported_fraud",
        scamFlag: 1,
      }
    case "confirmed_safe":
      return {
        primaryCategory: "safe",
        secondaryCategory: null,
        userDisposition: "marked_safe",
        scamFlag: 0,
      }
    case "wrong_detection":
      return {
        primaryCategory: "unknown",
        secondaryCategory: null,
        userDisposition: "wrong_detection",
        scamFlag: 0,
      }
    default:
      return {
        primaryCategory: "unknown",
        secondaryCategory: null,
        userDisposition: "unknown",
        scamFlag: 0,
      }
  }
}

function feedbackEventPayloadFromCategory(category, userDisposition = "") {
  const rawCategory = String(category || "unknown").trim().toLowerCase()
  const primaryCategory = ["false_positive", "not_spam"].includes(rawCategory)
    ? "safe"
    : canonicalCategory(rawCategory)
  const requestedDisposition = String(userDisposition || "").trim().toLowerCase()
  const allowedDispositions = new Set([
    "reported_fraud",
    "reported_spam",
    "reported_telemarketing",
    "reported_unknown",
    "marked_safe",
    "wrong_detection",
    "unknown",
  ])

  switch (primaryCategory) {
    case "fraud":
      return {
        primaryCategory,
        secondaryCategory: null,
        userDisposition: "reported_fraud",
        scamFlag: 1,
      }
    case "spam":
      return {
        primaryCategory,
        secondaryCategory: null,
        userDisposition: "reported_spam",
        scamFlag: 0,
      }
    case "telemarketing":
      return {
        primaryCategory,
        secondaryCategory: null,
        userDisposition: "reported_telemarketing",
        scamFlag: 0,
      }
    case "safe":
      return {
        primaryCategory,
        secondaryCategory: null,
        userDisposition: "marked_safe",
        scamFlag: 0,
      }
    default:
      return {
        primaryCategory: "unknown",
        secondaryCategory: null,
        userDisposition: allowedDispositions.has(requestedDisposition) ? requestedDisposition : "reported_unknown",
        scamFlag: 0,
      }
  }
}

function normalizeFeedbackTimestamp(value) {
  const timestamp = Number(value)
  return Number.isFinite(timestamp) && timestamp > 0 ? timestamp : Date.now()
}

function normalizeFeedbackBatchEvent(rawEvent, batchSource) {
  const event = rawEvent && typeof rawEvent === "object" && !Array.isArray(rawEvent)
    ? rawEvent
    : null

  if (!event) return null

  const eventId = String(event.event_id || event.eventId || event.id || "").trim()
  const number = normalizeNumber(
    event.number_e164 || event.number || event.phone_number || event.phoneNumber || ""
  )

  if (!eventId || !number) return null

  const payload = feedbackEventPayloadFromCategory(
    event.primary_category || event.category,
    event.user_disposition
  )
  const createdAt = normalizeFeedbackTimestamp(event.created_at ?? event.createdAt)
  const sourceContext = String(event.source_context || event.sourceContext || "ios_feedback_batch").trim() || "ios_feedback_batch"
  const dedupeKey = String(event.dedupe_key || event.dedupeKey || eventId).trim()

  return {
    eventId,
    dedupeKey,
    number,
    eventType: String(event.event_type || event.eventType || "user_report").trim() || "user_report",
    primaryCategory: payload.primaryCategory,
    secondaryCategory: payload.secondaryCategory,
    userDisposition: payload.userDisposition,
    sourceContext,
    scamFlag: payload.scamFlag,
    source: String(event.source || batchSource || "ios").trim() || "ios",
    platform: String(event.platform || "ios").trim() || "ios",
    appVersion: String(event.app_version || event.appVersion || "unknown").trim() || "unknown",
    createdAt,
    receivedAt: Date.now(),
  }
}

async function persistFeedbackBatchEvent(env, event) {
  try {
    const existing = await env.DB.prepare(`
      SELECT rowid AS id
      FROM feedback_events
      WHERE dedupe_key = ?1
      LIMIT 1
    `)
      .bind(event.dedupeKey)
      .first()

    if (existing?.id) {
      return true
    }
  } catch (error) {
    console.error("feedback_batch_dedupe_lookup_failed", error)
  }

  try {
    const result = await env.DB.prepare(`
      INSERT INTO feedback_events (
        event_id,
        number_e164,
        event_type,
        primary_category,
        secondary_category,
        user_disposition,
        source_context,
        displayed_label_at_time,
        displayed_confidence_band_at_time,
        dataset_presence_at_time,
        callkit_state_at_time,
        scam_flag,
        source,
        platform,
        app_version,
        created_at,
        received_at,
        dedupe_key,
        validation_status
      ) VALUES (
        ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19
      )
    `)
      .bind(
        event.eventId,
        event.number,
        event.eventType,
        event.primaryCategory,
        event.secondaryCategory,
        event.userDisposition,
        event.sourceContext,
        null,
        null,
        null,
        null,
        event.scamFlag,
        event.source,
        event.platform,
        event.appVersion,
        event.createdAt,
        event.receivedAt,
        event.dedupeKey,
        "accepted"
      )
      .run()

    const inserted = Number(result?.meta?.changes || 0) > 0
    if (inserted) {
      await persistFeedbackSourceAggregate(env, {
        source: event.source,
        sourceContext: event.sourceContext,
        platform: event.platform,
        category: event.primaryCategory,
        timestamp: event.createdAt,
        validationStatus: "accepted",
      })

      await persistFeedbackEntityAggregates(env, {
        number: event.number,
        category: event.primaryCategory,
        timestamp: event.createdAt,
        dedupeKey: `feedback_batch:${event.dedupeKey}`,
        source: event.source,
        sourceContext: event.sourceContext,
      })
    }

    return inserted
  } catch (error) {
    console.error("feedback_batch_insert_failed", error)
    return false
  }
}

async function handleSMSFeedbackBatch(env, body) {
  const rawEvents = Array.isArray(body?.events) ? body.events : []
  const events = rawEvents.slice(0, 500)
  const source = String(body?.source || "ios").trim() || "ios"
  let accepted = 0
  let inserted = 0

  for (const rawEvent of events) {
    const event = normalizeFeedbackBatchEvent(rawEvent, source)
    if (!event) continue

    accepted += 1
    if (await persistFeedbackBatchEvent(env, event)) {
      inserted += 1
    }
  }

  return jsonResponse({
    status: "ok",
    received: rawEvents.length,
    accepted,
    inserted,
  })
}

async function persistFeedbackEvent(env, {
  inputHash,
  number,
  message,
  normalizedMessage,
  userFeedback,
  reviewedLabel,
}) {
  const payload = feedbackEventPayloadFromUserFeedback(userFeedback)
  const dedupeKey = `sms_feedback:${inputHash}:${userFeedback}`
  const createdAt = Date.now()
  const eventId = `sms_feedback_${inputHash}_${createdAt}`

  try {
    const existing = await env.DB.prepare(`
      SELECT rowid AS id
      FROM feedback_events
      WHERE dedupe_key = ?1
      LIMIT 1
    `)
      .bind(dedupeKey)
      .first()

    if (existing?.id) {
      return true
    }
  } catch (error) {
    console.error("feedback_event_dedupe_lookup_failed", error)
  }

  let corroborationCount = 0

  try {
    const row = await env.DB.prepare(`
      SELECT COUNT(*) as count
      FROM sms_analysis_dataset
      WHERE normalized_message = ?1
        AND reviewed_label = ?2
        AND user_feedback IS NOT NULL
    `)
      .bind(normalizedMessage, reviewedLabel || "unknown")
      .first()

    corroborationCount = Number(row?.count || 0)
  } catch (error) {
    console.error("feedback_event_corroboration_lookup_failed", error)
  }

  const sourceContext =
    corroborationCount >= 5
      ? "worker_feedback_confirmed"
      : corroborationCount >= 2
        ? "worker_feedback_correlated"
        : "worker_feedback_single"

  try {
    
    const result = await env.DB.prepare(`
      INSERT INTO feedback_events (
        event_id,
        number_e164,
        event_type,
        primary_category,
        secondary_category,
        user_disposition,
        source_context,
        displayed_label_at_time,
        displayed_confidence_band_at_time,
        dataset_presence_at_time,
        callkit_state_at_time,
        scam_flag,
        source,
        platform,
        app_version,
        created_at,
        received_at,
        dedupe_key,
        validation_status
      ) VALUES (
        ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19
      )
    `)
      .bind(
        eventId,
        number || null,
        "sms_feedback",
        payload.primaryCategory,
        payload.secondaryCategory,
        payload.userDisposition,
        sourceContext,
        reviewedLabel || null,
        null,
        1,
        null,
        payload.scamFlag,
        "worker_feedback",
        "worker",
        "worker_v1",
        createdAt,
        createdAt,
        dedupeKey,
        "accepted"
      )
      .run()

    const inserted = Number(result?.meta?.changes || 0) > 0
    if (!inserted) {
      console.error("feedback_event_insert_failed_no_changes", result)
      return false
    }

    await persistFeedbackSourceAggregate(env, {
      source: "worker_feedback",
      sourceContext,
      platform: "worker",
      category: payload.primaryCategory,
      timestamp: createdAt,
      validationStatus: "accepted",
    })

    await persistFeedbackEntityAggregates(env, {
      number,
      message,
      category: payload.primaryCategory,
      timestamp: createdAt,
      dedupeKey,
      source: "worker_feedback",
      sourceContext,
    })

    return true
  } catch (error) {
    console.error("feedback_event_insert_failed", error)
    return false
  }
}

async function handleSMSFeedback(env, body) {
  if (Array.isArray(body?.events)) {
    return await handleSMSFeedbackBatch(env, body)
  }

  const message = normalizeText(body?.message)
  const number = normalizeNumber(
    body?.number || body?.phone_number || body?.phoneNumber || body?.sender || ""
  )
  const userFeedback = String(body?.user_feedback || "").trim().toLowerCase()

  if (!message) {
    return jsonResponse({ error: "missing message" }, 400)
  }

  if (!["confirmed_scam", "confirmed_safe", "wrong_detection"].includes(userFeedback)) {
    return jsonResponse({ error: "invalid user_feedback" }, 400)
  }

  const normalizedMessage = message.toLowerCase()
  const inputHash = await sha256Hex(`${number}|${normalizedMessage}`)
  const reviewedLabel = reviewedLabelFromFeedback(userFeedback)

  try {
    const existing = await env.DB.prepare(`
      SELECT input_hash
      FROM sms_analysis_dataset
      WHERE input_hash = ?1
      LIMIT 1
    `)
      .bind(inputHash)
      .first()

    if (existing?.input_hash) {
      await env.DB.prepare(`
        UPDATE sms_analysis_dataset
        SET user_feedback = ?1,
            reviewed_label = ?2,
            updated_at = unixepoch()
        WHERE input_hash = ?3
      `)
        .bind(userFeedback, reviewedLabel, inputHash)
        .run()
    } else {
      await env.DB.prepare(`
        INSERT INTO sms_analysis_dataset (
          input_hash,
          number_e164,
          message,
          normalized_message,
          heuristic_score,
          ai_score,
          final_score,
          risk_level,
          action,
          category,
          decision_source,
          model,
          model_version,
          reason_codes_json,
          explanation,
          user_feedback,
          reviewed_label,
          created_at,
          updated_at
        ) VALUES (
          ?1, ?2, ?3, ?4, NULL, NULL, 0, 'low', 'allow', 'unknown', 'feedback_only', 'user', 'feedback_v1', '[]', '', ?5, ?6, unixepoch(), unixepoch()
        )
      `)
        .bind(
          inputHash,
          number || null,
          message,
          normalizedMessage,
          userFeedback,
          reviewedLabel
        )
        .run()
    }

    const feedbackEventStored = await persistFeedbackEvent(env, {
      inputHash,
      number,
      message,
      normalizedMessage,
      userFeedback,
      reviewedLabel,
    })

    if (!feedbackEventStored) {
      return jsonResponse({ error: "feedback_event_persist_failed" }, 500)
    }

    return jsonResponse({ success: true })
  } catch (error) {
    console.error("sms_feedback_upsert_failed", error)
    return jsonResponse({ error: "feedback_persist_failed" }, 500)
  }
}
async function fastHeuristicDecision(env, message, precomputedHeuristic = null, precomputedDomains = null, precomputedTrustContext = null) {
  const hardRule = hardRuleDecision(message, precomputedDomains, precomputedTrustContext)
  if (hardRule.matched) {
    const result = await buildFinalAnalysis(env, {
      heuristicScore: hardRule.score,
      heuristicReasons: hardRule.reason_codes,
      aiResult: null,
      decisionSource: hardRule.decision_source,
      explanation: hardRule.explanation,
      sourceMessage: message,
      precomputedDomains,
      precomputedTrustContext,
    })

    return {
      matched: true,
      result,
      heuristicScore: hardRule.score,
      heuristicReasons: hardRule.reason_codes,
    }
  }

  const trustedOtpUrl = isTrustedOtpUrlMessage(message, precomputedDomains, precomputedTrustContext)
  const heuristic = trustedOtpUrl && precomputedHeuristic
    ? {
      score: Math.min(clampScore(precomputedHeuristic.score), 35),
      reasonCodes: uniqueReasonCodes([
        ...(precomputedHeuristic.reasonCodes || []).filter((code) => code !== "OTP_SCAM"),
        "TRUSTED_DOMAIN",
      ]),
    }
    : (precomputedHeuristic || runHeuristic(message))
  const score = heuristic.score
  const reasons = heuristic.reasonCodes

  if (score <= 15 && !requiresAIReviewForLowScore(message, reasons)) {
    const result = await buildFinalAnalysis(env, {
      heuristicScore: score,
      heuristicReasons: reasons,
      aiResult: null,
      decisionSource: "heuristic_fast_allow",
      explanation: "Risque faible détecté par heuristique rapide.",
      sourceMessage: message,
      precomputedDomains,
      precomputedTrustContext,
    })

    return {
      matched: true,
      result,
      heuristicScore: score,
      heuristicReasons: reasons,
    }
  }

  if (score >= 90) {
    const result = await buildFinalAnalysis(env, {
      heuristicScore: score,
      heuristicReasons: reasons,
      aiResult: null,
      decisionSource: "heuristic_fast_block",
      explanation: "Risque critique détecté par heuristique rapide.",
      sourceMessage: message,
      precomputedDomains,
      precomputedTrustContext,
    })

    return {
      matched: true,
      result,
      heuristicScore: score,
      heuristicReasons: reasons,
    }
  }

  return {
    matched: false,
    heuristicScore: score,
    heuristicReasons: reasons,
  }
}

  

function firstNonEmptyValue(values = []) {
  for (const value of values) {
    const normalized = normalizeText(value)
    if (normalized) return normalized
  }

  return ""
}

function smsAnalyzeMessageFromBody(body) {
  return firstNonEmptyValue([
    body?.message,
    body?.query?.message?.text,
    body?.query?.message?.body,
  ])
}

function smsAnalyzeNumberFromBody(body) {
  return normalizeNumber(firstNonEmptyValue([
    body?.number,
    body?.phone_number,
    body?.phoneNumber,
    body?.sender,
    body?.query?.sender,
  ]))
}

function isAppleMessageFilterAnalyzeBody(body) {
  return Boolean(
    body &&
    typeof body === "object" &&
    !Array.isArray(body) &&
    (body._version !== undefined || body.query !== undefined)
  )
}

function isSMSAnalyzeValidationOnly(body) {
  const source = String(body?.source || body?.report_surface || body?.query?.source || "")
    .trim()
    .toLowerCase()
  return [
    "worker_validation",
    "worker_post_deploy_test",
    "post_deploy_test",
    "synthetic_test",
  ].includes(source)
}

async function handleSMSAnalyze(env, body, ctx = null) {
  const message = smsAnalyzeMessageFromBody(body)
  const number = smsAnalyzeNumberFromBody(body)
  const appleFastBudget = isAppleMessageFilterAnalyzeBody(body)
  const validationOnly = isSMSAnalyzeValidationOnly(body)
  const persistAnalysis = !validationOnly

  if (!message) {
    return jsonResponse({ error: "missing message" }, 400)
  }

  const startedAt = Date.now()
  let monitorPath = "unknown"
  const normalizedMessage = message.toLowerCase()
  const inputHash = await sha256Hex(`${number}|${normalizedMessage}`)
  const scheduleAnalyzePersistence = (row) => {
    if (!persistAnalysis) return Promise.resolve()
    return scheduleSMSAnalysisPersistence(ctx, env, row)
  }

  const baseHeuristic = runHeuristic(message)
  const baseDomains = collectMessageDomains(message)
  let d1ReadsEstimate = baseDomains.length > 0 ? 1 : 0
  const baseTrustContext = await lookupTrustedDomains(env, baseDomains)
  const baseDomainReputation = analyzeDomainReputation(baseDomains, baseTrustContext)
  const baseDomainsTrusted = areDomainsTrusted(baseDomains, baseTrustContext)
  const shouldLookupBrandRegistry =
    baseDomains.length > 0 &&
    !baseDomainsTrusted &&
    !baseDomainReputation.reasons.includes("KNOWN_MALICIOUS_DOMAIN")
  if (shouldLookupBrandRegistry) {
    d1ReadsEstimate += 1
  }
  const brandRegistryContext = shouldLookupBrandRegistry
    ? await lookupBrandRegistry(env, message, baseDomains)
    : buildBrandRegistryContext([], message)
  const brandAdjustedHeuristic = adjustHeuristicForOfficialBrandDomains(
    baseHeuristic,
    baseDomains,
    brandRegistryContext
  )
  const brandRegistrySpoof = analyzeBrandRegistrySpoof(
    message,
    baseDomains,
    baseDomainsTrusted,
    brandRegistryContext
  )
  const baseHeuristicWithReputation = {
    score: clampScore(brandAdjustedHeuristic.score + baseDomainReputation.score + brandRegistrySpoof.score),
    reasonCodes: uniqueReasonCodes([
      ...brandAdjustedHeuristic.reasonCodes,
      ...baseDomainReputation.reasons,
      ...brandRegistrySpoof.reasons,
    ]),
  }
  const baseSpoof = containsSpoofing(message, baseDomains, baseDomainsTrusted, brandRegistryContext)
  const messageSpoof = baseSpoof || brandRegistrySpoof.reasons.includes("BRAND_SPOOF")
  const baseHasUrl = containsUrl(message)
  const baseHasUrgency = containsUrgency(message)
  const baseHasShortener = containsShortener(message)
  const baseHasIdentity = hasIdentityRequest(message)
  const baseHasAccountThreat = hasAccountThreat(message)
  const baseHasTelemarketing = hasTelemarketingContent(message)
  const baseHasSuspiciousPattern = containsSuspiciousPattern(message)
  const trustedTransactional = baseDomainsTrusted && isTransactionalLegitMessage(message) && !hasFraudCriticalReason(baseHeuristicWithReputation.reasonCodes)
  const businessReputationScenario = hasBusinessReputationScenario(message)
  const businessReputationCandidateNames = businessNameCandidatesFromMessage(message)
  const shouldLookupBusinessReputationEarly =
    businessReputationScenario &&
    !trustedTransactional &&
    !baseDomainsTrusted &&
    !baseDomainReputation.reasons.includes("KNOWN_MALICIOUS_DOMAIN") &&
    (
      baseDomains.length > 0 ||
      Boolean(number) ||
      businessReputationCandidateNames.length > 0
    )
  if (shouldLookupBusinessReputationEarly) {
    d1ReadsEstimate += 1
  }
  const earlyBusinessReputation = shouldLookupBusinessReputationEarly
    ? await analyzeBusinessReputationSignals(env, baseDomains, number, message)
    : { score: 0, reasons: [] }
  const shouldLookupLiveNumberEarly = Boolean(number)
  if (shouldLookupLiveNumberEarly) {
    d1ReadsEstimate += 1
  }
  const earlyLiveNumber = shouldLookupLiveNumberEarly
    ? await analyzeLiveLookupNumberSignals(env, number)
    : { score: 0, reasons: [] }
  const shouldLookupFeedbackNumberEarly = Boolean(number) && !trustedTransactional
  if (shouldLookupFeedbackNumberEarly) {
    d1ReadsEstimate += 1
  }
  const rawEarlyFeedbackNumber = shouldLookupFeedbackNumberEarly
    ? await analyzeFeedbackNumberSignals(env, number)
    : { score: 0, reasons: [] }
  const earlyFeedbackNumber = suppressSafeFeedbackEntityForCriticalReasons(
    rawEarlyFeedbackNumber,
    uniqueReasonCodes([
      ...baseHeuristicWithReputation.reasonCodes,
      ...earlyLiveNumber.reasons,
    ])
  )
  const baseHeuristicWithEarlyReputation = {
    score: clampScore(baseHeuristicWithReputation.score + earlyBusinessReputation.score + earlyLiveNumber.score + earlyFeedbackNumber.score),
    reasonCodes: uniqueReasonCodes([
      ...baseHeuristicWithReputation.reasonCodes,
      ...earlyBusinessReputation.reasons,
      ...earlyLiveNumber.reasons,
      ...earlyFeedbackNumber.reasons,
    ]),
  }

  const clearTelemarketingFastPath =
    baseHasTelemarketing &&
    !baseHasUrl &&
    !baseHasShortener &&
    !baseHasUrgency &&
    !baseHasIdentity &&
    !baseHasAccountThreat &&
    (baseDomainsTrusted || !baseSpoof) &&
    !baseHeuristicWithEarlyReputation.reasonCodes.includes("KNOWN_FRAUD_NUMBER") &&
    baseHeuristicWithEarlyReputation.score <= 80

  if (clearTelemarketingFastPath) {
    const telemarketingHeuristicScore = clampScore(45 + earlyBusinessReputation.score + earlyLiveNumber.score + earlyFeedbackNumber.score)
    const telemarketingReasons = uniqueReasonCodes([
      ...baseHeuristic.reasonCodes,
      ...baseDomainReputation.reasons,
      ...earlyBusinessReputation.reasons,
      ...earlyLiveNumber.reasons,
      ...earlyFeedbackNumber.reasons,
      "TELEMARKETING_PATTERN",
    ])

    const rawResult = buildCanonicalAnalysis({
      sourceMessage: message,
      heuristicScore: telemarketingHeuristicScore,
      aiScore: null,
      finalScore: telemarketingHeuristicScore,
      category: "telemarketing",
      action: actionFromScore(telemarketingHeuristicScore, "telemarketing"),
      confidence: confidenceFromScore(telemarketingHeuristicScore),
      riskLevel: riskLevelFromScore(telemarketingHeuristicScore),
      decisionSource: "heuristic_telemarketing_fast",
      reasonCodes: telemarketingReasons,
      explanation: "FASTPATH_TELEMARKETING_HEURISTIC_ONLY",
      model: "heuristic",
      modelVersion: "fast_v2_telemarketing",
      trustContext: null,
      precomputedDomains: baseDomains,
      precomputedTrustContext: baseTrustContext,
      precomputedBrandContext: brandRegistryContext,
    })

    const result = finalizeCanonicalAnalysisResult(rawResult, {
      inputHash,
      modelVersion: "fast_v2_telemarketing",
      processingTimeMs: Date.now() - startedAt,
    })

    const decision = getAnalysisDecision(result)
    const meta = getAnalysisMeta(result)

    await scheduleAnalyzePersistence({
      input_hash: inputHash,
      number_e164: number || null,
      message,
      normalized_message: normalizedMessage,
      heuristic_score: telemarketingHeuristicScore,
      ai_score: null,
      final_score: getAnalysisScore(result),
      risk_level: decision.risk_level,
      action: decision.action,
      category: decision.category,
      decision_source: decision.decision_source,
      model: meta.model,
      model_version: meta.model_version || "fast_v2_telemarketing",
      reason_codes_json: JSON.stringify(decision.reason_codes || []),
      explanation: decision.explanation || "",
      user_feedback: null,
      reviewed_label: null,
    })

    monitorPath = "telemarketing_fast"
    logSMSAnalyzePath({
      path: monitorPath,
      number,
      result,
      startedAt,
      usedAI: false,
      usedDomainAge: false,
      appleFastBudget,
      d1ReadsEstimate,
    })
    return jsonResponse(result)
  }

  const suspiciousCore =
    baseHasUrl ||
    baseHasUrgency ||
    (!baseDomainsTrusted && baseSpoof) ||
    baseHasSuspiciousPattern ||
    baseHasIdentity ||
    baseHasTelemarketing ||
    earlyBusinessReputation.score > 0 ||
    earlyLiveNumber.score > 0 ||
    earlyFeedbackNumber.score > 0

  const localFrequencyReadsEstimate = trustedTransactional || !suspiciousCore
    ? 0
    : (number ? 4 : 2)
  d1ReadsEstimate += localFrequencyReadsEstimate

  const localFrequency = trustedTransactional || !suspiciousCore
    ? { score: 0, reasons: [] }
    : await analyzeLocalFrequencySignals(env, number, normalizedMessage)
  const shouldCheckGlobalThreatGraph = Boolean(number || suspiciousCore)

  const fastDecision = await fastHeuristicDecision(env, message, baseHeuristicWithEarlyReputation, baseDomains, baseTrustContext)

  if (fastDecision.matched) {
    const rawResult = await buildFinalAnalysis(env, {
      heuristicScore: clampScore(fastDecision.heuristicScore + localFrequency.score),
      heuristicReasons: [...fastDecision.heuristicReasons, ...localFrequency.reasons],
      aiResult: null,
      decisionSource: `${getAnalysisDecision(fastDecision.result).decision_source}_with_frequency`,
      explanation: getAnalysisDecision(fastDecision.result).explanation,
      sourceMessage: message,
      precomputedDomains: baseDomains,
      precomputedTrustContext: baseTrustContext,
      precomputedBrandContext: brandRegistryContext,
    })

    const result = finalizeCanonicalAnalysisResult(rawResult, {
      inputHash,
      modelVersion: "fast_v1",
      processingTimeMs: Date.now() - startedAt,
    })

    const fastDecisionData = getAnalysisDecision(result)
    const fastMeta = getAnalysisMeta(result)

    await scheduleAnalyzePersistence({
      input_hash: inputHash,
      number_e164: number || null,
      message,
      normalized_message: normalizedMessage,
      heuristic_score: clampScore(fastDecision.heuristicScore + localFrequency.score),
      ai_score: null,
      final_score: getAnalysisScore(result),
      risk_level: fastDecisionData.risk_level,
      action: fastDecisionData.action,
      category: fastDecisionData.category,
      decision_source: fastDecisionData.decision_source,
      model: fastMeta.model,
      model_version: fastMeta.model_version || "fast_v1",
      reason_codes_json: JSON.stringify(fastDecisionData.reason_codes || []),
      explanation: fastDecisionData.explanation || "",
      user_feedback: null,
      reviewed_label: null,
    })

    monitorPath = "fast_heuristic"
    logSMSAnalyzePath({
      path: monitorPath,
      number,
      result,
      startedAt,
      usedAI: false,
      usedDomainAge: false,
      appleFastBudget,
      d1ReadsEstimate,
    })

    return jsonResponse(result)
  }


  const campaignFromFrequency = campaignPatternFromDistinctNumbers(localFrequency.distinctNumbers)
  const localGraphFromFrequency = localThreatGraphFromCount(localFrequency.messageCount)
  const useExternalEnrichment = !appleFastBudget
  const usedDomainAge = useExternalEnrichment && baseHasUrl
  const useLocalEnrichment = !trustedTransactional && suspiciousCore
  const clusterReadsEstimate = useLocalEnrichment && number ? 1 : 0
  const localGraphReadsEstimate = useLocalEnrichment && number ? 1 : 0
  const shouldLookupFeedbackEntityAggregates =
    useLocalEnrichment &&
    baseDomains.length > 0 &&
    !baseDomainsTrusted &&
    !baseDomainReputation.reasons.includes("KNOWN_MALICIOUS_DOMAIN")
  const shouldLookupExternalUrlEvidence =
    baseDomains.length > 0 &&
    !baseDomainsTrusted &&
    !baseDomainReputation.reasons.includes("KNOWN_MALICIOUS_DOMAIN")
  const shouldLookupBusinessReputation =
    !shouldLookupBusinessReputationEarly &&
    useLocalEnrichment &&
    businessReputationScenario &&
    !baseDomainsTrusted &&
    !baseDomainReputation.reasons.includes("KNOWN_MALICIOUS_DOMAIN") &&
    (
      baseDomains.length > 0 ||
      Boolean(number) ||
      businessReputationCandidateNames.length > 0
    )
  const feedbackEntityReadsEstimate = shouldLookupFeedbackEntityAggregates ? 1 : 0
  const externalUrlEvidenceReadsEstimate = shouldLookupExternalUrlEvidence ? 1 : 0
  const businessReputationReadsEstimate = shouldLookupBusinessReputation ? 1 : 0
  d1ReadsEstimate += clusterReadsEstimate + localGraphReadsEstimate + feedbackEntityReadsEstimate + externalUrlEvidenceReadsEstimate + businessReputationReadsEstimate

  const [
    domainRisk,
    cluster,
    reputation,
    carrier,
    campaign,
    globalGraph,
    localGraph,
    rawFeedbackEntity,
    externalUrlEvidence,
    businessReputation,
  ] = await Promise.all([
    usedDomainAge ? checkDomainAgeRisk(env, message).catch(() => ({ score: 0, reasons: [] })) : Promise.resolve({ score: 0, reasons: [] }),
    useLocalEnrichment ? analyzeNumberCluster(env, number) : Promise.resolve({ score: 0, reasons: [] }),
    useExternalEnrichment ? checkPhoneReputation(env, number) : Promise.resolve({ score: 0, reasons: [] }),
    useExternalEnrichment ? checkCarrierRisk(env, number) : Promise.resolve({ score: 0, reasons: [] }),
    useLocalEnrichment ? Promise.resolve(campaignFromFrequency) : Promise.resolve({ score: 0, reasons: [] }),
    useExternalEnrichment && shouldCheckGlobalThreatGraph ? fetchGlobalThreatGraph(env, number, normalizedMessage) : Promise.resolve({ score: 0, reasons: [] }),
    useLocalEnrichment
      ? number
        ? buildLocalThreatGraph(env, number, normalizedMessage)
        : Promise.resolve(localGraphFromFrequency)
      : Promise.resolve({ score: 0, reasons: [] }),
    shouldLookupFeedbackEntityAggregates ? analyzeFeedbackEntitySignals(env, baseDomains) : Promise.resolve({ score: 0, reasons: [] }),
    shouldLookupExternalUrlEvidence ? analyzeExternalUrlEvidenceSignals(env, baseDomains) : Promise.resolve({ score: 0, reasons: [] }),
    shouldLookupBusinessReputationEarly
      ? Promise.resolve({ score: 0, reasons: [] })
      : shouldLookupBusinessReputation ? analyzeBusinessReputationSignals(env, baseDomains, number, message) : Promise.resolve({ score: 0, reasons: [] }),
  ])

  const correlation = correlateSignals({
    hasUrl: baseHasUrl,
    spoof: baseDomainsTrusted ? false : messageSpoof,
    urgency: baseHasUrgency,
    cluster: !trustedTransactional && cluster.score > 20,
    reputation: reputation.score > 30,
  })

  const preFeedbackEntityReasons = [
    ...fastDecision.heuristicReasons,
    ...localFrequency.reasons,
    ...domainRisk.reasons,
    ...cluster.reasons,
    ...campaign.reasons,
    ...reputation.reasons,
    ...carrier.reasons,
    ...globalGraph.reasons,
    ...localGraph.reasons,
    ...externalUrlEvidence.reasons,
    ...businessReputation.reasons,
    ...correlation.reasons,
  ]
  const feedbackEntity = suppressSafeFeedbackEntityForCriticalReasons(rawFeedbackEntity, preFeedbackEntityReasons)

  const enrichedHeuristicScore = clampScore(
    fastDecision.heuristicScore +
    localFrequency.score +
    domainRisk.score +
    cluster.score +
    campaign.score +
    reputation.score +
    carrier.score +
    globalGraph.score +
    localGraph.score +
    externalUrlEvidence.score +
    businessReputation.score +
    correlation.score +
    feedbackEntity.score
  )

  const combinedReasons = [
    ...preFeedbackEntityReasons,
    ...feedbackEntity.reasons,
  ]


  const lowScoreNeedsAIReview = requiresAIReviewForLowScore(message, combinedReasons)
  const canUseSensitiveLowRiskFastWarn =
    enrichedHeuristicScore < 70 &&
    lowScoreNeedsAIReview &&
    !appleFastBudget &&
    !baseHasUrl &&
    !baseHasUrgency &&
    !baseHasShortener &&
    !trustedTransactional

  if ((enrichedHeuristicScore <= 35 && !lowScoreNeedsAIReview) || canUseSensitiveLowRiskFastWarn) {
    const lowRiskHeuristicScore = canUseSensitiveLowRiskFastWarn
      ? Math.max(enrichedHeuristicScore, 35)
      : enrichedHeuristicScore
    const lowRiskDecisionSource = canUseSensitiveLowRiskFastWarn
      ? "heuristic_fallback_enriched"
      : "heuristic_low_risk_enriched"
    const lowRiskExplanation = canUseSensitiveLowRiskFastWarn
      ? "Décision heuristique rapide pour signal sensible faible."
      : "Risque faible à modéré détecté avec enrichissement local."
    const rawResult = await buildFinalAnalysis(env, {
      heuristicScore: lowRiskHeuristicScore,
      heuristicReasons: combinedReasons,
      aiResult: null,
      decisionSource: lowRiskDecisionSource,
      explanation: lowRiskExplanation,
      sourceMessage: message,
      precomputedDomains: baseDomains,
      precomputedTrustContext: baseTrustContext,
      precomputedBrandContext: brandRegistryContext,
    })

    const result = finalizeCanonicalAnalysisResult(rawResult, {
      inputHash,
      modelVersion: canUseSensitiveLowRiskFastWarn ? "fast_sensitive_v1" : "fast_v2",
      processingTimeMs: Date.now() - startedAt,
    })

    const lowRiskDecision = getAnalysisDecision(result)
    const lowRiskMeta = getAnalysisMeta(result)

    await scheduleAnalyzePersistence({
      input_hash: inputHash,
      number_e164: number || null,
      message,
      normalized_message: normalizedMessage,
      heuristic_score: lowRiskHeuristicScore,
      ai_score: null,
      final_score: getAnalysisScore(result),
      risk_level: lowRiskDecision.risk_level,
      action: lowRiskDecision.action,
      category: lowRiskDecision.category,
      decision_source: lowRiskDecision.decision_source,
      model: lowRiskMeta.model,
      model_version: lowRiskMeta.model_version || (canUseSensitiveLowRiskFastWarn ? "fast_sensitive_v1" : "fast_v2"),
      reason_codes_json: JSON.stringify(lowRiskDecision.reason_codes || []),
      explanation: lowRiskDecision.explanation || "",
      user_feedback: null,
      reviewed_label: null,
    })

    monitorPath = canUseSensitiveLowRiskFastWarn ? "sensitive_low_risk_fast_warn" : "heuristic_low_risk_enriched"
    logSMSAnalyzePath({
      path: monitorPath,
      number,
      result,
      startedAt,
      usedAI: false,
      usedDomainAge,
      appleFastBudget,
      d1ReadsEstimate,
    })

    return jsonResponse(result)
  }

  if (enrichedHeuristicScore >= 70) {
    const rawResult = await buildFinalAnalysis(env, {
      heuristicScore: enrichedHeuristicScore,
      heuristicReasons: combinedReasons,
      aiResult: null,
      decisionSource: "heuristic_high_risk_enriched",
      explanation: "Risque élevé détecté avec enrichissement local.",
      sourceMessage: message,
      precomputedDomains: baseDomains,
      precomputedTrustContext: baseTrustContext,
      precomputedBrandContext: brandRegistryContext,
    })

    const result = finalizeCanonicalAnalysisResult(rawResult, {
      inputHash,
      modelVersion: "fast_v2",
      processingTimeMs: Date.now() - startedAt,
    })

    const highRiskDecision = getAnalysisDecision(result)
    const highRiskMeta = getAnalysisMeta(result)

    await scheduleAnalyzePersistence({
      input_hash: inputHash,
      number_e164: number || null,
      message,
      normalized_message: normalizedMessage,
      heuristic_score: enrichedHeuristicScore,
      ai_score: null,
      final_score: getAnalysisScore(result),
      risk_level: highRiskDecision.risk_level,
      action: highRiskDecision.action,
      category: highRiskDecision.category,
      decision_source: highRiskDecision.decision_source,
      model: highRiskMeta.model,
      model_version: highRiskMeta.model_version || "fast_v2",
      reason_codes_json: JSON.stringify(highRiskDecision.reason_codes || []),
      explanation: highRiskDecision.explanation || "",
      user_feedback: null,
      reviewed_label: null,
    })

    monitorPath = "heuristic_high_risk_enriched"
    logSMSAnalyzePath({
      path: monitorPath,
      number,
      result,
      startedAt,
      usedAI: false,
      usedDomainAge,
      appleFastBudget,
      d1ReadsEstimate,
    })

    return jsonResponse(result)
  }

  if (appleFastBudget) {
    const appleHeuristicScore = requiresAIReviewForLowScore(message, combinedReasons)
      ? Math.max(enrichedHeuristicScore, 35)
      : enrichedHeuristicScore
    const rawResult = await buildFinalAnalysis(env, {
      heuristicScore: appleHeuristicScore,
      heuristicReasons: combinedReasons,
      aiResult: null,
      decisionSource: "heuristic_fallback_enriched",
      explanation: "Décision heuristique enrichie avec budget extension Apple.",
      sourceMessage: message,
      precomputedDomains: baseDomains,
      precomputedTrustContext: baseTrustContext,
      precomputedBrandContext: brandRegistryContext,
    })

    const result = finalizeCanonicalAnalysisResult(rawResult, {
      inputHash,
      modelVersion: "apple_fast_v1",
      processingTimeMs: Date.now() - startedAt,
    })

    const appleDecision = getAnalysisDecision(result)
    const appleMeta = getAnalysisMeta(result)

    await scheduleAnalyzePersistence({
      input_hash: inputHash,
      number_e164: number || null,
      message,
      normalized_message: normalizedMessage,
      heuristic_score: appleHeuristicScore,
      ai_score: null,
      final_score: getAnalysisScore(result),
      risk_level: appleDecision.risk_level,
      action: appleDecision.action,
      category: appleDecision.category,
      decision_source: appleDecision.decision_source,
      model: appleMeta.model,
      model_version: appleMeta.model_version || "apple_fast_v1",
      reason_codes_json: JSON.stringify(appleDecision.reason_codes || []),
      explanation: appleDecision.explanation || "",
      user_feedback: null,
      reviewed_label: null,
    })

    monitorPath = "apple_fast_budget"
    logSMSAnalyzePath({
      path: monitorPath,
      number,
      result,
      startedAt,
      usedAI: false,
      usedDomainAge,
      appleFastBudget,
      d1ReadsEstimate,
    })

    return jsonResponse(result)
  }

  const trustedDomainFastAllow =
    baseDomains.length > 0 &&
    baseDomainsTrusted &&
    !hasFraudCriticalReason(combinedReasons)

  if (trustedDomainFastAllow) {
    const rawResult = await buildFinalAnalysis(env, {
      heuristicScore: enrichedHeuristicScore,
      heuristicReasons: combinedReasons,
      aiResult: null,
      decisionSource: "heuristic_fallback_enriched",
      explanation: "Décision heuristique rapide pour domaine trusted.",
      sourceMessage: message,
      precomputedDomains: baseDomains,
      precomputedTrustContext: baseTrustContext,
      precomputedBrandContext: brandRegistryContext,
    })

    const result = finalizeCanonicalAnalysisResult(rawResult, {
      inputHash,
      modelVersion: "fast_v2",
      processingTimeMs: Date.now() - startedAt,
    })

    const trustedDecision = getAnalysisDecision(result)
    const trustedMeta = getAnalysisMeta(result)

    await scheduleAnalyzePersistence({
      input_hash: inputHash,
      number_e164: number || null,
      message,
      normalized_message: normalizedMessage,
      heuristic_score: enrichedHeuristicScore,
      ai_score: null,
      final_score: getAnalysisScore(result),
      risk_level: trustedDecision.risk_level,
      action: trustedDecision.action,
      category: trustedDecision.category,
      decision_source: trustedDecision.decision_source,
      model: trustedMeta.model,
      model_version: trustedMeta.model_version || "fast_v2",
      reason_codes_json: JSON.stringify(trustedDecision.reason_codes || []),
      explanation: trustedDecision.explanation || "",
      user_feedback: null,
      reviewed_label: null,
    })

    monitorPath = "trusted_domain_fast_allow"
    logSMSAnalyzePath({
      path: monitorPath,
      number,
      result,
      startedAt,
      usedAI: false,
      usedDomainAge,
      appleFastBudget,
      d1ReadsEstimate,
    })

    return jsonResponse(result)
  }

  if (validationOnly) {
    const validationHeuristicScore = requiresAIReviewForLowScore(message, combinedReasons)
      ? Math.max(enrichedHeuristicScore, 35)
      : enrichedHeuristicScore
    const rawResult = await buildFinalAnalysis(env, {
      heuristicScore: validationHeuristicScore,
      heuristicReasons: combinedReasons,
      aiResult: null,
      decisionSource: "heuristic_fallback_enriched",
      explanation: "Décision heuristique enrichie avec budget validation Worker.",
      sourceMessage: message,
      precomputedDomains: baseDomains,
      precomputedTrustContext: baseTrustContext,
      precomputedBrandContext: brandRegistryContext,
    })

    const result = finalizeCanonicalAnalysisResult(rawResult, {
      inputHash,
      modelVersion: "validation_fast_v1",
      processingTimeMs: Date.now() - startedAt,
    })

    const validationDecision = getAnalysisDecision(result)
    const validationMeta = getAnalysisMeta(result)

    await scheduleAnalyzePersistence({
      input_hash: inputHash,
      number_e164: number || null,
      message,
      normalized_message: normalizedMessage,
      heuristic_score: validationHeuristicScore,
      ai_score: null,
      final_score: getAnalysisScore(result),
      risk_level: validationDecision.risk_level,
      action: validationDecision.action,
      category: validationDecision.category,
      decision_source: validationDecision.decision_source,
      model: validationMeta.model,
      model_version: validationMeta.model_version || "validation_fast_v1",
      reason_codes_json: JSON.stringify(validationDecision.reason_codes || []),
      explanation: validationDecision.explanation || "",
      user_feedback: null,
      reviewed_label: null,
    })

    monitorPath = "worker_validation_fast_budget"
    logSMSAnalyzePath({
      path: monitorPath,
      number,
      result,
      startedAt,
      usedAI: false,
      usedDomainAge,
      appleFastBudget,
      d1ReadsEstimate,
    })

    return jsonResponse(result)
  }

  try {
    const aiAnalysisContext = {
      heuristic_score: enrichedHeuristicScore,
      reason_codes: combinedReasons,
      domains: baseDomains,
      trusted_domains: baseDomains.filter((domain) => isDomainTrusted(domain, baseTrustContext)),
      trust_level: baseTrustContext?.trustLevel || "low",
      signals: {
        has_url: baseHasUrl,
        has_urgency: baseHasUrgency,
        has_shortener: baseHasShortener,
        has_spoof: baseDomainsTrusted ? false : messageSpoof,
        has_identity: baseHasIdentity,
        has_account_threat: baseHasAccountThreat,
        has_telemarketing: baseHasTelemarketing,
      },
    }
    const aiResult = await callOpenAI(env, message, number, aiAnalysisContext)

    const rawResult = await buildFinalAnalysis(env, {
      heuristicScore: enrichedHeuristicScore,
      heuristicReasons: combinedReasons,
      aiResult,
      decisionSource: aiResult ? "fusion_enriched" : "heuristic_fallback_enriched",
      explanation: aiResult?.explanation || "Décision heuristique enrichie avec fallback rapide.",
      sourceMessage: message,
      precomputedDomains: baseDomains,
      precomputedTrustContext: baseTrustContext,
      precomputedBrandContext: brandRegistryContext,
    })

    const result = finalizeCanonicalAnalysisResult(rawResult, {
      inputHash,
      modelVersion: env.OPENAI_MODEL || "gpt-5-mini",
      processingTimeMs: Date.now() - startedAt,
    })

    const fusionDecision = getAnalysisDecision(result)
    const fusionMeta = getAnalysisMeta(result)

    await scheduleAnalyzePersistence({
      input_hash: inputHash,
      number_e164: number || null,
      message,
      normalized_message: normalizedMessage,
      heuristic_score: enrichedHeuristicScore,
      ai_score: aiResult?.score ?? null,
      final_score: getAnalysisScore(result),
      risk_level: fusionDecision.risk_level,
      action: fusionDecision.action,
      category: fusionDecision.category,
      decision_source: fusionDecision.decision_source,
      model: fusionMeta.model,
      model_version: fusionMeta.model_version || (env.OPENAI_MODEL || "gpt-5-mini"),
      reason_codes_json: JSON.stringify(fusionDecision.reason_codes || []),
      explanation: fusionDecision.explanation || "",
      user_feedback: null,
      reviewed_label: null,
    })

    monitorPath = aiResult ? "fusion_enriched" : "heuristic_fallback_enriched"
    logSMSAnalyzePath({
      path: monitorPath,
      number,
      result,
      startedAt,
      usedAI: aiResult !== null,
      usedDomainAge,
      appleFastBudget,
      d1ReadsEstimate,
    })

    return jsonResponse(result)
  } catch (error) {
    console.error("sms_analyze_enriched_ai_failed", error)

    const rawResult = await buildFinalAnalysis(env, {
      heuristicScore: enrichedHeuristicScore,
      heuristicReasons: combinedReasons,
      aiResult: null,
      decisionSource: "heuristic_fallback_enriched",
      explanation: "Fallback heuristique enrichi.",
      sourceMessage: message,
      precomputedDomains: baseDomains,
      precomputedTrustContext: baseTrustContext,
      precomputedBrandContext: brandRegistryContext,
    })

    const result = finalizeCanonicalAnalysisResult(rawResult, {
      inputHash,
      modelVersion: "fallback_fast_v2",
      processingTimeMs: Date.now() - startedAt,
    })

    const fallbackDecision = getAnalysisDecision(result)
    const fallbackMeta = getAnalysisMeta(result)

    await scheduleAnalyzePersistence({
      input_hash: inputHash,
      number_e164: number || null,
      message,
      normalized_message: normalizedMessage,
      heuristic_score: enrichedHeuristicScore,
      ai_score: null,
      final_score: getAnalysisScore(result),
      risk_level: fallbackDecision.risk_level,
      action: fallbackDecision.action,
      category: fallbackDecision.category,
      decision_source: fallbackDecision.decision_source,
      model: fallbackMeta.model,
      model_version: fallbackMeta.model_version || "fallback_fast_v2",
      reason_codes_json: JSON.stringify(fallbackDecision.reason_codes || []),
      explanation: fallbackDecision.explanation || "",
      user_feedback: null,
      reviewed_label: null,
    })

    monitorPath = "heuristic_fallback_enriched_error"
    logSMSAnalyzePath({
      path: monitorPath,
      number,
      result,
      startedAt,
      usedAI: false,
      usedDomainAge,
      appleFastBudget,
      d1ReadsEstimate,
    })

    return jsonResponse(result)
  }
}

async function handleLookup(env, phoneNumber) {
  const number = normalizeNumber(phoneNumber)
  if (!number) return emptyResponse()

  const live = await lookupLive(env, number)
  if (live) return live

  const feedback = await fallbackFeedback(env, number)
  if (feedback) return feedback

  const reports = await fallbackReports(env, number)
  if (reports) return reports

  return emptyResponse()
}

async function handleNativeReport(env, body, forcedChannel = null) {
  const channel = String(
    forcedChannel || body?.channel || "sms"
  ).trim().toLowerCase()

  const number = normalizeNumber(
    body?.number || body?.phone_number || body?.phoneNumber || body?.sender || ""
  )
  const message = String(body?.message || "").trim()
  const source = String(body?.source || "ios_reporting_extension").trim() || "ios_reporting_extension"
  const reportSurface = String(
    body?.report_surface || body?.reportSurface || "apple_reporting_extension"
  ).trim() || "apple_reporting_extension"
  const reportedAtRaw = body?.reported_at ?? body?.reportedAt ?? Date.now()
  const reportedAt = Number(reportedAtRaw)

  if (!number) {
    return jsonResponse({ error: "missing number" }, 400)
  }

  if (!Number.isFinite(reportedAt)) {
    return jsonResponse({ error: "invalid reported_at" }, 400)
  }

  const normalizedMessage = message ? normalizeText(message).toLowerCase() : ""
  const sourceUrl = String(body?.source_url || body?.sourceUrl || body?.url || "").trim()
  const extractedUrls = [...new Set([
    ...extractUrls(message),
    ...(sourceUrl ? [sourceUrl] : []),
  ].filter(Boolean))]
  const extractedDomains = [...new Set(collectMessageDomains(`${message} ${sourceUrl}`))]
  const inputHash = await sha256Hex(
    message
      ? `${number}|${normalizedMessage}`
      : `${number}|${channel}|${reportedAt}`
  )

  if (channel === "sms" || channel === "mms") {
    const smsReportColumns = await ensureSMSReportsSchema(env)

    const insertColumns = [
      "number_e164",
      "message",
      "source",
      "channel",
      "report_surface",
      "reported_at",
      "created_at",
    ]
    const bindValues = [
      number,
      message,
      source,
      channel,
      reportSurface,
      reportedAt,
      Math.floor(Date.now() / 1000),
    ]

    if (smsReportColumns.has("normalized_message")) {
      insertColumns.push("normalized_message")
      bindValues.push(normalizedMessage)
    }

    if (smsReportColumns.has("input_hash")) {
      insertColumns.push("input_hash")
      bindValues.push(inputHash)
    }

    if (smsReportColumns.has("source_url")) {
      insertColumns.push("source_url")
      bindValues.push(sourceUrl)
    }

    if (smsReportColumns.has("urls_json")) {
      insertColumns.push("urls_json")
      bindValues.push(JSON.stringify(extractedUrls))
    }

    if (smsReportColumns.has("domains_json")) {
      insertColumns.push("domains_json")
      bindValues.push(JSON.stringify(extractedDomains))
    }

    const placeholders = insertColumns.map((_, index) => `?${index + 1}`).join(", ")

    await env.DB.prepare(`
      INSERT INTO sms_reports (${insertColumns.join(", ")})
      VALUES (${placeholders})
    `)
      .bind(...bindValues)
      .run()

    const feedbackCategory = feedbackCategoryFromNativeReport(body)

    await persistFeedbackSourceAggregate(env, {
      source,
      sourceContext: reportSurface,
      platform: "ios",
      reportSurface,
      channel,
      category: feedbackCategory,
      timestamp: reportedAt,
      validationStatus: "accepted",
    })

    await persistFeedbackEntityAggregates(env, {
      number,
      message,
      sourceUrl,
      category: feedbackCategory,
      timestamp: reportedAt,
      dedupeKey: `native_report:${channel}:${inputHash}:${feedbackCategory}`,
      source,
      sourceContext: reportSurface,
      reportSurface,
    })

    return jsonResponse({
      success: true,
      channel,
      number_e164: number,
      urls_count: extractedUrls.length,
      domains_count: extractedDomains.length,
    })
  }

  if (channel === "call") {
    await env.DB.prepare(`
      INSERT INTO call_reports (
        number_e164,
        source,
        channel,
        report_surface,
        reported_at,
        created_at
      ) VALUES (?1, ?2, ?3, ?4, ?5, unixepoch())
    `)
      .bind(number, source, channel, reportSurface, reportedAt)
      .run()

    const feedbackCategory = feedbackCategoryFromNativeReport(body)
    await persistFeedbackSourceAggregate(env, {
      source,
      sourceContext: reportSurface,
      platform: "ios",
      reportSurface,
      channel,
      category: feedbackCategory,
      timestamp: reportedAt,
      validationStatus: "accepted",
    })

    return jsonResponse({
      success: true,
      channel,
      number_e164: number,
    })
  }

  return jsonResponse({ error: "unsupported channel" }, 400)
}

export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url)

      if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/health")) {
        return healthResponse()
      }

      if (request.method === "GET" && url.pathname === "/.well-known/apple-app-site-association") {
        return appleAppSiteAssociationResponse()
      }

      if (request.method === "POST" && url.pathname === "/live-caller-id/lookup") {
        const body = await request.json().catch(() => null)
        const phoneNumber = body?.phone_number || body?.phoneNumber || body?.number || ""

        if (!phoneNumber) {
          return jsonResponse({ error: "missing phone_number" }, 400)
        }

        const result = await handleLookup(env, phoneNumber)
        return jsonResponse(result)
      }

      if (request.method === "POST" && url.pathname === "/live-caller-id/token") {
        return jsonResponse({
          token: liveCallerIDToken(env),
          expires_in: 3600,
        })
      }

      if (request.method === "POST" && url.pathname === "/ai/sms/analyze") {
        const body = await request.json().catch(() => null)
        if (!body) {
          return jsonResponse({ error: "invalid json" }, 400)
        }
        return await handleSMSAnalyze(env, body, ctx)
      }

      if (request.method === "POST" && url.pathname === "/ai/sms/feedback") {
        const body = await request.json().catch(() => null)
        if (!body) {
          return jsonResponse({ error: "invalid json" }, 400)
        }
        return await handleSMSFeedback(env, body)
      }

      if (request.method === "POST" && url.pathname === "/sms/report") {
        const body = await request.json().catch(() => null)
        if (!body) {
          return jsonResponse({ error: "invalid json" }, 400)
        }
        return await handleNativeReport(env, body, "sms")
      }

      if (request.method === "POST" && url.pathname === "/call/report") {
        const body = await request.json().catch(() => null)
        if (!body) {
          return jsonResponse({ error: "invalid json" }, 400)
        }
        return await handleNativeReport(env, body, "call")
      }

      if (request.method === "POST" && url.pathname === "/report") {
        const body = await request.json().catch(() => null)
        if (!body) {
          return jsonResponse({ error: "invalid json" }, 400)
        }
        return await handleNativeReport(env, body, null)
      }

      return new Response("Not found", { status: 404 })
    } catch (error) {
      console.error("worker_request_failed", error)
      return jsonResponse({ error: "internal_error" }, 500)
    }
  },
}
