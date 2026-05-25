#!/usr/bin/env node

import assert from "node:assert/strict"
import fs from "node:fs"
import path from "node:path"
import { fileURLToPath } from "node:url"
import vm from "node:vm"

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const workerPath = path.join(__dirname, "..", "worker.js")

function normalizeSql(sql) {
  return String(sql || "").trim().replace(/\s+/g, " ")
}

function tableInfoRows(names) {
  return names.map((name, index) => ({ cid: index, name }))
}

const defaultTableColumns = {
  sms_reports: [
    "id",
    "number_e164",
    "message",
    "source",
    "reported_at",
    "created_at",
    "channel",
    "report_surface",
    "normalized_message",
    "input_hash",
    "source_url",
    "urls_json",
    "domains_json",
  ],
  feedback_events: [
    "number_e164",
    "message",
    "user_feedback",
    "created_at",
    "event_id",
    "primary_category",
    "user_disposition",
    "dedupe_key",
    "validation_status",
  ],
}

class MockD1Statement {
  constructor(db, sql) {
    this.db = db
    this.sql = sql
    this.args = []
  }

  bind(...args) {
    const statement = new MockD1Statement(this.db, this.sql)
    statement.args = args
    return statement
  }

  async first() {
    return this.db.first(this.sql, this.args)
  }

  async all() {
    return this.db.all(this.sql, this.args)
  }

  async run() {
    this.db.runs.push({ sql: normalizeSql(this.sql), args: this.args })
    return { meta: { changes: 1 } }
  }
}

class MockD1 {
  constructor(options = {}) {
    this.options = options
    this.statements = []
    this.runs = []
  }

  prepare(sql) {
    this.statements.push(normalizeSql(sql))
    return new MockD1Statement(this, sql)
  }

  async all(sql) {
    const normalized = normalizeSql(sql)
    if (normalized.startsWith("PRAGMA table_info(")) {
      const tableName = normalized.match(/PRAGMA table_info\(([^)]+)\)/)?.[1] || ""
      const columns = this.options.tableColumns?.[tableName] || defaultTableColumns[tableName] || []
      return { results: tableInfoRows(columns) }
    }

    if (normalized.includes("FROM trusted_domains")) {
      return { results: this.options.trustedDomainRows || [] }
    }

    return { results: [] }
  }

  async first(sql) {
    const normalized = normalizeSql(sql)

    if (normalized.includes("FROM live_lookup")) {
      return this.options.liveLookupRow || null
    }

    if (normalized.includes("FROM feedback_events") && normalized.includes("ORDER BY created_at DESC")) {
      return this.options.feedbackLookupRow || null
    }

    if (normalized.includes("FROM feedback_events") && normalized.includes("validation_status = 'accepted'")) {
      return this.options.feedbackEventCounts || { scam_count: 0, safe_count: 0 }
    }

    if (normalized.includes("FROM sms_reports") && normalized.includes("SELECT category")) {
      return this.options.smsReportRow || null
    }

    if (normalized.includes("COUNT(DISTINCT number_e164) as distinct_numbers")) {
      return {
        count: this.options.messageCount || 0,
        distinct_numbers: this.options.distinctNumbers || 0,
      }
    }

    if (normalized.includes("COUNT(DISTINCT number_e164) as unique_numbers")) {
      return { unique_numbers: this.options.campaignUniqueNumbers || 0 }
    }

    if (normalized.includes("SUM(CASE WHEN user_feedback = 'confirmed_scam'")) {
      return this.options.datasetFeedbackCounts || { scam_count: 0, safe_count: 0 }
    }

    if (normalized.includes("WHERE number_e164 LIKE")) {
      return { count: this.options.clusterCount || 0 }
    }

    if (
      normalized.includes("FROM sms_analysis_dataset") &&
      normalized.includes("WHERE number_e164 = ?1") &&
      normalized.includes("OR normalized_message = ?2")
    ) {
      return { count: this.options.localGraphCount || 0 }
    }

    if (normalized.includes("FROM sms_analysis_dataset") && normalized.includes("WHERE number_e164 = ?1")) {
      return { count: this.options.numberCount || 0 }
    }

    if (normalized.includes("FROM sms_analysis_dataset") && normalized.includes("WHERE input_hash = ?1")) {
      return null
    }

    return null
  }
}

function makeEnv(options = {}) {
  const db = new MockD1(options)
  return {
    DB: db,
    OPENAI_API_KEY: options.openAIKey || "",
    OPENAI_MODEL: "gpt-5-mini",
    OPENAI_FETCH_TIMEOUT_MS: options.openAITimeoutMs || "",
    DOMAIN_CHECK_API_KEY: options.domainCheckApiKey || "",
    DOMAIN_API_USER: options.domainApiUser || "",
    REPUTATION_API_KEY: options.reputationApiKey || "",
    THREAT_GRAPH_URL: options.threatGraphUrl || "",
    THREAT_GRAPH_KEY: options.threatGraphKey || "",
    CARRIER_LOOKUP_ENABLED: options.carrierLookupEnabled || "",
    LIVE_CALLER_ID_TOKEN: "test-live-token",
    __db: db,
  }
}

function loadWorker(fetchImpl = async () => new Response("{}", { status: 404 }), options = {}) {
  const source = fs.readFileSync(workerPath, "utf8")
  const code = source.replace("export default {", "globalThis.worker = {")
  const logSink = typeof options.logSink === "function" ? options.logSink : null
  const context = {
    AbortController,
    Request,
    Response,
    TextEncoder,
    URL,
    clearTimeout,
    crypto: globalThis.crypto,
    fetch: fetchImpl,
    setTimeout,
    console: {
      log: (...args) => {
        if (logSink) logSink(args)
      },
      warn: () => {},
      error: (...args) => {
        if (process.env.CALLSHIELD_TEST_VERBOSE) {
          console.error(...args)
        }
      },
    },
  }

  vm.createContext(context)
  vm.runInContext(code, context, { filename: "worker.js" })
  return context
}

async function postJson(context, env, pathname, body, ctx = {}) {
  const response = await context.worker.fetch(
    new Request(`https://worker.test${pathname}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    }),
    env,
    ctx
  )

  return {
    status: response.status,
    payload: await response.json(),
  }
}

function trustedDomainRow(domain, overrides = {}) {
  return {
    domain,
    root_domain: domain,
    brand_key: overrides.brand_key || domain.split(".")[0],
    trust_score: overrides.trust_score ?? 100,
    trust_level: overrides.trust_level || "verified",
    status: overrides.status || "active",
  }
}

function decisionOf(payload) {
  return payload?.decision || {}
}

function scoreOf(payload) {
  return Number(payload?.features?.final_score ?? 0)
}

function reasonsOf(payload) {
  return decisionOf(payload).reason_codes || []
}

const context = loadWorker(async () => {
  return new Response(JSON.stringify({ output_text: "{not json" }), { status: 200 })
})

const tests = []

function test(name, fn) {
  tests.push({ name, fn })
}

test("safe SMS stays safe/allow", async () => {
  const env = makeEnv()
  const result = await postJson(context, env, "/ai/sms/analyze", {
    message: "Bonjour, votre rendez-vous est confirme demain a 14h.",
  })

  assert.equal(result.status, 200)
  assert.equal(decisionOf(result.payload).category, "safe")
  assert.equal(decisionOf(result.payload).action, "allow")
  assert.ok(scoreOf(result.payload) <= 15)
})

test("Apple Message Filter payload is accepted", async () => {
  const env = makeEnv()
  const result = await postJson(context, env, "/ai/sms/analyze", {
    _version: 1,
    query: {
      sender: "+33 6 12 34 56 78",
      message: {
        text: "Bonjour, votre rendez-vous est confirme demain a 14h.",
      },
    },
  })

  assert.equal(result.status, 200)
  assert.equal(result.payload.input.raw, "Bonjour, votre rendez-vous est confirme demain a 14h.")
  assert.equal(decisionOf(result.payload).category, "safe")
  assert.equal(decisionOf(result.payload).action, "allow")
  assert.ok(env.__db.runs.some((run) => run.args.includes("33612345678")))
})

test("Apple Message Filter payload without text is rejected", async () => {
  const env = makeEnv()
  const result = await postJson(context, env, "/ai/sms/analyze", {
    _version: 1,
    query: {
      sender: "+33 6 12 34 56 78",
      message: {},
    },
  })

  assert.equal(result.status, 400)
  assert.deepEqual(result.payload, { error: "missing message" })
})

test("Apple Message Filter fast budget skips OpenAI and external fetches", async () => {
  let fetchCalls = 0
  const appleContext = loadWorker(async () => {
    fetchCalls += 1
    return new Response(JSON.stringify({
      output_text: JSON.stringify({
        is_scam: false,
        score: 0,
        category: "safe",
        reason_codes: [],
        explanation: "benin",
      }),
    }), { status: 200 })
  })
  const env = makeEnv({
    openAIKey: "test-key",
    domainCheckApiKey: "domain-key",
    domainApiUser: "domain-user",
    reputationApiKey: "rep-key",
    threatGraphUrl: "https://threat.test/analyze",
    threatGraphKey: "threat-key",
    carrierLookupEnabled: "true",
  })
  const result = await postJson(appleContext, env, "/ai/sms/analyze", {
    _version: 1,
    query: {
      sender: "+33 6 12 34 56 78",
      message: {
        text: "Paiement requis pour votre livraison.",
      },
    },
  })

  assert.equal(result.status, 200)
  assert.equal(fetchCalls, 0)
  assert.equal(decisionOf(result.payload).decision_source, "heuristic_fallback_enriched")
  assert.equal(decisionOf(result.payload).action, "warn")
  assert.ok(scoreOf(result.payload) >= 35)
  assert.ok(reasonsOf(result.payload).includes("PAYMENT_PRESSURE"))
})

test("sms analysis path log includes observability fields", async () => {
  const logs = []
  const observedContext = loadWorker(async () => {
    return new Response(JSON.stringify({ output_text: "{not json" }), { status: 200 })
  }, {
    logSink(args) {
      logs.push(args)
    },
  })
  const env = makeEnv({ openAIKey: "test-key" })
  const result = await postJson(observedContext, env, "/ai/sms/analyze", {
    _version: 1,
    query: {
      sender: "+33 6 12 34 56 78",
      message: {
        text: "Paiement requis pour votre livraison.",
      },
    },
  })

  const entry = logs.find((args) => args[0] === "sms_analyze_path")
  assert.ok(entry, "expected sms_analyze_path log")

  const payload = JSON.parse(entry[1])
  assert.equal(result.status, 200)
  assert.equal(payload.path, "apple_fast_budget")
  assert.equal(payload.apple_fast_budget, true)
  assert.equal(payload.used_ai, false)
  assert.equal(payload.final_score, scoreOf(result.payload))
  assert.equal(payload.score, payload.final_score)
  assert.equal(payload.action, decisionOf(result.payload).action)
  assert.equal(payload.category, decisionOf(result.payload).category)
  assert.equal(payload.risk_level, decisionOf(result.payload).risk_level)
  assert.equal(payload.decision_source, decisionOf(result.payload).decision_source)
  assert.equal(typeof payload.processing_time_ms, "number")
  assert.equal(typeof payload.d1_reads_estimate, "number")
  assert.ok(payload.d1_reads_estimate >= 0)
})

test("sms analysis persistence is scheduled with waitUntil", async () => {
  const env = makeEnv()
  const scheduled = []
  const result = await postJson(context, env, "/ai/sms/analyze", {
    message: "Bonjour, votre rendez-vous est confirme demain a 14h.",
  }, {
    waitUntil(promise) {
      scheduled.push(Promise.resolve(promise))
    },
  })

  assert.equal(result.status, 200)
  assert.equal(decisionOf(result.payload).action, "allow")
  assert.equal(scheduled.length, 1)

  await Promise.all(scheduled)
  assert.equal(env.__db.runs.length, 2)
})

test("OTP-only SMS stays safe/allow", async () => {
  const env = makeEnv()
  const result = await postJson(context, env, "/ai/sms/analyze", {
    message: "Votre code de verification est 123456.",
  })

  assert.equal(result.status, 200)
  assert.equal(decisionOf(result.payload).category, "safe")
  assert.equal(decisionOf(result.payload).action, "allow")
  assert.ok(reasonsOf(result.payload).includes("OTP_ONLY"))
})

test("trusted La Poste tracking link is allowed", async () => {
  const env = makeEnv({
    trustedDomainRows: [
      trustedDomainRow("laposte.fr", { brand_key: "laposte", trust_level: "high" }),
    ],
  })
  const result = await postJson(context, env, "/ai/sms/analyze", {
    message: "Votre colis La Poste est expedie. Suivi https://laposte.fr/suivi",
  })

  assert.equal(result.status, 200)
  assert.equal(decisionOf(result.payload).category, "safe")
  assert.equal(decisionOf(result.payload).action, "allow")
  assert.ok(reasonsOf(result.payload).includes("TRUSTED_DOMAIN"))
})

test("fraud trusted_domains row produces malicious-domain signal", async () => {
  const env = makeEnv({
    trustedDomainRows: [
      trustedDomainRow("secure-login-verif.xyz", {
        brand_key: "",
        status: "fraud",
        trust_level: "low",
        trust_score: 0,
      }),
    ],
  })
  const result = await postJson(context, env, "/ai/sms/analyze", {
    message: "Urgent: votre compte est suspendu. Validez ici https://secure-login-verif.xyz",
  })

  assert.equal(result.status, 200)
  assert.equal(decisionOf(result.payload).category, "fraud")
  assert.equal(decisionOf(result.payload).action, "block")
  assert.ok(reasonsOf(result.payload).includes("KNOWN_MALICIOUS_DOMAIN"))
})

test("suspicious delivery URL becomes high-risk fraud", async () => {
  const env = makeEnv()
  const result = await postJson(context, env, "/ai/sms/analyze", {
    message: "Urgent: votre colis est bloque. Payez 0.99 EUR ici https://suivi-colis-secure.xyz",
  })

  assert.equal(result.status, 200)
  assert.equal(decisionOf(result.payload).category, "fraud")
  assert.equal(decisionOf(result.payload).action, "block")
  assert.ok(scoreOf(result.payload) >= 70)
})

test("invalid OpenAI payload returns null", async () => {
  const result = await context.callOpenAI(
    { OPENAI_API_KEY: "test-key", OPENAI_MODEL: "gpt-5-mini" },
    "Message ambigu avec lien",
    "",
    { heuristic_score: 45, reason_codes: ["URL"], domains: ["example.com"] }
  )

  assert.equal(result, null)
})

test("OpenAI timeout budget defaults and clamps safely", () => {
  assert.equal(context.openAIFetchTimeoutMs({}), 1500)
  assert.equal(context.openAIFetchTimeoutMs({ OPENAI_FETCH_TIMEOUT_MS: "900" }), 900)
  assert.equal(context.openAIFetchTimeoutMs({ OPENAI_FETCH_TIMEOUT_MS: "100" }), 500)
  assert.equal(context.openAIFetchTimeoutMs({ OPENAI_FETCH_TIMEOUT_MS: "5000" }), 2500)
})

test("carrier lookup disabled by default does not fetch", async () => {
  let fetchCalls = 0
  const carrierContext = loadWorker(async () => {
    fetchCalls += 1
    return new Response(JSON.stringify({ provider: "VoIP Carrier" }), { status: 200 })
  })
  const result = await carrierContext.checkCarrierRisk({}, "33612345678")

  assert.equal(fetchCalls, 0)
  assert.equal(result.score, 0)
  assert.deepEqual(Array.from(result.reasons), [])
})

test("carrier lookup enabled preserves carrier scoring", async () => {
  const fetchUrls = []
  const carrierContext = loadWorker(async (url) => {
    fetchUrls.push(String(url))
    return new Response(JSON.stringify({ spam: false, provider: "VoIP Carrier" }), { status: 200 })
  })
  const result = await carrierContext.checkCarrierRisk(
    { CARRIER_LOOKUP_ENABLED: "true" },
    "33612345678"
  )

  assert.equal(fetchUrls.length, 1)
  assert.ok(fetchUrls[0].includes("https://messageproviderlookup.com/api?number=33612345678"))
  assert.equal(result.score, 15)
  assert.deepEqual(Array.from(result.reasons), ["VOIP_NUMBER"])
})

test("safe AI cannot clear payment pressure warning", async () => {
  const message = "Paiement requis pour votre livraison."
  const heuristic = context.runHeuristic(message)
  const result = await context.buildFinalAnalysis(makeEnv(), {
    heuristicScore: heuristic.score,
    heuristicReasons: heuristic.reasonCodes,
    aiResult: { is_scam: false, score: 0, category: "safe", reason_codes: [], explanation: "benin" },
    decisionSource: "fusion_enriched",
    explanation: "benin",
    sourceMessage: message,
  })

  assert.ok(reasonsOf(result).includes("PAYMENT_PRESSURE"))
  assert.ok(scoreOf(result) >= 35)
  assert.equal(decisionOf(result).action, "warn")
})

test("low-risk payment pressure skips OpenAI and stays warning", async () => {
  let fetchCalls = 0
  const fallbackContext = loadWorker(async () => {
    fetchCalls += 1
    return new Response(JSON.stringify({ output_text: "{not json" }), { status: 200 })
  })
  const env = makeEnv({ openAIKey: "test-key" })
  const result = await postJson(fallbackContext, env, "/ai/sms/analyze", {
    message: "Paiement requis pour votre livraison.",
    number: "+33 6 00 00 00 04",
  })

  assert.equal(result.status, 200)
  assert.equal(fetchCalls, 0)
  assert.ok(reasonsOf(result.payload).includes("PAYMENT_PRESSURE"))
  assert.ok(scoreOf(result.payload) >= 35)
  assert.equal(decisionOf(result.payload).action, "warn")
  assert.equal(decisionOf(result.payload).decision_source, "heuristic_fallback_enriched")
})

test("safe AI cannot clear fake authority warning", async () => {
  const message = "Assistance securite: verifiez vos informations de compte."
  const heuristic = context.runHeuristic(message)
  const result = await context.buildFinalAnalysis(makeEnv(), {
    heuristicScore: heuristic.score,
    heuristicReasons: heuristic.reasonCodes,
    aiResult: { is_scam: false, score: 0, category: "safe", reason_codes: [], explanation: "benin" },
    decisionSource: "fusion_enriched",
    explanation: "benin",
    sourceMessage: message,
  })

  assert.ok(reasonsOf(result).includes("FAKE_AUTHORITY"))
  assert.ok(scoreOf(result) >= 35)
  assert.equal(decisionOf(result).action, "warn")
})

test("low-risk payment pressure without number skips AI and avoids redundant D1 reads", async () => {
  let fetchCalls = 0
  const aiContext = loadWorker(async () => {
    fetchCalls += 1
    return new Response(JSON.stringify({
      output_text: JSON.stringify({
        is_scam: false,
        score: 0,
        category: "safe",
        reason_codes: [],
        explanation: "benin",
      }),
    }), { status: 200 })
  })
  const env = makeEnv({ openAIKey: "test-key" })
  const result = await postJson(aiContext, env, "/ai/sms/analyze", {
    message: "Paiement requis pour votre livraison.",
  })

  assert.equal(result.status, 200)
  assert.equal(decisionOf(result.payload).decision_source, "heuristic_fallback_enriched")
  assert.equal(decisionOf(result.payload).action, "warn")
  assert.ok(scoreOf(result.payload) >= 35)
  assert.equal(fetchCalls, 0)
  assert.ok(env.__db.statements.length <= 4, `expected <= 4 D1 statements, got ${env.__db.statements.length}`)
  assert.equal(
    env.__db.statements.filter((sql) => sql.includes("WHERE number_e164 = ?1")).length,
    0
  )
})

test("repeated payment pressure without number skips AI", async () => {
  let fetchCalls = 0
  const aiContext = loadWorker(async () => {
    fetchCalls += 1
    return new Response(JSON.stringify({ output_text: "{not json" }), { status: 200 })
  })
  const env = makeEnv({ openAIKey: "test-key", messageCount: 3 })
  const result = await postJson(aiContext, env, "/ai/sms/analyze", {
    message: "Paiement requis pour votre livraison.",
  })

  assert.equal(result.status, 200)
  assert.equal(fetchCalls, 0)
  assert.ok(reasonsOf(result.payload).includes("PAYMENT_PRESSURE"))
  assert.ok(reasonsOf(result.payload).includes("REPEAT_MESSAGE"))
  assert.ok(scoreOf(result.payload) >= 40)
  assert.equal(decisionOf(result.payload).action, "warn")
})

test("account threat still reaches AI window", async () => {
  let fetchCalls = 0
  const aiContext = loadWorker(async () => {
    fetchCalls += 1
    return new Response(JSON.stringify({
      output_text: JSON.stringify({
        is_scam: true,
        score: 60,
        category: "fraud",
        reason_codes: ["ACCOUNT_THREAT"],
        explanation: "menace compte",
      }),
    }), { status: 200 })
  })
  const env = makeEnv({ openAIKey: "test-key" })
  const result = await postJson(aiContext, env, "/ai/sms/analyze", {
    message: "Suspension possible de votre compte.",
  })

  assert.equal(result.status, 200)
  assert.equal(fetchCalls, 1)
  assert.equal(decisionOf(result.payload).decision_source, "fusion_enriched")
  assert.equal(decisionOf(result.payload).category, "fraud")
  assert.equal(decisionOf(result.payload).action, "warn")
})

test("OpenAI fallback cannot clear account threat warning", async () => {
  let fetchCalls = 0
  const fallbackContext = loadWorker(async () => {
    fetchCalls += 1
    return new Response(JSON.stringify({ output_text: "{not json" }), { status: 200 })
  })
  const env = makeEnv({ openAIKey: "test-key" })
  const result = await postJson(fallbackContext, env, "/ai/sms/analyze", {
    message: "Suspension possible de votre compte.",
  })

  assert.equal(result.status, 200)
  assert.equal(fetchCalls, 1)
  assert.equal(decisionOf(result.payload).decision_source, "heuristic_fallback_enriched")
  assert.equal(decisionOf(result.payload).action, "warn")
  assert.ok(scoreOf(result.payload) >= 35)
})

test("frequency counters preserve derived campaign and local graph scoring", async () => {
  const spread = context.campaignPatternFromDistinctNumbers(11)
  assert.equal(spread.score, 25)
  assert.deepEqual(Array.from(spread.reasons), ["SPREAD_CAMPAIGN"])

  const multi = context.campaignPatternFromDistinctNumbers(21)
  assert.equal(multi.score, 40)
  assert.deepEqual(Array.from(multi.reasons), ["MULTI_NUMBER_CAMPAIGN"])

  const medium = context.localThreatGraphFromCount(11)
  assert.equal(medium.score, 20)
  assert.deepEqual(Array.from(medium.reasons), ["LOCAL_GRAPH_MEDIUM"])

  const high = context.localThreatGraphFromCount(31)
  assert.equal(high.score, 35)
  assert.deepEqual(Array.from(high.reasons), ["LOCAL_GRAPH_HIGH"])
})

test("iOS feedback fraud x2 adds USER_CONFIRMED_SCAM", async () => {
  const env = makeEnv({ feedbackEventCounts: { scam_count: 2, safe_count: 0 } })
  const result = await context.analyzeLocalFrequencySignals(env, "33612345678", "message")

  assert.equal(result.score, 30)
  assert.deepEqual(Array.from(result.reasons), ["USER_CONFIRMED_SCAM"])
})

test("iOS feedback safe x2 adds USER_CONFIRMED_SAFE", async () => {
  const env = makeEnv({ feedbackEventCounts: { scam_count: 0, safe_count: 2 } })
  const result = await context.analyzeLocalFrequencySignals(env, "33612345678", "message")

  assert.equal(result.score, -25)
  assert.deepEqual(Array.from(result.reasons), ["USER_CONFIRMED_SAFE"])
})

test("conflicting iOS feedback is neutral", async () => {
  const env = makeEnv({ feedbackEventCounts: { scam_count: 2, safe_count: 2 } })
  const result = await context.analyzeLocalFrequencySignals(env, "33612345678", "message")

  assert.equal(result.score, 0)
  assert.deepEqual(Array.from(result.reasons), [])
})

test("live caller lookup with no match returns stable empty JSON", async () => {
  const env = makeEnv({
    tableColumns: {
      ...defaultTableColumns,
      sms_reports: ["id", "number_e164", "created_at"],
    },
  })
  const result = await postJson(context, env, "/live-caller-id/lookup", {
    phone_number: "33600000001",
  })

  assert.equal(result.status, 200)
  assert.deepEqual(result.payload, {
    match: false,
    label: null,
    category: null,
    confidence: 0,
  })
})

;(async () => {
  let failed = 0

  for (const { name, fn } of tests) {
    try {
      await fn()
      console.log(`PASS ${name}`)
    } catch (error) {
      failed += 1
      console.error(`FAIL ${name}`)
      console.error(error?.stack || error)
    }
  }

  if (failed > 0) {
    console.error(`${failed}/${tests.length} tests failed`)
    process.exit(1)
  }

  console.log(`${tests.length} worker analysis tests passed`)
})()
