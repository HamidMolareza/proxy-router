import { useEffect, useRef, useState } from 'react'

const PROXY_TYPES = ['http', 'https', 'socks5']
const ROUTE_TYPES = ['direct', 'proxy', 'self', 'rejected']
const HISTORY_RANGE_OPTIONS = [
  { value: '1h', label: 'Last hour' },
  { value: '24h', label: 'Last 24 hours' },
  { value: '7d', label: 'Last 7 days' },
  { value: 'all', label: 'All time' },
]
const TAB_DEFINITIONS = [
  { id: 'overview', label: 'Overview' },
  { id: 'history', label: 'History' },
  { id: 'routing', label: 'Routing' },
  { id: 'quotas', label: 'Quotas' },
  { id: 'failures', label: 'Failures' },
]
const COMMON_SECOND_LEVEL_DOMAIN_LABELS = new Set([
  'ac',
  'co',
  'com',
  'edu',
  'gov',
  'mil',
  'net',
  'org',
  'sch',
])
const AUTO_PROXY_POLICY_LABEL = '2 failures -> probe -> success enables proxy'
const RULE_DURATION_OPTIONS = ['1h', '1d', '7d', '30d', '90d', 'always']
const EXEMPTION_DURATION_OPTIONS = ['2h', '6h', '12h', '1d', '7d', '30d', 'always']
const DEFAULT_ROUTING_PROFILE_ID = 'default'
const RULE_DURATION_SECONDS = {
  '1h': 3600,
  '1d': 86400,
  '7d': 7 * 86400,
  '30d': 30 * 86400,
  '90d': 90 * 86400,
  always: null,
}
const RULES_PAGE_SIZE = 10
const DEFAULT_FAILURE_PAGE_SIZE = 10
const BYTES_IN_MB = 1_000_000

function cx(...classes) {
  return classes.filter(Boolean).join(' ')
}

const pageClass = [
  'min-h-screen bg-[linear-gradient(180deg,#f6f2e9_0%,#ece6d8_100%)] text-[#1f2a30]',
  "font-['IBM_Plex_Sans','Noto_Sans',sans-serif]",
  '[&_h1]:text-2xl [&_h1]:leading-tight [&_h1]:font-bold sm:[&_h1]:text-3xl',
  '[&_h2]:text-lg [&_h2]:leading-snug [&_h2]:font-bold sm:[&_h2]:text-xl',
  '[&_h3]:text-base [&_h3]:leading-snug [&_h3]:font-bold',
  "[&_button]:min-h-10 [&_button]:cursor-pointer [&_button]:rounded-[10px] [&_button]:border [&_button]:border-[#c8c0b2] [&_button]:bg-[#fffdf8] [&_button]:px-3 [&_button]:py-2 [&_button]:text-[#1f2a30]",
  '[&_button:disabled]:cursor-default [&_button:disabled]:opacity-55',
  "[&_input[type='number']]:w-full [&_input[type='number']]:rounded-[10px] [&_input[type='number']]:border [&_input[type='number']]:border-[#d8d1c2] [&_input[type='number']]:bg-[#fffdf8] [&_input[type='number']]:px-3 [&_input[type='number']]:py-2",
  "[&_input[type='search']]:w-full [&_input[type='search']]:rounded-[10px] [&_input[type='search']]:border [&_input[type='search']]:border-[#d8d1c2] [&_input[type='search']]:bg-[#fffdf8] [&_input[type='search']]:px-3 [&_input[type='search']]:py-2",
  "[&_input[type='text']]:w-full [&_input[type='text']]:rounded-[10px] [&_input[type='text']]:border [&_input[type='text']]:border-[#d8d1c2] [&_input[type='text']]:bg-[#fffdf8] [&_input[type='text']]:px-3 [&_input[type='text']]:py-2",
  '[&_select]:w-full [&_select]:rounded-[10px] [&_select]:border [&_select]:border-[#d8d1c2] [&_select]:bg-[#fffdf8] [&_select]:px-3 [&_select]:py-2',
].join(' ')
const shellClass = 'mx-auto w-full max-w-[1200px] px-2 py-3 sm:px-4 sm:py-6'
const heroClass = 'mb-3 flex flex-col items-start gap-2 sm:mb-4 min-[901px]:flex-row min-[901px]:items-end min-[901px]:justify-between'
const panelClass = 'min-w-0 rounded-xl border border-[#d8d1c2] bg-[#fffdf8] p-3 shadow-[0_8px_20px_rgba(24,36,39,0.06)] sm:rounded-[18px] sm:p-4 sm:shadow-[0_12px_30px_rgba(24,36,39,0.08)]'
const subpanelClass = 'min-w-0 overflow-x-auto rounded-xl border border-[#e8e0d1] bg-gradient-to-b from-white to-[#f6f4ed] p-3 sm:rounded-[14px] sm:p-4'
const panelHeaderClass = 'flex flex-wrap items-stretch justify-between gap-3 sm:items-center sm:gap-4'
const noteClass = 'mt-2 text-sm leading-relaxed text-[#6a6f73]'
const mutedClass = 'text-[#6a6f73]'
const pillClass = 'inline-block max-w-full [overflow-wrap:anywhere] rounded-full bg-[#d9ece8] px-3 py-1.5 font-semibold text-[#116466]'
const warningPillClass = 'bg-[#f7e4bb] text-[#9b6b00]'
const mutedPillClass = 'bg-[#ece7dc] text-[#6a6f73]'
const gridClass = 'grid grid-cols-12 gap-4'
const cardGridClass = 'col-span-full grid grid-cols-1 gap-2 min-[361px]:grid-cols-2 sm:grid-cols-[repeat(auto-fit,minmax(150px,1fr))] sm:gap-3'
const cardClass = 'min-w-0 rounded-[10px] border border-[#e8e0d1] bg-gradient-to-b from-white to-[#f6f4ed] p-3 sm:rounded-[14px] sm:p-4'
const cardLabelClass = 'text-xs text-[#6a6f73] sm:text-sm'
const cardValueClass = 'mt-1 [overflow-wrap:anywhere] text-base leading-tight font-bold sm:text-xl'
const tableWrapClass = [
  '-mx-1 w-full overflow-x-auto px-1 pb-1 [-webkit-overflow-scrolling:touch]',
  '[&_table]:w-full [&_table]:border-collapse [&_table]:text-sm max-sm:[&_table]:min-w-[42rem] sm:[&_table]:text-[0.95rem]',
  '[&_th]:border-b [&_th]:border-[#ece5d8] [&_th]:px-2 [&_th]:py-2 [&_th]:text-left [&_th]:align-top [&_th]:text-xs [&_th]:font-semibold [&_th]:tracking-[0.05em] [&_th]:text-[#6a6f73] [&_th]:uppercase',
  '[&_td]:border-b [&_td]:border-[#ece5d8] [&_td]:px-2 [&_td]:py-2 [&_td]:align-top',
].join(' ')
const controlClass = 'flex min-w-0 flex-col gap-1 text-sm text-[#6a6f73] sm:min-w-36'
const controlsClass = 'mt-3 mb-1 grid grid-cols-1 gap-3 sm:flex sm:flex-wrap'
const fieldGridClass = 'mt-3 grid grid-cols-1 gap-3 sm:grid-cols-[repeat(auto-fit,minmax(180px,1fr))]'
const fieldClass = 'flex min-w-0 flex-col gap-1 text-sm text-[#6a6f73]'
const buttonRowClass = 'mt-3 flex flex-wrap gap-3 max-sm:[&>button]:w-full'
const tightButtonRowClass = 'mt-0 flex flex-wrap gap-3 max-sm:[&>button]:w-full'
const warnButtonClass = '!border-[#e4c980] !bg-[#f7e4bb] !text-[#6b4a00]'
const primaryButtonClass = '!border-[#116466] !bg-[#116466] !text-white'
const dirtyInputClass = '!border-[#116466] shadow-[0_0_0_3px_rgba(17,100,102,0.12)]'
const readOnlyInputClass = 'opacity-70'
const chipListClass = 'mt-3 flex flex-wrap gap-2'
const chipClass = 'inline-flex max-w-full items-center gap-2 [overflow-wrap:anywhere] rounded-full border border-[#ddd2bf] bg-white px-3 py-1.5 text-sm'
const chipButtonClass = '!min-h-0 !border-0 !bg-transparent !p-0 !font-bold !text-[#8c5a00]'
const ruleActionsClass = 'flex flex-wrap gap-2 max-sm:flex-col max-sm:items-stretch max-sm:[&_button]:w-full max-sm:[&_button]:whitespace-nowrap'
const rulePillClass = 'inline-flex items-center rounded-full border border-[#dbcdb7] bg-[#f1ece2] px-2 py-1 text-xs font-bold text-[#5a4631]'
const autoRulePillClass = '!border-[#b9d7d8] !bg-[#e3f1f1] !text-[#13595b]'
const ruleMetaClass = 'flex flex-col gap-1 text-sm'

function getTabFromHash() {
  const tabId = window.location.hash.replace(/^#/, '').trim()
  return TAB_DEFINITIONS.some((item) => item.id === tabId) ? tabId : 'overview'
}

function clamp(value, min, max) {
  return Math.min(Math.max(value, min), max)
}

function cloneJson(value) {
  return JSON.parse(JSON.stringify(value))
}

function emptyUsageSummary() {
  return {
    count: 0,
    uploaded_bytes: 0,
    downloaded_bytes: 0,
    total_bytes: 0,
  }
}

function emptyDashboardSnapshot() {
  return {
    started_at: 'Waiting for data',
    overall: emptyUsageSummary(),
    active_by_proxy: {},
    totals_by_proxy: {},
    totals_by_route: {},
    recent_requests: [],
    recent_failures: [],
    latest_request: null,
    totals_by_client: [],
    client_quota_status: {},
    failure_summary: {
      grouped_visible: [],
      grouped_ignored: [],
      visible_total: 0,
      ignored_total: 0,
      page_size: DEFAULT_FAILURE_PAGE_SIZE,
    },
    router_runtime: {
      network: {
        available: false,
        internet_label: '',
        route_interface: '',
        route_gateway: '',
        vpn_labels: [],
        signature: {
          internet_key: '',
          internet_label: '',
          route_interface: '',
          route_gateway: '',
          vpn_keys: [],
          vpn_labels: [],
        },
      },
      active_profile: {
        id: DEFAULT_ROUTING_PROFILE_ID,
        name: 'Shared',
        using_fallback: true,
      },
      upstream_status: emptyUpstreamStatus(),
    },
  }
}

function emptyUpstreamStatus() {
  return {
    enabled: false,
    type: 'http',
    host: '127.0.0.1',
    port: 0,
    connectivity: {
      status: 'disabled',
      checked_at: null,
      message: 'Upstream proxy is disabled.',
      protocol_verified: false,
    },
    last_success: null,
    last_failure: null,
  }
}

function emptyHistoryData() {
  return {
    range: '24h',
    range_title: 'Last 24 hours',
    proxy_type: 'all',
    summary: emptyUsageSummary(),
    series: [],
    top_destinations: [],
    invalid_lines: 0,
    available_proxy_types: [],
    time_range: {
      from: null,
      to: null,
    },
  }
}

function formatMb(byteCount) {
  return `${(Number(byteCount || 0) / BYTES_IN_MB).toFixed(2)} MB`
}

function formatPercent(numerator, denominator) {
  if (!denominator) {
    return '0%'
  }
  return `${Math.round((Number(numerator || 0) / Number(denominator)) * 100)}%`
}

function normalizeOptionalLimitMb(value) {
  const parsed = parseInt(value, 10)
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return null
  }
  return parsed
}

function formatLimitMb(value) {
  return value == null ? 'none' : formatMb(Number(value) * BYTES_IN_MB)
}

function formatDuration(seconds) {
  const remaining = Math.max(1, parseInt(seconds, 10) || 0)
  const days = Math.floor(remaining / 86400)
  const hours = Math.floor((remaining % 86400) / 3600)
  const minutes = Math.floor((remaining % 3600) / 60)
  const secs = remaining % 60
  const parts = []
  if (days) {
    parts.push(`${days}d`)
  }
  if (hours) {
    parts.push(`${hours}h`)
  }
  if (minutes) {
    parts.push(`${minutes}m`)
  }
  if (secs && !hours && !days) {
    parts.push(`${secs}s`)
  }
  return parts.join(' ') || 'under a minute'
}

function parseDateText(value) {
  if (!value) {
    return null
  }
  const parsed = new Date(String(value))
  return Number.isNaN(parsed.getTime()) ? null : parsed
}

function durationSecondsForCompactDuration(duration) {
  const normalized = String(duration || '').trim().toLowerCase()
  if (normalized === 'always') {
    return null
  }
  const match = normalized.match(/^(\d+)([smhdw])$/)
  if (!match) {
    return null
  }
  const amount = Number(match[1])
  const unit = match[2]
  if (!Number.isFinite(amount) || amount <= 0) {
    return null
  }
  if (unit === 's') {
    return amount
  }
  if (unit === 'm') {
    return amount * 60
  }
  if (unit === 'h') {
    return amount * 3600
  }
  if (unit === 'd') {
    return amount * 86400
  }
  if (unit === 'w') {
    return amount * 7 * 86400
  }
  return null
}

function normalizeExemptionDuration(value) {
  const normalized = String(value || '').trim().toLowerCase() || 'always'
  return normalized === 'always' || durationSecondsForCompactDuration(normalized) != null
    ? normalized
    : '2h'
}

function ensureExemptionExpiration(exemption, resetExpiration = false) {
  if (!exemption) {
    return exemption
  }
  const duration = normalizeExemptionDuration(exemption.duration)
  exemption.duration = duration
  if (duration === 'always') {
    exemption.expires_at = null
    return exemption
  }
  const seconds = durationSecondsForCompactDuration(duration)
  if (seconds == null) {
    exemption.expires_at = null
    return exemption
  }
  if (!exemption.expires_at || resetExpiration) {
    exemption.expires_at = new Date(Date.now() + seconds * 1000).toISOString()
  }
  return exemption
}

function isExemptionExpired(exemption) {
  const expiresAt = parseDateText(exemption && exemption.expires_at)
  return expiresAt ? expiresAt.getTime() <= Date.now() : false
}

function formatExemptionExpiry(exemption, nowMs) {
  const expiresAt = parseDateText(exemption && exemption.expires_at)
  if (!expiresAt) {
    return 'Permanent'
  }
  const remainingSeconds = Math.max(0, Math.floor((expiresAt.getTime() - nowMs) / 1000))
  return `active for ${formatDuration(remainingSeconds)} more · until ${expiresAt.toLocaleString()}`
}

function normalizeRuleSource(rule) {
  return rule && rule.source === 'auto' ? 'auto' : 'manual'
}

function normalizeRuleDuration(value, source) {
  const normalized = String(value || '').trim().toLowerCase()
  if (RULE_DURATION_OPTIONS.includes(normalized)) {
    return normalized
  }
  if (source === 'auto') {
    return '1h'
  }
  return 'always'
}

function ensureRuleExpiration(rule, resetExpiration = false) {
  if (!rule) {
    return rule
  }
  const duration = normalizeRuleDuration(rule.duration, normalizeRuleSource(rule))
  rule.duration = duration
  if (duration === 'always') {
    rule.expires_at = null
    return rule
  }
  const seconds = Object.prototype.hasOwnProperty.call(RULE_DURATION_SECONDS, duration)
    ? RULE_DURATION_SECONDS[duration]
    : null
  if (seconds == null) {
    rule.expires_at = null
    return rule
  }
  if (!rule.expires_at || resetExpiration) {
    rule.expires_at = new Date(Date.now() + seconds * 1000).toISOString()
  }
  return rule
}

function isRuleExpired(rule) {
  const expiresAt = parseDateText(rule && rule.expires_at)
  return expiresAt ? expiresAt.getTime() <= Date.now() : false
}

function formatRuleExpiry(rule, nowMs) {
  const expiresAt = parseDateText(rule && rule.expires_at)
  if (!expiresAt) {
    return 'Always'
  }
  const remainingSeconds = Math.max(0, Math.floor((expiresAt.getTime() - nowMs) / 1000))
  return `expires in ${formatDuration(remainingSeconds)} · until ${expiresAt.toLocaleString()}`
}

function summarizeDomain(host) {
  const normalizedHost = String(host || '').trim().toLowerCase().replace(/\.+$/, '')
  if (!normalizedHost || normalizedHost.includes(':') || /^\d+\.\d+\.\d+\.\d+$/.test(normalizedHost)) {
    return normalizedHost
  }
  const labels = normalizedHost.split('.').filter(Boolean)
  if (labels.length <= 2) {
    return normalizedHost
  }
  if (
    labels[labels.length - 1].length === 2 &&
    COMMON_SECOND_LEVEL_DOMAIN_LABELS.has(labels[labels.length - 2]) &&
    labels.length >= 3
  ) {
    return labels.slice(-3).join('.')
  }
  return labels.slice(-2).join('.')
}

function normalizeRulePattern(pattern) {
  return String(pattern || '')
    .trim()
    .toLowerCase()
    .replace(/^\*\./, '')
    .replace(/^\.+/, '')
    .replace(/\.+$/, '')
}

function normalizeRules(rules) {
  const normalizedRules = (Array.isArray(rules) ? rules : [])
    .map((rule) => {
      const source = normalizeRuleSource(rule)
      return ensureRuleExpiration({
        enabled: rule.enabled !== false,
        pattern: normalizeRulePattern(rule.pattern),
        match: ['exact', 'suffix', 'contains'].includes(rule.match) ? rule.match : 'suffix',
        action: ['proxy', 'block'].includes(rule.action) ? rule.action : 'direct',
        note: String(rule.note || ''),
        source,
        duration: normalizeRuleDuration(rule.duration, source),
        expires_at: rule.expires_at ? String(rule.expires_at) : null,
      })
    })
    .filter((rule) => !isRuleExpired(rule))

  const manualOverridePatterns = new Set(
    normalizedRules
      .filter((rule) => rule.enabled && rule.source !== 'auto' && normalizeRulePattern(rule.pattern))
      .map((rule) => normalizeRulePattern(rule.pattern)),
  )

  return normalizedRules
    .filter(
      (rule) => rule.source !== 'auto' || !manualOverridePatterns.has(normalizeRulePattern(rule.pattern)),
    )
    .sort((left, right) => {
      const leftRank = left.source === 'auto' ? 1 : 0
      const rightRank = right.source === 'auto' ? 1 : 0
      return leftRank - rightRank
    })
}

function normalizeProfileSignature(signature) {
  const source = signature && typeof signature === 'object' ? signature : {}
  return {
    internet_key: String(source.internet_key || '').trim(),
    internet_label: String(source.internet_label || '').trim(),
    route_interface: String(source.route_interface || '').trim(),
    route_gateway: String(source.route_gateway || '').trim(),
    vpn_keys: Array.from(
      new Set(
        (Array.isArray(source.vpn_keys) ? source.vpn_keys : [])
          .map((item) => String(item || '').trim())
          .filter(Boolean),
      ),
    ).sort(),
    vpn_labels: Array.from(
      new Set(
        (Array.isArray(source.vpn_labels) ? source.vpn_labels : [])
          .map((item) => String(item || '').trim())
          .filter(Boolean),
      ),
    ).sort(),
  }
}

function profileSignatureKey(signature) {
  const normalized = normalizeProfileSignature(signature)
  return JSON.stringify({
    internet_key: normalized.internet_key,
    route_interface: normalized.route_interface,
    route_gateway: normalized.route_gateway,
    vpn_keys: normalized.vpn_keys,
  })
}

function normalizeRoutingTarget(target) {
  const source = target && typeof target === 'object' ? target : {}
  const ignoredFailureHosts = Array.isArray(source.ignored_failure_hosts)
    ? source.ignored_failure_hosts
    : []

  return {
    default_action: source.default_action === 'proxy' ? 'proxy' : 'direct',
    ignored_failure_hosts: ignoredFailureHosts
      .map((host) => summarizeDomain(host) || String(host || '').trim().toLowerCase())
      .filter((host, index, items) => host && items.indexOf(host) === index),
    rules: normalizeRules(source.rules),
  }
}

function normalizeRoutingProfile(profile, index) {
  const source = profile && typeof profile === 'object' ? profile : {}
  const routingTarget = normalizeRoutingTarget(source)
  const fallbackId = `profile-${String(index + 1)}`
  const fallbackName = `Profile ${String(index + 1)}`
  return {
    id: String(source.id || fallbackId).trim() || fallbackId,
    name: String(source.name || fallbackName).trim() || fallbackName,
    enabled: source.enabled !== false,
    signature: normalizeProfileSignature(source.signature),
    default_action: routingTarget.default_action,
    ignored_failure_hosts: routingTarget.ignored_failure_hosts,
    rules: routingTarget.rules,
  }
}

function normalizeRouterConfig(config) {
  const source = config && typeof config === 'object' ? config : {}
  const upstream = source.upstream && typeof source.upstream === 'object' ? source.upstream : {}
  const autoProxyFailures =
    source.auto_proxy_failures && typeof source.auto_proxy_failures === 'object'
      ? source.auto_proxy_failures
      : {}
  const defaultClientTrafficLimit =
    source.default_client_traffic_limit && typeof source.default_client_traffic_limit === 'object'
      ? source.default_client_traffic_limit
      : {}
  const defaultRoutingTarget = normalizeRoutingTarget(source)

  return {
    default_action: defaultRoutingTarget.default_action,
    ignored_failure_hosts: defaultRoutingTarget.ignored_failure_hosts,
    default_client_traffic_limit: {
      enabled: Boolean(defaultClientTrafficLimit.enabled),
      max_past_hour_mb: normalizeOptionalLimitMb(defaultClientTrafficLimit.max_past_hour_mb),
      max_past_3h_mb: normalizeOptionalLimitMb(defaultClientTrafficLimit.max_past_3h_mb),
      note: String(defaultClientTrafficLimit.note || ''),
    },
    client_traffic_limits: (Array.isArray(source.client_traffic_limits) ? source.client_traffic_limits : []).map(
      (limit) => ({
        enabled: limit.enabled !== false,
        client: String(limit.client || '').trim(),
        max_past_hour_mb: normalizeOptionalLimitMb(limit.max_past_hour_mb),
        max_past_3h_mb: normalizeOptionalLimitMb(limit.max_past_3h_mb),
        note: String(limit.note || ''),
      }),
    ),
    client_traffic_exemptions: (Array.isArray(source.client_traffic_exemptions)
      ? source.client_traffic_exemptions
      : []
    )
      .map((exemption) =>
        ensureExemptionExpiration({
          enabled: exemption.enabled !== false,
          client: String(exemption.client || '').trim(),
          duration: normalizeExemptionDuration(exemption.duration),
          expires_at: exemption.expires_at ? String(exemption.expires_at) : null,
          note: String(exemption.note || ''),
        }),
      )
      .filter((exemption) => !isExemptionExpired(exemption)),
    auto_proxy_failures: {
      enabled: Boolean(autoProxyFailures.enabled),
    },
    upstream: {
      enabled: Boolean(upstream.enabled),
      type: upstream.type === 'socks5' ? 'socks5' : 'http',
      host: String(upstream.host || '127.0.0.1'),
      port: String(upstream.port || '8900'),
    },
    rules: defaultRoutingTarget.rules,
    routing_profiles: (Array.isArray(source.routing_profiles) ? source.routing_profiles : []).map(
      (profile, index) => normalizeRoutingProfile(profile, index),
    ),
  }
}

function isPersistableRule(rule) {
  return Boolean(normalizeRulePattern(rule && rule.pattern))
}

function isPersistableClientTrafficLimit(limit) {
  const client = String((limit && limit.client) || '').trim()
  if (!client) {
    return false
  }
  return limit.enabled === false || limit.max_past_hour_mb != null || limit.max_past_3h_mb != null
}

function isPersistableClientTrafficExemption(exemption) {
  return Boolean(String((exemption && exemption.client) || '').trim()) && !isExemptionExpired(exemption)
}

function buildPersistableRouterConfig(config) {
  const normalized = normalizeRouterConfig(config)
  return {
    ...normalized,
    client_traffic_limits: normalized.client_traffic_limits.filter((limit) => isPersistableClientTrafficLimit(limit)),
    client_traffic_exemptions: normalized.client_traffic_exemptions.filter((exemption) =>
      isPersistableClientTrafficExemption(exemption),
    ),
    rules: normalized.rules.filter((rule) => isPersistableRule(rule)),
    routing_profiles: normalized.routing_profiles.map((profile) => ({
      ...profile,
      rules: (profile.rules || []).filter((rule) => isPersistableRule(rule)),
    })),
  }
}

function countRouterDraftItems(config) {
  const normalized = normalizeRouterConfig(config)
  let count = normalized.rules.filter((rule) => !isPersistableRule(rule)).length
  count += normalized.client_traffic_limits.filter((limit) => !isPersistableClientTrafficLimit(limit)).length
  count += normalized.client_traffic_exemptions.filter((exemption) => !isPersistableClientTrafficExemption(exemption)).length
  count += normalized.routing_profiles.reduce(
    (sum, profile) => sum + (profile.rules || []).filter((rule) => !isPersistableRule(rule)).length,
    0,
  )
  return count
}

function getRoutingTargetById(config, profileId) {
  if (!profileId || profileId === DEFAULT_ROUTING_PROFILE_ID) {
    return config
  }
  const profiles = Array.isArray(config && config.routing_profiles) ? config.routing_profiles : []
  return profiles.find((profile) => profile.id === profileId) || null
}

function getEditorTargetLabel(config, profileId) {
  if (!profileId || profileId === DEFAULT_ROUTING_PROFILE_ID) {
    return 'Shared'
  }
  const profile = getRoutingTargetById(config, profileId)
  return profile ? profile.name || 'Profile' : 'Shared'
}

function getEffectiveEditorIgnoredDomains(config, profileId) {
  const sharedIgnored = Array.isArray(config.ignored_failure_hosts) ? config.ignored_failure_hosts : []
  if (!profileId || profileId === DEFAULT_ROUTING_PROFILE_ID) {
    return sharedIgnored
  }
  const currentTarget = getRoutingTargetById(config, profileId)
  const profileIgnored = currentTarget && Array.isArray(currentTarget.ignored_failure_hosts)
    ? currentTarget.ignored_failure_hosts
    : []
  return Array.from(new Set([...sharedIgnored, ...profileIgnored]))
}

function getEditorVisibleRuleEntries(config, profileId) {
  const sharedEntries = (config.rules || []).map((rule, index) => ({
    scope: DEFAULT_ROUTING_PROFILE_ID,
    scope_label: 'Shared',
    rule,
    index,
  }))
  if (!profileId || profileId === DEFAULT_ROUTING_PROFILE_ID) {
    return sharedEntries
  }
  const currentTarget = getRoutingTargetById(config, profileId)
  const profileLabel = currentTarget ? currentTarget.name || 'Profile' : 'Profile'
  const profileEntries = (currentTarget && Array.isArray(currentTarget.rules) ? currentTarget.rules : []).map(
    (rule, index) => ({
      scope: profileId,
      scope_label: profileLabel,
      rule,
      index,
    }),
  )
  return [...profileEntries, ...sharedEntries]
}

function ruleMatchesSearch(rule, searchTerm) {
  const normalizedSearch = String(searchTerm || '').trim().toLowerCase()
  if (!normalizedSearch) {
    return true
  }
  const haystack = [
    rule.scope,
    rule.pattern,
    rule.match,
    rule.action,
    rule.source,
    rule.note,
    rule.duration,
    rule.enabled ? 'enabled' : 'disabled',
  ]
    .map((value) => String(value || '').toLowerCase())
    .join(' ')
  return haystack.includes(normalizedSearch)
}

function ruleMatchesHost(rule, host) {
  const normalizedHost = String(host || '').trim().toLowerCase()
  const pattern = String((rule && rule.pattern) || '').trim().toLowerCase()
  if (!normalizedHost || !pattern) {
    return false
  }
  if (rule.match === 'exact') {
    return normalizedHost === pattern
  }
  if (rule.match === 'contains') {
    return normalizedHost.includes(pattern)
  }
  return normalizedHost === pattern || normalizedHost.endsWith(`.${pattern}`)
}

function failureDispositionForHost(host, config, profileId) {
  const normalizedHost = String(host || '').trim().toLowerCase()
  if (!normalizedHost) {
    return 'visible'
  }
  const normalizedDomain = summarizeDomain(normalizedHost)
  const ignoredDomains = new Set(
    getEffectiveEditorIgnoredDomains(config, profileId).map((item) => String(item).trim().toLowerCase()),
  )
  if (ignoredDomains.has(normalizedHost) || ignoredDomains.has(normalizedDomain)) {
    return 'ignored'
  }
  const entries = getEditorVisibleRuleEntries(config, profileId)
  for (const entry of entries) {
    const rule = entry.rule
    if (!rule || rule.enabled === false) {
      continue
    }
    if (ruleMatchesHost(rule, normalizedHost)) {
      return 'handled'
    }
  }
  return 'visible'
}

function routerConfigFingerprint(config) {
  return JSON.stringify(config)
}

function currentRouterRuntime(snapshot) {
  return snapshot && typeof snapshot === 'object' && snapshot.router_runtime ? snapshot.router_runtime : {}
}

function currentUpstreamStatus(snapshot) {
  const runtime = currentRouterRuntime(snapshot)
  const source = runtime.upstream_status && typeof runtime.upstream_status === 'object' ? runtime.upstream_status : {}
  const connectivity = source.connectivity && typeof source.connectivity === 'object' ? source.connectivity : {}
  const normalizeActivity = (activity) =>
    activity && typeof activity === 'object'
      ? {
          timestamp: activity.timestamp ? String(activity.timestamp) : null,
          destination: String(activity.destination || ''),
          error: activity.error ? String(activity.error) : '',
          context: activity.context ? String(activity.context) : '',
          proxy_label: String(activity.proxy_label || ''),
        }
      : null

  return {
    enabled: Boolean(source.enabled),
    type: source.type === 'socks5' ? 'socks5' : 'http',
    host: String(source.host || '127.0.0.1'),
    port: Number(source.port) || 0,
    connectivity: {
      status: String(connectivity.status || (source.enabled ? 'unknown' : 'disabled')),
      checked_at: connectivity.checked_at ? String(connectivity.checked_at) : null,
      message: String(
        connectivity.message || (source.enabled ? 'Waiting for an upstream connectivity check.' : 'Upstream proxy is disabled.'),
      ),
      protocol_verified: Boolean(connectivity.protocol_verified),
    },
    last_success: normalizeActivity(source.last_success),
    last_failure: normalizeActivity(source.last_failure),
  }
}

function formatStatusDateTime(value) {
  const parsed = parseDateText(value)
  return parsed ? parsed.toLocaleString() : 'Unknown time'
}

function buildUpstreamConnectivityLabel(upstreamStatus) {
  const status = String(upstreamStatus.connectivity.status || 'unknown')
  if (status === 'disabled') {
    return 'Disabled'
  }
  if (status === 'checking') {
    return 'Checking'
  }
  if (status === 'reachable') {
    return upstreamStatus.connectivity.protocol_verified ? 'Reachable' : 'TCP connected'
  }
  if (status === 'error') {
    return 'Failed'
  }
  return 'Unknown'
}

function buildUpstreamConnectivityPillClass(upstreamStatus) {
  const status = String(upstreamStatus.connectivity.status || 'unknown')
  if (status === 'error') {
    return cx(pillClass, warningPillClass)
  }
  if (status === 'disabled') {
    return cx(pillClass, mutedPillClass)
  }
  return pillClass
}

function buildUpstreamTrafficHeadline(upstreamStatus) {
  if (!upstreamStatus.enabled) {
    return 'Not in use'
  }
  const lastSuccessAt = parseDateText(upstreamStatus.last_success && upstreamStatus.last_success.timestamp)
  const lastFailureAt = parseDateText(upstreamStatus.last_failure && upstreamStatus.last_failure.timestamp)
  if (lastSuccessAt && (!lastFailureAt || lastSuccessAt.getTime() >= lastFailureAt.getTime())) {
    return 'Working'
  }
  if (lastFailureAt) {
    return 'Failing'
  }
  return 'Waiting for first proxied request'
}

function buildUpstreamTrafficNotes(upstreamStatus) {
  const notes = []
  if (upstreamStatus.last_success && upstreamStatus.last_success.timestamp) {
    notes.push(
      `Last success: ${formatStatusDateTime(upstreamStatus.last_success.timestamp)} -> ${upstreamStatus.last_success.destination}`,
    )
  }
  if (upstreamStatus.last_failure && upstreamStatus.last_failure.timestamp) {
    notes.push(
      `Last failure: ${formatStatusDateTime(upstreamStatus.last_failure.timestamp)} -> ${upstreamStatus.last_failure.destination} · ${upstreamStatus.last_failure.error}`,
    )
  }
  if (!notes.length) {
    notes.push('No proxied request has used the current upstream yet.')
  }
  return notes
}

function activeProfileId(snapshot) {
  const runtime = currentRouterRuntime(snapshot)
  const activeProfile = runtime.active_profile || {}
  return String(activeProfile.id || DEFAULT_ROUTING_PROFILE_ID)
}

function formatProfileInternetLabel(signature) {
  const normalized = normalizeProfileSignature(signature)
  return normalized.internet_label || normalized.route_interface || normalized.route_gateway || 'Unknown'
}

function formatProfileVpnLabel(signature) {
  const normalized = normalizeProfileSignature(signature)
  return normalized.vpn_labels.length ? normalized.vpn_labels.join(', ') : 'None'
}

function makeProfileNameFromSignature(signature) {
  const normalized = normalizeProfileSignature(signature)
  const baseLabel = normalized.internet_label || normalized.route_interface || 'Current network'
  return normalized.vpn_labels.length ? `${baseLabel} + ${normalized.vpn_labels.join(' + ')}` : baseLabel
}

function buildFailureView(snapshot, config, profileId) {
  const failureSummary = snapshot.failure_summary || { page_size: DEFAULT_FAILURE_PAGE_SIZE }
  const pageSize = failureSummary.page_size || DEFAULT_FAILURE_PAGE_SIZE
  const visibleGroups = new Map()
  const ignoredGroups = new Map()
  const handledGroups = new Set()

  ;(snapshot.recent_failures || []).forEach((failure) => {
    const host = String(failure.host || '').trim().toLowerCase()
    const domain = summarizeDomain(host)
    const key = domain || host || String(failure.destination || 'unknown')
    const disposition = failureDispositionForHost(host || key, config, profileId)
    if (disposition === 'handled') {
      handledGroups.add(key)
      return
    }
    const target = disposition === 'ignored' ? ignoredGroups : visibleGroups
    const existing = target.get(key) || {
      group_key: key,
      domain: domain || key,
      host: host || null,
      latest_timestamp: failure.timestamp,
      latest_error: failure.error,
      latest_destination: failure.destination,
      route_label: failure.route_label || 'direct',
      count: 0,
      methods: new Set(),
      clients: new Set(),
      hosts: new Set(),
    }
    existing.count += 1
    existing.methods.add(failure.method)
    existing.clients.add(failure.client)
    if (host) {
      existing.hosts.add(host)
    }
    if (String(failure.timestamp) >= String(existing.latest_timestamp)) {
      existing.latest_timestamp = failure.timestamp
      existing.latest_error = failure.error
      existing.latest_destination = failure.destination
      existing.route_label = failure.route_label || 'direct'
      existing.host = host || null
    }
    target.set(key, existing)
  })

  const finalizeGroups = (groups) =>
    Array.from(groups.values())
      .map((item) => ({
        group_key: item.group_key,
        domain: item.domain || item.group_key,
        host: item.host,
        latest_timestamp: item.latest_timestamp,
        latest_error: item.latest_error,
        latest_destination: item.latest_destination,
        route_label: item.route_label,
        count: item.count,
        client_count: item.clients.size,
        method_list: Array.from(item.methods).sort(),
        host_count: item.hosts.size,
        host_list_preview: Array.from(item.hosts).sort().slice(0, 3),
      }))
      .sort(
        (left, right) =>
          String(right.latest_timestamp).localeCompare(String(left.latest_timestamp)) ||
          right.count - left.count,
      )

  return {
    groups: finalizeGroups(visibleGroups),
    ignoredGroups: finalizeGroups(ignoredGroups),
    handledCount: handledGroups.size,
    pageSize,
  }
}

function formatChartTimestampLabel(timestamp) {
  const date = new Date(timestamp)
  if (Number.isNaN(date.getTime())) {
    return String(timestamp)
  }
  return date.toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

function buildUsageChartPoints(snapshot, limit = 12) {
  return (snapshot.recent_requests || [])
    .slice(0, limit)
    .reverse()
    .map((request) => ({
      label: formatChartTimestampLabel(request.timestamp),
      uploaded_bytes: Number(request.uploaded_bytes) || 0,
      downloaded_bytes: Number(request.downloaded_bytes) || 0,
      total_bytes: Number(request.total_bytes) || 0,
    }))
}

function buildOverviewCards(snapshot) {
  const overall = snapshot.overall || emptyUsageSummary()
  const activeTotal = Object.values(snapshot.active_by_proxy || {}).reduce((sum, count) => sum + count, 0)
  const directSummary = (snapshot.totals_by_route && snapshot.totals_by_route.direct) || emptyUsageSummary()
  const proxySummary = (snapshot.totals_by_route && snapshot.totals_by_route.proxy) || emptyUsageSummary()
  return [
    ['Started', snapshot.started_at],
    ['Active connections', String(activeTotal)],
    ['Requests handled', String(overall.count)],
    ['Direct handled', `${String(directSummary.count)} (${formatPercent(directSummary.count, overall.count)})`],
    ['Proxied handled', `${String(proxySummary.count)} (${formatPercent(proxySummary.count, overall.count)})`],
    ['Direct traffic', formatMb(directSummary.total_bytes)],
    ['Proxied traffic', formatMb(proxySummary.total_bytes)],
    ['Total traffic', formatMb(overall.total_bytes)],
  ]
}

function buildHistoryCards(history) {
  const summary = history.summary || emptyUsageSummary()
  return [
    ['Range', history.range_title || 'History'],
    ['Matched requests', String(summary.count || 0)],
    ['Total traffic', formatMb(summary.total_bytes || 0)],
    ['Upload', formatMb(summary.uploaded_bytes || 0)],
    ['Download', formatMb(summary.downloaded_bytes || 0)],
  ]
}

function buildHistoryNote(history) {
  const notes = []
  if (history.time_range && history.time_range.from && history.time_range.to) {
    notes.push(`${history.time_range.from} -> ${history.time_range.to}`)
  }
  if (history.invalid_lines) {
    notes.push(`Skipped invalid log lines: ${history.invalid_lines}`)
  }
  return notes.join(' · ') || 'Built from the append-only usage log.'
}

function buildProfileRuntimeItems(config, snapshot) {
  const runtime = currentRouterRuntime(snapshot)
  const network = runtime.network || {}
  const activeProfile = runtime.active_profile || {}
  const activeProfileConfig = (config.routing_profiles || []).find((profile) => profile.id === activeProfile.id)
  const currentInternetLabel = network.available
    ? network.internet_label || network.route_interface || network.route_gateway || 'Unknown network'
    : 'No active network detected'
  const currentVpnLabel = network.available
    ? Array.isArray(network.vpn_labels) && network.vpn_labels.length
      ? network.vpn_labels.join(', ')
      : 'None'
    : 'Unknown'
  const activeProfileLabel =
    activeProfile.id === DEFAULT_ROUTING_PROFILE_ID
      ? 'Shared'
      : (activeProfileConfig && activeProfileConfig.name) || activeProfile.name || 'Shared'
  const activeProfileMode = activeProfile.using_fallback ? 'Shared default' : 'Matched saved profile'
  return [
    ['Current internet', currentInternetLabel],
    ['Active VPNs', currentVpnLabel],
    ['Active profile', activeProfileLabel],
    ['Mode', activeProfileMode],
  ]
}

function buildRouterSummaryItems(config, profileId, snapshot) {
  const currentTarget = getRoutingTargetById(config, profileId) || config
  const visibleRuleEntries = getEditorVisibleRuleEntries(config, profileId)
  const enabledRules = visibleRuleEntries.filter((entry) => entry.rule && entry.rule.enabled).length
  const enabledClientLimits = config.client_traffic_limits.filter((limit) => limit.enabled).length
  const enabledClientExemptions = config.client_traffic_exemptions.filter((exemption) => exemption.enabled).length
  const defaultClientLimit = config.default_client_traffic_limit || {}
  const autoProxyStatus = config.auto_proxy_failures.enabled ? AUTO_PROXY_POLICY_LABEL : 'Disabled'
  const runtime = currentRouterRuntime(snapshot)
  const activeProfile = runtime.active_profile || {}
  const activeProfileConfig = (config.routing_profiles || []).find((profile) => profile.id === activeProfile.id)
  const editorTargetLabel = getEditorTargetLabel(config, profileId)
  const upstreamStatus = currentUpstreamStatus(snapshot)
  const upstreamLabel = config.upstream.enabled
    ? `${config.upstream.type}://${config.upstream.host || '?'}:${config.upstream.port || '?'}`
    : 'Disabled'
  const defaultClientLimitLabel = defaultClientLimit.enabled
    ? `1h ${defaultClientLimit.max_past_hour_mb ?? 'none'}MB · 3h ${defaultClientLimit.max_past_3h_mb ?? 'none'}MB`
    : 'Disabled'
  return [
    ['Edit target', editorTargetLabel],
    [
      'Active profile',
      activeProfile.id === DEFAULT_ROUTING_PROFILE_ID
        ? 'Shared'
        : (activeProfileConfig && activeProfileConfig.name) || activeProfile.name || 'Shared',
    ],
    ['Rules', String(visibleRuleEntries.length)],
    ['Enabled', String(enabledRules)],
    ['Default', currentTarget.default_action],
    ['Upstream', upstreamLabel],
    ['Upstream check', buildUpstreamConnectivityLabel(upstreamStatus)],
    ['Auto proxy', autoProxyStatus],
    ['Default quota', defaultClientLimitLabel],
    ['Client limits', `${enabledClientLimits}/${config.client_traffic_limits.length}`],
    ['Exemptions', `${enabledClientExemptions}/${config.client_traffic_exemptions.length}`],
    ['Ignored domains', String(getEffectiveEditorIgnoredDomains(config, profileId).length)],
  ]
}

function buildRouterStatusText(config, lastSavedConfig, profileId, options = {}) {
  const { draftCount = 0, isSaving = false, saveError = '' } = options
  const dirty =
    routerConfigFingerprint(buildPersistableRouterConfig(config)) !==
    routerConfigFingerprint(buildPersistableRouterConfig(lastSavedConfig))
  const visibleRuleEntries = getEditorVisibleRuleEntries(config, profileId)
  const editorLabel = getEditorTargetLabel(config, profileId)
  const draftLabel = draftCount === 1 ? '1 draft item still local' : `${draftCount} draft items still local`
  if (saveError) {
    return `Sync paused · ${saveError} · editing ${editorLabel}`
  }
  if (isSaving) {
    return draftCount ? `Saving changes… ${draftLabel} · editing ${editorLabel}` : `Saving changes… editing ${editorLabel}`
  }
  if (dirty) {
    return draftCount ? `Changes pending sync · ${draftLabel} · editing ${editorLabel}` : `Changes pending sync · editing ${editorLabel}`
  }
  if (draftCount) {
    return `${draftLabel} until required fields are filled · editing ${editorLabel}`
  }
  return `Auto-sync on · ${visibleRuleEntries.length} rules · ${config.client_traffic_limits.length} client limits · ${config.client_traffic_exemptions.length} exemptions · ${
    config.upstream.enabled ? 'upstream on' : 'upstream off'
  } · editing ${editorLabel}`
}

function buildRulesExportPayload(config) {
  const normalized = buildPersistableRouterConfig(config)
  return {
    exported_at: new Date().toISOString(),
    shared: {
      default_action: normalized.default_action,
      ignored_failure_hosts: normalized.ignored_failure_hosts,
      rules: normalized.rules,
    },
    routing_profiles: (normalized.routing_profiles || []).map((profile) => ({
      id: profile.id,
      name: profile.name,
      enabled: profile.enabled,
      signature: profile.signature,
      default_action: profile.default_action,
      ignored_failure_hosts: profile.ignored_failure_hosts,
      rules: profile.rules,
    })),
  }
}

function buildLiveSocketUrl() {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  return `${protocol}//${window.location.host}/api/live`
}

function createProfileId() {
  if (globalThis.crypto && typeof globalThis.crypto.randomUUID === 'function') {
    return `profile-${globalThis.crypto.randomUUID().slice(0, 8)}`
  }
  return `profile-${Date.now().toString(36)}`
}

function BucketChart({ series, emptyMessage, ariaLabel }) {
  if (!series.length) {
    return <div className="pt-2 text-[#6a6f73]">{emptyMessage}</div>
  }

  const svgWidth = 720
  const svgHeight = 220
  const paddingTop = 14
  const paddingRight = 12
  const paddingBottom = 40
  const paddingLeft = 12
  const innerWidth = svgWidth - paddingLeft - paddingRight
  const innerHeight = svgHeight - paddingTop - paddingBottom
  const slotWidth = innerWidth / series.length
  const barWidth = Math.min(Math.max(slotWidth * 0.58, 10), 34)
  const maxTotal = Math.max(...series.map((point) => Number(point.total_bytes) || 0), 1)
  const tickEvery = Math.max(1, Math.floor((series.length + 2) / 4))

  return (
    <div className="mt-3">
      <div className="mb-2 flex flex-wrap gap-4 text-sm text-[#6a6f73]">
        <span className="inline-flex items-center gap-2">
          <i className="inline-block size-3.5 rounded-full bg-[#116466]"></i>
          Upload
        </span>
        <span className="inline-flex items-center gap-2">
          <i className="inline-block size-3.5 rounded-full bg-[#7cc6bb]"></i>
          Download
        </span>
      </div>
      <svg className="block h-auto w-full overflow-visible" viewBox={`0 0 ${svgWidth} ${svgHeight}`} role="img" aria-label={ariaLabel}>
        <line
          className="stroke-[#d9d2c3] stroke-1"
          x1={paddingLeft}
          y1={paddingTop + innerHeight}
          x2={svgWidth - paddingRight}
          y2={paddingTop + innerHeight}
        ></line>
        {series.map((point, index) => {
          const uploadedBytes = Number(point.uploaded_bytes) || 0
          const downloadedBytes = Number(point.downloaded_bytes) || 0
          const x = paddingLeft + slotWidth * index + (slotWidth - barWidth) / 2
          const downloadHeight = (downloadedBytes / maxTotal) * innerHeight
          const uploadHeight = (uploadedBytes / maxTotal) * innerHeight
          const yBase = paddingTop + innerHeight
          const downloadY = yBase - downloadHeight
          const uploadY = downloadY - uploadHeight
          const shouldShowLabel = index % tickEvery === 0 || index === series.length - 1

          return (
            <g key={`${point.label}-${index}`}>
              <rect
                className="fill-[#7cc6bb]"
                x={x.toFixed(2)}
                y={downloadY.toFixed(2)}
                width={barWidth.toFixed(2)}
                height={downloadHeight.toFixed(2)}
                rx="5"
                ry="5"
              >
                <title>{`${point.label} download ${formatMb(downloadedBytes)}`}</title>
              </rect>
              {uploadHeight > 0 ? (
                <rect
                  className="fill-[#116466]"
                  x={x.toFixed(2)}
                  y={uploadY.toFixed(2)}
                  width={barWidth.toFixed(2)}
                  height={uploadHeight.toFixed(2)}
                  rx="5"
                  ry="5"
                >
                  <title>{`${point.label} upload ${formatMb(uploadedBytes)}`}</title>
                </rect>
              ) : null}
              {shouldShowLabel ? (
                <text className="fill-[#6a6f73] font-sans text-xs" x={(x + barWidth / 2).toFixed(2)} y={svgHeight - 14} textAnchor="middle">
                  {point.label}
                </text>
              ) : null}
            </g>
          )
        })}
      </svg>
    </div>
  )
}

function App() {
  const [activeTab, setActiveTab] = useState(getTabFromHash())
  const [dashboardSnapshot, setDashboardSnapshot] = useState(emptyDashboardSnapshot())
  const [historyData, setHistoryData] = useState(emptyHistoryData())
  const [historyRange, setHistoryRange] = useState('24h')
  const [historyProxyType, setHistoryProxyType] = useState('all')
  const [status, setStatus] = useState({ text: 'Connecting to live dashboard…', warning: false })
  const [historyError, setHistoryError] = useState('')
  const [nowMs, setNowMs] = useState(() => Date.now())
  const [currentRouterConfig, setCurrentRouterConfig] = useState(normalizeRouterConfig({}))
  const [lastSavedRouterConfig, setLastSavedRouterConfig] = useState(normalizeRouterConfig({}))
  const [currentFailurePage, setCurrentFailurePage] = useState(1)
  const [currentRulesPage, setCurrentRulesPage] = useState(1)
  const [currentRulesSearchTerm, setCurrentRulesSearchTerm] = useState('')
  const [currentEditorProfileId, setCurrentEditorProfileId] = useState(DEFAULT_ROUTING_PROFILE_ID)
  const [routerStatusOverride, setRouterStatusOverride] = useState(null)
  const [isClearingTraffic, setIsClearingTraffic] = useState(false)
  const [isSavingRouter, setIsSavingRouter] = useState(false)
  const [routerSaveError, setRouterSaveError] = useState('')
  const [routerEditVersion, setRouterEditVersion] = useState(0)
  const routerEditVersionRef = useRef(0)
  const liveSocketRef = useRef(null)
  const liveSocketReconnectRef = useRef(null)
  const historyRefreshTimerRef = useRef(null)
  const activeTabRef = useRef(activeTab)
  const historyRangeRef = useRef(historyRange)
  const historyProxyTypeRef = useRef(historyProxyType)
  const routerHasLocalChangesRef = useRef(false)
  const refreshHistoryRef = useRef(null)
  const loadRouterConfigRef = useRef(null)
  const autoSelectedRulesTargetRef = useRef(false)

  const safeEditorProfileId =
    currentEditorProfileId === DEFAULT_ROUTING_PROFILE_ID ||
    getRoutingTargetById(currentRouterConfig, currentEditorProfileId)
      ? currentEditorProfileId
      : DEFAULT_ROUTING_PROFILE_ID
  const currentEditorTarget = getRoutingTargetById(currentRouterConfig, safeEditorProfileId) || currentRouterConfig
  const currentActiveProfileId = activeProfileId(dashboardSnapshot)
  const currentActiveProfileLabel = getEditorTargetLabel(currentRouterConfig, currentActiveProfileId)
  const activeProfileAutoRules = (() => {
    if (!currentActiveProfileId || currentActiveProfileId === DEFAULT_ROUTING_PROFILE_ID) {
      return []
    }
    const activeTarget = getRoutingTargetById(currentRouterConfig, currentActiveProfileId)
    if (!activeTarget || !Array.isArray(activeTarget.rules)) {
      return []
    }
    return activeTarget.rules.filter(
      (rule) => rule && rule.enabled !== false && normalizeRuleSource(rule) === 'auto' && normalizeRulePattern(rule.pattern),
    )
  })()
  const editorDiffersFromActiveProfile = safeEditorProfileId !== currentActiveProfileId
  const routerPersistableConfig = buildPersistableRouterConfig(currentRouterConfig)
  const savedRouterPersistableConfig = buildPersistableRouterConfig(lastSavedRouterConfig)
  const routerPersistableFingerprint = routerConfigFingerprint(routerPersistableConfig)
  const lastSavedRouterFingerprint = routerConfigFingerprint(savedRouterPersistableConfig)
  const routerDirty = routerPersistableFingerprint !== lastSavedRouterFingerprint
  const routerDraftCount = countRouterDraftItems(currentRouterConfig)
  const routerHasLocalChanges = routerDirty || routerDraftCount > 0
  const routerStatus =
    routerStatusOverride || {
      text: buildRouterStatusText(currentRouterConfig, lastSavedRouterConfig, safeEditorProfileId, {
        draftCount: routerDraftCount,
        isSaving: isSavingRouter,
        saveError: routerSaveError,
      }),
      warning: Boolean(routerSaveError),
    }
  const rulesEntries = getEditorVisibleRuleEntries(currentRouterConfig, safeEditorProfileId)
  const orderedRules = rulesEntries
    .filter((entry) => ruleMatchesSearch({ ...entry.rule, scope: entry.scope_label }, currentRulesSearchTerm))
    .sort((left, right) => {
      const scopeRankLeft = left.scope === safeEditorProfileId ? 0 : 1
      const scopeRankRight = right.scope === safeEditorProfileId ? 0 : 1
      if (scopeRankLeft !== scopeRankRight) {
        return scopeRankLeft - scopeRankRight
      }
      const leftRank = left.rule.source === 'auto' ? 1 : 0
      const rightRank = right.rule.source === 'auto' ? 1 : 0
      if (leftRank !== rightRank) {
        return leftRank - rightRank
      }
      return left.index - right.index
    })
  const totalRulePages = Math.max(1, Math.ceil(orderedRules.length / RULES_PAGE_SIZE))
  const rulesPage = clamp(currentRulesPage, 1, totalRulePages)
  const pagedRules = orderedRules.slice((rulesPage - 1) * RULES_PAGE_SIZE, rulesPage * RULES_PAGE_SIZE)
  const failureView = buildFailureView(dashboardSnapshot, currentRouterConfig, safeEditorProfileId)
  const totalFailurePages = Math.max(1, Math.ceil(failureView.groups.length / failureView.pageSize))
  const failurePage = clamp(currentFailurePage, 1, totalFailurePages)
  const failurePageItems = failureView.groups.slice(
    (failurePage - 1) * failureView.pageSize,
    failurePage * failureView.pageSize,
  )
  const historyCards = buildHistoryCards(historyData)
  const overviewCards = buildOverviewCards(dashboardSnapshot)
  const usageChartPoints = buildUsageChartPoints(dashboardSnapshot)
  const profileRuntimeItems = buildProfileRuntimeItems(currentRouterConfig, dashboardSnapshot)
  const upstreamStatus = currentUpstreamStatus(dashboardSnapshot)
  const routerSummaryItems = buildRouterSummaryItems(
    currentRouterConfig,
    safeEditorProfileId,
    dashboardSnapshot,
  )
  const historyNote = historyError || buildHistoryNote(historyData)
  const ignoredDomains = (() => {
    const items = []
    const sharedIgnored = Array.isArray(currentRouterConfig.ignored_failure_hosts)
      ? currentRouterConfig.ignored_failure_hosts
      : []
    for (const domain of sharedIgnored) {
      items.push({ domain, scope: DEFAULT_ROUTING_PROFILE_ID, scope_label: 'Shared' })
    }
    if (safeEditorProfileId !== DEFAULT_ROUTING_PROFILE_ID) {
      const profileIgnored = Array.isArray(currentEditorTarget.ignored_failure_hosts)
        ? currentEditorTarget.ignored_failure_hosts
        : []
      for (const domain of profileIgnored) {
        items.push({
          domain,
          scope: safeEditorProfileId,
          scope_label: currentEditorTarget.name || 'Profile',
        })
      }
    }
    return items
  })()

  useEffect(() => {
    document.title = 'proxy-router dashboard'
  }, [])

  useEffect(() => {
    function handleHashChange() {
      setActiveTab(getTabFromHash())
    }

    window.addEventListener('hashchange', handleHashChange)
    return () => {
      window.removeEventListener('hashchange', handleHashChange)
    }
  }, [])

  useEffect(() => {
    const nextHash = `#${activeTab}`
    if (window.location.hash !== nextHash) {
      window.history.replaceState(null, '', nextHash)
    }
  }, [activeTab])

  async function loadRouterConfig({ showStatus = false } = {}) {
    const response = await fetch('/api/router-config', {
      cache: 'no-store',
      headers: {
        Accept: 'application/json',
      },
    })
    if (!response.ok) {
      throw new Error(`router config HTTP ${response.status}`)
    }
    const loadedConfig = normalizeRouterConfig(await response.json())
    setCurrentRouterConfig(loadedConfig)
    setLastSavedRouterConfig(cloneJson(loadedConfig))
    setRouterSaveError('')
    if (showStatus) {
      setRouterStatusOverride({
        text: `Loaded from disk · ${new Date().toLocaleTimeString()}`,
        warning: false,
      })
    } else {
      setRouterStatusOverride(null)
    }
  }

  async function refreshHistory(rangeValue = historyRange, proxyTypeValue = historyProxyType) {
    const params = new URLSearchParams()
    params.set('range', rangeValue)
    if (proxyTypeValue !== 'all') {
      params.set('proxy_type', proxyTypeValue)
    }

    const response = await fetch(`/api/history?${params.toString()}`, {
      cache: 'no-store',
      headers: {
        Accept: 'application/json',
      },
    })
    if (!response.ok) {
      throw new Error(`history HTTP ${response.status}`)
    }
    const history = await response.json()
    setHistoryData(history)
    setHistoryError('')
    if (proxyTypeValue !== 'all' && !history.available_proxy_types.includes(proxyTypeValue)) {
      setHistoryProxyType('all')
    }
  }

  useEffect(() => {
    let cancelled = false

    async function loadInitialRouterConfig() {
      try {
        const response = await fetch('/api/router-config', {
          cache: 'no-store',
          headers: {
            Accept: 'application/json',
          },
        })
        if (!response.ok) {
          throw new Error(`router config HTTP ${response.status}`)
        }
        const loadedConfig = normalizeRouterConfig(await response.json())
        if (!cancelled) {
          setCurrentRouterConfig(loadedConfig)
          setLastSavedRouterConfig(cloneJson(loadedConfig))
          setRouterSaveError('')
          setRouterStatusOverride(null)
        }
      } catch (error) {
        if (!cancelled) {
          setRouterStatusOverride({
            text: `Initial config load failed: ${error.message}`,
            warning: true,
          })
        }
      }
    }

    loadInitialRouterConfig()

    return () => {
      cancelled = true
    }
  }, [])

  useEffect(() => {
    routerEditVersionRef.current = routerEditVersion
  }, [routerEditVersion])

  useEffect(() => {
    activeTabRef.current = activeTab
    historyRangeRef.current = historyRange
    historyProxyTypeRef.current = historyProxyType
    routerHasLocalChangesRef.current = routerHasLocalChanges
  }, [activeTab, historyRange, historyProxyType, routerHasLocalChanges])

  useEffect(() => {
    refreshHistoryRef.current = refreshHistory
    loadRouterConfigRef.current = loadRouterConfig
  })

  useEffect(() => {
    if (autoSelectedRulesTargetRef.current) {
      return undefined
    }
    if (!currentActiveProfileId || currentActiveProfileId === DEFAULT_ROUTING_PROFILE_ID) {
      return undefined
    }
    if (!getRoutingTargetById(currentRouterConfig, currentActiveProfileId)) {
      return undefined
    }
    const timeoutId = window.setTimeout(() => {
      if (currentEditorProfileId !== currentActiveProfileId) {
        setCurrentEditorProfileId(currentActiveProfileId)
        setCurrentRulesPage(1)
        setRouterStatusOverride({
          text: `Showing rules for the active profile ${currentActiveProfileLabel}. Shared rules still apply underneath it.`,
          warning: false,
        })
      }
      autoSelectedRulesTargetRef.current = true
    }, 0)
    return () => {
      window.clearTimeout(timeoutId)
    }
  }, [currentActiveProfileId, currentActiveProfileLabel, currentEditorProfileId, currentRouterConfig])

  useEffect(() => {
    let disposed = false
    let reconnectDelayMs = 1000

    function scheduleHistoryRefresh() {
      if (historyRefreshTimerRef.current != null) {
        return
      }
      historyRefreshTimerRef.current = window.setTimeout(() => {
        historyRefreshTimerRef.current = null
        const refresh = refreshHistoryRef.current
        if (!refresh) {
          return
        }
        refresh(historyRangeRef.current, historyProxyTypeRef.current).catch((error) => {
          setHistoryError(`History refresh paused: ${error.message}`)
        })
      }, 250)
    }

    function connectLiveSocket() {
      if (disposed) {
        return
      }

      const socket = new WebSocket(buildLiveSocketUrl())
      liveSocketRef.current = socket

      socket.addEventListener('open', () => {
        reconnectDelayMs = 1000
        setStatus({
          text: `Live socket connected · ${new Date().toLocaleTimeString()}`,
          warning: false,
        })
      })

      socket.addEventListener('message', (event) => {
        let payload
        try {
          payload = JSON.parse(event.data)
        } catch {
          return
        }

        if (payload.type === 'heartbeat') {
          return
        }

        if (payload.type !== 'snapshot' || !payload.snapshot) {
          return
        }

        setNowMs(Date.now())
        setDashboardSnapshot(payload.snapshot)
        setStatus({
          text: `Live socket connected · ${new Date().toLocaleTimeString()}`,
          warning: false,
        })

        if (payload.router_config_changed && !routerHasLocalChangesRef.current && loadRouterConfigRef.current) {
          loadRouterConfigRef.current().catch((error) => {
            setRouterStatusOverride({
              text: `Config refresh failed: ${error.message}`,
              warning: true,
            })
          })
        }

        if (payload.history_changed && activeTabRef.current === 'history') {
          scheduleHistoryRefresh()
        }
      })

      socket.addEventListener('close', () => {
        if (disposed) {
          return
        }
        setStatus({
          text: `Live socket disconnected · retrying in ${Math.round(reconnectDelayMs / 1000)}s`,
          warning: true,
        })
        liveSocketReconnectRef.current = window.setTimeout(() => {
          liveSocketReconnectRef.current = null
          reconnectDelayMs = Math.min(reconnectDelayMs * 2, 10000)
          connectLiveSocket()
        }, reconnectDelayMs)
      })

      socket.addEventListener('error', () => {
        try {
          socket.close()
        } catch {
          // Ignore close errors during reconnect handling.
        }
      })
    }

    connectLiveSocket()

    return () => {
      disposed = true
      if (liveSocketReconnectRef.current != null) {
        window.clearTimeout(liveSocketReconnectRef.current)
        liveSocketReconnectRef.current = null
      }
      if (historyRefreshTimerRef.current != null) {
        window.clearTimeout(historyRefreshTimerRef.current)
        historyRefreshTimerRef.current = null
      }
      if (liveSocketRef.current) {
        try {
          liveSocketRef.current.close()
        } catch {
          // Ignore socket close errors during unmount.
        }
        liveSocketRef.current = null
      }
    }
  }, [])

  useEffect(() => {
    if (activeTab !== 'history') {
      return
    }
    const timeoutId = window.setTimeout(() => {
      const refresh = refreshHistoryRef.current
      if (!refresh) {
        return
      }
      refresh(historyRange, historyProxyType).catch((error) => {
        setHistoryError(`History refresh paused: ${error.message}`)
      })
    }, 0)
    return () => {
      window.clearTimeout(timeoutId)
    }
  }, [activeTab, historyRange, historyProxyType])

  useEffect(() => {
    if (!routerDirty) {
      return undefined
    }

    const requestVersion = routerEditVersion
    const configToPersist = JSON.parse(routerPersistableFingerprint)
    const timeoutId = window.setTimeout(() => {
      setIsSavingRouter(true)
      fetch('/api/router-config', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
        body: JSON.stringify(configToPersist),
      })
        .then(async (response) => {
          const payload = await response.json().catch(() => ({ error: 'invalid JSON response' }))
          if (!response.ok) {
            throw new Error(payload.error || `router config HTTP ${response.status}`)
          }

          const normalizedConfig = normalizeRouterConfig(payload)
          setLastSavedRouterConfig(cloneJson(normalizedConfig))
          setRouterSaveError('')
          setRouterStatusOverride(null)
          setCurrentRouterConfig((existingConfig) => {
            const existingPersistableFingerprint = routerConfigFingerprint(buildPersistableRouterConfig(existingConfig))
            const normalizedFingerprint = routerConfigFingerprint(buildPersistableRouterConfig(normalizedConfig))
            if (routerEditVersionRef.current !== requestVersion) {
              return existingConfig
            }
            if (existingPersistableFingerprint !== normalizedFingerprint) {
              return existingConfig
            }
            return countRouterDraftItems(existingConfig) ? existingConfig : normalizedConfig
          })
        })
        .catch((error) => {
          setRouterSaveError(error.message)
          setRouterStatusOverride(null)
        })
        .finally(() => {
          setIsSavingRouter(false)
        })
    }, 500)

    return () => {
      window.clearTimeout(timeoutId)
    }
  }, [routerDirty, routerEditVersion, routerPersistableFingerprint])

  function setLocalRouterConfig(nextConfig, options = {}) {
    setCurrentRouterConfig(normalizeRouterConfig(nextConfig))
    setRouterEditVersion((version) => version + 1)
    setRouterSaveError('')
    if (Object.prototype.hasOwnProperty.call(options, 'editorProfileId')) {
      setCurrentEditorProfileId(options.editorProfileId)
    }
    if (options.resetRulesPage) {
      setCurrentRulesPage(1)
    }
    if (options.activateTab) {
      setActiveTab(options.activateTab)
    }
    if (options.message) {
      setRouterStatusOverride({
        text: options.message,
        warning: Boolean(options.warning),
      })
    } else {
      setRouterStatusOverride(null)
    }
  }

  function addRule(rule = null) {
    const nextConfig = cloneJson(currentRouterConfig)
    const target = getRoutingTargetById(nextConfig, safeEditorProfileId) || nextConfig
    target.rules.unshift(
      ensureRuleExpiration(
        rule || {
          enabled: true,
          pattern: '',
          match: 'suffix',
          action: 'proxy',
          note: '',
          source: 'manual',
          duration: 'always',
          expires_at: null,
        },
      ),
    )
    setLocalRouterConfig(nextConfig, {
      activateTab: 'routing',
      resetRulesPage: true,
      message: 'Rule draft added. It syncs automatically after you enter a host pattern.',
    })
  }

  function updateRuleField(scope, index, field, value) {
    const nextConfig = cloneJson(currentRouterConfig)
    const targetScope = getRoutingTargetById(nextConfig, scope)
    if (!targetScope || !targetScope.rules[index]) {
      return
    }
    const rule = targetScope.rules[index]
    if (rule.source === 'auto') {
      return
    }
    rule[field] = value
    if (field === 'duration') {
      ensureRuleExpiration(rule, true)
    } else {
      ensureRuleExpiration(rule, false)
    }
    setLocalRouterConfig(nextConfig)
  }

  function addClientTrafficLimit(limit = null) {
    const nextConfig = cloneJson(currentRouterConfig)
    nextConfig.client_traffic_limits.push(
      limit || {
        enabled: true,
        client: '',
        max_past_hour_mb: null,
        max_past_3h_mb: null,
        note: '',
      },
    )
    setLocalRouterConfig(nextConfig, {
      activateTab: 'quotas',
      message: 'Client traffic limit draft added. It syncs automatically after you enter a client and limit.',
    })
  }

  function updateClientTrafficLimitField(index, field, value) {
    const nextConfig = cloneJson(currentRouterConfig)
    if (!nextConfig.client_traffic_limits[index]) {
      return
    }
    nextConfig.client_traffic_limits[index][field] = value
    setLocalRouterConfig(nextConfig)
  }

  function addClientTrafficExemption(exemption = null) {
    const nextConfig = cloneJson(currentRouterConfig)
    nextConfig.client_traffic_exemptions.push(
      ensureExemptionExpiration(
        exemption || {
          enabled: true,
          client: '',
          duration: '2h',
          expires_at: null,
          note: '',
        },
      ),
    )
    setLocalRouterConfig(nextConfig, {
      activateTab: 'quotas',
      message: 'Quota exemption draft added. It syncs automatically after you enter a client.',
    })
  }

  function updateClientTrafficExemptionField(index, field, value) {
    const nextConfig = cloneJson(currentRouterConfig)
    if (!nextConfig.client_traffic_exemptions[index]) {
      return
    }
    nextConfig.client_traffic_exemptions[index][field] = value
    if (field === 'duration') {
      ensureExemptionExpiration(nextConfig.client_traffic_exemptions[index], true)
    } else {
      ensureExemptionExpiration(nextConfig.client_traffic_exemptions[index], false)
    }
    setLocalRouterConfig(nextConfig)
  }

  function clearCurrentScopeRules() {
    const editorLabel = getEditorTargetLabel(currentRouterConfig, safeEditorProfileId)
    const confirmed = window.confirm(
      `Clear all rules in ${editorLabel}? Shared rules in other scopes will be kept unless you remove them separately.`,
    )
    if (!confirmed) {
      return
    }
    const nextConfig = cloneJson(currentRouterConfig)
    const currentTarget = getRoutingTargetById(nextConfig, safeEditorProfileId) || nextConfig
    currentTarget.rules = []
    setLocalRouterConfig(nextConfig, {
      resetRulesPage: true,
      message: `Rules cleared for ${editorLabel}. Syncing automatically.`,
    })
  }

  function exportRulesConfig() {
    const payload = buildRulesExportPayload(currentRouterConfig)
    const blob = new Blob([JSON.stringify(payload, null, 2) + '\n'], {
      type: 'application/json',
    })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = `proxy-router-rules-${new Date().toISOString().replaceAll(':', '-')}.json`
    document.body.appendChild(link)
    link.click()
    link.remove()
    URL.revokeObjectURL(url)
    setRouterStatusOverride({
      text: 'Rules exported as JSON for all scopes.',
      warning: false,
    })
  }

  function ignoreAutoRule(scope, index) {
    const nextConfig = cloneJson(currentRouterConfig)
    const targetScope = getRoutingTargetById(nextConfig, scope)
    const rule = targetScope && targetScope.rules ? targetScope.rules[index] : null
    if (!rule || rule.source !== 'auto') {
      return
    }
    const pattern = normalizeRulePattern(rule.pattern)
    targetScope.rules[index] = {
      enabled: true,
      pattern,
      match: rule.match === 'exact' || rule.match === 'contains' ? rule.match : 'suffix',
      action: 'direct',
      note: pattern ? `ignored auto-proxy rule for ${pattern}` : 'ignored auto-proxy rule',
      source: 'manual',
      duration: 'always',
      expires_at: null,
    }
    setLocalRouterConfig(nextConfig, {
      message: 'Auto rule converted to a permanent direct rule. Syncing automatically.',
    })
  }

  function ignoreFailureHost(host) {
    const normalizedHost = summarizeDomain(host) || String(host || '').trim().toLowerCase()
    if (!normalizedHost) {
      return
    }
    const nextConfig = cloneJson(currentRouterConfig)
    const currentTarget = getRoutingTargetById(nextConfig, safeEditorProfileId) || nextConfig
    if (!currentTarget.ignored_failure_hosts.includes(normalizedHost)) {
      currentTarget.ignored_failure_hosts.push(normalizedHost)
    }
    setLocalRouterConfig(nextConfig, {
      message: 'Domain added to ignored failures. Syncing automatically.',
    })
  }

  function createProfileFromCurrentNetwork() {
    const runtime = currentRouterRuntime(dashboardSnapshot)
    const network = runtime.network || {}
    const signature = normalizeProfileSignature(network.signature)
    const hasSignatureIdentity = Boolean(
      signature.internet_key || signature.route_interface || signature.route_gateway || signature.vpn_keys.length,
    )
    if (!network.available || !hasSignatureIdentity) {
      setRouterStatusOverride({
        text: 'No active network signature is available for a new profile right now.',
        warning: true,
      })
      return
    }

    const nextConfig = cloneJson(currentRouterConfig)
    const existingProfile = (nextConfig.routing_profiles || []).find(
      (profile) => profileSignatureKey(profile.signature) === profileSignatureKey(signature),
    )
    if (existingProfile) {
      setCurrentEditorProfileId(existingProfile.id)
      setCurrentRulesPage(1)
      setRouterStatusOverride({
        text: 'A profile for the current network already exists. Switched the editor to it.',
        warning: false,
      })
      return
    }

    const sourceProfileId = activeProfileId(dashboardSnapshot)
    const sourceTarget = cloneJson(getRoutingTargetById(nextConfig, sourceProfileId) || nextConfig)
    const profileId = createProfileId()
    nextConfig.routing_profiles.push({
      id: profileId,
      name: makeProfileNameFromSignature(signature),
      enabled: true,
      signature,
      default_action: sourceTarget.default_action || 'direct',
      ignored_failure_hosts: Array.isArray(sourceTarget.ignored_failure_hosts)
        ? sourceTarget.ignored_failure_hosts
        : [],
      rules: Array.isArray(sourceTarget.rules) ? sourceTarget.rules : [],
    })
    setLocalRouterConfig(nextConfig, {
      editorProfileId: profileId,
      resetRulesPage: true,
      message: 'Profile created from the current network. Syncing automatically.',
    })
  }

  async function triggerUpstreamCheck() {
    try {
      const response = await fetch('/api/upstream/check', {
        method: 'POST',
        headers: {
          Accept: 'application/json',
        },
      })
      const payload = await response.json().catch(() => ({ error: 'invalid JSON response' }))
      if (!response.ok) {
        throw new Error(payload.error || `upstream check HTTP ${response.status}`)
      }
      if (payload.status) {
        setDashboardSnapshot((existingSnapshot) => ({
          ...existingSnapshot,
          router_runtime: {
            ...currentRouterRuntime(existingSnapshot),
            upstream_status: payload.status,
          },
        }))
      }
      setRouterStatusOverride(null)
    } catch (error) {
      setRouterStatusOverride({
        text: `Could not start an upstream connectivity check: ${error.message}`,
        warning: true,
      })
    }
  }

  async function clearTrafficData() {
    const confirmed = window.confirm(
      'Clear all recorded traffic history and live counters? Router rules and config will not be changed.',
    )
    if (!confirmed) {
      return
    }

    setIsClearingTraffic(true)
    try {
      const response = await fetch('/api/traffic-data/clear', {
        method: 'POST',
        headers: {
          Accept: 'application/json',
        },
      })
      const payload = await response.json().catch(() => ({ error: 'invalid JSON response' }))
      if (!response.ok) {
        throw new Error(payload.error || `traffic clear HTTP ${response.status}`)
      }
      setCurrentFailurePage(1)
      if (payload.snapshot) {
        setDashboardSnapshot(payload.snapshot)
      }
      if (payload.history) {
        setHistoryData(payload.history)
        setHistoryError('')
      } else {
        await refreshHistory()
      }
      setStatus({
        text: `Traffic data cleared · ${new Date().toLocaleTimeString()}`,
        warning: false,
      })
    } finally {
      setIsClearingTraffic(false)
    }
  }

  return (
    <main className={pageClass}>
      <div className={shellClass}>
      <section className={heroClass}>
        <div>
          <h1>proxy-router dashboard</h1>
          <p>Current session view for traffic totals, per-device usage, and the latest completed request.</p>
        </div>
        <div className={cx(pillClass, status.warning && warningPillClass)}>{status.text}</div>
      </section>

      <section className={cx(panelClass, 'mb-4')}>
        <div className={panelHeaderClass}>
          <div>
            <h2>Configuration</h2>
            <div className={noteClass}>Routing profiles, rules, quotas, and exemptions sync automatically.</div>
          </div>
          <div className="flex w-full flex-col items-stretch gap-3 sm:w-auto sm:flex-row sm:items-center sm:flex-wrap">
            <div className={cx(pillClass, routerStatus.warning && warningPillClass)}>{routerStatus.text}</div>
            <button
              type="button"
              disabled={isSavingRouter}
              onClick={() => {
                loadRouterConfig({ showStatus: true }).catch((error) => {
                  setRouterStatusOverride({
                    text: `Reload failed: ${error.message}`,
                    warning: true,
                  })
                })
              }}
            >
              Reload from disk
            </button>
          </div>
        </div>
      </section>

      <section className="mb-4 grid grid-cols-2 gap-2 min-[361px]:grid-cols-3 sm:flex sm:flex-wrap" aria-label="Dashboard tabs">
        {TAB_DEFINITIONS.map((tab) => (
          <button
            key={tab.id}
            className={cx(
              'w-full rounded-[10px] px-2 py-2 text-sm sm:w-auto sm:rounded-full sm:px-4',
              activeTab === tab.id && primaryButtonClass,
            )}
            type="button"
            aria-pressed={activeTab === tab.id ? 'true' : 'false'}
            onClick={() => setActiveTab(tab.id)}
          >
            {tab.label}
          </button>
        ))}
      </section>

      {activeTab === 'overview' ? (
        <section className="block">
          <section className={gridClass}>
            <div className={cardGridClass} id="summary-cards">
              {overviewCards.map(([label, value]) => (
                <div className={cardClass} key={label}>
                  <div className={cardLabelClass}>{label}</div>
                  <div className={cx(cardValueClass, label === 'Started' && 'text-sm leading-snug sm:text-base')}>
                    {value}
                  </div>
                </div>
              ))}
            </div>

            <section className={cx(panelClass, 'col-span-full lg:col-span-7')}>
              <h2>Recent traffic</h2>
              <BucketChart
                series={usageChartPoints}
                emptyMessage="No recent traffic yet."
                ariaLabel="Recent traffic by request"
              />
            </section>

            <section className={cx(panelClass, 'col-span-full lg:col-span-5')}>
              <h2>Latest request</h2>
              {dashboardSnapshot.latest_request ? (
                <div>
                  {[
                    ['Time', dashboardSnapshot.latest_request.timestamp],
                    ['Proxy', dashboardSnapshot.latest_request.proxy_type],
                    ['Method', dashboardSnapshot.latest_request.method],
                    ['Client', dashboardSnapshot.latest_request.client],
                    ['Destination', dashboardSnapshot.latest_request.destination],
                    ['Route', dashboardSnapshot.latest_request.route_label || 'direct'],
                    ['Upload', formatMb(dashboardSnapshot.latest_request.uploaded_bytes)],
                    ['Download', formatMb(dashboardSnapshot.latest_request.downloaded_bytes)],
                    ['Total', formatMb(dashboardSnapshot.latest_request.total_bytes)],
                  ].map(([label, value]) => (
                    <div className="grid grid-cols-[minmax(4.5rem,0.75fr)_minmax(0,1fr)] gap-3 border-b border-[#ece5d8] py-2 last:border-b-0 sm:flex sm:justify-between sm:gap-4" key={label}>
                      <span className="min-w-0 text-[#6a6f73] sm:min-w-24">{label}</span>
                      <span className="break-words text-left font-semibold sm:text-right">{value}</span>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="pt-2 text-[#6a6f73]">No completed requests yet.</div>
              )}
            </section>

            <section className={cx(panelClass, 'col-span-full lg:col-span-6')}>
              <h2>By proxy</h2>
              <div className={tableWrapClass}>
                <table>
                  <thead>
                    <tr>
                      <th>Proxy</th>
                      <th>Handled</th>
                      <th>Active</th>
                      <th>Upload</th>
                      <th>Download</th>
                      <th>Total</th>
                    </tr>
                  </thead>
                  <tbody>
                    {PROXY_TYPES.map((proxyType) => {
                      const summary = dashboardSnapshot.totals_by_proxy[proxyType] || emptyUsageSummary()
                      const activeCount = dashboardSnapshot.active_by_proxy[proxyType] || 0
                      return (
                        <tr key={proxyType}>
                          <td>{proxyType}</td>
                          <td>{summary.count}</td>
                          <td>{activeCount}</td>
                          <td>{formatMb(summary.uploaded_bytes)}</td>
                          <td>{formatMb(summary.downloaded_bytes)}</td>
                          <td>{formatMb(summary.total_bytes)}</td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            </section>

            <section className={cx(panelClass, 'col-span-full lg:col-span-6')}>
              <h2>By route</h2>
              <div className={tableWrapClass}>
                <table>
                  <thead>
                    <tr>
                      <th>Route</th>
                      <th>Handled</th>
                      <th>Req share</th>
                      <th>Upload</th>
                      <th>Download</th>
                      <th>Total</th>
                      <th>Traffic share</th>
                    </tr>
                  </thead>
                  <tbody>
                    {ROUTE_TYPES.map((routeType) => {
                      const summary =
                        (dashboardSnapshot.totals_by_route && dashboardSnapshot.totals_by_route[routeType]) ||
                        emptyUsageSummary()
                      const overall = dashboardSnapshot.overall || emptyUsageSummary()
                      return (
                        <tr key={routeType}>
                          <td>{routeType}</td>
                          <td>{summary.count}</td>
                          <td>{formatPercent(summary.count, overall.count)}</td>
                          <td>{formatMb(summary.uploaded_bytes)}</td>
                          <td>{formatMb(summary.downloaded_bytes)}</td>
                          <td>{formatMb(summary.total_bytes)}</td>
                          <td>{formatPercent(summary.total_bytes, overall.total_bytes)}</td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            </section>

            <section className={cx(panelClass, 'col-span-full')}>
              <h2>Recent requests</h2>
              {dashboardSnapshot.recent_requests.length ? (
                <div className={tableWrapClass}>
                  <table>
                    <thead>
                      <tr>
                        <th>Time</th>
                        <th>Proxy</th>
                        <th>Method</th>
                        <th>Client</th>
                        <th>Destination</th>
                        <th>Route</th>
                        <th>Total</th>
                      </tr>
                    </thead>
                    <tbody>
                      {dashboardSnapshot.recent_requests.map((request, index) => (
                        <tr key={`${request.timestamp}-${request.destination}-${index}`}>
                          <td>{request.timestamp}</td>
                          <td>{request.proxy_type}</td>
                          <td>{request.method}</td>
                          <td>{request.client}</td>
                          <td className="max-w-md break-words">{request.destination}</td>
                          <td>{request.route_label || 'direct'}</td>
                          <td>{formatMb(request.total_bytes)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="pt-2 text-[#6a6f73]">No recent requests yet.</div>
              )}
            </section>
          </section>
        </section>
      ) : null}

      {activeTab === 'history' ? (
        <section className="block">
          <section className={gridClass}>
            <section className={cx(panelClass, 'col-span-full')}>
              <div className={panelHeaderClass}>
                <h2>History</h2>
                <button className={warnButtonClass} id="clear-traffic-button" type="button" disabled={isClearingTraffic} onClick={() => {
                  clearTrafficData().catch((error) => {
                    setStatus({
                      text: `Traffic clear failed: ${error.message}`,
                      warning: true,
                    })
                  })
                }}>
                  {isClearingTraffic ? 'Clearing…' : 'Clear traffic data'}
                </button>
              </div>

              <div className={controlsClass}>
                <label className={controlClass}>
                  <span>Range</span>
                  <select value={historyRange} onChange={(event) => setHistoryRange(event.target.value)}>
                    {HISTORY_RANGE_OPTIONS.map((option) => (
                      <option key={option.value} value={option.value}>
                        {option.label}
                      </option>
                    ))}
                  </select>
                </label>
                <label className={controlClass}>
                  <span>Proxy</span>
                  <select value={historyProxyType} onChange={(event) => setHistoryProxyType(event.target.value)}>
                    <option value="all">All proxies</option>
                    {historyData.available_proxy_types.map((proxyType) => (
                      <option key={proxyType} value={proxyType}>
                        {proxyType}
                      </option>
                    ))}
                  </select>
                </label>
              </div>

              <div className={cx(cardGridClass, 'mt-2')}>
                {historyCards.map(([label, value]) => (
                  <div className={cardClass} key={label}>
                    <div className={cardLabelClass}>{label}</div>
                    <div className={cardValueClass}>{value}</div>
                  </div>
                ))}
              </div>
              <div className={noteClass}>{historyNote}</div>

              <div className="mt-3 grid grid-cols-1 items-start gap-4 lg:grid-cols-[minmax(0,2.1fr)_minmax(280px,1fr)]">
                <section className={subpanelClass}>
                  <h3>Traffic over time</h3>
                  {historyError ? (
                    <div className="pt-2 text-[#6a6f73]">{historyError}</div>
                  ) : (
                    <BucketChart
                      series={historyData.series || []}
                      emptyMessage="No historical traffic matched this filter."
                      ariaLabel="Traffic over time"
                    />
                  )}
                </section>

                <section className={subpanelClass}>
                  <h3>Top destinations</h3>
                  {historyError ? (
                    <div className="pt-2 text-[#6a6f73]">History data is unavailable right now.</div>
                  ) : historyData.top_destinations.length ? (
                    <table>
                      <thead>
                        <tr>
                          <th>Destination</th>
                          <th>Requests</th>
                          <th>Total</th>
                        </tr>
                      </thead>
                      <tbody>
                        {historyData.top_destinations.map((item) => (
                          <tr key={item.destination}>
                            <td className="max-w-md break-words">{item.destination}</td>
                            <td>{item.count}</td>
                            <td>{formatMb(item.total_bytes)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  ) : (
                    <div className="pt-2 text-[#6a6f73]">No destinations matched this filter.</div>
                  )}
                </section>
              </div>
            </section>
          </section>
        </section>
      ) : null}

      {activeTab === 'routing' ? (
        <section className="block">
          <section className={gridClass}>
            <section className={cx(panelClass, 'col-span-full')}>
              <div className={panelHeaderClass}>
                <div>
                  <h2>Routing</h2>
                  <div className={noteClass}>Profiles, upstream proxy, auto-proxy policy, and host rules.</div>
                </div>
              </div>

              <div className="mt-3 grid grid-cols-12 gap-4">
                <section className={cx(subpanelClass, 'col-span-full lg:col-span-4')}>
                  <h3>Profiles</h3>
                  <div className={noteClass}>Detect the current internet and VPN set, then match its saved routing profile.</div>
                  <div className="mt-3 grid grid-cols-1 gap-2 min-[361px]:grid-cols-2 sm:grid-cols-[repeat(auto-fit,minmax(140px,1fr))] sm:gap-3">
                    {profileRuntimeItems.map(([label, value]) => (
                      <div className="min-w-0 rounded-xl border border-[#e8e0d1] bg-white p-3" key={label}>
                        <div className="text-xs text-[#6a6f73]">{label}</div>
                        <div className="mt-1 [overflow-wrap:anywhere] font-bold">{value}</div>
                      </div>
                    ))}
                  </div>

                  <div className={buttonRowClass}>
                    <button id="create-profile-from-current-button" type="button" onClick={createProfileFromCurrentNetwork}>
                      Create profile from current network
                    </button>
                  </div>

                  <div className={tableWrapClass}>
                    <table>
                      <thead>
                        <tr>
                          <th>Enabled</th>
                          <th>Name</th>
                          <th>Internet</th>
                          <th>VPNs</th>
                          <th>Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {currentRouterConfig.routing_profiles.length ? (
                          currentRouterConfig.routing_profiles.map((profile, index) => (
                            <tr key={profile.id}>
                              <td>
                                <input
                                  type="checkbox"
                                  checked={profile.enabled}
                                  onChange={(event) => {
                                    const nextConfig = cloneJson(currentRouterConfig)
                                    nextConfig.routing_profiles[index].enabled = event.target.checked
                                    setLocalRouterConfig(nextConfig, {
                                      message: 'Profile updated. Syncing automatically.',
                                    })
                                  }}
                                />
                              </td>
                              <td>
                                <input
                                  type="text"
                                  value={profile.name}
                                  placeholder="Profile name"
                                  onChange={(event) => {
                                    const nextConfig = cloneJson(currentRouterConfig)
                                    nextConfig.routing_profiles[index].name = event.target.value
                                    setLocalRouterConfig(nextConfig, {
                                      message: 'Profile updated. Syncing automatically.',
                                    })
                                  }}
                                />
                                <small>{profile.id === activeProfileId(dashboardSnapshot) ? 'Active now' : 'Saved profile'}</small>
                              </td>
                              <td>{formatProfileInternetLabel(profile.signature)}</td>
                              <td>{formatProfileVpnLabel(profile.signature)}</td>
                              <td className={ruleActionsClass}>
                                <button
                                  type="button"
                                  onClick={() => {
                                    autoSelectedRulesTargetRef.current = true
                                    setCurrentEditorProfileId(profile.id)
                                    setCurrentRulesPage(1)
                                    setRouterStatusOverride({
                                      text: 'Switched the rules editor to the selected profile.',
                                      warning: false,
                                    })
                                  }}
                                >
                                  Edit
                                </button>
                                <button
                                  type="button"
                                  onClick={() => {
                                    const nextConfig = cloneJson(currentRouterConfig)
                                    nextConfig.routing_profiles.splice(index, 1)
                                    const nextEditorId =
                                      safeEditorProfileId === profile.id
                                        ? DEFAULT_ROUTING_PROFILE_ID
                                        : safeEditorProfileId
                                    setLocalRouterConfig(nextConfig, {
                                      editorProfileId: nextEditorId,
                                      message: 'Profile removed. Syncing automatically.',
                                    })
                                  }}
                                >
                                  Delete
                                </button>
                              </td>
                            </tr>
                          ))
                        ) : (
                          <tr>
                            <td colSpan="5" className="pt-2 text-[#6a6f73]">
                              No saved network-specific profiles yet.
                            </td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  </div>

                  <div className={cx(noteClass, 'mt-4')}>Global upstream and routing status</div>
                  <h3>Upstream proxy</h3>
                  <label className="mt-3 flex items-start gap-2 font-semibold leading-snug text-[#1f2a30] [&_input]:mt-1">
                    <input
                      className={cx(routerHasLocalChanges && dirtyInputClass)}
                      type="checkbox"
                      checked={currentRouterConfig.upstream.enabled}
                      onChange={(event) => {
                        const nextConfig = cloneJson(currentRouterConfig)
                        nextConfig.upstream.enabled = event.target.checked
                        setLocalRouterConfig(nextConfig)
                      }}
                    />
                    <span>Enable upstream proxy</span>
                  </label>
                  <div className={fieldGridClass}>
                    <label className={fieldClass}>
                      <span>Proxy type</span>
                      <select
                        className={cx(routerHasLocalChanges && dirtyInputClass)}
                        value={currentRouterConfig.upstream.type}
                        onChange={(event) => {
                          const nextConfig = cloneJson(currentRouterConfig)
                          nextConfig.upstream.type = event.target.value === 'socks5' ? 'socks5' : 'http'
                          setLocalRouterConfig(nextConfig)
                        }}
                      >
                        <option value="http">HTTP proxy</option>
                        <option value="socks5">SOCKS5 proxy</option>
                      </select>
                    </label>
                    <label className={fieldClass}>
                      <span>Host</span>
                      <input
                        className={cx(routerHasLocalChanges && dirtyInputClass)}
                        type="text"
                        value={currentRouterConfig.upstream.host}
                        placeholder="127.0.0.1"
                        onChange={(event) => {
                          const nextConfig = cloneJson(currentRouterConfig)
                          nextConfig.upstream.host = event.target.value.trim()
                          setLocalRouterConfig(nextConfig)
                        }}
                      />
                    </label>
                    <label className={fieldClass}>
                      <span>Port</span>
                      <input
                        className={cx(routerHasLocalChanges && dirtyInputClass)}
                        type="number"
                        min="1"
                        max="65535"
                        value={currentRouterConfig.upstream.port}
                        placeholder="8900"
                        onChange={(event) => {
                          const nextConfig = cloneJson(currentRouterConfig)
                          nextConfig.upstream.port = event.target.value.trim()
                          setLocalRouterConfig(nextConfig)
                        }}
                      />
                    </label>
                  </div>
                  <div className={noteClass}>
                    In the Docker Compose deployment, proxy-router uses host networking so a host-side upstream proxy
                    can use
                    <strong> 127.0.0.1</strong>.
                  </div>
                  <div className={buttonRowClass}>
                    <button
                      type="button"
                      onClick={triggerUpstreamCheck}
                      disabled={upstreamStatus.enabled && upstreamStatus.connectivity.status === 'checking'}
                    >
                      {upstreamStatus.enabled && upstreamStatus.connectivity.status === 'checking'
                        ? 'Checking upstream…'
                        : 'Check upstream now'}
                    </button>
                  </div>
                  <div className="mt-3 grid grid-cols-1 gap-2 min-[361px]:grid-cols-2 sm:grid-cols-[repeat(auto-fit,minmax(140px,1fr))] sm:gap-3">
                    <div className="min-w-0 rounded-xl border border-[#e8e0d1] bg-white p-3">
                      <div className="text-xs text-[#6a6f73]">Connectivity</div>
                      <div className="mt-1 [overflow-wrap:anywhere] font-bold">
                        <span className={buildUpstreamConnectivityPillClass(upstreamStatus)}>
                          {buildUpstreamConnectivityLabel(upstreamStatus)}
                        </span>
                      </div>
                      <div className={noteClass}>
                        {upstreamStatus.connectivity.message}
                        {upstreamStatus.connectivity.checked_at
                          ? ` Checked at ${formatStatusDateTime(upstreamStatus.connectivity.checked_at)}.`
                          : ''}
                      </div>
                    </div>
                    <div className="min-w-0 rounded-xl border border-[#e8e0d1] bg-white p-3">
                      <div className="text-xs text-[#6a6f73]">Real traffic</div>
                      <div className="mt-1 [overflow-wrap:anywhere] font-bold">{buildUpstreamTrafficHeadline(upstreamStatus)}</div>
                      {buildUpstreamTrafficNotes(upstreamStatus).map((note) => (
                        <div className={noteClass} key={note}>
                          {note}
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="mt-3 grid grid-cols-1 gap-2 min-[361px]:grid-cols-2 sm:grid-cols-[repeat(auto-fit,minmax(140px,1fr))] sm:gap-3">
                    {routerSummaryItems.map(([label, value]) => (
                      <div className="min-w-0 rounded-xl border border-[#e8e0d1] bg-white p-3" key={label}>
                        <div className="text-xs text-[#6a6f73]">{label}</div>
                        <div className="mt-1 [overflow-wrap:anywhere] font-bold">{value}</div>
                      </div>
                    ))}
                  </div>

                  <div className={noteClass}>Auto proxy failing domains</div>
                  <label className="mt-3 flex items-start gap-2 font-semibold leading-snug text-[#1f2a30] [&_input]:mt-1">
                    <input
                      className={cx(routerHasLocalChanges && dirtyInputClass)}
                      type="checkbox"
                      checked={currentRouterConfig.auto_proxy_failures.enabled}
                      onChange={(event) => {
                        const nextConfig = cloneJson(currentRouterConfig)
                        nextConfig.auto_proxy_failures.enabled = event.target.checked
                        setLocalRouterConfig(nextConfig)
                      }}
                    />
                    <span>Probe failing domains with the upstream proxy before enabling auto proxy</span>
                  </label>
                  <div className={noteClass}>
                    Policy: 2 direct failures trigger one proxy probe. If the probe succeeds, the domain is auto-routed
                    through proxy using the escalating schedule 1h, 1d, 7d, 30d, 90d. A longer duration is only earned
                    after the previous duration fully expires. If the probe fails, the domain stays in Failed requests
                    for manual review until a later direct or proxy success clears it.
                  </div>

                  <div className={noteClass}>Ignored failure domains for the selected rules target</div>
                  <div className={chipListClass}>
                    {ignoredDomains.length ? (
                      ignoredDomains.map((item) => (
                        <div className={chipClass} key={`${item.scope}-${item.domain}`}>
                          <span>{`${item.scope_label}: ${item.domain}`}</span>
                          <button
                            type="button"
                            aria-label={`Remove ${item.domain}`}
                            className={chipButtonClass}
                            onClick={() => {
                              const nextConfig = cloneJson(currentRouterConfig)
                              const targetScope = getRoutingTargetById(nextConfig, item.scope) || nextConfig
                              targetScope.ignored_failure_hosts = (targetScope.ignored_failure_hosts || []).filter(
                                (host) => host !== item.domain,
                              )
                              setLocalRouterConfig(nextConfig, {
                                message: 'Ignored domain removed. Syncing automatically.',
                              })
                            }}
                          >
                            x
                          </button>
                        </div>
                      ))
                    ) : (
                      <div className={mutedClass}>No ignored domains yet.</div>
                    )}
                  </div>
                </section>

                <section className={cx(subpanelClass, 'col-span-full lg:col-span-8')}>
                  <div className={panelHeaderClass}>
                    <h3>Rules</h3>
                    <div className={tightButtonRowClass}>
                      <button id="add-rule-button" type="button" onClick={() => addRule()}>
                        Add rule
                      </button>
                      <button className={warnButtonClass} id="clear-rules-button" type="button" onClick={clearCurrentScopeRules}>
                        Clear rules
                      </button>
                      <button id="export-rules-button" type="button" onClick={exportRulesConfig}>
                        Export rules
                      </button>
                    </div>
                  </div>

                  <div className={cx(controlsClass, 'mt-3')}>
                    <label className={cx(controlClass, 'sm:min-w-64')}>
                      <span>Edit rules for</span>
                      <select
                        value={safeEditorProfileId}
                        onChange={(event) => {
                          autoSelectedRulesTargetRef.current = true
                          setCurrentEditorProfileId(event.target.value || DEFAULT_ROUTING_PROFILE_ID)
                          setCurrentRulesPage(1)
                          setRouterStatusOverride(null)
                        }}
                      >
                        <option value={DEFAULT_ROUTING_PROFILE_ID}>Shared</option>
                        {currentRouterConfig.routing_profiles.map((profile) => (
                          <option key={profile.id} value={profile.id}>
                            {profile.name}
                          </option>
                        ))}
                      </select>
                    </label>
                    <label className={controlClass}>
                      <span>Default action</span>
                      <select
                        className={cx(routerHasLocalChanges && dirtyInputClass)}
                        value={currentEditorTarget.default_action}
                        onChange={(event) => {
                          const nextConfig = cloneJson(currentRouterConfig)
                          const target = getRoutingTargetById(nextConfig, safeEditorProfileId) || nextConfig
                          target.default_action = event.target.value === 'proxy' ? 'proxy' : 'direct'
                          setLocalRouterConfig(nextConfig)
                        }}
                      >
                        <option value="direct">Direct</option>
                        <option value="proxy">Proxy</option>
                      </select>
                    </label>
                    <label className={cx(controlClass, 'sm:min-w-80')}>
                      <span>Search rules</span>
                      <input
                        type="search"
                        value={currentRulesSearchTerm}
                        placeholder="pattern, action, source, note"
                        onChange={(event) => {
                          setCurrentRulesSearchTerm(event.target.value.trim())
                          setCurrentRulesPage(1)
                        }}
                      />
                    </label>
                  </div>

                  {currentActiveProfileId !== DEFAULT_ROUTING_PROFILE_ID ? (
                    <div className={cx(noteClass, 'mt-4')}>
                      Active network profile:
                      <strong>{` ${currentActiveProfileLabel}`}</strong>
                      {activeProfileAutoRules.length
                        ? ` · ${activeProfileAutoRules.length} auto-detected proxy domains are currently stored there.`
                        : ' · no auto-detected proxy domains are active there right now.'}
                    </div>
                  ) : null}

                  {editorDiffersFromActiveProfile && currentActiveProfileId !== DEFAULT_ROUTING_PROFILE_ID ? (
                    <div className={tightButtonRowClass}>
                      <button
                        type="button"
                        onClick={() => {
                          autoSelectedRulesTargetRef.current = true
                          setCurrentEditorProfileId(currentActiveProfileId)
                          setCurrentRulesPage(1)
                          setRouterStatusOverride({
                            text: `Switched the rules editor to the active profile ${currentActiveProfileLabel}.`,
                            warning: false,
                          })
                        }}
                      >
                        Switch to active profile
                      </button>
                    </div>
                  ) : null}

                  {activeProfileAutoRules.length ? (
                    <div className={chipListClass}>
                      {activeProfileAutoRules.map((rule) => (
                        <div className={chipClass} key={`${currentActiveProfileId}-${rule.pattern}`}>
                          <span>{rule.pattern}</span>
                        </div>
                      ))}
                    </div>
                  ) : null}

                  <div className="mt-3 mb-2 flex flex-col items-stretch justify-between gap-3 sm:flex-row sm:flex-wrap sm:items-center">
                    <div className={mutedClass}>
                      {orderedRules.length
                        ? currentRulesSearchTerm
                          ? `${orderedRules.length} of ${rulesEntries.length} rules match`
                          : `${orderedRules.length} total rules`
                        : currentRulesSearchTerm
                          ? `No rules match "${currentRulesSearchTerm}".`
                          : 'No rules yet.'}
                    </div>
                    <div className="grid w-full grid-cols-1 items-center gap-2 min-[361px]:grid-cols-[minmax(0,1fr)_auto_minmax(0,1fr)] sm:w-auto sm:flex sm:flex-wrap">
                      <button
                        id="rules-prev-button"
                        type="button"
                        disabled={rulesPage <= 1}
                        onClick={() => setCurrentRulesPage((page) => Math.max(1, page - 1))}
                      >
                        Previous
                      </button>
                      <span className={mutedClass}>{`Page ${rulesPage} / ${totalRulePages}`}</span>
                      <button
                        id="rules-next-button"
                        type="button"
                        disabled={rulesPage >= totalRulePages}
                        onClick={() => setCurrentRulesPage((page) => page + 1)}
                      >
                        Next
                      </button>
                    </div>
                  </div>

                  <div className={tableWrapClass}>
                    <table>
                      <thead>
                        <tr>
                          <th>Scope</th>
                          <th>Enabled</th>
                          <th>Pattern</th>
                          <th>Match</th>
                          <th>Action</th>
                          <th>Source</th>
                          <th>Duration</th>
                          <th>Note</th>
                          <th>Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {orderedRules.length ? (
                          pagedRules.map((entry) => {
                            const rule = entry.rule
                            return (
                              <tr key={`${entry.scope}-${entry.index}-${rule.pattern}-${rule.note}`}>
                                <td>
                                  <span className={rulePillClass}>{entry.scope_label}</span>
                                </td>
                                <td>
                                  <input
                                    type="checkbox"
                                    checked={rule.enabled}
                                    disabled={rule.source === 'auto'}
                                    onChange={(event) =>
                                      updateRuleField(entry.scope, entry.index, 'enabled', event.target.checked)
                                    }
                                  />
                                </td>
                                <td>
                                  <input
                                    className={cx(rule.source === 'auto' && readOnlyInputClass)}
                                    type="text"
                                    value={rule.pattern}
                                    placeholder="gigabyte.com"
                                    disabled={rule.source === 'auto'}
                                    onChange={(event) =>
                                      updateRuleField(entry.scope, entry.index, 'pattern', event.target.value)
                                    }
                                  />
                                </td>
                                <td>
                                  <select
                                    className={cx(rule.source === 'auto' && readOnlyInputClass)}
                                    value={rule.match}
                                    disabled={rule.source === 'auto'}
                                    onChange={(event) =>
                                      updateRuleField(entry.scope, entry.index, 'match', event.target.value)
                                    }
                                  >
                                    <option value="suffix">Suffix</option>
                                    <option value="exact">Exact</option>
                                    <option value="contains">Contains</option>
                                  </select>
                                </td>
                                <td>
                                  <select
                                    className={cx(rule.source === 'auto' && readOnlyInputClass)}
                                    value={rule.action}
                                    disabled={rule.source === 'auto'}
                                    onChange={(event) =>
                                      updateRuleField(entry.scope, entry.index, 'action', event.target.value)
                                    }
                                  >
                                    <option value="direct">Direct</option>
                                    <option value="proxy">Proxy</option>
                                    <option value="block">Block</option>
                                  </select>
                                </td>
                                <td>
                                  <div className={ruleMetaClass}>
                                    <span className={cx(rulePillClass, rule.source === 'auto' && autoRulePillClass)}>
                                      {rule.source === 'auto' ? 'Auto' : 'Manual'}
                                    </span>
                                    <small>{rule.source === 'auto' ? 'Auto-managed' : 'User-managed'}</small>
                                  </div>
                                </td>
                                <td>
                                  {rule.source === 'auto' ? (
                                    <div className={ruleMetaClass}>
                                      <strong>{rule.duration}</strong>
                                      <small>{formatRuleExpiry(rule, nowMs)}</small>
                                    </div>
                                  ) : (
                                    <div className={ruleMetaClass}>
                                      <select
                                        value={rule.duration}
                                        onChange={(event) =>
                                          updateRuleField(entry.scope, entry.index, 'duration', event.target.value)
                                        }
                                      >
                                        {RULE_DURATION_OPTIONS.map((duration) => (
                                          <option key={duration} value={duration}>
                                            {duration}
                                          </option>
                                        ))}
                                      </select>
                                      <small>{formatRuleExpiry(rule, nowMs)}</small>
                                    </div>
                                  )}
                                </td>
                                <td>
                                  <input
                                    className={cx(rule.source === 'auto' && readOnlyInputClass)}
                                    type="text"
                                    value={rule.note}
                                    placeholder="optional note"
                                    disabled={rule.source === 'auto'}
                                    onChange={(event) =>
                                      updateRuleField(entry.scope, entry.index, 'note', event.target.value)
                                    }
                                  />
                                </td>
                                <td className={ruleActionsClass}>
                                  {rule.source === 'auto' ? (
                                    <button type="button" onClick={() => ignoreAutoRule(entry.scope, entry.index)}>
                                      Ignore
                                    </button>
                                  ) : (
                                    <button
                                      type="button"
                                      onClick={() => {
                                        const nextConfig = cloneJson(currentRouterConfig)
                                        const targetScope = getRoutingTargetById(nextConfig, entry.scope)
                                        if (!targetScope || !targetScope.rules[entry.index]) {
                                          return
                                        }
                                        targetScope.rules.splice(entry.index, 1)
                                        setLocalRouterConfig(nextConfig, {
                                          message: 'Rule removed. Syncing automatically.',
                                        })
                                      }}
                                    >
                                      Delete
                                    </button>
                                  )}
                                </td>
                              </tr>
                            )
                          })
                        ) : (
                          <tr>
                            <td colSpan="9" className="pt-2 text-[#6a6f73]">
                              {currentRulesSearchTerm
                                ? 'No rules match the current search.'
                                : 'No rules yet. Add one to override the default action.'}
                            </td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                </section>
              </div>
            </section>
          </section>
        </section>
      ) : null}

      {activeTab === 'quotas' ? (
        <section className="block">
          <section className={gridClass}>
            <section className={cx(panelClass, 'col-span-full')}>
              <div className={panelHeaderClass}>
                <div>
                  <h2>Quotas</h2>
                  <div className={noteClass}>
                    Default quotas apply to every device unless a custom limit or exemption matches first.
                  </div>
                </div>
              </div>

              <div className={noteClass}>Default traffic quota for all devices</div>
              <label className="mt-3 flex items-start gap-2 font-semibold leading-snug text-[#1f2a30] [&_input]:mt-1">
                <input
                  className={cx(routerHasLocalChanges && dirtyInputClass)}
                  type="checkbox"
                  checked={currentRouterConfig.default_client_traffic_limit.enabled}
                  onChange={(event) => {
                    const nextConfig = cloneJson(currentRouterConfig)
                    nextConfig.default_client_traffic_limit.enabled = event.target.checked
                    setLocalRouterConfig(nextConfig)
                  }}
                />
                <span>Enable default quota for every device</span>
              </label>
              <div className={fieldGridClass}>
                <label className={fieldClass}>
                  <span>Last hour (MB)</span>
                  <input
                    className={cx(routerHasLocalChanges && dirtyInputClass)}
                    type="number"
                    min="1"
                    value={currentRouterConfig.default_client_traffic_limit.max_past_hour_mb ?? ''}
                    placeholder="1500"
                    onChange={(event) => {
                      const nextConfig = cloneJson(currentRouterConfig)
                      nextConfig.default_client_traffic_limit.max_past_hour_mb = normalizeOptionalLimitMb(
                        event.target.value,
                      )
                      setLocalRouterConfig(nextConfig)
                    }}
                  />
                </label>
                <label className={fieldClass}>
                  <span>Last 3h (MB)</span>
                  <input
                    className={cx(routerHasLocalChanges && dirtyInputClass)}
                    type="number"
                    min="1"
                    value={currentRouterConfig.default_client_traffic_limit.max_past_3h_mb ?? ''}
                    placeholder="3500"
                    onChange={(event) => {
                      const nextConfig = cloneJson(currentRouterConfig)
                      nextConfig.default_client_traffic_limit.max_past_3h_mb = normalizeOptionalLimitMb(
                        event.target.value,
                      )
                      setLocalRouterConfig(nextConfig)
                    }}
                  />
                </label>
                <label className={fieldClass}>
                  <span>Note</span>
                  <input
                    className={cx(routerHasLocalChanges && dirtyInputClass)}
                    type="text"
                    value={currentRouterConfig.default_client_traffic_limit.note || ''}
                    placeholder="optional note"
                    onChange={(event) => {
                      const nextConfig = cloneJson(currentRouterConfig)
                      nextConfig.default_client_traffic_limit.note = event.target.value
                      setLocalRouterConfig(nextConfig)
                    }}
                  />
                </label>
              </div>

              <div className={noteClass}>
                Custom client IP or CIDR limits override the default. Exemptions override both limits.
              </div>

              <div className={cx(panelHeaderClass, 'mt-4')}>
                <h3>Client traffic limits</h3>
                <button id="add-client-limit-button" type="button" onClick={() => addClientTrafficLimit()}>
                  Add limit
                </button>
              </div>
              <div className={noteClass}>
                Match one client IP or CIDR and cap its traffic over the last hour and last 3 hours.
              </div>

              <div className={tableWrapClass}>
                <table>
                  <thead>
                    <tr>
                      <th>Enabled</th>
                      <th>Client IP / CIDR</th>
                      <th>Last hour (MB)</th>
                      <th>Last 3h (MB)</th>
                      <th>Note</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {currentRouterConfig.client_traffic_limits.length ? (
                      currentRouterConfig.client_traffic_limits.map((limit, index) => (
                        <tr key={`${limit.client}-${index}`}>
                          <td>
                            <input
                              type="checkbox"
                              checked={limit.enabled}
                              onChange={(event) =>
                                updateClientTrafficLimitField(index, 'enabled', event.target.checked)
                              }
                            />
                          </td>
                          <td>
                            <input
                              type="text"
                              value={limit.client}
                              placeholder="192.168.1.50 or 192.168.1.0/24"
                              onChange={(event) => updateClientTrafficLimitField(index, 'client', event.target.value)}
                            />
                          </td>
                          <td>
                            <input
                              type="number"
                              min="1"
                              value={limit.max_past_hour_mb ?? ''}
                              placeholder="1500"
                              onChange={(event) =>
                                updateClientTrafficLimitField(
                                  index,
                                  'max_past_hour_mb',
                                  normalizeOptionalLimitMb(event.target.value),
                                )
                              }
                            />
                          </td>
                          <td>
                            <input
                              type="number"
                              min="1"
                              value={limit.max_past_3h_mb ?? ''}
                              placeholder="3500"
                              onChange={(event) =>
                                updateClientTrafficLimitField(
                                  index,
                                  'max_past_3h_mb',
                                  normalizeOptionalLimitMb(event.target.value),
                                )
                              }
                            />
                          </td>
                          <td>
                            <input
                              type="text"
                              value={limit.note}
                              placeholder="optional note"
                              onChange={(event) => updateClientTrafficLimitField(index, 'note', event.target.value)}
                            />
                          </td>
                          <td className={ruleActionsClass}>
                            <button
                              type="button"
                              onClick={() => {
                                const nextConfig = cloneJson(currentRouterConfig)
                                nextConfig.client_traffic_limits.splice(index, 1)
                                setLocalRouterConfig(nextConfig, {
                                  message: 'Client traffic limit removed. Syncing automatically.',
                                })
                              }}
                            >
                              Delete
                            </button>
                          </td>
                        </tr>
                      ))
                    ) : (
                      <tr>
                        <td colSpan="6" className="pt-2 text-[#6a6f73]">
                          No client traffic limits yet.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>

              <div className={cx(panelHeaderClass, 'mt-4')}>
                <h3>Quota exemptions</h3>
                <button id="add-client-exemption-button" type="button" onClick={() => addClientTrafficExemption()}>
                  Add exemption
                </button>
              </div>
              <div className={noteClass}>
                Use exemptions to exclude devices permanently or suspend quota enforcement for a limited time such as 2h.
              </div>

              <div className={tableWrapClass}>
                <table>
                  <thead>
                    <tr>
                      <th>Enabled</th>
                      <th>Client IP / CIDR</th>
                      <th>Duration</th>
                      <th>Active until</th>
                      <th>Note</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {currentRouterConfig.client_traffic_exemptions.length ? (
                      currentRouterConfig.client_traffic_exemptions.map((exemption, index) => (
                        <tr key={`${exemption.client}-${index}`}>
                          <td>
                            <input
                              type="checkbox"
                              checked={exemption.enabled}
                              onChange={(event) =>
                                updateClientTrafficExemptionField(index, 'enabled', event.target.checked)
                              }
                            />
                          </td>
                          <td>
                            <input
                              type="text"
                              value={exemption.client}
                              placeholder="127.0.0.1 or 192.168.1.0/24"
                              onChange={(event) => updateClientTrafficExemptionField(index, 'client', event.target.value)}
                            />
                          </td>
                          <td>
                            <select
                              value={exemption.duration}
                              onChange={(event) =>
                                updateClientTrafficExemptionField(index, 'duration', event.target.value)
                              }
                            >
                              {EXEMPTION_DURATION_OPTIONS.map((duration) => (
                                <option key={duration} value={duration}>
                                  {duration}
                                </option>
                              ))}
                            </select>
                          </td>
                          <td>
                            <div className={ruleMetaClass}>
                              <strong>{exemption.expires_at ? new Date(exemption.expires_at).toLocaleString() : 'Permanent'}</strong>
                              <small>{formatExemptionExpiry(exemption, nowMs)}</small>
                            </div>
                          </td>
                          <td>
                            <input
                              type="text"
                              value={exemption.note}
                              placeholder="optional note"
                              onChange={(event) => updateClientTrafficExemptionField(index, 'note', event.target.value)}
                            />
                          </td>
                          <td className={ruleActionsClass}>
                            <button
                              type="button"
                              onClick={() => {
                                const nextConfig = cloneJson(currentRouterConfig)
                                nextConfig.client_traffic_exemptions.splice(index, 1)
                                setLocalRouterConfig(nextConfig, {
                                  message: 'Quota exemption removed. Syncing automatically.',
                                })
                              }}
                            >
                              Delete
                            </button>
                          </td>
                        </tr>
                      ))
                    ) : (
                      <tr>
                        <td colSpan="6" className="pt-2 text-[#6a6f73]">
                          No quota exemptions yet.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </section>

            <section className={cx(panelClass, 'col-span-full')}>
              <h2>By device</h2>
              {dashboardSnapshot.totals_by_client.length ? (
                <div className={tableWrapClass}>
                  <table>
                    <thead>
                      <tr>
                        <th>Client IP</th>
                        <th>Active</th>
                        <th>Handled</th>
                        <th>Proxy types</th>
                        <th>Last 1h</th>
                        <th>Limit 1h</th>
                        <th>Last 3h</th>
                        <th>Limit 3h</th>
                        <th>Status</th>
                        <th>Upload</th>
                        <th>Download</th>
                        <th>Total</th>
                        <th>Last seen</th>
                      </tr>
                    </thead>
                    <tbody>
                      {dashboardSnapshot.totals_by_client.map((client) => {
                        const quota = dashboardSnapshot.client_quota_status[client.client] || {}
                        const usage = quota.usage || {}
                        const limit = quota.limit || {}
                        const used1h = Number((usage['1h'] || {}).total_bytes || 0)
                        const used3h = Number((usage['3h'] || {}).total_bytes || 0)
                        const limitScope =
                          limit.scope === 'default'
                            ? 'Default'
                            : limit.scope === 'custom'
                              ? 'Custom'
                              : limit.scope === 'exempt'
                                ? 'Exempt'
                                : ''
                        const statusText = quota.limit
                          ? limit.scope === 'exempt'
                            ? limit.expires_at
                              ? `Exempt for ${formatDuration(
                                  Math.max(1, Math.floor((new Date(limit.expires_at).getTime() - nowMs) / 1000)),
                                )}`
                              : 'Exempt'
                            : quota.allowed === false
                              ? `Blocked (${limitScope || 'Limit'}) for ${formatDuration(
                                  quota.retry_after_seconds,
                                )}`
                              : `Within ${limitScope || 'configured'} limit`
                          : 'No limit'
                        return (
                          <tr key={client.client}>
                            <td>{client.client}</td>
                            <td>{client.active_connections}</td>
                            <td>{client.count}</td>
                            <td>{(client.proxy_types || []).join(', ') || 'none yet'}</td>
                            <td>{formatMb(used1h)}</td>
                            <td>{formatLimitMb(limit.max_past_hour_mb)}</td>
                            <td>{formatMb(used3h)}</td>
                            <td>{formatLimitMb(limit.max_past_3h_mb)}</td>
                            <td>{statusText}</td>
                            <td>{formatMb(client.uploaded_bytes)}</td>
                            <td>{formatMb(client.downloaded_bytes)}</td>
                            <td>{formatMb(client.total_bytes)}</td>
                            <td>{client.last_seen_at || 'waiting for first request'}</td>
                          </tr>
                        )
                      })}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="pt-2 text-[#6a6f73]">No client traffic has been recorded yet.</div>
              )}
            </section>
          </section>
        </section>
      ) : null}

      {activeTab === 'failures' ? (
        <section className="block">
          <section className={gridClass}>
            <section className={cx(panelClass, 'col-span-full')}>
              <h2>Failed requests</h2>
              <div className={noteClass}>
                Grouped by effective domain. Ignore noisy domains or add direct/proxy rules from the latest failure group.
              </div>
              <div className="mt-3 mb-2 flex flex-col items-stretch justify-between gap-3 sm:flex-row sm:flex-wrap sm:items-center">
                <div className={mutedClass}>
                  {`${failureView.groups.length} grouped domains shown${
                    failureView.ignoredGroups.length ? ` · ${failureView.ignoredGroups.length} ignored` : ''
                  }${failureView.handledCount ? ` · ${failureView.handledCount} handled by local rules` : ''}`}
                </div>
                <div className="grid w-full grid-cols-1 items-center gap-2 min-[361px]:grid-cols-[minmax(0,1fr)_auto_minmax(0,1fr)] sm:w-auto sm:flex sm:flex-wrap">
                  <button
                    type="button"
                    disabled={failurePage <= 1}
                    onClick={() => setCurrentFailurePage((page) => Math.max(1, page - 1))}
                  >
                    Previous
                  </button>
                  <span className={mutedClass}>{`Page ${failurePage} / ${totalFailurePages}`}</span>
                  <button
                    type="button"
                    disabled={failurePage >= totalFailurePages}
                    onClick={() => setCurrentFailurePage((page) => page + 1)}
                  >
                    Next
                  </button>
                </div>
              </div>

              {failurePageItems.length ? (
                <div className={tableWrapClass}>
                  <table>
                    <thead>
                      <tr>
                        <th>Latest</th>
                        <th>Domain</th>
                        <th>Count</th>
                        <th>Methods</th>
                        <th>Clients</th>
                        <th>Route</th>
                        <th>Latest error</th>
                        <th>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {failurePageItems.map((group) => (
                        <tr key={group.group_key}>
                          <td>{group.latest_timestamp}</td>
                          <td className="max-w-md break-words">
                            <strong>{group.domain || group.group_key}</strong>
                            <br />
                            <span className={mutedClass}>{`${group.host_count} host(s) · latest ${
                              group.host || group.domain || group.group_key
                            }`}</span>
                          </td>
                          <td>{group.count}</td>
                          <td>{(group.method_list || []).join(', ')}</td>
                          <td>{group.client_count}</td>
                          <td>{group.route_label || 'direct'}</td>
                          <td>{group.latest_error}</td>
                          <td className={ruleActionsClass}>
                            <button
                              type="button"
                              onClick={() =>
                                addRule({
                                  enabled: true,
                                  pattern: String(group.domain || group.group_key).trim().toLowerCase(),
                                  match: 'suffix',
                                  action: 'proxy',
                                  note: `from failed domain ${String(group.domain || group.group_key).trim().toLowerCase()}`,
                                  source: 'manual',
                                  duration: 'always',
                                  expires_at: null,
                                })
                              }
                            >
                              Proxy domain
                            </button>
                            {group.host && group.host !== group.domain ? (
                              <button
                                type="button"
                                onClick={() =>
                                  addRule({
                                    enabled: true,
                                    pattern: String(group.host).trim().toLowerCase(),
                                    match: 'exact',
                                    action: 'proxy',
                                    note: `from failed domain ${String(group.host).trim().toLowerCase()}`,
                                    source: 'manual',
                                    duration: 'always',
                                    expires_at: null,
                                  })
                                }
                              >
                                Proxy exact host
                              </button>
                            ) : null}
                            <button
                              type="button"
                              onClick={() =>
                                addRule({
                                  enabled: true,
                                  pattern: String(group.domain || group.group_key).trim().toLowerCase(),
                                  match: 'suffix',
                                  action: 'direct',
                                  note: `from failed domain ${String(group.domain || group.group_key).trim().toLowerCase()}`,
                                  source: 'manual',
                                  duration: 'always',
                                  expires_at: null,
                                })
                              }
                            >
                              Direct domain
                            </button>
                            <button
                              className={warnButtonClass}
                              type="button"
                              onClick={() =>
                                addRule({
                                  enabled: true,
                                  pattern: String(group.domain || group.group_key).trim().toLowerCase(),
                                  match: 'suffix',
                                  action: 'block',
                                  note: `from failed domain ${String(group.domain || group.group_key).trim().toLowerCase()}`,
                                  source: 'manual',
                                  duration: 'always',
                                  expires_at: null,
                                })
                              }
                            >
                              Block domain
                            </button>
                            <button className={warnButtonClass} type="button" onClick={() => ignoreFailureHost(group.domain || group.group_key)}>
                              Ignore
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="pt-2 text-[#6a6f73]">
                  {failureView.ignoredGroups.length
                    ? 'All failed domains are currently ignored.'
                    : failureView.handledCount
                      ? 'No actionable failed domains remain. Existing local rules already cover them.'
                      : 'No failed requests recorded yet.'}
                </div>
              )}

              <div className={noteClass}>
                {failureView.ignoredGroups.length
                  ? `Ignored domains: ${failureView.ignoredGroups
                      .map((item) => item.domain || item.group_key)
                      .join(', ')}`
                  : ''}
              </div>
            </section>
          </section>
        </section>
      ) : null}
      </div>
    </main>
  )
}

export default App
