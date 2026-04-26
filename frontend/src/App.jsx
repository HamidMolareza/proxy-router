import { useEffect, useState } from 'react'
import './styles.css'

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
    },
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
      .filter((exemption) => exemption.client && !isExemptionExpired(exemption)),
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
  return JSON.stringify(normalizeRouterConfig(config))
}

function currentRouterRuntime(snapshot) {
  return snapshot && typeof snapshot === 'object' && snapshot.router_runtime ? snapshot.router_runtime : {}
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
    ['Auto proxy', autoProxyStatus],
    ['Default quota', defaultClientLimitLabel],
    ['Client limits', `${enabledClientLimits}/${config.client_traffic_limits.length}`],
    ['Exemptions', `${enabledClientExemptions}/${config.client_traffic_exemptions.length}`],
    ['Ignored domains', String(getEffectiveEditorIgnoredDomains(config, profileId).length)],
  ]
}

function buildRouterStatusText(config, lastSavedConfig, profileId) {
  const dirty = routerConfigFingerprint(config) !== routerConfigFingerprint(lastSavedConfig)
  const visibleRuleEntries = getEditorVisibleRuleEntries(config, profileId)
  const editorLabel = getEditorTargetLabel(config, profileId)
  if (dirty) {
    return `Unsaved changes · ${
      visibleRuleEntries.filter((entry) => entry.rule && entry.rule.enabled).length
    } enabled rules · ${
      config.client_traffic_limits.filter((limit) => limit.enabled).length
    } active client limits · ${
      config.client_traffic_exemptions.filter((exemption) => exemption.enabled).length
    } active exemptions · editing ${editorLabel}`
  }
  return `Config in sync · ${visibleRuleEntries.length} rules · ${config.client_traffic_limits.length} client limits · ${config.client_traffic_exemptions.length} exemptions · ${
    config.upstream.enabled ? 'upstream on' : 'upstream off'
  } · editing ${editorLabel}`
}

function buildRulesExportPayload(config) {
  const normalized = normalizeRouterConfig(config)
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

function BucketChart({ series, emptyMessage, ariaLabel }) {
  if (!series.length) {
    return <div className="empty">{emptyMessage}</div>
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
    <div className="chart-shell">
      <div className="chart-legend">
        <span>
          <i className="legend-swatch legend-upload"></i>
          Upload
        </span>
        <span>
          <i className="legend-swatch legend-download"></i>
          Download
        </span>
      </div>
      <svg className="usage-chart-svg" viewBox={`0 0 ${svgWidth} ${svgHeight}`} role="img" aria-label={ariaLabel}>
        <line
          className="chart-axis"
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
                className="chart-download"
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
                  className="chart-upload"
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
                <text className="chart-label" x={(x + barWidth / 2).toFixed(2)} y={svgHeight - 14} textAnchor="middle">
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

  const safeEditorProfileId =
    currentEditorProfileId === DEFAULT_ROUTING_PROFILE_ID ||
    getRoutingTargetById(currentRouterConfig, currentEditorProfileId)
      ? currentEditorProfileId
      : DEFAULT_ROUTING_PROFILE_ID
  const currentEditorTarget = getRoutingTargetById(currentRouterConfig, safeEditorProfileId) || currentRouterConfig
  const routerDirty =
    routerConfigFingerprint(currentRouterConfig) !== routerConfigFingerprint(lastSavedRouterConfig)
  const routerStatus =
    routerStatusOverride || {
      text: buildRouterStatusText(currentRouterConfig, lastSavedRouterConfig, safeEditorProfileId),
      warning: false,
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

  async function loadRouterConfig({ silent = false } = {}) {
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
    if (silent && routerDirty) {
      return
    }
    setCurrentRouterConfig(loadedConfig)
    setLastSavedRouterConfig(cloneJson(loadedConfig))
    if (!silent) {
      setRouterStatusOverride({
        text: `Loaded from disk · ${new Date().toLocaleTimeString()}`,
        warning: false,
      })
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

    async function refreshAll() {
      try {
        const response = await fetch('/api/dashboard', {
          cache: 'no-store',
          headers: {
            Accept: 'application/json',
          },
        })
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}`)
        }
        const snapshot = await response.json()
        if (!cancelled) {
          setNowMs(Date.now())
          setDashboardSnapshot(snapshot)
          setStatus({
            text: `Live updates every 2 seconds · ${new Date().toLocaleTimeString()}`,
            warning: false,
          })
        }
        if (!routerDirty) {
          try {
            const configResponse = await fetch('/api/router-config', {
              cache: 'no-store',
              headers: {
                Accept: 'application/json',
              },
            })
            if (configResponse.ok) {
              const loadedConfig = normalizeRouterConfig(await configResponse.json())
              if (!cancelled) {
                setCurrentRouterConfig(loadedConfig)
                setLastSavedRouterConfig(cloneJson(loadedConfig))
              }
            }
          } catch {
            // Keep the last local config state if the silent refresh fails.
          }
        }
      } catch (error) {
        if (!cancelled) {
          setStatus({
            text: `Live updates paused: ${error.message}`,
            warning: true,
          })
        }
      }

      try {
        const params = new URLSearchParams()
        params.set('range', historyRange)
        if (historyProxyType !== 'all') {
          params.set('proxy_type', historyProxyType)
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
        if (!cancelled) {
          setHistoryData(history)
          setHistoryError('')
          if (historyProxyType !== 'all' && !history.available_proxy_types.includes(historyProxyType)) {
            setHistoryProxyType('all')
          }
        }
      } catch (error) {
        if (!cancelled) {
          setHistoryError(`History refresh paused: ${error.message}`)
        }
      }
    }

    refreshAll()
    const intervalId = window.setInterval(refreshAll, 2000)

    return () => {
      cancelled = true
      window.clearInterval(intervalId)
    }
  }, [historyRange, historyProxyType, routerDirty])

  function setLocalRouterConfig(nextConfig, options = {}) {
    setCurrentRouterConfig(normalizeRouterConfig(nextConfig))
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
      message: 'Rule added locally. Save config to apply it.',
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
      message: 'Client traffic limit added locally. Save config to apply it.',
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
      message: 'Quota exemption added locally. Save config to apply it.',
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
      `Clear all rules in ${editorLabel}? Shared rules in other scopes will be kept until you save.`,
    )
    if (!confirmed) {
      return
    }
    const nextConfig = cloneJson(currentRouterConfig)
    const currentTarget = getRoutingTargetById(nextConfig, safeEditorProfileId) || nextConfig
    currentTarget.rules = []
    setLocalRouterConfig(nextConfig, {
      resetRulesPage: true,
      message: `Rules cleared locally for ${editorLabel}. Save config to apply the change.`,
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
      message: 'Auto rule converted to a permanent direct rule. Save config to apply the change.',
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
      message: 'Domain added to ignored failures. Save config to apply the change.',
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
    const profileId = `profile-${Math.random().toString(36).slice(2, 10)}`
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
      message: 'Profile created locally from the current network. Review it and save config.',
    })
  }

  async function saveRouterConfig() {
    setIsSavingRouter(true)
    try {
      const response = await fetch('/api/router-config', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
        body: JSON.stringify(normalizeRouterConfig(currentRouterConfig)),
      })
      const payload = await response.json().catch(() => ({ error: 'invalid JSON response' }))
      if (!response.ok) {
        throw new Error(payload.error || `router config HTTP ${response.status}`)
      }
      const normalizedConfig = normalizeRouterConfig(payload)
      setCurrentRouterConfig(normalizedConfig)
      setLastSavedRouterConfig(cloneJson(normalizedConfig))
      setRouterStatusOverride({
        text: `Saved · ${new Date().toLocaleTimeString()}`,
        warning: false,
      })
    } finally {
      setIsSavingRouter(false)
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
    <main className="app-shell">
      <section className="hero">
        <div>
          <h1>proxy-router dashboard</h1>
          <p>Current session view for traffic totals, per-device usage, and the latest completed request.</p>
        </div>
        <div className={`pill ${status.warning ? 'pill-warning' : ''}`}>{status.text}</div>
      </section>

      <section className="panel config-bar">
        <div className="panel-header">
          <div>
            <h2>Configuration</h2>
            <div className="router-note">Routing profiles, rules, quotas, and exemptions are saved together.</div>
          </div>
          <div className="config-actions">
            <div className={`pill ${routerStatus.warning ? 'pill-warning' : ''}`}>{routerStatus.text}</div>
            <button className="primary" type="button" disabled={!routerDirty || isSavingRouter} onClick={() => {
              saveRouterConfig().catch((error) => {
                setRouterStatusOverride({
                  text: `Save failed: ${error.message}`,
                  warning: true,
                })
              })
            }}>
              {isSavingRouter ? 'Saving…' : 'Save config'}
            </button>
            <button
              type="button"
              onClick={() => {
                loadRouterConfig().catch((error) => {
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

      <section className="tabs" aria-label="Dashboard tabs">
        {TAB_DEFINITIONS.map((tab) => (
          <button
            key={tab.id}
            className={`tab-button ${activeTab === tab.id ? 'is-active' : ''}`}
            type="button"
            aria-pressed={activeTab === tab.id ? 'true' : 'false'}
            onClick={() => setActiveTab(tab.id)}
          >
            {tab.label}
          </button>
        ))}
      </section>

      {activeTab === 'overview' ? (
        <section className="tab-panel is-active">
          <section className="grid">
            <div className="cards" id="summary-cards">
              {overviewCards.map(([label, value]) => (
                <div className="card" key={label}>
                  <div className="card-label">{label}</div>
                  <div className={label === 'Started' ? 'card-value card-value-started' : 'card-value'}>{value}</div>
                </div>
              ))}
            </div>

            <section className="panel usage-chart">
              <h2>Recent traffic</h2>
              <BucketChart
                series={usageChartPoints}
                emptyMessage="No recent traffic yet."
                ariaLabel="Recent traffic by request"
              />
            </section>

            <section className="panel latest">
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
                    <div className="detail-row" key={label}>
                      <span className="detail-label">{label}</span>
                      <span className="detail-value">{value}</span>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="empty">No completed requests yet.</div>
              )}
            </section>

            <section className="panel totals">
              <h2>By proxy</h2>
              <div className="table-wrap">
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

            <section className="panel route-totals">
              <h2>By route</h2>
              <div className="table-wrap">
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

            <section className="panel recent">
              <h2>Recent requests</h2>
              {dashboardSnapshot.recent_requests.length ? (
                <div className="table-wrap">
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
                          <td className="destination">{request.destination}</td>
                          <td>{request.route_label || 'direct'}</td>
                          <td>{formatMb(request.total_bytes)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="empty">No recent requests yet.</div>
              )}
            </section>
          </section>
        </section>
      ) : null}

      {activeTab === 'history' ? (
        <section className="tab-panel is-active">
          <section className="grid">
            <section className="panel history">
              <div className="panel-header">
                <h2>History</h2>
                <button className="warn" id="clear-traffic-button" type="button" disabled={isClearingTraffic} onClick={() => {
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

              <div className="controls">
                <label className="control">
                  <span>Range</span>
                  <select value={historyRange} onChange={(event) => setHistoryRange(event.target.value)}>
                    {HISTORY_RANGE_OPTIONS.map((option) => (
                      <option key={option.value} value={option.value}>
                        {option.label}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="control">
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

              <div className="history-summary">
                {historyCards.map(([label, value]) => (
                  <div className="card" key={label}>
                    <div className="card-label">{label}</div>
                    <div className="card-value">{value}</div>
                  </div>
                ))}
              </div>
              <div className="history-note">{historyNote}</div>

              <div className="history-grid">
                <section className="subpanel">
                  <h3>Traffic over time</h3>
                  {historyError ? (
                    <div className="empty">{historyError}</div>
                  ) : (
                    <BucketChart
                      series={historyData.series || []}
                      emptyMessage="No historical traffic matched this filter."
                      ariaLabel="Traffic over time"
                    />
                  )}
                </section>

                <section className="subpanel">
                  <h3>Top destinations</h3>
                  {historyError ? (
                    <div className="empty">History data is unavailable right now.</div>
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
                            <td className="destination">{item.destination}</td>
                            <td>{item.count}</td>
                            <td>{formatMb(item.total_bytes)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  ) : (
                    <div className="empty">No destinations matched this filter.</div>
                  )}
                </section>
              </div>
            </section>
          </section>
        </section>
      ) : null}

      {activeTab === 'routing' ? (
        <section className="tab-panel is-active">
          <section className="grid">
            <section className="panel router">
              <div className="panel-header">
                <div>
                  <h2>Routing</h2>
                  <div className="router-note">Profiles, upstream proxy, auto-proxy policy, and host rules.</div>
                </div>
              </div>

              <div className="router-grid">
                <section className="router-card">
                  <h3>Profiles</h3>
                  <div className="router-note">Detect the current internet and VPN set, then match its saved routing profile.</div>
                  <div className="router-summary">
                    {profileRuntimeItems.map(([label, value]) => (
                      <div className="mini-card" key={label}>
                        <div className="mini-label">{label}</div>
                        <div className="mini-value">{value}</div>
                      </div>
                    ))}
                  </div>

                  <div className="button-row">
                    <button id="create-profile-from-current-button" type="button" onClick={createProfileFromCurrentNetwork}>
                      Create profile from current network
                    </button>
                  </div>

                  <div className="table-wrap">
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
                                      message: 'Profile updated locally. Save config to apply the change.',
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
                                      message: 'Profile updated locally. Save config to apply the change.',
                                    })
                                  }}
                                />
                                <small>{profile.id === activeProfileId(dashboardSnapshot) ? 'Active now' : 'Saved profile'}</small>
                              </td>
                              <td>{formatProfileInternetLabel(profile.signature)}</td>
                              <td>{formatProfileVpnLabel(profile.signature)}</td>
                              <td className="rule-actions">
                                <button
                                  type="button"
                                  onClick={() => {
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
                                      message: 'Profile removed locally. Save config to apply the change.',
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
                            <td colSpan="5" className="empty">
                              No saved network-specific profiles yet.
                            </td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  </div>

                  <div className="router-note section-gap">Global upstream and routing status</div>
                  <h3>Upstream proxy</h3>
                  <label className="checkbox-row">
                    <input
                      className={routerDirty ? 'input-dirty' : ''}
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
                  <div className="field-grid">
                    <label className="field">
                      <span>Proxy type</span>
                      <select
                        className={routerDirty ? 'input-dirty' : ''}
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
                    <label className="field">
                      <span>Host</span>
                      <input
                        className={routerDirty ? 'input-dirty' : ''}
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
                    <label className="field">
                      <span>Port</span>
                      <input
                        className={routerDirty ? 'input-dirty' : ''}
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

                  <div className="router-summary">
                    {routerSummaryItems.map(([label, value]) => (
                      <div className="mini-card" key={label}>
                        <div className="mini-label">{label}</div>
                        <div className="mini-value">{value}</div>
                      </div>
                    ))}
                  </div>

                  <div className="router-note">Auto proxy failing domains</div>
                  <label className="checkbox-row">
                    <input
                      className={routerDirty ? 'input-dirty' : ''}
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
                  <div className="router-note">
                    Policy: 2 direct failures trigger one proxy probe. If the probe succeeds, the domain is auto-routed
                    through proxy using the escalating schedule 1h, 1d, 7d, 30d, 90d. A longer duration is only earned
                    after the previous duration fully expires. If the probe fails, the domain stays in Failed requests
                    for manual review until a later direct or proxy success clears it.
                  </div>

                  <div className="router-note">Ignored failure domains for the selected rules target</div>
                  <div className="chip-list">
                    {ignoredDomains.length ? (
                      ignoredDomains.map((item) => (
                        <div className="chip" key={`${item.scope}-${item.domain}`}>
                          <span>{`${item.scope_label}: ${item.domain}`}</span>
                          <button
                            type="button"
                            aria-label={`Remove ${item.domain}`}
                            onClick={() => {
                              const nextConfig = cloneJson(currentRouterConfig)
                              const targetScope = getRoutingTargetById(nextConfig, item.scope) || nextConfig
                              targetScope.ignored_failure_hosts = (targetScope.ignored_failure_hosts || []).filter(
                                (host) => host !== item.domain,
                              )
                              setLocalRouterConfig(nextConfig, {
                                message: 'Ignored domain removed locally. Save config to apply the change.',
                              })
                            }}
                          >
                            x
                          </button>
                        </div>
                      ))
                    ) : (
                      <div className="muted">No ignored domains yet.</div>
                    )}
                  </div>
                </section>

                <section className="router-rules">
                  <div className="panel-header">
                    <h3>Rules</h3>
                    <div className="button-row tight-row">
                      <button id="add-rule-button" type="button" onClick={() => addRule()}>
                        Add rule
                      </button>
                      <button className="warn" id="clear-rules-button" type="button" onClick={clearCurrentScopeRules}>
                        Clear rules
                      </button>
                      <button id="export-rules-button" type="button" onClick={exportRulesConfig}>
                        Export rules
                      </button>
                    </div>
                  </div>

                  <div className="controls top-tight">
                    <label className="control control-wide">
                      <span>Edit rules for</span>
                      <select
                        value={safeEditorProfileId}
                        onChange={(event) => {
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
                    <label className="control">
                      <span>Default action</span>
                      <select
                        className={routerDirty ? 'input-dirty' : ''}
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
                    <label className="control control-search">
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

                  <div className="failure-controls top-tight">
                    <div className="muted">
                      {orderedRules.length
                        ? currentRulesSearchTerm
                          ? `${orderedRules.length} of ${rulesEntries.length} rules match`
                          : `${orderedRules.length} total rules`
                        : currentRulesSearchTerm
                          ? `No rules match "${currentRulesSearchTerm}".`
                          : 'No rules yet.'}
                    </div>
                    <div className="pager">
                      <button
                        id="rules-prev-button"
                        type="button"
                        disabled={rulesPage <= 1}
                        onClick={() => setCurrentRulesPage((page) => Math.max(1, page - 1))}
                      >
                        Previous
                      </button>
                      <span className="muted">{`Page ${rulesPage} / ${totalRulePages}`}</span>
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

                  <div className="table-wrap">
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
                                  <span className="rule-pill">{entry.scope_label}</span>
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
                                    className={rule.source === 'auto' ? 'rule-readonly' : ''}
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
                                    className={rule.source === 'auto' ? 'rule-readonly' : ''}
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
                                    className={rule.source === 'auto' ? 'rule-readonly' : ''}
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
                                  <div className="rule-meta">
                                    <span className={`rule-pill ${rule.source === 'auto' ? 'rule-pill-auto' : ''}`}>
                                      {rule.source === 'auto' ? 'Auto' : 'Manual'}
                                    </span>
                                    <small>{rule.source === 'auto' ? 'Auto-managed' : 'User-managed'}</small>
                                  </div>
                                </td>
                                <td>
                                  {rule.source === 'auto' ? (
                                    <div className="rule-meta">
                                      <strong>{rule.duration}</strong>
                                      <small>{formatRuleExpiry(rule, nowMs)}</small>
                                    </div>
                                  ) : (
                                    <div className="rule-meta">
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
                                    className={rule.source === 'auto' ? 'rule-readonly' : ''}
                                    type="text"
                                    value={rule.note}
                                    placeholder="optional note"
                                    disabled={rule.source === 'auto'}
                                    onChange={(event) =>
                                      updateRuleField(entry.scope, entry.index, 'note', event.target.value)
                                    }
                                  />
                                </td>
                                <td className="rule-actions">
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
                                          message: 'Rule removed locally. Save config to apply the change.',
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
                            <td colSpan="9" className="empty">
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
        <section className="tab-panel is-active">
          <section className="grid">
            <section className="panel quotas">
              <div className="panel-header">
                <div>
                  <h2>Quotas</h2>
                  <div className="router-note">
                    Default quotas apply to every device unless a custom limit or exemption matches first.
                  </div>
                </div>
              </div>

              <div className="router-note">Default traffic quota for all devices</div>
              <label className="checkbox-row">
                <input
                  className={routerDirty ? 'input-dirty' : ''}
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
              <div className="field-grid">
                <label className="field">
                  <span>Last hour (MB)</span>
                  <input
                    className={routerDirty ? 'input-dirty' : ''}
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
                <label className="field">
                  <span>Last 3h (MB)</span>
                  <input
                    className={routerDirty ? 'input-dirty' : ''}
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
                <label className="field">
                  <span>Note</span>
                  <input
                    className={routerDirty ? 'input-dirty' : ''}
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

              <div className="router-note">
                Custom client IP or CIDR limits override the default. Exemptions override both limits.
              </div>

              <div className="panel-header section-gap">
                <h3>Client traffic limits</h3>
                <button id="add-client-limit-button" type="button" onClick={() => addClientTrafficLimit()}>
                  Add limit
                </button>
              </div>
              <div className="router-note">
                Match one client IP or CIDR and cap its traffic over the last hour and last 3 hours.
              </div>

              <div className="table-wrap">
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
                          <td className="rule-actions">
                            <button
                              type="button"
                              onClick={() => {
                                const nextConfig = cloneJson(currentRouterConfig)
                                nextConfig.client_traffic_limits.splice(index, 1)
                                setLocalRouterConfig(nextConfig, {
                                  message: 'Client traffic limit removed locally. Save config to apply the change.',
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
                        <td colSpan="6" className="empty">
                          No client traffic limits yet.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>

              <div className="panel-header section-gap">
                <h3>Quota exemptions</h3>
                <button id="add-client-exemption-button" type="button" onClick={() => addClientTrafficExemption()}>
                  Add exemption
                </button>
              </div>
              <div className="router-note">
                Use exemptions to exclude devices permanently or suspend quota enforcement for a limited time such as 2h.
              </div>

              <div className="table-wrap">
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
                            <div className="rule-meta">
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
                          <td className="rule-actions">
                            <button
                              type="button"
                              onClick={() => {
                                const nextConfig = cloneJson(currentRouterConfig)
                                nextConfig.client_traffic_exemptions.splice(index, 1)
                                setLocalRouterConfig(nextConfig, {
                                  message: 'Quota exemption removed locally. Save config to apply the change.',
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
                        <td colSpan="6" className="empty">
                          No quota exemptions yet.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </section>

            <section className="panel clients">
              <h2>By device</h2>
              {dashboardSnapshot.totals_by_client.length ? (
                <div className="table-wrap">
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
                <div className="empty">No client traffic has been recorded yet.</div>
              )}
            </section>
          </section>
        </section>
      ) : null}

      {activeTab === 'failures' ? (
        <section className="tab-panel is-active">
          <section className="grid">
            <section className="panel failures">
              <h2>Failed requests</h2>
              <div className="router-note">
                Grouped by effective domain. Ignore noisy domains or add direct/proxy rules from the latest failure group.
              </div>
              <div className="failure-controls">
                <div className="muted">
                  {`${failureView.groups.length} grouped domains shown${
                    failureView.ignoredGroups.length ? ` · ${failureView.ignoredGroups.length} ignored` : ''
                  }${failureView.handledCount ? ` · ${failureView.handledCount} handled by local rules` : ''}`}
                </div>
                <div className="pager">
                  <button
                    type="button"
                    disabled={failurePage <= 1}
                    onClick={() => setCurrentFailurePage((page) => Math.max(1, page - 1))}
                  >
                    Previous
                  </button>
                  <span className="muted">{`Page ${failurePage} / ${totalFailurePages}`}</span>
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
                <div className="table-wrap">
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
                          <td className="destination">
                            <strong>{group.domain || group.group_key}</strong>
                            <br />
                            <span className="muted">{`${group.host_count} host(s) · latest ${
                              group.host || group.domain || group.group_key
                            }`}</span>
                          </td>
                          <td>{group.count}</td>
                          <td>{(group.method_list || []).join(', ')}</td>
                          <td>{group.client_count}</td>
                          <td>{group.route_label || 'direct'}</td>
                          <td>{group.latest_error}</td>
                          <td className="rule-actions">
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
                              className="warn"
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
                            <button className="warn" type="button" onClick={() => ignoreFailureHost(group.domain || group.group_key)}>
                              Ignore
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="empty">
                  {failureView.ignoredGroups.length
                    ? 'All failed domains are currently ignored.'
                    : failureView.handledCount
                      ? 'No actionable failed domains remain. Existing local rules already cover them.'
                      : 'No failed requests recorded yet.'}
                </div>
              )}

              <div className="router-note">
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
    </main>
  )
}

export default App
