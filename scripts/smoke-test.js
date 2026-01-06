#!/usr/bin/env node

const args = process.argv.slice(2);

function getArgValue(flag) {
  const index = args.indexOf(flag);
  if (index === -1) return null;
  return args[index + 1] || null;
}

function normalizeBaseUrl(value) {
  if (!value) return null;
  const trimmed = value.trim();
  if (!trimmed) return null;
  const withProtocol = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  return withProtocol.replace(/\/$/, '');
}

function ensureApiBase(baseUrl) {
  if (!baseUrl) return null;
  if (baseUrl.endsWith('/api')) return baseUrl;
  return `${baseUrl}/api`;
}

function toDateString(date) {
  return date.toISOString().split('T')[0];
}

async function fetchJson(url, options = {}) {
  const response = await fetch(url, options);
  const text = await response.text();
  let data;
  try {
    data = text ? JSON.parse(text) : {};
  } catch (error) {
    throw new Error(`Non-JSON response (${response.status}): ${text.slice(0, 200)}`);
  }
  if (!response.ok) {
    const message = data?.message || text || response.statusText;
    throw new Error(`HTTP ${response.status}: ${message}`);
  }
  return data;
}

async function run() {
  const baseInput = getArgValue('--base-url')
    || process.env.API_BASE_URL
    || process.env.BASE_URL
    || process.env.VERCEL_URL
    || 'http://localhost:3001';

  const baseUrl = normalizeBaseUrl(baseInput);
  const apiBase = ensureApiBase(baseUrl);
  if (!apiBase) {
    throw new Error('Missing base URL. Provide --base-url or set API_BASE_URL.');
  }

  const startDate = getArgValue('--start-date')
    || process.env.START_DATE
    || toDateString(new Date());

  console.log(`Smoke testing: ${apiBase}`);
  console.log(`Start date: ${startDate}`);

  const baseWithSlash = apiBase.endsWith('/') ? apiBase : `${apiBase}/`;
  const healthUrl = new URL('health', baseWithSlash).toString();
  const health = await fetchJson(healthUrl);
  if (health.status !== 'ok') {
    throw new Error(`Health check failed: ${JSON.stringify(health)}`);
  }
  console.log('Health check OK');

  const weekUrl = new URL(`bookings/week?start_date=${encodeURIComponent(startDate)}`, baseWithSlash).toString();
  const weekData = await fetchJson(weekUrl, { headers: { 'Cache-Control': 'no-store' } });
  if (!weekData.success) {
    throw new Error(`Weekly bookings returned error: ${JSON.stringify(weekData)}`);
  }
  const dayCount = Array.isArray(weekData.days) ? weekData.days.length : 0;
  console.log(`Weekly bookings OK (${dayCount} days)`);
}

run().catch(error => {
  console.error(`Smoke test failed: ${error.message}`);
  process.exit(1);
});
