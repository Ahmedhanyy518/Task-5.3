import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so there is no token to attach by hand anymore.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

// ---- Anti-CSRF -------------------------------------------------------------
// Every state-changing request (anything but GET/HEAD/OPTIONS) must carry the
// per-session CSRF token in the `x-csrf-token` header. The token comes from
// GET /csrf-token, which also sets the matching httpOnly cookie. An attacker's
// page can neither call that endpoint and read the answer (CORS) nor set a
// custom header from an auto-submitting form, which is what defeats CSRF.
const SAFE_METHODS = new Set(['get', 'head', 'options'])
// Pre-auth routes run before a session exists and are exempt on the server too.
const CSRF_EXEMPT = ['/auth/login', '/auth/register']
const CSRF_TOKEN_URL = '/csrf-token'

let csrfToken = null
let pendingFetch = null

async function fetchCsrfToken() {
  if (!pendingFetch) {
    pendingFetch = api.get(CSRF_TOKEN_URL)
      .then(res => { csrfToken = res.data.csrfToken; return csrfToken })
      .finally(() => { pendingFetch = null })
  }
  return pendingFetch
}

export function clearCsrfToken() { csrfToken = null }

function needsCsrfToken(config) {
  const method = (config.method || 'get').toLowerCase()
  const url = config.url || ''
  if (SAFE_METHODS.has(method)) return false
  if (url.includes(CSRF_TOKEN_URL)) return false
  return !CSRF_EXEMPT.some(p => url.startsWith(p))
}

function setHeader(config, name, value) {
  if (!config.headers) config.headers = {}
  if (typeof config.headers.set === 'function') config.headers.set(name, value)
  else config.headers[name] = value
}

// Attach the token to every mutating request, fetching it lazily the first time.
api.interceptors.request.use(async (config) => {
  if (!needsCsrfToken(config)) return config
  try {
    const token = csrfToken || await fetchCsrfToken()
    setHeader(config, 'x-csrf-token', token)
  } catch {
    // Not logged in (401) or API down: send as-is and let the server answer.
  }
  return config
})

api.interceptors.response.use(
  (res) => {
    // The token is bound to the session. Whenever the session changes (login,
    // register, logout) drop the cached token so the next write fetches a new one.
    if (/\/auth\/(login|register|logout)$/.test(res.config?.url || '')) clearCsrfToken()
    return res
  },
  async (err) => {
    const cfg = err.config
    const rejectedForCsrf = err.response?.status === 403 && err.response?.data?.code === 'EBADCSRFTOKEN'
    // A stale token (e.g. another tab re-logged in): refresh once and retry.
    if (rejectedForCsrf && cfg && !cfg._csrfRetried) {
      cfg._csrfRetried = true
      clearCsrfToken()
      return api.request(cfg)
    }
    return Promise.reject(err)
  }
)
