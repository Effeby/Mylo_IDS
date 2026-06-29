import axios from 'axios'

// ─── CLIENTS AXIOS ────────────────────────────────────────────────────
// Django Backend (auth + BDD + River)
const DJANGO_URL = import.meta.env.VITE_DJANGO_URL || 'https://mylo-ids.site'
const FASTAPI_URL = import.meta.env.VITE_FASTAPI_URL || 'https://mylo-ids.site/api/ml'

const django = axios.create({
  baseURL: DJANGO_URL,
  headers: { 'Content-Type': 'application/json' },
})

// FastAPI (inférence XGBoost directe)
const fastapi = axios.create({
  baseURL: FASTAPI_URL,
  headers: { 'Content-Type': 'application/json' },
})

// ─── JWT INTERCEPTOR ──────────────────────────────────────────────────
django.interceptors.request.use(config => {
  const token = localStorage.getItem('mylo_access')
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

// Refresh automatique si token expiré
django.interceptors.response.use(
  res => res,
  async err => {
    const original = err.config
    const isAuthRequest = original.url?.includes('/api/auth/login/') || original.url?.includes('/api/auth/refresh/')

    if (err.response?.status === 401 && !original._retry && !isAuthRequest) {
      original._retry = true
      try {
        const refresh = localStorage.getItem('mylo_refresh')
        const { data } = await axios.post('https://mylo-ids.site/api/auth/refresh/', { refresh })
        localStorage.setItem('mylo_access', data.access)
        original.headers.Authorization = `Bearer ${data.access}`
        return django(original)
      } catch {
        localStorage.clear()
        window.location.href = '/'
      }
    }
    return Promise.reject(err)
  }
)

// ─── AUTH ──────────────────────────────────────────────────────────────
export const login = async (username, password) => {
  const { data } = await django.post('/api/auth/login/', { username, password })
  return data
}

export const getTotpSetup = async () => {
  const { data } = await django.get('/api/auth/totp/setup/')
  return data
}

export const activateTotp = async (code) => {
  const { data } = await django.post('/api/auth/totp/activate/', { code })
  return data
}

export const verifyTotpWithToken = async (code, accessToken) => {
  const { data } = await axios.post(`${DJANGO_URL}/api/auth/totp/verify/`, { code }, {
    headers: { Authorization: `Bearer ${accessToken}` },
  })
  return data
}

export const changeMyPassword = async (password, currentPassword = '', accessToken = null) => {
  const headers = { 'Content-Type': 'application/json' }
  if (accessToken) {
    headers.Authorization = `Bearer ${accessToken}`
  }
  const { data } = await axios.patch(`${DJANGO_URL}/api/auth/me/`, {
    password,
    current_password: currentPassword,
  }, { headers })
  return data
}

export const resetUserTotp = async (userId) => {
  const { data } = await django.post(`/api/auth/totp/reset/${userId}/`)
  return data
}

export const logout = async () => {
  try {
    const refresh = localStorage.getItem('mylo_refresh')
    await django.post('/api/auth/logout/', { refresh })
  } catch {}
  localStorage.removeItem('mylo_access')
  localStorage.removeItem('mylo_refresh')
  localStorage.removeItem('mylo_user')
}

export const getUser = () => {
  try { return JSON.parse(localStorage.getItem('mylo_user')) }
  catch { return null }
}

export const getOrganisationName = () => {
  const user = getUser()
  return user?.organisation?.name || 'Mon organisation'
}

export const isAuthenticated = () => !!localStorage.getItem('mylo_access')

// ─── ALERTES (Django BDD) ──────────────────────────────────────────────
export const getAlerts = (params = {}) =>
  django.get('/api/alerts/', { params }).then(r => r.data)

export const getAlertDetail = (id) =>
  django.get(`/api/alerts/${id}/`).then(r => r.data)

export const updateAlertStatus = (id, status) =>
  django.patch(`/api/alerts/${id}/`, { status }).then(r => r.data)

export const getAlertStats = () =>
  django.get('/api/alerts/stats/').then(r => r.data)

// ─── ANALYSE (Django → FastAPI XGBoost) ───────────────────────────────
export const analyzeTraffic = (trafficData) =>
  django.post('/api/alerts/analyze/', trafficData).then(r => r.data)

// ─── BLACKLIST ─────────────────────────────────────────────────────────
export const getBlacklist = () =>
  django.get('/api/alerts/blacklist/').then(r => r.data)

export const blockIP = (ip_address, reason = 'Bloqué manuellement') =>
  django.post('/api/alerts/blacklist/', { ip_address, reason }).then(r => r.data)

export const unblockIP = (ip_address) =>
  django.delete('/api/alerts/blacklist/', { data: { ip_address } }).then(r => r.data)

// ─── RIVER (apprentissage en ligne) ────────────────────────────────────
export const getRiverStatus = () =>
  django.get('/api/actions/river/status/').then(r => r.data)

export const riverLearn = (features, label) =>
  django.post('/api/actions/river/learn/', { features, label }).then(r => r.data)

export const riverPredict = (features) =>
  django.post('/api/actions/river/predict/', { features }).then(r => r.data)

// ─── RAPPORTS ──────────────────────────────────────────────────────────
export const generateReport = (params = {}) =>
  django.get('/api/reports/generate/', { params }).then(r => r.data)

export const exportCSV = () => {
  const token = localStorage.getItem('mylo_access')
  window.open(`https://mylo-ids.site/api/reports/export/csv/?token=${token}`, '_blank')
}

export const exportJSON = () => {
  const token = localStorage.getItem('mylo_access')
  window.open(`https://mylo-ids.site/api/reports/export/json/?token=${token}`, '_blank')
}

// ─── FASTAPI DIRECT (inférence rapide sans passer par Django) ─────────
export const fastapiPredict = (data) =>
  fastapi.post('/predict', data).then(r => r.data)

export const fastapiHealth = () =>
  fastapi.get('/health').then(r => r.data)

export const fastapiStats = () =>
  fastapi.get('/stats').then(r => r.data)

// ─── SIMULATION (trafic réseau exemple) ─────────────────────────────────
const ATTACK_SAMPLES = {
  Normal:      { src_bytes: 215, dst_bytes: 45076, duration: 0, logged_in: 1, count: 8, srv_count: 8, serror_rate: 0, rerror_rate: 0, same_srv_rate: 1, diff_srv_rate: 0, dst_host_count: 9, dst_host_srv_count: 9, dst_host_same_srv_rate: 1, dst_host_diff_srv_rate: 0.11, dst_host_same_src_port_rate: 0.11, dst_host_serror_rate: 0, dst_host_rerror_rate: 0, srv_serror_rate: 0, flag: 10, protocol_type: 2, duration: 0 },
  DoS:         { src_bytes: 0, dst_bytes: 0, duration: 0, logged_in: 0, count: 511, srv_count: 511, serror_rate: 1, rerror_rate: 0, same_srv_rate: 1, diff_srv_rate: 0, dst_host_count: 255, dst_host_srv_count: 255, dst_host_same_srv_rate: 1, dst_host_diff_srv_rate: 0, dst_host_same_src_port_rate: 1, dst_host_serror_rate: 1, dst_host_rerror_rate: 0, srv_serror_rate: 1, flag: 5, protocol_type: 2 },
  DDoS:        { src_bytes: 0, dst_bytes: 0, duration: 0, logged_in: 0, count: 511, srv_count: 511, serror_rate: 0.5, rerror_rate: 0, same_srv_rate: 0.5, diff_srv_rate: 0.5, dst_host_count: 255, dst_host_srv_count: 200, dst_host_same_srv_rate: 0.8, dst_host_diff_srv_rate: 0.2, dst_host_same_src_port_rate: 0.5, dst_host_serror_rate: 0.5, dst_host_rerror_rate: 0, srv_serror_rate: 0.5, flag: 5, protocol_type: 2 },
  Probe:       { src_bytes: 0, dst_bytes: 0, duration: 0, logged_in: 0, count: 1, srv_count: 1, serror_rate: 0, rerror_rate: 1, same_srv_rate: 1, diff_srv_rate: 0, dst_host_count: 255, dst_host_srv_count: 1, dst_host_same_srv_rate: 0, dst_host_diff_srv_rate: 1, dst_host_same_src_port_rate: 0, dst_host_serror_rate: 0, dst_host_rerror_rate: 1, srv_serror_rate: 0, flag: 10, protocol_type: 0 },
  BruteForce:  { src_bytes: 4582, dst_bytes: 92, duration: 3, logged_in: 0, count: 50, srv_count: 50, serror_rate: 0, rerror_rate: 0.87, same_srv_rate: 1, diff_srv_rate: 0, dst_host_count: 50, dst_host_srv_count: 50, dst_host_same_srv_rate: 1, dst_host_diff_srv_rate: 0, dst_host_same_src_port_rate: 0.02, dst_host_serror_rate: 0, dst_host_rerror_rate: 0.87, srv_serror_rate: 0, flag: 10, protocol_type: 2 },
  WebAttack:   { src_bytes: 1200, dst_bytes: 800, duration: 1, logged_in: 1, count: 5, srv_count: 5, serror_rate: 0, rerror_rate: 0, same_srv_rate: 1, diff_srv_rate: 0, dst_host_count: 5, dst_host_srv_count: 5, dst_host_same_srv_rate: 1, dst_host_diff_srv_rate: 0, dst_host_same_src_port_rate: 0.8, dst_host_serror_rate: 0, dst_host_rerror_rate: 0, srv_serror_rate: 0, flag: 10, protocol_type: 2 },
  R2L:         { src_bytes: 2000, dst_bytes: 500, duration: 5, logged_in: 0, count: 3, srv_count: 3, serror_rate: 0, rerror_rate: 0, same_srv_rate: 1, diff_srv_rate: 0, dst_host_count: 3, dst_host_srv_count: 3, dst_host_same_srv_rate: 1, dst_host_diff_srv_rate: 0, dst_host_same_src_port_rate: 1, dst_host_serror_rate: 0, dst_host_rerror_rate: 0, srv_serror_rate: 0, flag: 10, protocol_type: 2 },
  U2R:         { src_bytes: 105, dst_bytes: 146, duration: 0, logged_in: 1, count: 1, srv_count: 1, serror_rate: 0, rerror_rate: 0, same_srv_rate: 1, diff_srv_rate: 0, dst_host_count: 1, dst_host_srv_count: 1, dst_host_same_srv_rate: 1, dst_host_diff_srv_rate: 0, dst_host_same_src_port_rate: 1, dst_host_serror_rate: 0, dst_host_rerror_rate: 0, srv_serror_rate: 0, flag: 10, protocol_type: 2 },
  Botnet:      { src_bytes: 500, dst_bytes: 300, duration: 10, logged_in: 0, count: 100, srv_count: 80, serror_rate: 0.1, rerror_rate: 0, same_srv_rate: 0.8, diff_srv_rate: 0.2, dst_host_count: 100, dst_host_srv_count: 80, dst_host_same_srv_rate: 0.8, dst_host_diff_srv_rate: 0.2, dst_host_same_src_port_rate: 0.5, dst_host_serror_rate: 0.1, dst_host_rerror_rate: 0, srv_serror_rate: 0.1, flag: 10, protocol_type: 2 },
  Infiltration:{ src_bytes: 800, dst_bytes: 600, duration: 30, logged_in: 1, count: 2, srv_count: 2, serror_rate: 0, rerror_rate: 0, same_srv_rate: 1, diff_srv_rate: 0, dst_host_count: 2, dst_host_srv_count: 2, dst_host_same_srv_rate: 1, dst_host_diff_srv_rate: 0, dst_host_same_src_port_rate: 1, dst_host_serror_rate: 0, dst_host_rerror_rate: 0, srv_serror_rate: 0, flag: 10, protocol_type: 2 },
}

const addNoise = (base) => {
  const noisy = { ...base }
  for (const k of ['src_bytes', 'dst_bytes', 'count', 'srv_count']) {
    if (noisy[k] !== undefined) {
      noisy[k] = Math.max(0, noisy[k] + Math.floor((Math.random() - 0.5) * noisy[k] * 0.3))
    }
  }
  return noisy
}

export const generateSample = (forceType = null) => {
  const types  = Object.keys(ATTACK_SAMPLES)
  // Distribution réaliste : 60% Normal, 40% attaques
  const weights = [6, 3, 2, 2, 1, 1, 1, 0.5, 0.5, 0.5]
  let type = forceType

  if (!type) {
    const total = weights.reduce((a, b) => a + b, 0)
    let r = Math.random() * total
    for (let i = 0; i < types.length; i++) {
      r -= weights[i]
      if (r <= 0) { type = types[i]; break }
    }
  }

  return { type, data: addNoise(ATTACK_SAMPLES[type]) }
}