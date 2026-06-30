import axios from 'axios';

const api = axios.create({ baseURL: '/api' });

api.interceptors.request.use(cfg => {
  const token = localStorage.getItem('siem_token');
  if (token) cfg.headers.Authorization = `Bearer ${token}`;
  return cfg;
});

api.interceptors.response.use(
  res => res,
  err => {
    if (err.response?.status === 401) {
      localStorage.removeItem('siem_token');
      window.location.href = '/login';
    }
    return Promise.reject(err);
  }
);

export const authApi = {
  login: (username, password) => api.post('/auth/login', { username, password }),
  me: () => api.get('/auth/me'),
};

export const dashboardApi = {
  stats: () => api.get('/dashboard/stats'),
};

export const alertsApi = {
  list: (params) => api.get('/alerts', { params }),
  stats: () => api.get('/alerts/stats'),
  get: (id) => api.get(`/alerts/${id}`),
  update: (id, data) => api.patch(`/alerts/${id}`, data),
};

export const eventsApi = {
  list: (params) => api.get('/events', { params }),
  stats: () => api.get('/events/stats'),
  kql: (query) => api.post('/events/kql', { query }),
};

export const intelApi = {
  iocs: (params) => api.get('/intel/iocs', { params }),
  createIoc: (data) => api.post('/intel/iocs', data),
  feeds: () => api.get('/intel/feeds'),
};

export const correlationApi = {
  rules: () => api.get('/correlation/rules'),
  toggleRule: (id, enabled) => api.patch(`/correlation/rules/${id}`, { enabled }),
  createRule: (data) => api.post('/correlation/rules', data),
};

export const soarApi = {
  playbooks: () => api.get('/soar/playbooks'),
  execute: (id, alertId) => api.post(`/soar/playbooks/${id}/execute`, { alert_id: alertId }),
  execution: (id) => api.get(`/soar/executions/${id}`),
};

export const uebaApi = {
  scores: () => api.get('/ueba/scores'),
};

export const kqlApi = {
  queries: () => api.get('/kql/queries'),
  save: (data) => api.post('/kql/queries', data),
  run: (query) => eventsApi.kql(query),
};

export const agentsApi = {
  list: () => api.get('/agents'),
  stats: () => api.get('/agents/stats'),
  get: (id) => api.get(`/agents/${id}`),
  update: (id, data) => api.patch(`/agents/${id}`, data),
  remove: (id) => api.delete(`/agents/${id}`),
};

export const deployApi = {
  create: (data) => api.post('/deploy', data),
  list: () => api.get('/deploy'),
  get: (id) => api.get(`/deploy/${id}`),
  script: (os) => api.get(`/deploy/script/${os}`, { responseType: 'text' }),
};

export const assetsApi = {
  list: (params) => api.get('/agents/assets/list', { params }),
  stats: () => api.get('/agents/assets/stats'),
  get: (agentId) => api.get(`/agents/assets/${agentId}`),
};

export const vulnApi = {
  list: (params) => api.get('/agents/assets/vulnerabilities', { params }),
  stats: () => api.get('/agents/assets/vulnerabilities/stats'),
  forAsset: (agentId) => api.get(`/agents/assets/${agentId}/vulnerabilities`),
};

export const ocsfApi = {
  parse: (raw) => api.post('/ocsf/parse', { raw }),
  schema: () => api.get('/ocsf/schema'),
  stats: () => api.get('/ocsf/stats'),
  events: (params) => api.get('/ocsf/events', { params }),
  event: (id) => api.get(`/ocsf/events/${id}`),
};

export const incidentsApi = {
  list: (params) => api.get('/incidents', { params }),
  create: (data) => api.post('/incidents', data),
  createFromAlert: (alertId) => api.post(`/incidents/from-alert/${alertId}`),
  get: (id) => api.get(`/incidents/${id}`),
  update: (id, data) => api.patch(`/incidents/${id}`, data),
  addNote: (id, note) => api.post(`/incidents/${id}/notes`, { note }),
  linkAlert: (id, alertId) => api.post(`/incidents/${id}/alerts`, { alert_id: alertId }),
};

export default api;
