import axios from 'axios';

const client = axios.create({
  baseURL: '/api',
  timeout: 60000,
});

export async function scanLockfile(file) {
  const form = new FormData();
  form.append('file', file);
  const res = await client.post('/scan', form, {
    headers: { 'Content-Type': 'multipart/form-data' },
    timeout: 300000,
  });
  return res.data;
}

export async function getProjects() {
  const res = await client.get('/projects');
  return res.data;
}

export async function getGraph(projectId) {
  const res = await client.get(`/graph/${projectId}`);
  return res.data;
}

export async function getPaths(projectId, cveId) {
  const res = await client.get(`/paths/${projectId}/${cveId}`);
  return res.data;
}

export async function getVulnerabilities(projectId) {
  const res = await client.get(`/vulnerabilities/${projectId}`);
  return res.data;
}

export async function getAnalysis(projectId) {
  const res = await client.get(`/analysis/${projectId}`);
  return res.data;
}

export async function deleteProject(projectId) {
  const res = await client.delete(`/projects/${projectId}`);
  return res.data;
}
