<script>
  import { getAnalysis, getVulnerabilities } from '../api.js';
  import { onMount } from 'svelte';

  let { projectId = null } = $props();

  let analysis = $state(null);
  let vulnerabilities = $state([]);
  let loading = $state(false);
  let error = $state(null);
  let loadedProjectId = $state(null);

  const SEVERITY_COLORS = {
    CRITICAL: '#f85149',
    HIGH: '#f0883e',
    MEDIUM: '#d29922',
    LOW: '#8b949e',
  };

  $effect(() => {
    if (projectId && projectId !== loadedProjectId) {
      loadAnalysis(projectId);
    }
  });

  async function loadAnalysis(pid) {
    loading = true;
    error = null;
    try {
      const [analysisData, vulnData] = await Promise.all([
        getAnalysis(pid),
        getVulnerabilities(pid),
      ]);
      analysis = analysisData;
      vulnerabilities = Array.isArray(vulnData) ? vulnData : vulnData.vulnerabilities || [];
      loadedProjectId = pid;
    } catch (err) {
      error = err.response?.data?.error || err.message || 'Failed to load analysis';
    } finally {
      loading = false;
    }
  }

  function severityBreakdown() {
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    if (analysis?.summary?.severity_breakdown) {
      return { ...counts, ...analysis.summary.severity_breakdown };
    }
    vulnerabilities.forEach((v) => {
      const sev = (v.severity || 'LOW').toUpperCase();
      if (counts[sev] !== undefined) counts[sev]++;
    });
    return counts;
  }

  function totalVulns() {
    const bd = severityBreakdown();
    return Object.values(bd).reduce((a, b) => a + b, 0);
  }

  function barMaxWidth(count) {
    const total = totalVulns();
    if (total === 0) return 0;
    return (count / total) * 100;
  }

  function topPackages() {
    if (analysis?.risk_scores && Array.isArray(analysis.risk_scores)) {
      return analysis.risk_scores.slice(0, 10);
    }
    return [];
  }

  function mostConnected() {
    if (analysis?.critical_packages && Array.isArray(analysis.critical_packages)) {
      return analysis.critical_packages.slice(0, 10);
    }
    return [];
  }

  function pieSections() {
    const bd = severityBreakdown();
    const total = totalVulns();
    if (total === 0) return [];
    let cumulative = 0;
    const sections = [];
    for (const [sev, count] of Object.entries(bd)) {
      if (count === 0) continue;
      const pct = (count / total) * 100;
      sections.push({
        severity: sev,
        count,
        pct,
        offset: cumulative,
        color: SEVERITY_COLORS[sev],
      });
      cumulative += pct;
    }
    return sections;
  }

  function pieCoords(pct, offset) {
    const startAngle = (offset / 100) * 2 * Math.PI - Math.PI / 2;
    const endAngle = ((offset + pct) / 100) * 2 * Math.PI - Math.PI / 2;
    const largeArc = pct > 50 ? 1 : 0;
    const x1 = 50 + 40 * Math.cos(startAngle);
    const y1 = 50 + 40 * Math.sin(startAngle);
    const x2 = 50 + 40 * Math.cos(endAngle);
    const y2 = 50 + 40 * Math.sin(endAngle);
    return `M 50 50 L ${x1} ${y1} A 40 40 0 ${largeArc} 1 ${x2} ${y2} Z`;
  }
</script>

<div class="dashboard">
  {#if loading}
    <div class="dash-loading">
      <div class="spinner"></div>
      <p>Loading analysis...</p>
    </div>
  {:else if error}
    <div class="dash-error">{error}</div>
  {:else if analysis}
    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-value">{analysis.summary?.total_packages || 0}</div>
        <div class="stat-label">Total Packages</div>
      </div>
      <div class="stat-card">
        <div class="stat-value" style="color: #f85149">{totalVulns()}</div>
        <div class="stat-label">Vulnerabilities</div>
      </div>
      <div class="stat-card">
        <div class="stat-value" style="color: #f85149">{severityBreakdown().CRITICAL}</div>
        <div class="stat-label">Critical</div>
      </div>
      <div class="stat-card">
        <div class="stat-value" style="color: #f0883e">{severityBreakdown().HIGH}</div>
        <div class="stat-label">High</div>
      </div>
    </div>

    <div class="charts-row">
      <div class="chart-card">
        <h4>Severity Breakdown</h4>
        <div class="bar-chart">
          {#each Object.entries(severityBreakdown()) as [sev, count]}
            <div class="bar-row">
              <span class="bar-label">{sev}</span>
              <div class="bar-track">
                <div class="bar-fill" style="width: {barMaxWidth(count)}%; background: {SEVERITY_COLORS[sev]}"></div>
              </div>
              <span class="bar-count">{count}</span>
            </div>
          {/each}
        </div>
      </div>

      <div class="chart-card">
        <h4>Distribution</h4>
        <div class="pie-container">
          {#if totalVulns() > 0}
            <svg viewBox="0 0 100 100" class="pie-chart">
              {#each pieSections() as sec}
                <path d={pieCoords(sec.pct, sec.offset)} fill={sec.color} stroke="#161b22" stroke-width="1"/>
              {/each}
            </svg>
            <div class="pie-legend">
              {#each pieSections() as sec}
                <div class="legend-item">
                  <span class="legend-dot" style="background: {sec.color}"></span>
                  <span>{sec.severity}: {sec.count}</span>
                </div>
              {/each}
            </div>
          {:else}
            <p class="no-data">No vulnerabilities found</p>
          {/if}
        </div>
      </div>
    </div>

    <div class="tables-row">
      {#if topPackages().length > 0}
        <div class="table-card">
          <h4>Top Critical Packages</h4>
          <table>
            <thead>
              <tr><th>Package</th><th>Risk Score</th></tr>
            </thead>
            <tbody>
              {#each topPackages() as pkg, i}
                <tr>
                  <td>
                    <span class="rank">#{i + 1}</span>
                    {pkg.name}
                  </td>
                  <td>
                    <span class="risk-score" style="color: {pkg.risk_score >= 8 ? '#f85149' : pkg.risk_score >= 5 ? '#f0883e' : '#d29922'}">
                      {typeof pkg.risk_score === 'number' ? pkg.risk_score.toFixed(1) : pkg.risk_score}
                    </span>
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}

      {#if mostConnected().length > 0}
        <div class="table-card">
          <h4>Critical Gateway Packages</h4>
          <table>
            <thead>
              <tr><th>Package</th><th>Downstream Vulns</th></tr>
            </thead>
            <tbody>
              {#each mostConnected() as pkg, i}
                <tr>
                  <td>
                    <span class="rank">#{i + 1}</span>
                    {pkg.name}@{pkg.version}
                  </td>
                  <td>{pkg.downstream_vulnerability_count ?? 0}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    </div>

    {#if vulnerabilities.length > 0}
      <div class="vuln-details-section">
        <h4>Vulnerability Details</h4>
        {#each vulnerabilities as vuln, i (vuln.id || i)}
          <div class="vuln-card" style="border-left-color: {SEVERITY_COLORS[vuln.severity] || '#484f58'}">
            <div class="vuln-card-header">
              <span class="sev-badge" style="background: {SEVERITY_COLORS[vuln.severity] || '#484f58'}">
                {vuln.severity || 'UNKNOWN'}
              </span>
              <span class="vuln-card-id">{vuln.id}</span>
            </div>

            {#if vuln.summary}
              <p class="vuln-card-summary">{vuln.summary}</p>
            {/if}

            {#if vuln.affected_packages && vuln.affected_packages.length > 0}
              <div class="vuln-card-packages">
                <span class="vuln-card-label">Affects:</span>
                {#each vuln.affected_packages as pkg}
                  <span class="affected-pkg">{pkg.name}@{pkg.version}</span>
                {/each}
              </div>
            {/if}

            {#if vuln.aliases && vuln.aliases.length > 0}
              <div class="vuln-card-aliases">
                {#each vuln.aliases as alias}
                  <span class="alias-chip">{alias}</span>
                {/each}
              </div>
            {/if}

            {#if vuln.references && vuln.references.length > 0}
              <div class="vuln-card-refs">
                {#each vuln.references.slice(0, 3) as ref}
                  <a href={typeof ref === 'string' ? ref : ref.url} target="_blank" rel="noopener">
                    {(typeof ref === 'string' ? ref : ref.url || '').replace(/^https?:\/\//, '').slice(0, 60)}
                  </a>
                {/each}
              </div>
            {/if}
          </div>
        {/each}
      </div>
    {/if}

  {:else}
    <div class="dash-loading">
      <p>No analysis data available</p>
    </div>
  {/if}
</div>

<style>
  .dashboard {
    padding: 1.5rem;
    overflow-y: auto;
    height: 100%;
  }

  .dash-loading {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    height: 100%;
    color: #8b949e;
    gap: 1rem;
  }

  .dash-error {
    color: #f85149;
    text-align: center;
    padding: 2rem;
  }

  .spinner {
    width: 32px;
    height: 32px;
    border: 3px solid #30363d;
    border-top-color: #58a6ff;
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
  }

  @keyframes spin {
    to { transform: rotate(360deg); }
  }

  .stats-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 1rem;
    margin-bottom: 1.5rem;
  }

  .stat-card {
    background: #1c2128;
    border: 1px solid #21262d;
    border-radius: 8px;
    padding: 1.25rem;
    text-align: center;
  }

  .stat-value {
    font-size: 2rem;
    font-weight: 700;
    color: #e6edf3;
  }

  .stat-label {
    font-size: 0.8rem;
    color: #8b949e;
    margin-top: 0.25rem;
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }

  .charts-row {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1rem;
    margin-bottom: 1.5rem;
  }

  .chart-card {
    background: #1c2128;
    border: 1px solid #21262d;
    border-radius: 8px;
    padding: 1.25rem;
  }

  .chart-card h4 {
    margin: 0 0 1rem;
    font-size: 0.85rem;
    color: #8b949e;
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }

  .bar-chart {
    display: flex;
    flex-direction: column;
    gap: 0.6rem;
  }

  .bar-row {
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }

  .bar-label {
    width: 70px;
    font-size: 0.75rem;
    color: #8b949e;
    text-transform: uppercase;
  }

  .bar-track {
    flex: 1;
    height: 20px;
    background: #21262d;
    border-radius: 4px;
    overflow: hidden;
  }

  .bar-fill {
    height: 100%;
    border-radius: 4px;
    transition: width 0.5s ease;
    min-width: 2px;
  }

  .bar-count {
    width: 30px;
    text-align: right;
    font-size: 0.85rem;
    color: #e6edf3;
    font-weight: 600;
  }

  .pie-container {
    display: flex;
    align-items: center;
    gap: 1.5rem;
  }

  .pie-chart {
    width: 120px;
    height: 120px;
  }

  .pie-legend {
    display: flex;
    flex-direction: column;
    gap: 0.4rem;
  }

  .legend-item {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    font-size: 0.8rem;
    color: #c9d1d9;
  }

  .legend-dot {
    width: 10px;
    height: 10px;
    border-radius: 2px;
    flex-shrink: 0;
  }

  .no-data {
    color: #484f58;
    font-size: 0.85rem;
  }

  .tables-row {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1rem;
  }

  .table-card {
    background: #1c2128;
    border: 1px solid #21262d;
    border-radius: 8px;
    padding: 1.25rem;
  }

  .table-card h4 {
    margin: 0 0 0.75rem;
    font-size: 0.85rem;
    color: #8b949e;
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }

  table {
    width: 100%;
    border-collapse: collapse;
  }

  th {
    text-align: left;
    padding: 0.4rem 0.5rem;
    font-size: 0.7rem;
    color: #484f58;
    text-transform: uppercase;
    border-bottom: 1px solid #21262d;
  }

  td {
    padding: 0.5rem;
    font-size: 0.8rem;
    color: #c9d1d9;
    border-bottom: 1px solid #21262d22;
  }

  .rank {
    color: #484f58;
    font-size: 0.7rem;
    margin-right: 0.4rem;
  }

  .risk-score {
    font-weight: 700;
  }

  .vuln-details-section {
    margin-top: 1.5rem;
  }

  .vuln-details-section h4 {
    margin: 0 0 1rem;
    font-size: 0.85rem;
    color: #8b949e;
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }

  .vuln-card {
    background: #1c2128;
    border: 1px solid #21262d;
    border-left: 4px solid #484f58;
    border-radius: 8px;
    padding: 1rem;
    margin-bottom: 0.75rem;
  }

  .vuln-card-header {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    margin-bottom: 0.4rem;
  }

  .sev-badge {
    padding: 0.15rem 0.5rem;
    border-radius: 4px;
    font-size: 0.65rem;
    font-weight: 700;
    color: #fff;
    text-transform: uppercase;
    letter-spacing: 0.03em;
    flex-shrink: 0;
  }

  .vuln-card-id {
    font-size: 0.85rem;
    font-weight: 600;
    color: #e6edf3;
    word-break: break-all;
  }

  .vuln-card-summary {
    font-size: 0.8rem;
    color: #8b949e;
    line-height: 1.5;
    margin: 0.3rem 0 0.5rem;
  }

  .vuln-card-packages {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 0.3rem;
    margin-bottom: 0.4rem;
  }

  .vuln-card-label {
    font-size: 0.7rem;
    color: #484f58;
    text-transform: uppercase;
  }

  .affected-pkg {
    font-size: 0.75rem;
    padding: 0.1rem 0.4rem;
    background: #388bfd22;
    color: #58a6ff;
    border-radius: 3px;
    font-weight: 500;
  }

  .vuln-card-aliases {
    display: flex;
    flex-wrap: wrap;
    gap: 0.25rem;
    margin-bottom: 0.4rem;
  }

  .alias-chip {
    font-size: 0.65rem;
    padding: 0.1rem 0.35rem;
    background: #30363d;
    color: #c9d1d9;
    border-radius: 3px;
  }

  .vuln-card-refs {
    display: flex;
    flex-direction: column;
    gap: 0.2rem;
  }

  .vuln-card-refs a {
    font-size: 0.72rem;
    color: #58a6ff;
    text-decoration: none;
    word-break: break-all;
  }

  .vuln-card-refs a:hover {
    text-decoration: underline;
  }

  @media (max-width: 800px) {
    .stats-grid {
      grid-template-columns: repeat(2, 1fr);
    }
    .charts-row, .tables-row {
      grid-template-columns: 1fr;
    }
  }
</style>
