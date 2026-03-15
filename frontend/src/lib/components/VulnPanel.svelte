<script>
  import { getPaths, getVulnerabilities } from '../api.js';

  let { selectedNode = null, projectId = null, onShowPaths = () => {} } = $props();

  let paths = $state(null);
  let loadingPaths = $state(false);
  let pkgVulns = $state([]);
  let loadingVulns = $state(false);
  let lastFetchedPkg = $state(null);

  const SEVERITY_COLORS = {
    CRITICAL: '#f85149',
    HIGH: '#f0883e',
    MEDIUM: '#d29922',
    LOW: '#8b949e',
  };

  function sevColor(sev) {
    return SEVERITY_COLORS[(sev || '').toUpperCase()] || '#8b949e';
  }

  // Fetch vulns for the selected package when it changes
  $effect(() => {
    const node = selectedNode;
    if (node && node.type === 'package' && node.vuln_count > 0) {
      const pkgKey = node.id || `${node.name}@${node.version}`;
      if (pkgKey !== lastFetchedPkg) {
        loadPkgVulns(pkgKey);
      }
    } else {
      pkgVulns = [];
      lastFetchedPkg = null;
    }
  });

  async function loadPkgVulns(pkgKey) {
    loadingVulns = true;
    lastFetchedPkg = pkgKey;
    try {
      const data = await getVulnerabilities(projectId);
      const allVulns = data.vulnerabilities || data || [];
      // Filter to vulns affecting this package
      const pkgName = selectedNode?.name;
      const pkgVersion = selectedNode?.version;
      pkgVulns = allVulns.filter((v) => {
        if (!v.affected_packages) return false;
        return v.affected_packages.some(
          (p) => p.name === pkgName && p.version === pkgVersion
        );
      });
    } catch (e) {
      pkgVulns = [];
    } finally {
      loadingVulns = false;
    }
  }

  async function showPaths() {
    if (!selectedNode || !projectId) return;
    const cveId = selectedNode.cve_id || selectedNode.id;
    loadingPaths = true;
    try {
      const data = await getPaths(projectId, cveId);
      paths = data.paths || data;
      onShowPaths(paths);
    } catch (e) {
      paths = [];
    } finally {
      loadingPaths = false;
    }
  }

  function resetPaths() {
    paths = null;
    onShowPaths(null);
  }
</script>

<div class="vuln-panel">
  {#if !selectedNode}
    <div class="panel-empty">
      <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="#484f58" stroke-width="1.5">
        <circle cx="12" cy="12" r="10"/>
        <line x1="12" y1="16" x2="12" y2="12"/>
        <line x1="12" y1="8" x2="12.01" y2="8"/>
      </svg>
      <p>Click a node in the graph to view details</p>
    </div>
  {:else if selectedNode.type === 'vulnerability'}
    <div class="panel-content">
      <div class="panel-header">
        <span class="severity-badge" style="background: {sevColor(selectedNode.severity)}">
          {selectedNode.severity || 'UNKNOWN'}
        </span>
        <button class="close-btn" aria-label="Close" onclick={() => { selectedNode = null; resetPaths(); }}>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
          </svg>
        </button>
      </div>

      <h3 class="cve-title">{selectedNode.cve_id || selectedNode.label || selectedNode.id}</h3>

      {#if selectedNode.summary || selectedNode.description}
        <p class="vuln-summary">{selectedNode.summary || selectedNode.description}</p>
      {/if}

      {#if selectedNode.cvss_score != null}
        <div class="info-row">
          <span class="info-label">CVSS Score</span>
          <span class="info-value cvss" style="color: {sevColor(selectedNode.severity)}">{selectedNode.cvss_score}</span>
        </div>
      {/if}

      {#if selectedNode.affected_packages && selectedNode.affected_packages.length > 0}
        <div class="section">
          <h4>Affected Packages</h4>
          <ul class="pkg-list">
            {#each selectedNode.affected_packages as pkg}
              <li class="pkg-item">
                <span class="pkg-name">{typeof pkg === 'string' ? pkg : pkg.name || ''}</span>
                {#if pkg.version}
                  <span class="pkg-version">{pkg.version}</span>
                {/if}
              </li>
            {/each}
          </ul>
        </div>
      {/if}

      <div class="section">
        <button class="action-btn" onclick={showPaths} disabled={loadingPaths}>
          {#if loadingPaths}
            Loading...
          {:else}
            Show Attack Paths
          {/if}
        </button>
        {#if paths !== null}
          <button class="action-btn secondary" onclick={resetPaths}>Reset Paths</button>
          <p class="path-count">{paths.length} path{paths.length !== 1 ? 's' : ''} found</p>
        {/if}
      </div>

      {#if selectedNode.references && selectedNode.references.length > 0}
        <div class="section">
          <h4>References</h4>
          <ul class="ref-list">
            {#each selectedNode.references as ref}
              <li>
                <a href={typeof ref === 'string' ? ref : ref.url} target="_blank" rel="noopener">
                  {typeof ref === 'string' ? ref : ref.url || ref.source || 'Link'}
                </a>
              </li>
            {/each}
          </ul>
        </div>
      {/if}
    </div>
  {:else}
    <div class="panel-content">
      <div class="panel-header">
        {#if selectedNode.vuln_count > 0}
          <span class="severity-badge" style="background: {sevColor(selectedNode.max_severity)}">
            {selectedNode.vuln_count} vuln{selectedNode.vuln_count !== 1 ? 's' : ''}
          </span>
        {:else}
          <span class="type-badge clean">Clean</span>
        {/if}
        <button class="close-btn" aria-label="Close" onclick={() => { selectedNode = null; }}>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
          </svg>
        </button>
      </div>

      <h3 class="pkg-title">{selectedNode.name || selectedNode.label || selectedNode.id}</h3>

      {#if selectedNode.version}
        <div class="info-row">
          <span class="info-label">Version</span>
          <span class="info-value">{selectedNode.version}</span>
        </div>
      {/if}

      {#if selectedNode.ecosystem}
        <div class="info-row">
          <span class="info-label">Ecosystem</span>
          <span class="info-value">{selectedNode.ecosystem}</span>
        </div>
      {/if}

      {#if selectedNode.vuln_count > 0}
        <div class="section">
          <h4>Vulnerabilities</h4>
          {#if loadingVulns}
            <div class="loading-small">Loading...</div>
          {:else if pkgVulns.length > 0}
            <ul class="vuln-list">
              {#each pkgVulns as vuln, i (vuln.id || i)}
                <li class="vuln-detail">
                  <div class="vuln-header">
                    <span class="severity-badge small" style="background: {sevColor(vuln.severity)}">
                      {vuln.severity || 'UNKNOWN'}
                    </span>
                    <span class="vuln-id">{vuln.id}</span>
                  </div>
                  {#if vuln.summary}
                    <p class="vuln-desc">{vuln.summary}</p>
                  {/if}
                  {#if vuln.aliases && vuln.aliases.length > 0}
                    <div class="vuln-aliases">
                      {#each vuln.aliases as alias}
                        <span class="alias-tag">{alias}</span>
                      {/each}
                    </div>
                  {/if}
                  {#if vuln.references && vuln.references.length > 0}
                    <div class="vuln-refs">
                      {#each vuln.references.slice(0, 3) as ref}
                        <a href={typeof ref === 'string' ? ref : ref.url} target="_blank" rel="noopener">
                          {(typeof ref === 'string' ? ref : ref.url || '').replace(/^https?:\/\//, '').slice(0, 50)}
                        </a>
                      {/each}
                    </div>
                  {/if}
                </li>
              {/each}
            </ul>
          {:else}
            <p class="no-data">No vulnerability details available</p>
          {/if}
        </div>
      {:else}
        <div class="section">
          <p class="clean-msg">No known vulnerabilities for this package version.</p>
        </div>
      {/if}
    </div>
  {/if}
</div>

<style>
  .vuln-panel {
    height: 100%;
    overflow-y: auto;
    background: #161b22;
    border-left: 1px solid #21262d;
  }

  .panel-empty {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    height: 100%;
    gap: 0.75rem;
    color: #484f58;
    font-size: 0.85rem;
    padding: 1rem;
    text-align: center;
  }

  .panel-content {
    padding: 1rem;
  }

  .panel-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.75rem;
  }

  .severity-badge {
    padding: 0.2rem 0.6rem;
    border-radius: 4px;
    font-size: 0.7rem;
    font-weight: 700;
    color: #fff;
    text-transform: uppercase;
    letter-spacing: 0.03em;
  }

  .type-badge {
    padding: 0.2rem 0.6rem;
    border-radius: 4px;
    font-size: 0.7rem;
    font-weight: 600;
    color: #58a6ff;
    background: #58a6ff22;
    text-transform: uppercase;
  }

  .close-btn {
    background: none;
    border: none;
    color: #484f58;
    cursor: pointer;
    padding: 0.2rem;
    border-radius: 4px;
  }

  .close-btn:hover {
    color: #e6edf3;
    background: #21262d;
  }

  .cve-title, .pkg-title {
    margin: 0 0 0.75rem;
    font-size: 1rem;
    color: #e6edf3;
    word-break: break-all;
  }

  .vuln-summary {
    font-size: 0.85rem;
    color: #8b949e;
    line-height: 1.5;
    margin: 0 0 1rem;
  }

  .info-row {
    display: flex;
    justify-content: space-between;
    padding: 0.4rem 0;
    border-bottom: 1px solid #21262d;
    font-size: 0.85rem;
  }

  .info-label {
    color: #8b949e;
  }

  .info-value {
    color: #e6edf3;
    font-weight: 500;
  }

  .cvss {
    font-weight: 700;
    font-size: 1rem;
  }

  .section {
    margin-top: 1rem;
  }

  .section h4 {
    margin: 0 0 0.5rem;
    font-size: 0.8rem;
    color: #8b949e;
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }

  .pkg-list, .vuln-list, .ref-list {
    list-style: none;
    margin: 0;
    padding: 0;
  }

  .pkg-item {
    display: flex;
    justify-content: space-between;
    padding: 0.35rem 0.5rem;
    background: #1c2128;
    margin-bottom: 0.25rem;
    border-radius: 4px;
    font-size: 0.8rem;
  }

  .pkg-name {
    color: #e6edf3;
  }

  .pkg-version {
    color: #8b949e;
    font-family: monospace;
    font-size: 0.75rem;
  }

  .vuln-item {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.35rem 0.5rem;
    background: #1c2128;
    margin-bottom: 0.25rem;
    border-radius: 4px;
    font-size: 0.8rem;
    color: #e6edf3;
  }

  .severity-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    flex-shrink: 0;
  }

  .ref-list li {
    margin-bottom: 0.3rem;
  }

  .ref-list a {
    color: #58a6ff;
    font-size: 0.8rem;
    text-decoration: none;
    word-break: break-all;
  }

  .ref-list a:hover {
    text-decoration: underline;
  }

  .action-btn {
    width: 100%;
    padding: 0.5rem;
    background: #388bfd;
    color: #fff;
    border: none;
    border-radius: 6px;
    cursor: pointer;
    font-size: 0.85rem;
    font-weight: 500;
    transition: background 0.15s;
    margin-bottom: 0.5rem;
  }

  .action-btn:hover {
    background: #58a6ff;
  }

  .action-btn:disabled {
    opacity: 0.6;
    cursor: wait;
  }

  .action-btn.secondary {
    background: #21262d;
    color: #c9d1d9;
  }

  .action-btn.secondary:hover {
    background: #30363d;
  }

  .path-count {
    text-align: center;
    font-size: 0.8rem;
    color: #8b949e;
    margin: 0;
  }

  .type-badge.clean {
    background: #3fb95022;
    color: #3fb950;
  }

  .severity-badge.small {
    padding: 0.1rem 0.4rem;
    font-size: 0.6rem;
  }

  .loading-small {
    color: #484f58;
    font-size: 0.8rem;
    padding: 0.5rem;
  }

  .vuln-detail {
    background: #1c2128;
    border-radius: 6px;
    padding: 0.6rem;
    margin-bottom: 0.5rem;
    border-left: 3px solid #30363d;
  }

  .vuln-header {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    margin-bottom: 0.3rem;
  }

  .vuln-id {
    font-size: 0.8rem;
    font-weight: 600;
    color: #e6edf3;
    word-break: break-all;
  }

  .vuln-desc {
    font-size: 0.78rem;
    color: #8b949e;
    line-height: 1.4;
    margin: 0.3rem 0;
  }

  .vuln-aliases {
    display: flex;
    flex-wrap: wrap;
    gap: 0.25rem;
    margin-top: 0.3rem;
  }

  .alias-tag {
    font-size: 0.65rem;
    padding: 0.1rem 0.35rem;
    background: #30363d;
    color: #c9d1d9;
    border-radius: 3px;
  }

  .vuln-refs {
    display: flex;
    flex-direction: column;
    gap: 0.15rem;
    margin-top: 0.3rem;
  }

  .vuln-refs a {
    font-size: 0.7rem;
    color: #58a6ff;
    text-decoration: none;
    word-break: break-all;
  }

  .vuln-refs a:hover {
    text-decoration: underline;
  }

  .clean-msg {
    color: #3fb950;
    font-size: 0.85rem;
    margin: 0;
  }

  .no-data {
    color: #484f58;
    font-size: 0.8rem;
  }
</style>
