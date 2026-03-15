<script>
  import { onMount, onDestroy } from 'svelte';
  import { getGraph } from '../api.js';
  import { initGraph, fitToView, searchNode, resetHighlight } from '../graph.js';

  let { projectId = null, onNodeSelect = () => {} } = $props();

  let cy = $state(null);
  let containerEl = $state(null);
  let searchQuery = $state('');
  let searchResults = $state(null);
  let loading = $state(false);
  let error = $state(null);
  let loadedProjectId = $state(null);

  $effect(() => {
    if (projectId && projectId !== loadedProjectId) {
      loadGraph(projectId);
    }
  });

  onDestroy(() => {
    if (cy) {
      cy.destroy();
      cy = null;
    }
  });

  async function loadGraph(pid) {
    loading = true;
    error = null;
    try {
      const data = await getGraph(pid);
      if (cy) {
        cy.destroy();
        cy = null;
      }
      const elements = buildElements(data);
      if (containerEl) {
        cy = initGraph(containerEl, elements, handleNodeClick);
      }
      loadedProjectId = pid;
    } catch (err) {
      error = err.response?.data?.error || err.message || 'Failed to load graph';
    } finally {
      loading = false;
    }
  }

  function buildElements(data) {
    const nodes = [];
    const edges = [];

    if (data.nodes) {
      data.nodes.forEach((n, i) => {
        // Backend returns {data: {id, label, type, ...}}
        const d = n.data || n;
        nodes.push({
          data: {
            id: d.id || String(i),
            label: d.label || `${d.name || ''}@${d.version || ''}`,
            type: d.type || 'package',
            name: d.name,
            version: d.version,
            ecosystem: d.ecosystem,
            severity: d.severity,
            summary: d.summary,
            vuln_count: d.vuln_count ?? 0,
            max_severity: d.max_severity || null,
            sev_critical: d.sev_critical ?? 0,
            sev_high: d.sev_high ?? 0,
            sev_medium: d.sev_medium ?? 0,
            sev_low: d.sev_low ?? 0,
          },
        });
      });
    }

    if (data.edges) {
      data.edges.forEach((e, i) => {
        const d = e.data || e;
        edges.push({
          data: {
            id: d.id || `e${i}`,
            source: d.source,
            target: d.target,
            relation: d.type || d.relation || 'DEPENDS_ON',
          },
        });
      });
    }

    return [...nodes, ...edges];
  }

  function handleNodeClick(data) {
    onNodeSelect(data);
  }

  function handleZoomIn() {
    if (cy) cy.zoom({ level: cy.zoom() * 1.3, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
  }

  function handleZoomOut() {
    if (cy) cy.zoom({ level: cy.zoom() / 1.3, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
  }

  function handleFit() {
    if (cy) fitToView(cy);
  }

  function handleSearch() {
    if (cy) {
      resetHighlight(cy);
      if (searchQuery.trim()) {
        searchResults = searchNode(cy, searchQuery);
      } else {
        searchResults = null;
      }
    }
  }

  export function getCy() {
    return cy;
  }
</script>

<div class="graph-view">
  <div class="toolbar">
    <div class="tool-group">
      <button class="tool-btn" onclick={handleFit} title="Fit to view">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M8 3H5a2 2 0 00-2 2v3m18 0V5a2 2 0 00-2-2h-3m0 18h3a2 2 0 002-2v-3M3 16v3a2 2 0 002 2h3"/>
        </svg>
      </button>
      <button class="tool-btn" onclick={handleZoomIn} title="Zoom in">+</button>
      <button class="tool-btn" onclick={handleZoomOut} title="Zoom out">-</button>
    </div>

    <div class="tool-group search-group">
      <input
        type="text"
        class="search-input"
        placeholder="Search packages..."
        bind:value={searchQuery}
        onkeydown={(e) => e.key === 'Enter' && handleSearch()}
      />
      <button class="tool-btn" aria-label="Search" onclick={handleSearch}>
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
        </svg>
      </button>
      {#if searchResults !== null}
        <span class="search-count">{searchResults} found</span>
      {/if}
    </div>
  </div>

  <div class="graph-container" bind:this={containerEl}>
    {#if loading}
      <div class="graph-overlay">
        <div class="spinner"></div>
        <p>Loading dependency graph...</p>
      </div>
    {/if}
    {#if error}
      <div class="graph-overlay error">
        <p>{error}</p>
      </div>
    {/if}
  </div>
</div>

<style>
  .graph-view {
    display: flex;
    flex-direction: column;
    height: 100%;
    width: 100%;
  }

  .toolbar {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    padding: 0.5rem 0.75rem;
    background: #161b22;
    border-bottom: 1px solid #21262d;
    flex-wrap: wrap;
    min-height: 44px;
  }

  .tool-group {
    display: flex;
    align-items: center;
    gap: 0.3rem;
  }

  .tool-label {
    font-size: 0.7rem;
    color: #8b949e;
    text-transform: uppercase;
    margin-right: 0.2rem;
  }

  .tool-btn {
    background: #21262d;
    border: 1px solid #30363d;
    color: #c9d1d9;
    padding: 0.3rem 0.5rem;
    border-radius: 4px;
    cursor: pointer;
    font-size: 0.75rem;
    display: flex;
    align-items: center;
    gap: 0.2rem;
    transition: all 0.15s;
  }

  .tool-btn:hover {
    background: #30363d;
    border-color: #484f58;
  }

  .tool-btn.active {
    background: #388bfd33;
    border-color: #58a6ff;
    color: #58a6ff;
  }

  .filters {
    gap: 0.5rem;
  }

  .filter-cb {
    display: flex;
    align-items: center;
    gap: 0.2rem;
    font-size: 0.75rem;
    color: var(--sev-color);
    cursor: pointer;
  }

  .filter-cb input {
    accent-color: var(--sev-color);
  }

  .search-group {
    margin-left: auto;
  }

  .search-input {
    background: #0d1117;
    border: 1px solid #30363d;
    color: #e6edf3;
    padding: 0.3rem 0.6rem;
    border-radius: 4px;
    font-size: 0.8rem;
    width: 160px;
    outline: none;
  }

  .search-input:focus {
    border-color: #58a6ff;
  }

  .search-count {
    font-size: 0.7rem;
    color: #8b949e;
  }

  .graph-container {
    flex: 1;
    position: relative;
    background: #0d1117;
    min-height: 400px;
  }

  .graph-overlay {
    position: absolute;
    inset: 0;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    background: #0d1117ee;
    color: #8b949e;
    z-index: 10;
    gap: 1rem;
  }

  .graph-overlay.error {
    color: #f85149;
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
</style>
