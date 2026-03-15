<script>
  import { getProjects, deleteProject } from '../api.js';
  import { onMount } from 'svelte';

  let { selectedProjectId = null, onSelectProject = () => {}, onProjectsChanged = () => {} } = $props();

  let projects = $state([]);
  let loading = $state(true);
  let confirmDeleteId = $state(null);

  const ECO_COLORS = {
    npm: '#cb3837',
    pip: '#3776ab',
    cargo: '#dea584',
    go: '#00add8',
  };

  onMount(() => {
    loadProjects();
  });

  export async function loadProjects() {
    loading = true;
    try {
      const data = await getProjects();
      projects = Array.isArray(data) ? data : data.projects || [];
    } catch (e) {
      projects = [];
    } finally {
      loading = false;
    }
  }

  async function handleDelete(id, e) {
    e.stopPropagation();
    if (confirmDeleteId === id) {
      try {
        await deleteProject(id);
        projects = projects.filter((p) => p.project_id !== id);
        if (selectedProjectId === id) {
          onSelectProject(null);
        }
        onProjectsChanged();
      } catch (err) {
        // silently ignore
      }
      confirmDeleteId = null;
    } else {
      confirmDeleteId = id;
      setTimeout(() => { confirmDeleteId = null; }, 3000);
    }
  }

  function sevCount(project, severity) {
    if (!project.vulnerabilities) return 0;
    if (typeof project.vulnerabilities === 'number') return severity === 'total' ? project.vulnerabilities : 0;
    if (severity === 'total') {
      return Object.values(project.vulnerabilities).reduce((a, b) => a + b, 0);
    }
    return project.vulnerabilities[severity] || 0;
  }
</script>

<div class="project-list">
  <div class="list-header">
    <h3>Projects</h3>
    <span class="count">{projects.length}</span>
  </div>

  {#if loading}
    <div class="loading">Loading...</div>
  {:else if projects.length === 0}
    <div class="empty">No projects scanned yet. Upload a lockfile to get started.</div>
  {:else}
    <div class="items">
      {#each projects as project (project.project_id)}
        <div
          class="project-item"
          class:selected={selectedProjectId === project.project_id}
          role="button"
          tabindex="0"
          onclick={() => onSelectProject(project)}
          onkeydown={(e) => e.key === 'Enter' && onSelectProject(project)}
        >
          <div class="project-top">
            <span class="project-name">{project.project_id}</span>
            <span class="eco-badge" style="background: {ECO_COLORS[project.ecosystem] || '#484f58'}">
              {project.ecosystem || '?'}
            </span>
          </div>
          <div class="project-bottom">
            <div class="vuln-counts">
              {#if project.vulnerability_count != null}
                <span class="vuln-total">{project.vulnerability_count} vulns</span>
              {:else}
                {#each ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as sev}
                  {@const c = sevCount(project, sev)}
                  {#if c > 0}
                    <span class="sev-dot" style="background: {sev === 'CRITICAL' ? '#f85149' : sev === 'HIGH' ? '#f0883e' : sev === 'MEDIUM' ? '#d29922' : '#8b949e'}">{c}</span>
                  {/if}
                {/each}
              {/if}
            </div>
            <button
              class="delete-btn"
              class:confirm={confirmDeleteId === project.project_id}
              onclick={(e) => handleDelete(project.project_id, e)}
              title={confirmDeleteId === project.project_id ? 'Click again to confirm' : 'Delete project'}
            >
              {confirmDeleteId === project.project_id ? 'Sure?' : ''}
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <polyline points="3 6 5 6 21 6" />
                <path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2" />
              </svg>
            </button>
          </div>
        </div>
      {/each}
    </div>
  {/if}
</div>

<style>
  .project-list {
    display: flex;
    flex-direction: column;
    height: 100%;
  }

  .list-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0.75rem 1rem;
    border-bottom: 1px solid #21262d;
  }

  .list-header h3 {
    margin: 0;
    font-size: 0.85rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: #8b949e;
  }

  .count {
    background: #30363d;
    color: #c9d1d9;
    padding: 0.1rem 0.45rem;
    border-radius: 10px;
    font-size: 0.75rem;
  }

  .loading, .empty {
    padding: 1.5rem 1rem;
    color: #484f58;
    font-size: 0.85rem;
    text-align: center;
  }

  .items {
    overflow-y: auto;
    flex: 1;
  }

  .project-item {
    display: block;
    width: 100%;
    text-align: left;
    background: none;
    border: none;
    border-bottom: 1px solid #21262d;
    padding: 0.75rem 1rem;
    cursor: pointer;
    transition: background 0.15s;
    color: #e6edf3;
    font-family: inherit;
  }

  .project-item:hover {
    background: #1c2128;
  }

  .project-item.selected {
    background: #1c2128;
    border-left: 3px solid #58a6ff;
  }

  .project-top {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.35rem;
  }

  .project-name {
    font-size: 0.9rem;
    font-weight: 500;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    max-width: 150px;
  }

  .eco-badge {
    font-size: 0.65rem;
    padding: 0.1rem 0.4rem;
    border-radius: 3px;
    color: #fff;
    text-transform: uppercase;
    font-weight: 600;
  }

  .project-bottom {
    display: flex;
    justify-content: space-between;
    align-items: center;
  }

  .vuln-counts {
    display: flex;
    gap: 0.3rem;
    align-items: center;
  }

  .vuln-total {
    font-size: 0.75rem;
    color: #8b949e;
  }

  .sev-dot {
    font-size: 0.65rem;
    padding: 0.05rem 0.35rem;
    border-radius: 3px;
    color: #fff;
    font-weight: 600;
  }

  .delete-btn {
    background: none;
    border: none;
    color: #484f58;
    cursor: pointer;
    padding: 0.2rem;
    display: flex;
    align-items: center;
    gap: 0.25rem;
    font-size: 0.7rem;
    border-radius: 4px;
    transition: all 0.15s;
  }

  .delete-btn:hover {
    color: #f85149;
    background: #f8514922;
  }

  .delete-btn.confirm {
    color: #f85149;
    background: #f8514922;
  }
</style>
