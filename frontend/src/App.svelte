<script>
  import Upload from './lib/components/Upload.svelte';
  import ProjectList from './lib/components/ProjectList.svelte';
  import GraphView from './lib/components/GraphView.svelte';
  import VulnPanel from './lib/components/VulnPanel.svelte';
  import AnalysisDashboard from './lib/components/AnalysisDashboard.svelte';
  import { highlightPaths, resetHighlight } from './lib/graph.js';

  let selectedProject = $state(null);
  let selectedNode = $state(null);
  let activeView = $state('graph');
  let showUpload = $state(false);
  let projectListRef = $state(null);
  let graphViewRef = $state(null);

  function handleSelectProject(project) {
    if (!project) {
      selectedProject = null;
      selectedNode = null;
      return;
    }
    selectedProject = project;
    selectedNode = null;
    activeView = 'graph';
    showUpload = false;
  }

  function handleUploadSuccess(result) {
    showUpload = false;
    if (result && result.project_id) {
      selectedProject = {
        project_id: result.project_id,
        ecosystem: result.ecosystem,
        package_count: result.packages_parsed,
        vulnerability_count: result.summary?.vulnerability_count || 0,
      };
    }
    activeView = 'graph';
    if (projectListRef) {
      projectListRef.loadProjects();
    }
  }

  function handleNodeSelect(data) {
    selectedNode = data;
  }

  function handleShowPaths(paths) {
    if (graphViewRef) {
      const cy = graphViewRef.getCy();
      if (cy) {
        if (paths) {
          highlightPaths(cy, paths);
        } else {
          resetHighlight(cy);
        }
      }
    }
  }
</script>

<div class="app-layout">
  <header class="app-header">
    <div class="header-left">
      <h1 class="app-title">
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#58a6ff" stroke-width="2">
          <circle cx="12" cy="5" r="3"/><circle cx="5" cy="19" r="3"/><circle cx="19" cy="19" r="3"/>
          <line x1="12" y1="8" x2="5" y2="16"/><line x1="12" y1="8" x2="19" y2="16"/>
        </svg>
        DepGra
      </h1>
      <span class="tagline">Dependency Vulnerability Tracker</span>
    </div>
    <div class="header-right">
      {#if selectedProject}
        <div class="view-toggle">
          <button class="toggle-btn" class:active={activeView === 'graph'} onclick={() => activeView = 'graph'}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <circle cx="12" cy="5" r="2"/><circle cx="5" cy="19" r="2"/><circle cx="19" cy="19" r="2"/>
              <line x1="12" y1="7" x2="5" y2="17"/><line x1="12" y1="7" x2="19" y2="17"/>
            </svg>
            Graph
          </button>
          <button class="toggle-btn" class:active={activeView === 'dashboard'} onclick={() => activeView = 'dashboard'}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/>
              <rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/>
            </svg>
            Analysis
          </button>
        </div>
      {/if}
    </div>
  </header>

  <div class="app-body">
    <aside class="sidebar">
      <button class="upload-trigger" onclick={() => { showUpload = true; selectedProject = null; selectedNode = null; }}>
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>
        </svg>
        New Scan
      </button>
      <ProjectList
        bind:this={projectListRef}
        selectedProjectId={selectedProject?.id}
        onSelectProject={handleSelectProject}
      />
    </aside>

    <main class="main-content">
      {#if showUpload || !selectedProject}
        <Upload onUploadSuccess={handleUploadSuccess} />
      {:else}
        <div class="view-layer" class:hidden={activeView !== 'graph'}>
          <GraphView
            bind:this={graphViewRef}
            projectId={selectedProject.project_id}
            onNodeSelect={handleNodeSelect}
          />
        </div>
        <div class="view-layer" class:hidden={activeView !== 'dashboard'}>
          <AnalysisDashboard projectId={selectedProject.project_id} />
        </div>
      {/if}
    </main>

    {#if selectedProject && activeView === 'graph'}
      <aside class="detail-panel">
        <VulnPanel
          selectedNode={selectedNode}
          projectId={selectedProject.project_id}
          onShowPaths={handleShowPaths}
        />
      </aside>
    {/if}
  </div>
</div>

<style>
  .app-layout {
    display: flex;
    flex-direction: column;
    height: 100vh;
    width: 100vw;
    overflow: hidden;
  }

  .app-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0 1.25rem;
    height: 52px;
    background: #161b22;
    border-bottom: 1px solid #21262d;
    flex-shrink: 0;
  }

  .header-left {
    display: flex;
    align-items: center;
    gap: 1rem;
  }

  .app-title {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    margin: 0;
    font-size: 1.1rem;
    font-weight: 700;
    color: #e6edf3;
  }

  .tagline {
    font-size: 0.8rem;
    color: #484f58;
  }

  .header-right {
    display: flex;
    align-items: center;
  }

  .view-toggle {
    display: flex;
    gap: 0.25rem;
    background: #0d1117;
    padding: 0.2rem;
    border-radius: 6px;
  }

  .toggle-btn {
    display: flex;
    align-items: center;
    gap: 0.35rem;
    padding: 0.35rem 0.75rem;
    background: none;
    border: none;
    color: #8b949e;
    font-size: 0.8rem;
    cursor: pointer;
    border-radius: 4px;
    transition: all 0.15s;
  }

  .toggle-btn:hover {
    color: #c9d1d9;
  }

  .toggle-btn.active {
    background: #21262d;
    color: #58a6ff;
  }

  .app-body {
    display: flex;
    flex: 1;
    overflow: hidden;
  }

  .sidebar {
    width: 260px;
    background: #161b22;
    border-right: 1px solid #21262d;
    display: flex;
    flex-direction: column;
    flex-shrink: 0;
    overflow: hidden;
  }

  .upload-trigger {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.4rem;
    margin: 0.75rem;
    padding: 0.5rem;
    background: #238636;
    color: #fff;
    border: none;
    border-radius: 6px;
    cursor: pointer;
    font-size: 0.85rem;
    font-weight: 500;
    transition: background 0.15s;
  }

  .upload-trigger:hover {
    background: #2ea043;
  }

  .main-content {
    flex: 1;
    overflow: hidden;
    background: #0d1117;
    display: flex;
    flex-direction: column;
    position: relative;
  }

  .view-layer {
    position: absolute;
    inset: 0;
    display: flex;
    flex-direction: column;
  }

  .view-layer.hidden {
    visibility: hidden;
    pointer-events: none;
  }

  .detail-panel {
    width: 300px;
    flex-shrink: 0;
    overflow: hidden;
  }

  @media (max-width: 900px) {
    .sidebar {
      width: 200px;
    }
    .detail-panel {
      width: 240px;
    }
    .tagline {
      display: none;
    }
  }
</style>
