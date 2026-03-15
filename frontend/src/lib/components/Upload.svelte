<script>
  import { scanLockfile } from '../api.js';

  let dragActive = $state(false);
  let scanning = $state(false);
  let error = $state(null);

  let { onUploadSuccess = () => {} } = $props();

  const SUPPORTED = [
    { name: 'package-lock.json', eco: 'npm' },
    { name: 'Cargo.lock', eco: 'cargo' },
    { name: 'poetry.lock', eco: 'pip' },
    { name: 'requirements.txt', eco: 'pip' },
    { name: 'go.mod', eco: 'go' },
  ];

  function handleDragOver(e) {
    e.preventDefault();
    dragActive = true;
  }

  function handleDragLeave() {
    dragActive = false;
  }

  async function handleDrop(e) {
    e.preventDefault();
    dragActive = false;
    const files = e.dataTransfer?.files;
    if (files && files.length > 0) {
      await uploadFile(files[0]);
    }
  }

  async function handleFileSelect(e) {
    const files = e.target.files;
    if (files && files.length > 0) {
      await uploadFile(files[0]);
    }
  }

  async function uploadFile(file) {
    scanning = true;
    error = null;
    try {
      const result = await scanLockfile(file);
      onUploadSuccess(result);
    } catch (err) {
      error = err.response?.data?.error || err.message || 'Upload failed';
    } finally {
      scanning = false;
    }
  }
</script>

<div class="upload-container">
  <div
    class="dropzone"
    class:drag-active={dragActive}
    ondragover={handleDragOver}
    ondragleave={handleDragLeave}
    ondrop={handleDrop}
    role="button"
    tabindex="0"
  >
    {#if scanning}
      <div class="spinner-wrap">
        <div class="spinner"></div>
        <p>Scanning dependencies...</p>
      </div>
    {:else}
      <div class="drop-icon">
        <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
          <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4" />
          <polyline points="17 8 12 3 7 8" />
          <line x1="12" y1="3" x2="12" y2="15" />
        </svg>
      </div>
      <p class="drop-text">Drag & drop a lockfile here</p>
      <p class="drop-sub">or</p>
      <label class="file-btn">
        Browse Files
        <input type="file" onchange={handleFileSelect} accept=".json,.lock,.txt,.mod" hidden />
      </label>
    {/if}
  </div>

  {#if error}
    <div class="error-msg">{error}</div>
  {/if}

  <div class="supported">
    <p class="supported-title">Supported formats</p>
    <div class="format-list">
      {#each SUPPORTED as fmt}
        <span class="format-badge">
          <span class="eco-tag">{fmt.eco}</span>
          {fmt.name}
        </span>
      {/each}
    </div>
  </div>
</div>

<style>
  .upload-container {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    height: 100%;
    padding: 2rem;
    gap: 1.5rem;
  }

  .dropzone {
    width: 100%;
    max-width: 500px;
    border: 2px dashed #30363d;
    border-radius: 12px;
    padding: 3rem 2rem;
    text-align: center;
    transition: all 0.2s;
    background: #1c2128;
    cursor: pointer;
  }

  .dropzone:hover,
  .drag-active {
    border-color: #58a6ff;
    background: #1c2128cc;
  }

  .drop-icon {
    color: #484f58;
    margin-bottom: 1rem;
  }

  .drop-text {
    font-size: 1.1rem;
    color: #e6edf3;
    margin: 0 0 0.5rem;
  }

  .drop-sub {
    color: #484f58;
    margin: 0 0 0.75rem;
    font-size: 0.85rem;
  }

  .file-btn {
    display: inline-block;
    padding: 0.5rem 1.25rem;
    background: #238636;
    color: #fff;
    border-radius: 6px;
    cursor: pointer;
    font-size: 0.9rem;
    transition: background 0.2s;
  }

  .file-btn:hover {
    background: #2ea043;
  }

  .spinner-wrap {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 1rem;
    color: #8b949e;
  }

  .spinner {
    width: 36px;
    height: 36px;
    border: 3px solid #30363d;
    border-top-color: #58a6ff;
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
  }

  @keyframes spin {
    to { transform: rotate(360deg); }
  }

  .error-msg {
    color: #f85149;
    background: #f8514922;
    padding: 0.6rem 1rem;
    border-radius: 6px;
    font-size: 0.9rem;
    max-width: 500px;
    width: 100%;
    text-align: center;
  }

  .supported {
    max-width: 500px;
    width: 100%;
  }

  .supported-title {
    color: #8b949e;
    font-size: 0.8rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin: 0 0 0.75rem;
    text-align: center;
  }

  .format-list {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    justify-content: center;
  }

  .format-badge {
    background: #21262d;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 0.35rem 0.6rem;
    font-size: 0.8rem;
    color: #c9d1d9;
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
  }

  .eco-tag {
    background: #58a6ff33;
    color: #58a6ff;
    padding: 0.1rem 0.35rem;
    border-radius: 3px;
    font-size: 0.7rem;
    font-weight: 600;
    text-transform: uppercase;
  }
</style>
