import cytoscape from 'cytoscape';

const SEVERITY_COLORS = {
  CRITICAL: '#f85149',
  HIGH: '#f0883e',
  MEDIUM: '#d29922',
  LOW: '#8b949e',
};
const CLEAN_COLOR = '#3fb950';

function sevColor(severity) {
  return SEVERITY_COLORS[severity?.toUpperCase()] || null;
}

// ---------------------------------------------------------------------------
// DAG layout — topological sort, O(V+E), one code path for all sizes
// ---------------------------------------------------------------------------
function dagLayout(cy) {
  const nodes = cy.nodes();
  const edges = cy.edges();
  if (nodes.length === 0) return;

  // Build adjacency + in-degree
  const children = {};
  const inDeg = {};
  const allIds = new Set();

  nodes.forEach((n) => {
    const id = n.id();
    allIds.add(id);
    children[id] = [];
    inDeg[id] = 0;
  });

  edges.forEach((e) => {
    const src = e.source().id();
    const tgt = e.target().id();
    if (allIds.has(src) && allIds.has(tgt)) {
      children[src].push(tgt);
      inDeg[tgt]++;
    }
  });

  // Kahn's topological sort with depth tracking
  const depth = {};
  let queue = [];
  for (const id of allIds) {
    if (inDeg[id] === 0) {
      queue.push(id);
      depth[id] = 0;
    }
  }

  while (queue.length > 0) {
    const next = [];
    for (const id of queue) {
      for (const cid of children[id]) {
        depth[cid] = Math.max(depth[cid] || 0, depth[id] + 1);
        inDeg[cid]--;
        if (inDeg[cid] === 0) next.push(cid);
      }
    }
    queue = next;
  }

  // Cycles / disconnected — put at depth 0
  for (const id of allIds) {
    if (depth[id] === undefined) depth[id] = 0;
  }

  // Group by row
  const rows = {};
  for (const [id, d] of Object.entries(depth)) {
    if (!rows[d]) rows[d] = [];
    rows[d].push(id);
  }
  // Sort each row alphabetically for stability
  for (const d of Object.keys(rows)) rows[d].sort();

  // Adaptive spacing: shrink columns if rows are wide, grow if narrow
  const maxRowLen = Math.max(...Object.values(rows).map((r) => r.length), 1);
  const colWidth = Math.max(80, Math.min(200, 16000 / maxRowLen));
  const rowHeight = Math.max(70, Math.min(130, 10000 / (Object.keys(rows).length || 1)));

  // Assign positions
  const positions = {};
  const maxD = Math.max(...Object.keys(rows).map(Number), 0);

  for (let d = 0; d <= maxD; d++) {
    const row = rows[d] || [];
    const totalW = row.length * colWidth;
    const startX = -totalW / 2 + colWidth / 2;
    const y = d * rowHeight;
    row.forEach((id, col) => {
      positions[id] = { x: startX + col * colWidth, y };
    });
  }

  // Apply in one batch
  cy.startBatch();
  nodes.forEach((n) => {
    const pos = positions[n.id()];
    if (pos) n.position(pos);
  });
  cy.endBatch();

  cy.fit(undefined, 40);
  cy.center();
}

// ---------------------------------------------------------------------------
// Cytoscape initialization — one consistent style for all graph sizes
// ---------------------------------------------------------------------------
export function initGraph(container, elements, onNodeClick) {
  // Filter out vulnerability diamond nodes — all info is on the package node
  const filtered = elements.filter((el) => {
    if (el.data?.type === 'vulnerability') return false;
    if (el.data?.relation === 'AFFECTS' || el.data?.type === 'AFFECTS') return false;
    return true;
  });

  const cy = cytoscape({
    container,
    elements: filtered,
    style: [
      // --- Clean packages (green border) ---
      {
        selector: 'node[vuln_count=0]',
        style: {
          shape: 'round-rectangle',
          'background-color': '#161b22',
          label: 'data(label)',
          color: '#8b949e',
          'text-valign': 'center',
          'text-halign': 'center',
          'font-size': '9px',
          'text-wrap': 'ellipsis',
          'text-max-width': '110px',
          width: 120,
          height: 32,
          'border-width': 2,
          'border-color': CLEAN_COLOR,
          'text-outline-color': '#161b22',
          'text-outline-width': 1,
        },
      },
      // --- Vulnerable packages (severity-colored border) ---
      {
        selector: 'node[vuln_count>0]',
        style: {
          shape: 'round-rectangle',
          'background-color': '#161b22',
          label: 'data(label)',
          color: '#e6edf3',
          'text-valign': 'center',
          'text-halign': 'center',
          'font-size': '10px',
          'font-weight': 'bold',
          'text-wrap': 'ellipsis',
          'text-max-width': '120px',
          width: 130,
          height: 36,
          'border-width': 3,
          'border-color': function (ele) {
            return sevColor(ele.data('max_severity')) || '#f0883e';
          },
          'text-outline-color': '#161b22',
          'text-outline-width': 1,
        },
      },
      // --- Dependency edges ---
      {
        selector: 'edge',
        style: {
          'line-color': '#30363d',
          'target-arrow-color': '#30363d',
          'target-arrow-shape': 'triangle',
          'arrow-scale': 0.6,
          'curve-style': 'bezier',
          width: 1,
          opacity: 0.5,
        },
      },
      // --- Highlighted ---
      {
        selector: '.faded',
        style: { opacity: 0.08 },
      },
      {
        selector: '.highlighted',
        style: {
          opacity: 1,
          'border-width': 4,
          'z-index': 999,
          'text-opacity': 1,
        },
      },
      {
        selector: 'edge.highlighted',
        style: {
          opacity: 0.8,
          width: 2.5,
          'z-index': 999,
        },
      },
      {
        selector: '.search-match',
        style: {
          'border-width': 4,
          'border-color': '#d2a8ff',
          'z-index': 1000,
        },
      },
    ],
    layout: { name: 'preset' },
    minZoom: 0.05,
    maxZoom: 4,
    // Performance: render textures during interaction
    textureOnViewport: true,
    hideEdgesOnViewport: filtered.length > 800,
  });

  dagLayout(cy);

  // --- Click: highlight node + connected edges + neighbors ---
  cy.on('tap', 'node', function (evt) {
    const node = evt.target;
    // Clear previous selection
    cy.elements().removeClass('faded highlighted');
    // Fade everything
    cy.elements().addClass('faded');
    // Highlight clicked node
    node.removeClass('faded').addClass('highlighted');
    // Highlight connected edges
    node.connectedEdges().removeClass('faded').addClass('highlighted');
    // Highlight neighbor nodes
    node.neighborhood('node').removeClass('faded').addClass('highlighted');

    if (onNodeClick) onNodeClick(node.data());
  });

  // Click background to reset
  cy.on('tap', function (evt) {
    if (evt.target === cy) {
      cy.elements().removeClass('faded highlighted');
    }
  });

  // --- Tooltip ---
  let tooltip = null;

  cy.on('mouseover', 'node', function (evt) {
    container.style.cursor = 'pointer';
    const d = evt.target.data();
    const pos = evt.renderedPosition;
    if (tooltip) tooltip.remove();

    tooltip = document.createElement('div');
    tooltip.className = 'cy-tooltip';

    const vc = d.vuln_count || 0;
    let statusHtml;
    if (vc === 0) {
      statusHtml = '<span style="color:#3fb950">No known vulnerabilities</span>';
    } else {
      const parts = [];
      if (d.sev_critical) parts.push(`<span style="color:#f85149">${d.sev_critical} critical</span>`);
      if (d.sev_high) parts.push(`<span style="color:#f0883e">${d.sev_high} high</span>`);
      if (d.sev_medium) parts.push(`<span style="color:#d29922">${d.sev_medium} medium</span>`);
      if (d.sev_low) parts.push(`<span style="color:#8b949e">${d.sev_low} low</span>`);
      const other = vc - (d.sev_critical || 0) - (d.sev_high || 0) - (d.sev_medium || 0) - (d.sev_low || 0);
      if (other > 0) parts.push(`${other} other`);
      statusHtml = parts.join(', ');
    }

    tooltip.innerHTML = `
      <div style="font-weight:700; margin-bottom:4px">${d.name || ''}@${d.version || ''}</div>
      ${statusHtml}
    `;

    const rect = container.getBoundingClientRect();
    tooltip.style.position = 'fixed';
    tooltip.style.left = (rect.left + pos.x) + 'px';
    tooltip.style.top = (rect.top + pos.y - 12) + 'px';
    tooltip.style.transform = 'translate(-50%, -100%)';
    document.body.appendChild(tooltip);
  });

  cy.on('mouseout', 'node', function () {
    container.style.cursor = 'default';
    if (tooltip) { tooltip.remove(); tooltip = null; }
  });

  cy.on('destroy', function () {
    if (tooltip) { tooltip.remove(); tooltip = null; }
  });

  return cy;
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------
export function highlightPaths(cy, paths) {
  cy.elements().addClass('faded');
  if (!paths || !paths.length) return;
  for (const path of paths) {
    if (!path?.length) continue;
    for (const node of path) {
      const id = typeof node === 'string' ? node : node.uid || node.id;
      const el = cy.getElementById(id);
      if (el.length) el.removeClass('faded').addClass('highlighted');
    }
    for (let i = 0; i < path.length - 1; i++) {
      const a = typeof path[i] === 'string' ? path[i] : path[i].uid || path[i].id;
      const b = typeof path[i + 1] === 'string' ? path[i + 1] : path[i + 1].uid || path[i + 1].id;
      cy.edges().filter((e) => {
        const s = e.source().id(), t = e.target().id();
        return (s === a && t === b) || (s === b && t === a);
      }).removeClass('faded').addClass('highlighted');
    }
  }
}

export function resetHighlight(cy) {
  cy.elements().removeClass('faded highlighted search-match');
}

export function fitToView(cy) {
  cy.fit(undefined, 40);
  cy.center();
}

export function applyLayout(cy) {
  dagLayout(cy);
}

export function searchNode(cy, query) {
  cy.elements().removeClass('search-match');
  if (!query?.trim()) return null;
  const q = query.toLowerCase().trim();
  const matched = cy.nodes().filter((n) => {
    const name = (n.data('name') || n.data('label') || '').toLowerCase();
    return name.includes(q);
  });
  if (matched.length > 0) {
    matched.addClass('search-match');
    cy.animate({ fit: { eles: matched, padding: 80 }, duration: 300 });
  }
  return matched.length;
}
