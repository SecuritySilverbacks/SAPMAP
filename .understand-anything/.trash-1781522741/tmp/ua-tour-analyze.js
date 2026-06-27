#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');

function die(msg) {
  process.stderr.write(`[tour-analyze] ${msg}\n`);
  process.exit(1);
}

const [, , inPath, outPath] = process.argv;
if (!inPath || !outPath) die('usage: ua-tour-analyze.js <input.json> <output.json>');

let raw;
try { raw = fs.readFileSync(inPath, 'utf8'); } catch (e) { die(`read input failed: ${e.message}`); }

let data;
try { data = JSON.parse(raw); } catch (e) { die(`parse input failed: ${e.message}`); }

const nodes = Array.isArray(data.nodes) ? data.nodes : [];
const edges = Array.isArray(data.edges) ? data.edges : [];
const layers = Array.isArray(data.layers) ? data.layers : [];

// Build node index
const nodeById = new Map();
for (const n of nodes) {
  if (n && n.id) nodeById.set(n.id, n);
}

// Filter edges so we only count edges between nodes that exist in our node set.
// The edges file contains class/function-level edges as well; we only care about file→file links.
const fileEdges = edges.filter(e => e && nodeById.has(e.source) && nodeById.has(e.target));

// Build adjacency for fan-in/fan-out and BFS
const outAdj = new Map();   // source -> [{target, type}]
const inAdj = new Map();    // target -> [{source, type}]
for (const id of nodeById.keys()) {
  outAdj.set(id, []);
  inAdj.set(id, []);
}
for (const e of fileEdges) {
  outAdj.get(e.source).push({ target: e.target, type: e.type });
  inAdj.get(e.target).push({ source: e.source, type: e.type });
}

// A. Fan-in ranking
const fanInRanking = [...nodeById.values()]
  .map(n => ({ id: n.id, fanIn: inAdj.get(n.id).length, name: n.name }))
  .sort((a, b) => b.fanIn - a.fanIn)
  .slice(0, 20);

// B. Fan-out ranking
const fanOutRanking = [...nodeById.values()]
  .map(n => ({ id: n.id, fanOut: outAdj.get(n.id).length, name: n.name }))
  .sort((a, b) => b.fanOut - a.fanOut)
  .slice(0, 20);

// C. Entry point candidates
const ENTRY_NAMES = new Set([
  'index.ts', 'index.js', 'main.ts', 'main.js', 'app.ts', 'app.js',
  'server.ts', 'server.js', 'mod.rs', 'main.go', 'main.py', 'main.rs',
  'manage.py', 'app.py', 'wsgi.py', 'asgi.py', 'run.py', '__main__.py',
  'Application.java', 'Main.java', 'Program.cs', 'config.ru',
  'index.php', 'App.swift', 'Application.kt', 'main.cpp', 'main.c',
]);

const fanOutSorted = [...fanOutRanking].sort((a, b) => b.fanOut - a.fanOut);
const top10pctFanOut = new Set(fanOutSorted.slice(0, Math.max(1, Math.ceil(nodes.length * 0.1))).map(x => x.id));
const fanInSorted = [...nodeById.values()]
  .map(n => ({ id: n.id, fanIn: inAdj.get(n.id).length }))
  .sort((a, b) => a.fanIn - b.fanIn);
const bottom25pctFanIn = new Set(fanInSorted.slice(0, Math.max(1, Math.ceil(nodes.length * 0.25))).map(x => x.id));

const entryScores = [];
for (const n of nodeById.values()) {
  let score = 0;
  const name = n.name || path.basename(n.filePath || '');
  const fp = (n.filePath || '').replace(/\\/g, '/');
  const depth = fp.split('/').filter(Boolean).length;

  if (n.type === 'document' || /\.md$/i.test(name)) {
    if (name.toLowerCase() === 'readme.md' && depth <= 1) score += 5;
    else if (depth <= 1) score += 2;
  } else if (n.type === 'file') {
    if (ENTRY_NAMES.has(name)) score += 3;
    if (depth <= 2) score += 1;
    if (top10pctFanOut.has(n.id)) score += 1;
    if (bottom25pctFanIn.has(n.id)) score += 1;
  }

  if (score > 0) entryScores.push({ id: n.id, score, name, summary: n.summary || '' });
}
entryScores.sort((a, b) => b.score - a.score);
const entryPointCandidates = entryScores.slice(0, 5);

// D. BFS from top code entry point
function pickCodeEntry() {
  for (const c of entryScores) {
    const n = nodeById.get(c.id);
    if (n && n.type !== 'document') return c.id;
  }
  return null;
}
const bfsStart = pickCodeEntry();
const bfsOrder = [];
const depthMap = {};
if (bfsStart) {
  const visited = new Set([bfsStart]);
  const queue = [{ id: bfsStart, depth: 0 }];
  depthMap[bfsStart] = 0;
  while (queue.length) {
    const { id, depth } = queue.shift();
    bfsOrder.push(id);
    for (const { target, type } of outAdj.get(id) || []) {
      if (visited.has(target)) continue;
      if (type !== 'imports' && type !== 'calls') continue;
      visited.add(target);
      depthMap[target] = depth + 1;
      queue.push({ id: target, depth: depth + 1 });
    }
  }
}
const byDepth = {};
for (const [id, d] of Object.entries(depthMap)) {
  (byDepth[d] = byDepth[d] || []).push(id);
}

// E. Non-code inventory
const nonCodeFiles = {
  documentation: [],
  infrastructure: [],
  data: [],
  config: [],
};
const DOC_TYPES = new Set(['document']);
const INFRA_TYPES = new Set(['service', 'pipeline', 'resource']);
const DATA_TYPES = new Set(['table', 'schema', 'endpoint']);
const CFG_TYPES = new Set(['config']);
for (const n of nodeById.values()) {
  const rec = { id: n.id, name: n.name, summary: n.summary || '' };
  if (DOC_TYPES.has(n.type)) nonCodeFiles.documentation.push(rec);
  else if (INFRA_TYPES.has(n.type)) nonCodeFiles.infrastructure.push(rec);
  else if (DATA_TYPES.has(n.type)) nonCodeFiles.data.push(rec);
  else if (CFG_TYPES.has(n.type)) nonCodeFiles.config.push(rec);
  // Detect README and other root markdown by name even if classified as file
  else if (/\.md$/i.test(n.name || '') && (n.filePath || '').split('/').length <= 2) {
    nonCodeFiles.documentation.push(rec);
  }
}

// F. Tightly coupled clusters: bidirectional edges, then expand
const bidirPairs = [];
const edgeSet = new Set();
for (const e of fileEdges) {
  if (e.type === 'imports' || e.type === 'calls') {
    edgeSet.add(`${e.source}|${e.target}|${e.type}`);
  }
}
const seenPair = new Set();
for (const e of fileEdges) {
  if (e.type !== 'imports' && e.type !== 'calls') continue;
  const back = `${e.target}|${e.source}|${e.type}`;
  if (edgeSet.has(back)) {
    const key = [e.source, e.target].sort().join('|');
    if (!seenPair.has(key)) {
      seenPair.add(key);
      bidirPairs.push([e.source, e.target]);
    }
  }
}
// Build clusters from bidir pairs by union-find-ish grouping
const parent = new Map();
function find(x) { while (parent.get(x) !== x) { parent.set(x, parent.get(parent.get(x))); x = parent.get(x); } return x; }
function union(a, b) { const ra = find(a), rb = find(b); if (ra !== rb) parent.set(ra, rb); }
for (const [a, b] of bidirPairs) {
  if (!parent.has(a)) parent.set(a, a);
  if (!parent.has(b)) parent.set(b, b);
  union(a, b);
}
const clusterMap = new Map();
for (const id of parent.keys()) {
  const r = find(id);
  if (!clusterMap.has(r)) clusterMap.set(r, []);
  clusterMap.get(r).push(id);
}
let clusters = [...clusterMap.values()].filter(c => c.length >= 2 && c.length <= 6);

// Score each cluster by internal edge count
const clusterRecords = clusters.map(c => {
  const setIds = new Set(c);
  let count = 0;
  for (const id of c) {
    for (const e of outAdj.get(id) || []) {
      if (setIds.has(e.target)) count++;
    }
  }
  return { nodes: c, edgeCount: count };
}).sort((a, b) => b.edgeCount - a.edgeCount).slice(0, 10);

// G. Layers
const layerOut = {
  count: layers.length,
  list: layers.map(l => ({ id: l.id, name: l.name, description: l.description })),
};

// H. Node summary index
const nodeSummaryIndex = {};
for (const n of nodeById.values()) {
  nodeSummaryIndex[n.id] = { name: n.name, type: n.type, summary: n.summary || '' };
}

const result = {
  scriptCompleted: true,
  entryPointCandidates,
  fanInRanking,
  fanOutRanking,
  bfsTraversal: {
    startNode: bfsStart,
    order: bfsOrder,
    depthMap,
    byDepth,
  },
  nonCodeFiles,
  clusters: clusterRecords,
  layers: layerOut,
  nodeSummaryIndex,
  totalNodes: nodes.length,
  totalEdges: edges.length,
  totalFileEdges: fileEdges.length,
};

try { fs.writeFileSync(outPath, JSON.stringify(result, null, 2)); } catch (e) { die(`write output failed: ${e.message}`); }
process.exit(0);
