#!/usr/bin/env node
'use strict';

const fs = require('fs');

function main() {
  const inputPath = process.argv[2];
  const outputPath = process.argv[3];
  if (!inputPath || !outputPath) {
    console.error('usage: ua-arch-analyze.js <input.json> <output.json>');
    process.exit(1);
  }

  const data = JSON.parse(fs.readFileSync(inputPath, 'utf8'));
  const fileNodes = data.fileNodes || [];
  const importEdges = data.importEdges || [];
  const allEdges = data.allEdges || [];

  // ---------- Common path prefix ----------
  const paths = fileNodes.map(n => n.filePath || '');
  function commonPrefix(strs) {
    if (strs.length === 0) return '';
    let prefix = strs[0];
    for (const s of strs) {
      while (s.indexOf(prefix) !== 0) {
        prefix = prefix.slice(0, -1);
        if (!prefix) return '';
      }
    }
    // trim to last '/'
    const i = prefix.lastIndexOf('/');
    return i === -1 ? '' : prefix.slice(0, i + 1);
  }
  const prefix = commonPrefix(paths);

  // ---------- Directory grouping ----------
  // Use first path segment after the common prefix; if file is at the root,
  // use the file extension/type bucket like "(root)".
  function groupOf(filePath) {
    if (!filePath) return '(root)';
    const rel = filePath.startsWith(prefix) ? filePath.slice(prefix.length) : filePath;
    const parts = rel.split('/').filter(Boolean);
    if (parts.length <= 1) return '(root)';
    let top = parts[0];
    // Treat modules/<sub> as a richer group (e.g., modules/core)
    if (top === 'modules' && parts.length >= 3) {
      return 'modules/' + parts[1];
    }
    if (top === 'tools' && parts.length >= 3) {
      return 'tools/' + parts[1];
    }
    if (top === 'docs' && parts.length >= 3) {
      return 'docs/' + parts[1];
    }
    if (top === '.understand-anything') {
      return '.understand-anything';
    }
    return top;
  }

  const directoryGroups = {};
  for (const n of fileNodes) {
    const g = groupOf(n.filePath);
    if (!directoryGroups[g]) directoryGroups[g] = [];
    directoryGroups[g].push(n.id);
  }

  // ---------- Node type grouping ----------
  const nodeTypeGroups = {};
  for (const n of fileNodes) {
    const t = n.type || 'file';
    if (!nodeTypeGroups[t]) nodeTypeGroups[t] = [];
    nodeTypeGroups[t].push(n.id);
  }

  // ---------- ID -> file path / group lookup ----------
  const idToGroup = {};
  const idToPath = {};
  const idToType = {};
  for (const n of fileNodes) {
    idToGroup[n.id] = groupOf(n.filePath);
    idToPath[n.id] = n.filePath || '';
    idToType[n.id] = n.type || 'file';
  }

  // ---------- Fan-in / fan-out from importEdges ----------
  const fanIn = {};
  const fanOut = {};
  for (const e of importEdges) {
    fanOut[e.source] = (fanOut[e.source] || 0) + 1;
    fanIn[e.target] = (fanIn[e.target] || 0) + 1;
  }

  // ---------- Cross-category edges (using allEdges) ----------
  const crossKey = {};
  for (const e of allEdges) {
    const ft = idToType[e.source] || (e.source && e.source.split(':')[0]) || '?';
    const tt = idToType[e.target] || (e.target && e.target.split(':')[0]) || '?';
    if (ft === tt) continue; // same-type
    const k = ft + '|' + tt + '|' + (e.type || '?');
    crossKey[k] = (crossKey[k] || 0) + 1;
  }
  const crossCategoryEdges = Object.entries(crossKey).map(([k, count]) => {
    const [fromType, toType, edgeType] = k.split('|');
    return { fromType, toType, edgeType, count };
  }).sort((a, b) => b.count - a.count);

  // ---------- Inter-group import frequency ----------
  const interKey = {};
  for (const e of importEdges) {
    const fg = idToGroup[e.source];
    const tg = idToGroup[e.target];
    if (!fg || !tg || fg === tg) continue;
    const k = fg + '||' + tg;
    interKey[k] = (interKey[k] || 0) + 1;
  }
  const interGroupImports = Object.entries(interKey).map(([k, count]) => {
    const [from, to] = k.split('||');
    return { from, to, count };
  }).sort((a, b) => b.count - a.count);

  // ---------- Intra-group density ----------
  const intraGroupDensity = {};
  const groupEdgeTotal = {};
  const groupEdgeInternal = {};
  for (const e of importEdges) {
    const fg = idToGroup[e.source];
    const tg = idToGroup[e.target];
    if (fg) groupEdgeTotal[fg] = (groupEdgeTotal[fg] || 0) + 1;
    if (tg && tg !== fg) groupEdgeTotal[tg] = (groupEdgeTotal[tg] || 0) + 1;
    if (fg && fg === tg) groupEdgeInternal[fg] = (groupEdgeInternal[fg] || 0) + 1;
  }
  for (const g of Object.keys(directoryGroups)) {
    const total = groupEdgeTotal[g] || 0;
    const internal = groupEdgeInternal[g] || 0;
    intraGroupDensity[g] = {
      internalEdges: internal,
      totalEdges: total,
      density: total === 0 ? 0 : internal / total,
    };
  }

  // ---------- Pattern matching ----------
  const patterns = {
    'routes': 'api', 'api': 'api', 'controllers': 'api', 'endpoints': 'api', 'handlers': 'api',
    'services': 'service', 'core': 'service', 'lib': 'service', 'domain': 'service', 'logic': 'service',
    'models': 'data', 'db': 'data', 'data': 'data', 'persistence': 'data', 'repository': 'data', 'entities': 'data',
    'components': 'ui', 'views': 'ui', 'pages': 'ui', 'ui': 'ui', 'layouts': 'ui', 'screens': 'ui',
    'middleware': 'middleware', 'plugins': 'middleware', 'interceptors': 'middleware', 'guards': 'middleware',
    'utils': 'utility', 'helpers': 'utility', 'common': 'utility', 'shared': 'utility', 'tools': 'utility',
    'config': 'config', 'constants': 'config', 'env': 'config', 'settings': 'config',
    '__tests__': 'test', 'test': 'test', 'tests': 'test', 'spec': 'test', 'specs': 'test',
    'types': 'types', 'interfaces': 'types', 'schemas': 'types', 'contracts': 'types', 'dtos': 'types',
    'hooks': 'hooks',
    'store': 'state', 'state': 'state', 'reducers': 'state', 'actions': 'state', 'slices': 'state',
    'assets': 'assets', 'static': 'assets', 'public': 'assets',
    'migrations': 'data',
    'management': 'config', 'commands': 'config',
    'templatetags': 'utility',
    'signals': 'service',
    'serializers': 'api',
    'cmd': 'entry',
    'internal': 'service',
    'pkg': 'utility',
    'docs': 'documentation', 'documentation': 'documentation', 'wiki': 'documentation',
    'deploy': 'infrastructure', 'deployment': 'infrastructure', 'infra': 'infrastructure', 'infrastructure': 'infrastructure',
    '.github': 'ci-cd', '.gitlab': 'ci-cd', '.circleci': 'ci-cd',
    'k8s': 'infrastructure', 'kubernetes': 'infrastructure', 'helm': 'infrastructure', 'charts': 'infrastructure',
    'terraform': 'infrastructure', 'tf': 'infrastructure',
    'docker': 'infrastructure',
    'sql': 'data', 'database': 'data', 'schema': 'data',
    'scripts': 'config',
    'discovery': 'service',
    'exploitation': 'service',
    'postex': 'service',
    'data_extraction': 'data',
    'protocols': 'service',
    'automation': 'service',
  };
  const patternMatches = {};
  for (const g of Object.keys(directoryGroups)) {
    // strip parent prefix like "modules/" to look up sub-name
    const segs = g.split('/');
    const last = segs[segs.length - 1];
    let label = patterns[g] || patterns[last];
    if (!label) {
      if (g === '(root)') label = 'entry';
      else if (g === '.understand-anything') label = 'meta';
    }
    if (label) patternMatches[g] = label;
  }

  // ---------- Deployment topology ----------
  const allPaths = fileNodes.map(n => n.filePath || '');
  const hasDockerfile = allPaths.some(p => /(^|\/)Dockerfile($|\.)/.test(p));
  const hasCompose = allPaths.some(p => /docker-compose/.test(p));
  const hasK8s = allPaths.some(p => /(^|\/)(k8s|kubernetes|helm|charts)\//.test(p));
  const hasTerraform = allPaths.some(p => /\.(tf|tfvars)$/.test(p));
  const hasCI = allPaths.some(p => /(\.github\/workflows|\.gitlab-ci|Jenkinsfile|\.circleci)/.test(p));
  const infraFiles = allPaths.filter(p =>
    /Dockerfile/.test(p) || /docker-compose/.test(p) ||
    /(^|\/)(k8s|kubernetes|helm|terraform)\//.test(p) ||
    /\.(tf|tfvars)$/.test(p) ||
    /(\.github\/workflows|\.gitlab-ci|Jenkinsfile)/.test(p) ||
    /Makefile/.test(p)
  );
  const deploymentTopology = {
    hasDockerfile, hasCompose, hasK8s, hasTerraform, hasCI, infraFiles,
  };

  // ---------- Data pipeline detection ----------
  const schemaFiles = allPaths.filter(p => /\.(graphql|gql|proto|prisma)$/.test(p) || /(^|\/)schema(s)?\//.test(p));
  const migrationFiles = allPaths.filter(p => /(^|\/)migrations\//.test(p) || /\.sql$/.test(p));
  const dataModelFiles = allPaths.filter(p => /(^|\/)models\//.test(p) || /sapmap_models\.py$/.test(p));
  const apiHandlerFiles = allPaths.filter(p => /(^|\/)(routes|api|controllers|handlers)\//.test(p) || /sapmap_gui\.py$/.test(p));
  const dataPipeline = { schemaFiles, migrationFiles, dataModelFiles, apiHandlerFiles };

  // ---------- Documentation coverage ----------
  const docFiles = fileNodes.filter(n => (n.type === 'document') || /\.md$/.test(n.filePath || '') || /\.rst$/.test(n.filePath || ''));
  const groupsWithDocs = new Set();
  for (const d of docFiles) {
    const g = idToGroup[d.id];
    if (g) groupsWithDocs.add(g);
  }
  const totalGroups = Object.keys(directoryGroups).length;
  const undocumentedGroups = Object.keys(directoryGroups).filter(g => !groupsWithDocs.has(g));
  const docCoverage = {
    groupsWithDocs: groupsWithDocs.size,
    totalGroups,
    coverageRatio: totalGroups === 0 ? 0 : groupsWithDocs.size / totalGroups,
    undocumentedGroups,
  };

  // ---------- Dependency direction ----------
  const pairCounts = {};
  for (const e of importEdges) {
    const fg = idToGroup[e.source];
    const tg = idToGroup[e.target];
    if (!fg || !tg || fg === tg) continue;
    const key = fg + '||' + tg;
    pairCounts[key] = (pairCounts[key] || 0) + 1;
  }
  const dependencyDirection = [];
  const seen = new Set();
  for (const k of Object.keys(pairCounts)) {
    const [a, b] = k.split('||');
    if (seen.has(a + '|' + b) || seen.has(b + '|' + a)) continue;
    const ab = pairCounts[a + '||' + b] || 0;
    const ba = pairCounts[b + '||' + a] || 0;
    if (ab >= ba && ab > 0) {
      dependencyDirection.push({ dependent: a, dependsOn: b });
    } else if (ba > 0) {
      dependencyDirection.push({ dependent: b, dependsOn: a });
    }
    seen.add(a + '|' + b);
    seen.add(b + '|' + a);
  }

  // ---------- File stats ----------
  const filesPerGroup = {};
  for (const g of Object.keys(directoryGroups)) {
    filesPerGroup[g] = directoryGroups[g].length;
  }
  const nodeTypeCounts = {};
  for (const t of Object.keys(nodeTypeGroups)) {
    nodeTypeCounts[t] = nodeTypeGroups[t].length;
  }
  const fileStats = {
    totalFileNodes: fileNodes.length,
    filesPerGroup,
    nodeTypeCounts,
    commonPrefix: prefix,
  };

  const out = {
    scriptCompleted: true,
    directoryGroups,
    nodeTypeGroups,
    crossCategoryEdges,
    interGroupImports,
    intraGroupDensity,
    patternMatches,
    deploymentTopology,
    dataPipeline,
    docCoverage,
    dependencyDirection,
    fileStats,
    fileFanIn: fanIn,
    fileFanOut: fanOut,
  };

  fs.writeFileSync(outputPath, JSON.stringify(out, null, 2));
}

try {
  main();
} catch (err) {
  console.error(err && err.stack || String(err));
  process.exit(1);
}
