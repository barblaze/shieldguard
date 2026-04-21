let acorn = null;

async function getAcorn() {
  if (!acorn) {
    acorn = await import('acorn').then(m => m?.default || m);
  }
  return acorn;
}

export async function parseJavaScript(code, filename) {
  try {
    const acorn = await getAcorn();
    return acorn.parse(code, {
      ecmaVersion: 2022,
      sourceType: 'module',
      locations: true,
      tokens: true,
      comment: true,
      allowImportExportEverywhere: true,
      allowAwaitOutsideFunction: true,
      allowReturnOutsideFunction: true,
    });
  } catch (e) {
    return { error: e.message, line: e.loc?.line };
  }
}

export function findNodes(ast, type) {
  const results = [];
  function walk(node) {
    if (!node || typeof node !== 'object') return;
    if (node.type === type) results.push(node);
    for (const key in node) {
      if (key === 'loc' || key === 'range') continue;
      if (Array.isArray(node[key])) {
        node[key].forEach(walk);
      } else if (node[key] && typeof node[key] === 'object') {
        walk(node[key]);
      }
    }
  }
  walk(ast);
  return results;
}

export function getNodeText(ast, node) {
  if (!node) return '';
  const { start, end } = node.loc || {};
  if (!ast.code || !start || !end) return '';
  return ast.code.slice(start.column, end.column);
}

export function getCallees(node) {
  if (!node) return [];
  if (node.type === 'CallExpression') {
    if (node.callee.type === 'Identifier') return [node.callee.name];
    if (node.callee.type === 'MemberExpression' && node.callee.object) {
      return [node.callee.property.name || node.callee.property.value];
    }
  }
  return [];
}

export function getMemberObject(node) {
  if (node?.type === 'MemberExpression') {
    if (node.object?.type === 'Identifier') return node.object.name;
    if (node.object?.type === 'MemberExpression') return getMemberObject(node.object);
  }
  return null;
}