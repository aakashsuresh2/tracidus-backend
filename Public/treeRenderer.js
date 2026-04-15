/* treeRenderer.js — TRACIDUS Manifestation Tree
   Model-line aligned renderer (text + balls + path spine)
   Uses SVG only. No cards. No compression chaos.
*/

(function () {

  const MOUNT_CLASS = 'manifest-mount';
  const SVG_ID = 'tracidus-tree-svg';

  const XSTEP = 220;
  const YSTEP = 48;
  const BALL_R = 6;

  const LINK_Y_OFFSET = 10; // ✅ underline fix

  const COLOR_LINE = 'rgba(255,255,255,0.10)';
  const COLOR_ACTIVE = '#00f6ff';
  const COLOR_TEXT = '#e6eef8';
  const COLOR_MUTED = 'rgba(200,220,240,0.55)';

  let expanded = new Set();
  let selectedPath = [];

  const NS = 'http://www.w3.org/2000/svg';

  function $(q){ return document.querySelector(q); }

  function createSVG(){
    const mount = $('.' + MOUNT_CLASS);
    if(!mount) return null;
    mount.innerHTML = '';
    const svg = document.createElementNS(NS,'svg');
    svg.id = SVG_ID;
    svg.style.width = '100%';
    svg.style.height = '100%';
    mount.appendChild(svg);
    return svg;
  }

  function findPathTo(id, root){
    const path = [];
    let found = false;

    (function dfs(n){
      if(found) return;
      path.push(n.id);
      if(n.id === id){ found = true; return; }
      if(n.children){
        const order = (n.options || []).map(o=>o.id).filter(Boolean);
        const keys = order.length ? order : Object.keys(n.children);
        for(const k of keys){
          dfs(n.children[k]);
          if(found) return;
        }
      }
      path.pop();
    })(root);

    return found ? path : [];
  }

  function computeVisible(root){
    const out = [];
    let idx = 0;

    (function dfs(n, depth, parent){
      out.push({ node:n, id:n.id, depth, parent, index:idx++ });
      if(n.children && expanded.has(n.id)){
        const order = (n.options || []).map(o=>o.id).filter(Boolean);
        const keys = order.length ? order : Object.keys(n.children);
        for(const k of keys){
          dfs(n.children[k], depth+1, n.id);
        }
      }
    })(root,0,null);

    return out;
  }

  function render(root){
    const svg = createSVG();
    if(!svg) return;

    const nodes = computeVisible(root);
    if(!nodes.length) return;

    const maxDepth = Math.max(...nodes.map(n=>n.depth));
    const width = Math.max(1000, (maxDepth+2)*XSTEP);
    const height = Math.max(600, (nodes.length+2)*YSTEP);
    svg.setAttribute('viewBox', `0 0 ${width} ${height}`);

    const pos = {};
    nodes.forEach(n=>{
      pos[n.id] = {
        x: 40 + n.depth*XSTEP,
        y: 40 + n.index*YSTEP
      };
    });

    /* ---------- LINKS ---------- */
    const linkLayer = document.createElementNS(NS,'g');
    svg.appendChild(linkLayer);

    nodes.forEach(n=>{
      if(!n.node.children || !expanded.has(n.id)) return;
      const order = (n.node.options || []).map(o=>o.id).filter(Boolean);
      const keys = order.length ? order : Object.keys(n.node.children);
      for(const cid of keys){
        if(!pos[cid]) continue;

        const p = pos[n.id];
        const c = pos[cid];

        const startX = p.x + 24;
        const startY = p.y + LINK_Y_OFFSET; // ✅ moved down
        const endX = c.x - 12;
        const endY = c.y + LINK_Y_OFFSET;   // ✅ moved down
        const midX = Math.max(p.x + 80, (startX+endX)/2);

        const d = `M ${startX} ${startY} L ${midX} ${startY} L ${midX} ${endY} L ${endX} ${endY}`;
        const path = document.createElementNS(NS,'path');
        path.setAttribute('d', d);
        path.setAttribute('fill','none');

        let active = false;
        for(let i=0;i<selectedPath.length-1;i++){
          if(selectedPath[i]===n.id && selectedPath[i+1]===cid){
            active = true; break;
          }
        }

        path.setAttribute('stroke', active ? COLOR_ACTIVE : COLOR_LINE);
        path.setAttribute('stroke-width', active ? 3.2 : 1.4);
        linkLayer.appendChild(path);
      }
    });

    /* ---------- NODES ---------- */
    const nodeLayer = document.createElementNS(NS,'g');
    svg.appendChild(nodeLayer);

    nodes.forEach(n=>{
      const p = pos[n.id];
      const g = document.createElementNS(NS,'g');
      g.setAttribute('transform', `translate(${p.x},${p.y})`);
      g.style.cursor = 'pointer';

      const onPath = selectedPath.includes(n.id);

      const ball = document.createElementNS(NS,'circle');
      ball.setAttribute('cx', -14);
      ball.setAttribute('cy', 0);
      ball.setAttribute('r', BALL_R);
      ball.setAttribute('fill', '#000');
      ball.setAttribute('stroke', onPath ? COLOR_ACTIVE : 'rgba(255,255,255,0.2)');
      ball.setAttribute('stroke-width', onPath ? 3 : 1);
      g.appendChild(ball);

      const label = document.createElementNS(NS,'text');
      label.setAttribute('x', n.id === root.id ? 8 : 0);
      label.setAttribute('y', 0);
      label.setAttribute('fill', onPath ? COLOR_ACTIVE : COLOR_TEXT);
      label.setAttribute('font-size','14');
      label.setAttribute('dominant-baseline','middle');
      label.textContent = n.node.label || n.node.title || n.node.outcomeTitle || n.id;
      g.appendChild(label);

      if(n.node.children){
        const mark = document.createElementNS(NS,'text');
        mark.setAttribute('x', label.textContent.length*7 + 12);
        mark.setAttribute('y', 2);
        mark.setAttribute('fill', COLOR_MUTED);
        mark.setAttribute('font-size','12');
        mark.textContent = expanded.has(n.id) ? '−' : '+';
        g.appendChild(mark);
      }

      g.addEventListener('click', ev=>{
        ev.stopPropagation();
        const path = findPathTo(n.id, root);
        if(!path.length) return;

        selectedPath = path.slice();
        expanded.add(n.id);
        path.forEach(id=>expanded.add(id));

        render(root);
        if(window.__tracidusShowSide) window.__tracidusShowSide(n.node);
      });

      nodeLayer.appendChild(g);
    });

    const rootEl = nodeLayer.firstChild;
    if(rootEl) nodeLayer.appendChild(rootEl);
  }

  window.renderManifestationScene = function(){
    const root = window.__manifestationScenario;
    if(!root) return;
    expanded = new Set([root.id]);
    selectedPath = [];
    render(root);
  };

})();
