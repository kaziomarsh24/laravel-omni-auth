import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs';

function getTheme() {
  const current = document.documentElement.dataset.theme;
  return current === 'light' ? 'default' : 'dark';
}

// Lightbox state
let activeModal = null;
let currentZoom = 1;
let isPanning = false;
let startX = 0;
let startY = 0;
let translateX = 0;
let translateY = 0;

function createLightboxModal() {
  let modal = document.getElementById('mermaid-lightbox-modal');
  if (modal) return modal;

  modal = document.createElement('div');
  modal.id = 'mermaid-lightbox-modal';
  modal.style.cssText = `
    display: none;
    position: fixed;
    top: 0;
    left: 0;
    width: 100vw;
    height: 100vh;
    background: rgba(11, 12, 20, 0.92);
    backdrop-filter: blur(16px);
    -webkit-backdrop-filter: blur(16px);
    z-index: 999999;
    align-items: center;
    justify-content: center;
    overflow: hidden;
    user-select: none;
  `;

  // Toolbar
  const toolbar = document.createElement('div');
  toolbar.style.cssText = `
    position: absolute;
    top: 1.5rem;
    right: 1.5rem;
    display: flex;
    gap: 0.5rem;
    z-index: 1000000;
    background: rgba(255, 255, 255, 0.08);
    border: 1px solid rgba(255, 255, 255, 0.15);
    padding: 0.35rem 0.5rem;
    border-radius: 9999px;
    box-shadow: 0 10px 25px rgba(0, 0, 0, 0.4);
  `;

  function createBtn(title, svgIcon, onClick) {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.title = title;
    btn.innerHTML = svgIcon;
    btn.style.cssText = `
      background: transparent;
      border: none;
      color: #ffffff;
      padding: 0.4rem;
      border-radius: 9999px;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      transition: background 0.15s ease, transform 0.1s ease;
    `;
    btn.onmouseenter = () => (btn.style.background = 'rgba(255, 255, 255, 0.15)');
    btn.onmouseleave = () => (btn.style.background = 'transparent');
    btn.onclick = onClick;
    return btn;
  }

  // Zoom In
  toolbar.appendChild(
    createBtn('Zoom In', '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line><line x1="11" y1="8" x2="11" y2="14"></line><line x1="8" y1="11" x2="14" y2="11"></line></svg>', () => {
      currentZoom = Math.min(currentZoom + 0.25, 4);
      updateTransform();
    })
  );

  // Zoom Out
  toolbar.appendChild(
    createBtn('Zoom Out', '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line><line x1="8" y1="11" x2="14" y2="11"></line></svg>', () => {
      currentZoom = Math.max(currentZoom - 0.25, 0.5);
      updateTransform();
    })
  );

  // Reset
  toolbar.appendChild(
    createBtn('Reset View', '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"></path><path d="M3 3v5h5"></path></svg>', () => {
      currentZoom = 1;
      translateX = 0;
      translateY = 0;
      updateTransform();
    })
  );

  // Close
  toolbar.appendChild(
    createBtn('Close (Esc)', '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>', closeLightbox)
  );

  const contentContainer = document.createElement('div');
  contentContainer.id = 'mermaid-lightbox-content';
  contentContainer.style.cssText = `
    width: 90vw;
    height: 85vh;
    display: flex;
    align-items: center;
    justify-content: center;
    cursor: grab;
    transition: transform 0.05s ease-out;
  `;

  // Pan / Drag handling
  contentContainer.onmousedown = (e) => {
    isPanning = true;
    startX = e.clientX - translateX;
    startY = e.clientY - translateY;
    contentContainer.style.cursor = 'grabbing';
  };

  window.addEventListener('mousemove', (e) => {
    if (!isPanning) return;
    translateX = e.clientX - startX;
    translateY = e.clientY - startY;
    updateTransform();
  });

  window.addEventListener('mouseup', () => {
    isPanning = false;
    contentContainer.style.cursor = 'grab';
  });

  // Mouse Wheel Zoom
  modal.addEventListener('wheel', (e) => {
    e.preventDefault();
    const delta = e.deltaY * -0.0015;
    currentZoom = Math.min(Math.max(0.4, currentZoom + delta), 4.5);
    updateTransform();
  }, { passive: false });

  // Escape to close
  window.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeLightbox();
  });

  function updateTransform() {
    contentContainer.style.transform = `translate(${translateX}px, ${translateY}px) scale(${currentZoom})`;
  }

  modal.appendChild(toolbar);
  modal.appendChild(contentContainer);
  document.body.appendChild(modal);

  return modal;
}

function openLightbox(svgElement) {
  const modal = createLightboxModal();
  const content = modal.querySelector('#mermaid-lightbox-content');
  content.innerHTML = svgElement.outerHTML;
  
  const innerSvg = content.querySelector('svg');
  if (innerSvg) {
    innerSvg.style.maxWidth = '85vw';
    innerSvg.style.maxHeight = '80vh';
    innerSvg.style.width = 'auto';
    innerSvg.style.height = 'auto';
  }

  currentZoom = 1;
  translateX = 0;
  translateY = 0;
  content.style.transform = `translate(0px, 0px) scale(1)`;

  modal.style.display = 'flex';
  activeModal = modal;
}

function closeLightbox() {
  const modal = document.getElementById('mermaid-lightbox-modal');
  if (modal) modal.style.display = 'none';
  activeModal = null;
}

async function renderMermaidDiagrams() {
  const codeBlocks = document.querySelectorAll('pre[data-language="mermaid"]');
  if (codeBlocks.length === 0) return;

  const isLight = document.documentElement.dataset.theme === 'light';

  mermaid.initialize({
    startOnLoad: false,
    theme: getTheme(),
    fontFamily: 'Inter, system-ui, -apple-system, sans-serif',
    themeVariables: {
      primaryColor: '#f43f5e',
      primaryTextColor: '#ffffff',
      primaryBorderColor: '#fb7185',
      lineColor: '#f43f5e',
      actorBkg: isLight ? '#ffffff' : '#181a28',
      actorBorder: '#f43f5e',
      actorTextColor: isLight ? '#0f172a' : '#f8fafc',
      actorLineColor: isLight ? '#94a3b8' : '#475569',
      signalColor: isLight ? '#334155' : '#cbd5e1',
      signalTextColor: isLight ? '#0f172a' : '#f8fafc',
      labelBoxBkgColor: isLight ? '#f1f5f9' : '#181b2a',
      labelBoxBorderColor: '#6366f1',
      labelTextColor: isLight ? '#0f172a' : '#ffffff',
      loopTextColor: isLight ? '#0f172a' : '#ffffff',
      noteBkgColor: isLight ? '#eff6ff' : '#1c2237',
      noteBorderColor: '#3b82f6',
      noteTextColor: isLight ? '#1e3a8a' : '#93c5fd',
    },
    sequence: {
      actorFontSize: 13,
      noteFontSize: 12,
      messageFontSize: 12,
      mirrorActors: false,
      useMaxWidth: true,
      boxMargin: 10,
    },
  });

  for (let i = 0; i < codeBlocks.length; i++) {
    const pre = codeBlocks[i];
    const container = pre.closest('.expressive-code') || pre.closest('figure') || pre;

    if (!container.dataset.rawMermaid) {
      const code = pre.querySelector('code');
      const rawText = (code ? code.innerText : pre.innerText).trim();
      container.dataset.rawMermaid = rawText;
    }

    const rawDefinition = container.dataset.rawMermaid;
    const diagramId = `mermaid-dia-${Date.now()}-${i}`;

    try {
      const { svg } = await mermaid.render(diagramId, rawDefinition);

      let wrapper = container.nextElementSibling;
      if (!wrapper || !wrapper.classList.contains('mermaid-rendered-wrapper')) {
        wrapper = document.createElement('div');
        wrapper.className = 'mermaid-rendered-wrapper';
        wrapper.style.position = 'relative';
        wrapper.style.display = 'flex';
        wrapper.style.justifyContent = 'center';
        wrapper.style.margin = '2rem 0';
        wrapper.style.padding = '2rem 1.75rem';
        wrapper.style.background = isLight ? '#ffffff' : 'rgba(15, 17, 27, 0.75)';
        wrapper.style.border = isLight ? '1px solid #e2e8f0' : '1px solid rgba(255, 255, 255, 0.08)';
        wrapper.style.borderRadius = '16px';
        wrapper.style.boxShadow = isLight ? '0 4px 20px rgba(0,0,0,0.05)' : '0 10px 30px -10px rgba(0, 0, 0, 0.5)';
        wrapper.style.overflowX = 'auto';
        wrapper.style.cursor = 'zoom-in';

        // Zoom Badge
        const zoomBadge = document.createElement('div');
        zoomBadge.className = 'mermaid-zoom-badge';
        zoomBadge.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align: middle; margin-right: 4px;"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line><line x1="11" y1="8" x2="11" y2="14"></line><line x1="8" y1="11" x2="14" y2="11"></line></svg> Click to Zoom / Fullscreen';
        zoomBadge.style.cssText = `
          position: absolute;
          top: 0.75rem;
          right: 0.75rem;
          font-family: var(--sl-font);
          font-size: 0.75rem;
          font-weight: 600;
          padding: 0.25rem 0.65rem;
          border-radius: 9999px;
          background: ${isLight ? 'rgba(0,0,0,0.06)' : 'rgba(255,255,255,0.08)'};
          color: ${isLight ? '#475569' : '#94a3b8'};
          border: 1px solid ${isLight ? '#e2e8f0' : 'rgba(255,255,255,0.12)'};
          pointer-events: none;
          transition: all 0.2s ease;
        `;
        wrapper.appendChild(zoomBadge);

        container.style.display = 'none';
        container.parentNode.insertBefore(wrapper, container.nextSibling);
      } else {
        wrapper.style.background = isLight ? '#ffffff' : 'rgba(15, 17, 27, 0.75)';
        wrapper.style.border = isLight ? '1px solid #e2e8f0' : '1px solid rgba(255, 255, 255, 0.08)';
      }

      // Preserve badge
      let badge = wrapper.querySelector('.mermaid-zoom-badge');
      wrapper.innerHTML = svg;
      if (!badge) {
        badge = document.createElement('div');
        badge.className = 'mermaid-zoom-badge';
        badge.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align: middle; margin-right: 4px;"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line><line x1="11" y1="8" x2="11" y2="14"></line><line x1="8" y1="11" x2="14" y2="11"></line></svg> Click to Zoom / Fullscreen';
        badge.style.cssText = `
          position: absolute;
          top: 0.75rem;
          right: 0.75rem;
          font-family: var(--sl-font);
          font-size: 0.75rem;
          font-weight: 600;
          padding: 0.25rem 0.65rem;
          border-radius: 9999px;
          background: ${isLight ? 'rgba(0,0,0,0.06)' : 'rgba(255,255,255,0.08)'};
          color: ${isLight ? '#475569' : '#94a3b8'};
          border: 1px solid ${isLight ? '#e2e8f0' : 'rgba(255,255,255,0.12)'};
          pointer-events: none;
        `;
      }
      wrapper.appendChild(badge);

      const svgEl = wrapper.querySelector('svg');
      if (svgEl) {
        svgEl.style.maxWidth = '100%';
        svgEl.style.height = 'auto';
        wrapper.onclick = () => openLightbox(svgEl);
      }
    } catch (err) {
      console.error('Mermaid render error:', err);
    }
  }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', renderMermaidDiagrams);
} else {
  renderMermaidDiagrams();
}

document.addEventListener('astro:page-load', renderMermaidDiagrams);

const observer = new MutationObserver((mutations) => {
  for (const m of mutations) {
    if (m.type === 'attributes' && m.attributeName === 'data-theme') {
      renderMermaidDiagrams();
    }
  }
});
observer.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
