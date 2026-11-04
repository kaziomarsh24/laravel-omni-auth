import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs';

function getTheme() {
  const current = document.documentElement.dataset.theme;
  return current === 'light' ? 'default' : 'dark';
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
        wrapper.style.display = 'flex';
        wrapper.style.justifyContent = 'center';
        wrapper.style.margin = '2rem 0';
        wrapper.style.padding = '1.75rem';
        wrapper.style.background = isLight ? '#ffffff' : 'rgba(15, 17, 27, 0.75)';
        wrapper.style.border = isLight ? '1px solid #e2e8f0' : '1px solid rgba(255, 255, 255, 0.08)';
        wrapper.style.borderRadius = '16px';
        wrapper.style.boxShadow = isLight ? '0 4px 20px rgba(0,0,0,0.05)' : '0 10px 30px -10px rgba(0, 0, 0, 0.5)';
        wrapper.style.overflowX = 'auto';
        container.style.display = 'none';
        container.parentNode.insertBefore(wrapper, container.nextSibling);
      } else {
        wrapper.style.background = isLight ? '#ffffff' : 'rgba(15, 17, 27, 0.75)';
        wrapper.style.border = isLight ? '1px solid #e2e8f0' : '1px solid rgba(255, 255, 255, 0.08)';
      }
      wrapper.innerHTML = svg;
      const svgEl = wrapper.querySelector('svg');
      if (svgEl) {
        svgEl.style.maxWidth = '100%';
        svgEl.style.height = 'auto';
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
