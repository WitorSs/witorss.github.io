---
title: Tools
layout: page
icon: fas fa-toolbox
order: 3
---

Security tools I've built: small, focused, and written to be used. Each one
comes with a full write-up explaining the decisions behind it. The source lives
in the [tools directory](https://github.com/WitorSs/witorss.github.io/tree/main/tools)
of this site's repository.

<style>
  .tool-list { display: flex; flex-direction: column; gap: 1.2rem; margin-top: 1.5rem; }
  .tool-card {
    display: flex; align-items: center; gap: 1.2rem;
    border: 1px solid var(--card-border-color, #30363d);
    background: var(--card-bg, #22272e);
    border-radius: 12px; padding: 1.2rem 1.4rem;
    text-decoration: none; color: inherit;
    transition: transform .15s ease, box-shadow .15s ease;
  }
  .tool-card:hover { transform: translateY(-2px); box-shadow: 0 6px 18px rgba(0,0,0,.25); }
  .tool-icon {
    flex-shrink: 0; width: 54px; height: 54px; border-radius: 12px;
    display: flex; align-items: center; justify-content: center;
    background: linear-gradient(135deg, #1f6feb, #388bfd); color: #fff; font-size: 1.5rem;
  }
  .tool-body h3 { margin: 0 0 .3rem; font-size: 1.15rem; }
  .tool-body p { margin: 0; color: var(--text-muted-color, #8b949e); font-size: .93rem; line-height: 1.45; }
  .tool-tags { margin-top: .5rem; display: flex; gap: .4rem; flex-wrap: wrap; }
  .tool-tags span {
    font-size: .72rem; padding: .12rem .55rem; border-radius: 20px;
    background: var(--tag-bg, #2d333b); color: var(--text-muted-color, #8b949e);
  }
</style>

<div class="tool-list">

  <a class="tool-card" href="/posts/scan2report/">
    <div class="tool-icon"><i class="fas fa-file-code"></i></div>
    <div class="tool-body">
      <h3>scan2report</h3>
      <p>Turns messy Nmap XML output into a clean, prioritized report in Markdown and HTML, reordering open ports by how interesting they are and explaining where to look first.</p>
      <div class="tool-tags"><span>Python</span><span>Nmap</span><span>Automation</span><span>Reporting</span></div>
    </div>
  </a>


  <a class="tool-card" href="/posts/logsentry/">
    <div class="tool-icon"><i class="fas fa-shield-halved"></i></div>
    <div class="tool-body">
      <h3>logsentry</h3>
      <p>Reads an SSH auth log and surfaces the attacks buried in it: brute-force sources and, most important, any brute force that ended in a successful login. Markdown and HTML output.</p>
      <div class="tool-tags"><span>Python</span><span>Blue Team</span><span>Log Analysis</span><span>Detection</span></div>
    </div>
  </a>

</div>
