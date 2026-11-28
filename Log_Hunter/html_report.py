"""Self-contained HTML dashboard report (standard library only).

Builds a single offline HTML file: KPI tiles, severity breakdown, ranked bar
charts and a sortable/filterable findings table. All values are escaped.
"""

from __future__ import annotations

import html
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

SEVERITIES = ("critical", "high", "medium", "low", "info")


@dataclass
class Report:
    tool: str
    title: str
    subtitle: str = ""
    meta: dict[str, Any] = field(default_factory=dict)
    kpis: list[tuple[str, Any, str]] = field(default_factory=list)  # (label, value, tone)
    charts: list[tuple[str, list[tuple[str, int]]]] = field(default_factory=list)
    columns: list[str] = field(default_factory=list)
    rows: list[dict[str, Any]] = field(default_factory=list)  # needs "severity" + column keys
    empty_message: str = "No findings."
    extras: list[tuple[str, str]] = field(default_factory=list)  # (title, preformatted text)

    def severity_counts(self) -> dict[str, int]:
        counts = dict.fromkeys(SEVERITIES, 0)
        for row in self.rows:
            sev = str(row.get("severity", "info")).lower()
            counts[sev if sev in counts else "info"] += 1
        return counts


def _e(value: Any) -> str:
    if isinstance(value, (list, tuple)):
        value = ", ".join(str(v) for v in value)
    return html.escape("" if value is None else str(value))


def render(report: Report) -> str:
    counts = report.severity_counts()
    kpis = "".join(
        f'<div class="kpi {tone}"><b>{_e(value)}</b><span>{_e(label)}</span></div>'
        for label, value, tone in report.kpis
    )
    sevbar = "".join(
        f'<i class="s-{s}" style="flex:{counts[s]}" title="{s}: {counts[s]}"></i>'
        for s in SEVERITIES
        if counts[s]
    )
    legend = "".join(
        f'<span><i class="dot s-{s}"></i>{s} <b>{counts[s]}</b></span>' for s in SEVERITIES
    )
    charts = ""
    for title, items in report.charts:
        if not items:
            continue
        peak = max(v for _, v in items) or 1
        bars = "".join(
            f'<div class="bar"><span class="lbl" title="{_e(k)}">{_e(k)}</span>'
            f'<span class="track"><span class="fill" style="width:{v / peak * 100:.1f}%"></span></span>'
            f'<span class="val">{v}</span></div>'
            for k, v in items
        )
        charts += f'<section class="card"><h3>{_e(title)}</h3>{bars}</section>'

    extras = "".join(f'<section class="card"><h3>{_e(t)}</h3><pre class="pre">{_e(body)}</pre></section>' for t, body in report.extras)
    head = "".join(f"<th>{_e(c)}</th>" for c in ["Severity", *report.columns])
    body = ""
    for row in report.rows:
        sev = str(row.get("severity", "info")).lower()
        cells = "".join(f"<td>{_e(row.get(c, ''))}</td>" for c in report.columns)
        body += f'<tr data-sev="{_e(sev)}"><td><span class="sev s-{_e(sev)}">{_e(sev)}</span></td>{cells}</tr>'
    if not report.rows:
        body = f'<tr><td colspan="{len(report.columns) + 1}" class="empty">{_e(report.empty_message)}</td></tr>'
    meta = " · ".join(f"<span>{_e(k)}: <b>{_e(v)}</b></span>" for k, v in report.meta.items())
    filters = "".join(
        f'<button data-f="{s}">{s} ({counts[s]})</button>' for s in SEVERITIES if counts[s]
    )
    return TEMPLATE.format(
        title=_e(report.title),
        tool=_e(report.tool),
        subtitle=_e(report.subtitle),
        generated=datetime.now().strftime("%Y-%m-%d %H:%M"),
        meta=meta,
        kpis=kpis,
        sevbar=sevbar or '<i class="s-none" style="flex:1"></i>',
        legend=legend,
        charts=charts,
        extras=extras,
        filters=filters,
        head=head,
        body=body,
        total=sum(counts.values()),
    )


def write(report: Report, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render(report))


TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} — {tool}</title>
<style>
:root{{--bg:#0a0d14;--card:#111622;--line:#1f2737;--text:#dbe3f1;--dim:#7c879b;--acc:#36f1cd;
--critical:#ff4d6d;--high:#ff8a3d;--medium:#ffcc4d;--low:#3ddc84;--info:#5aa9ff}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);
font:14px/1.5 Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}}
header{{padding:28px 40px 22px;border-bottom:1px solid var(--line);
background:radial-gradient(800px 300px at 10% -40%,rgba(54,241,205,.16),transparent),var(--bg)}}
.brand{{font:600 13px ui-monospace,Menlo,monospace;color:var(--acc);letter-spacing:.08em;text-transform:uppercase}}
h1{{margin:6px 0 4px;font-size:26px}}.sub{{color:var(--dim)}}
.meta{{margin-top:10px;color:var(--dim);font-size:13px;display:flex;gap:6px;flex-wrap:wrap}}
.meta b{{color:var(--text);font-weight:600}}
main{{padding:24px 40px 48px;display:grid;gap:16px}}
.kpis{{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px}}
.kpi{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px 18px}}
.kpi b{{display:block;font:700 28px ui-monospace,Menlo,monospace}}
.kpi span{{color:var(--dim);font-size:12px;text-transform:uppercase;letter-spacing:.06em}}
.kpi.bad b{{color:var(--critical)}}.kpi.warn b{{color:var(--high)}}
.kpi.good b{{color:var(--low)}}.kpi.acc b{{color:var(--acc)}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px 20px}}
.card h3{{margin:0 0 12px;font-size:14px;color:var(--dim);text-transform:uppercase;letter-spacing:.06em}}
.sevbar{{display:flex;height:12px;border-radius:99px;overflow:hidden;background:var(--line)}}
.legend{{display:flex;gap:18px;margin-top:10px;color:var(--dim);font-size:13px;text-transform:capitalize}}
.legend b{{color:var(--text)}}.dot{{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:6px}}
.s-critical{{background:var(--critical)}}.s-high{{background:var(--high)}}.s-medium{{background:var(--medium)}}
.s-low{{background:var(--low)}}.s-info{{background:var(--info)}}.s-none{{background:var(--line)}}
.charts{{display:grid;grid-template-columns:repeat(auto-fit,minmax(340px,1fr));gap:16px}}
.bar{{display:grid;grid-template-columns:minmax(90px,38%) 1fr 44px;gap:10px;align-items:center;margin:7px 0}}
.lbl{{font:12.5px ui-monospace,Menlo,monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.track{{height:10px;background:#0b0f18;border-radius:99px;overflow:hidden}}
.fill{{display:block;height:100%;border-radius:99px;background:linear-gradient(90deg,var(--acc),#7c5cff)}}
.val{{text-align:right;font:12.5px ui-monospace,Menlo,monospace;color:var(--dim)}}
.toolbar{{display:flex;gap:8px;align-items:center;margin-bottom:12px;flex-wrap:wrap}}
.toolbar input{{flex:1;min-width:200px;background:#0b0f18;border:1px solid var(--line);border-radius:8px;
color:var(--text);padding:8px 12px;font:13px ui-monospace,Menlo,monospace}}
.toolbar button{{background:#0b0f18;border:1px solid var(--line);color:var(--dim);border-radius:99px;
padding:5px 12px;font:12px ui-monospace,Menlo,monospace;cursor:pointer;text-transform:capitalize}}
.toolbar button.on{{border-color:var(--acc);color:var(--acc)}}
table{{width:100%;border-collapse:collapse}}th{{text-align:left;color:var(--dim);font-size:12px;
text-transform:uppercase;letter-spacing:.05em;padding:8px 10px;border-bottom:1px solid var(--line);cursor:pointer}}
td{{padding:10px;border-bottom:1px solid var(--line);vertical-align:top;word-break:break-word}}
td:not(:last-child){{white-space:nowrap}}
td:not(:first-child){{font-family:ui-monospace,Menlo,monospace;font-size:12.5px}}
tr:hover td{{background:#141a28}}
.sev{{display:inline-block;min-width:74px;text-align:center;padding:2px 8px;border-radius:6px;
font:700 11px ui-monospace,Menlo,monospace;text-transform:uppercase;color:#0a0d14}}
.empty{{text-align:center;color:var(--dim);padding:28px}}
.pre{{margin:0;font:12.5px/1.6 ui-monospace,Menlo,monospace;color:var(--text);white-space:pre;overflow-x:auto}}
footer{{color:var(--dim);font-size:12px;text-align:center;padding:0 0 28px}}
</style></head><body>
<header><div class="brand">{tool}</div><h1>{title}</h1><div class="sub">{subtitle}</div>
<div class="meta"><span>generated <b>{generated}</b></span> · {meta}</div></header>
<main>
<div class="kpis">{kpis}</div>
<section class="card"><h3>Severity breakdown · {total} findings</h3>
<div class="sevbar">{sevbar}</div><div class="legend">{legend}</div></section>
<div class="charts">{charts}</div>
{extras}
<section class="card"><h3>Findings</h3>
<div class="toolbar"><input id="q" placeholder="Filter findings…" aria-label="Filter">{filters}</div>
<table id="t"><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></section>
</main>
<footer>Generated by {tool} · self-contained report, no external resources</footer>
<script>
(function(){{
  var q=document.getElementById('q'),rows=[].slice.call(document.querySelectorAll('#t tbody tr[data-sev]')),
      active=null,btns=[].slice.call(document.querySelectorAll('.toolbar button'));
  function apply(){{var t=q.value.toLowerCase();rows.forEach(function(r){{
    var ok=(!active||r.dataset.sev===active)&&r.textContent.toLowerCase().indexOf(t)>-1;
    r.style.display=ok?'':'none';}});}}
  q.addEventListener('input',apply);
  btns.forEach(function(b){{b.addEventListener('click',function(){{
    active=active===b.dataset.f?null:b.dataset.f;
    btns.forEach(function(x){{x.classList.toggle('on',x.dataset.f===active);}});apply();}});}});
  var order={{critical:0,high:1,medium:2,low:3,info:4}};
  [].slice.call(document.querySelectorAll('#t th')).forEach(function(th,i){{
    var asc=true;th.addEventListener('click',function(){{
      var tb=document.querySelector('#t tbody');rows.sort(function(a,b){{
        var x=a.cells[i].textContent,y=b.cells[i].textContent;
        if(i===0){{x=order[x];y=order[y];}}
        return (x>y?1:x<y?-1:0)*(asc?1:-1);}});
      rows.forEach(function(r){{tb.appendChild(r);}});asc=!asc;}});}});
}})();
</script></body></html>
"""
