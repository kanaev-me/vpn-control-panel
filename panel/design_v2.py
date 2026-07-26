#!/usr/bin/env python3
"""Visual design layer for authenticated VPN pages.

The stylesheet is intentionally dependency-free and appended after the legacy
CSS. It changes presentation only: no route, form, table or data logic lives
here.
"""

from __future__ import annotations


def design_v2_css() -> str:
    return r"""

/* vpn-design-v2 */
:root {
  --bg: #060b14;
  --bg2: #0a1220;
  --card: #101827;
  --card2: #152033;
  --line: rgba(170, 194, 230, .13);
  --line-strong: rgba(170, 194, 230, .22);
  --text: #f4f7ff;
  --muted: #91a0b7;
  --ok: #4cdda0;
  --warn: #ffc36d;
  --bad: #ff7188;
  --blue: #77b7ff;
  --violet: #9b8cff;
  --surface: rgba(15, 24, 40, .84);
  --surface-soft: rgba(255, 255, 255, .038);
  --shadow-card: 0 24px 70px rgba(0, 0, 0, .24), inset 0 1px 0 rgba(255, 255, 255, .035);
  --shadow-soft: 0 12px 36px rgba(0, 0, 0, .17);
}

html {
  min-width: 320px;
  background: var(--bg);
}

body {
  min-height: 100vh;
  margin: 0;
  color: var(--text);
  background:
    radial-gradient(circle at 12% -10%, rgba(78, 139, 230, .20), transparent 34%),
    radial-gradient(circle at 88% 0%, rgba(117, 91, 230, .12), transparent 31%),
    linear-gradient(180deg, #08111f 0%, #060b14 48%, #050911 100%);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, sans-serif;
  -webkit-font-smoothing: antialiased;
  text-rendering: optimizeLegibility;
}

body::before {
  content: "";
  position: fixed;
  inset: 0;
  pointer-events: none;
  opacity: .22;
  background-image:
    linear-gradient(rgba(255,255,255,.018) 1px, transparent 1px),
    linear-gradient(90deg, rgba(255,255,255,.018) 1px, transparent 1px);
  background-size: 42px 42px;
  mask-image: linear-gradient(to bottom, #000, transparent 58%);
}

.wrap,
main {
  position: relative;
  width: min(100%, 1340px);
  margin: 0 auto;
}

.wrap {
  padding: 28px 24px 56px;
}

.shell-head {
  margin-bottom: 22px;
}

.shell-topline {
  min-height: 38px;
  margin-bottom: 14px;
}

.shell-kicker {
  display: inline-flex;
  align-items: center;
  gap: 9px;
  margin: 0;
  color: #a8cfff;
  font-size: 12px;
  letter-spacing: .14em;
}

.shell-kicker::before {
  content: "";
  width: 9px;
  height: 9px;
  border-radius: 999px;
  background: linear-gradient(135deg, var(--blue), var(--ok));
  box-shadow: 0 0 0 5px rgba(101, 168, 255, .10), 0 0 22px rgba(101, 168, 255, .42);
}

.shell-user-name,
.shell-logout-button {
  min-height: 34px;
  border-color: rgba(255,255,255,.09);
  background: rgba(8, 15, 27, .60);
  box-shadow: inset 0 1px 0 rgba(255,255,255,.035);
}

.shell-user-name {
  color: #aebbd0;
}

.shell-logout-button {
  transition: border-color .16s ease, background .16s ease, color .16s ease;
}

.shell-nav {
  gap: 5px;
  padding: 5px;
  margin-bottom: 22px;
  border-color: rgba(167, 195, 235, .13);
  background: rgba(5, 10, 19, .60);
  box-shadow: 0 12px 40px rgba(0,0,0,.16), inset 0 1px 0 rgba(255,255,255,.04);
}

.shell-link {
  min-height: 36px;
  padding: 0 15px;
  color: #95a5bc;
  transition: color .16s ease, background .16s ease, box-shadow .16s ease, transform .16s ease;
}

.shell-link.active {
  color: #fff;
  background: linear-gradient(135deg, rgba(91, 160, 255, .29), rgba(126, 104, 255, .19));
  box-shadow: 0 0 0 1px rgba(115, 176, 255, .32), 0 8px 24px rgba(57, 113, 205, .16);
}

.shell-title {
  max-width: 920px;
}

.shell-title h1,
h1 {
  color: #f8faff;
  font-weight: 850;
  letter-spacing: -.052em;
  text-wrap: balance;
}

.shell-title h1 {
  font-size: clamp(36px, 5vw, 54px);
  line-height: .96;
}

.shell-subtitle {
  max-width: 760px;
  color: #96a5bb;
  line-height: 1.4;
}

.card {
  position: relative;
  margin: 14px 0;
  padding: 20px;
  overflow: clip;
  border: 1px solid var(--line);
  border-radius: 24px;
  background:
    linear-gradient(180deg, rgba(255,255,255,.052), rgba(255,255,255,.018)),
    var(--surface);
  box-shadow: var(--shadow-card);
}

.card::before {
  content: "";
  position: absolute;
  inset: 0 0 auto;
  height: 1px;
  pointer-events: none;
  background: linear-gradient(90deg, transparent, rgba(174, 211, 255, .30), transparent);
  opacity: .60;
}

.card > :first-child {
  position: relative;
}

.card h2 {
  margin-top: 0;
  color: #f4f7ff;
  font-size: clamp(23px, 3vw, 30px);
  line-height: 1.05;
  letter-spacing: -.035em;
  text-wrap: balance;
}

.card h3 {
  color: #eef4ff;
  letter-spacing: -.02em;
}

.muted,
.cellhint,
.person-sub,
.access-meta,
.match-note-v1,
.net-loc-v1 {
  color: var(--muted);
}

.grid {
  gap: 14px;
}

.section-head {
  gap: 16px;
  margin-bottom: 18px;
}

.section-head h2 {
  letter-spacing: -.035em;
}

a {
  text-underline-offset: 3px;
}

a:focus-visible,
button:focus-visible,
input:focus-visible,
select:focus-visible,
summary:focus-visible {
  outline: 3px solid rgba(119, 183, 255, .42);
  outline-offset: 3px;
}

button,
.btn,
.softButton,
.primaryButton,
.dangerButton,
.create-back-link,
.networks-actions-v1 a {
  min-height: 40px;
  border-radius: 14px;
  font-weight: 850;
  transition: transform .16s ease, border-color .16s ease, background .16s ease, box-shadow .16s ease;
}

.btn,
.softButton,
.create-back-link,
.networks-actions-v1 a {
  border-color: rgba(167, 195, 235, .14);
  background: rgba(255,255,255,.048);
  box-shadow: inset 0 1px 0 rgba(255,255,255,.035);
}

.primary,
.primaryButton {
  color: #07111f;
  background: linear-gradient(135deg, #eaf3ff 0%, #a9c9ff 56%, #b8b0ff 100%);
  box-shadow: 0 12px 30px rgba(83, 141, 235, .20), inset 0 1px 0 rgba(255,255,255,.65);
}

input,
select,
textarea,
.textInput {
  border-color: rgba(167, 195, 235, .16) !important;
  background: rgba(5, 11, 21, .66) !important;
  color: var(--text) !important;
  box-shadow: inset 0 1px 0 rgba(255,255,255,.025);
}

input::placeholder,
textarea::placeholder {
  color: #69788e;
}

.tablewrap {
  overflow: auto;
  border-radius: 18px;
  border: 1px solid rgba(167, 195, 235, .10);
  background: rgba(3, 8, 16, .22);
}

.tablewrap table {
  margin: 0;
}

th {
  color: #8494ab;
  font-size: 11px;
  letter-spacing: .07em;
  text-transform: uppercase;
}

td,
th {
  border-color: rgba(167, 195, 235, .09);
}

.pill {
  box-shadow: inset 0 1px 0 rgba(255,255,255,.035);
}

.home-check-list,
.access-device-list,
.access-problem-list,
.people-list,
.match-list-v1 {
  gap: 11px;
}

.home-check-row,
.access-device-card,
.access-problem-row,
.person-card,
.person-device,
.access-card,
.network-card-v1,
.match-row-v1,
.city-pill-v1,
.channel-cal-line,
.channel-kpi,
.cr-kpi,
.cr-user {
  border-color: rgba(167, 195, 235, .12);
  background: linear-gradient(180deg, rgba(255,255,255,.044), rgba(255,255,255,.018));
  box-shadow: inset 0 1px 0 rgba(255,255,255,.025);
}

.home-check-row,
.access-device-card,
.access-card,
.person-card,
.network-card-v1,
.match-row-v1 {
  border-radius: 19px;
}

.access-card {
  min-height: 78px;
  padding: 14px 15px;
}

.access-card .access-name,
.person-title,
.device-access,
.net-top-v1 strong,
.match-title-v1 {
  color: #f5f8ff;
}

.person-device,
.access-problem-row,
.city-pill-v1,
.channel-cal-line {
  border-radius: 15px;
}

.access-problem-summary,
.net-top-v1 span,
.net-facts-v1 span,
.match-facts2-v1 span,
.net-clients-v1 a,
.channel-badge {
  box-shadow: inset 0 1px 0 rgba(255,255,255,.035);
}

.channel-hero {
  border-radius: 26px;
  border-color: rgba(119, 183, 255, .19);
  background:
    radial-gradient(circle at 0% 0%, rgba(101,168,255,.22), transparent 43%),
    radial-gradient(circle at 100% 0%, rgba(155,140,255,.13), transparent 38%),
    linear-gradient(180deg, rgba(255,255,255,.068), rgba(255,255,255,.022));
  box-shadow: 0 28px 80px rgba(19, 61, 119, .16), inset 0 1px 0 rgba(255,255,255,.05);
}

.channel-now b {
  color: #fff;
  text-shadow: 0 12px 36px rgba(87, 151, 245, .18);
}

.channel-bar,
.cr-col-track,
.cr-day-track {
  background: rgba(1, 6, 13, .44);
  border-color: rgba(167, 195, 235, .10);
}

.channel-bar i,
.cr-col-track i,
.cr-day-track i,
.channel-mini-row i u {
  background: linear-gradient(180deg, #8dc3ff, #5aa5ff 48%, #4cdda0);
  box-shadow: 0 0 18px rgba(91, 166, 255, .22);
}

.channel-kpi,
.cr-kpi {
  border-radius: 18px;
}

.networks-hero-v1 h1 {
  color: #f8faff;
  letter-spacing: -.052em;
}

.network-card-v1.net-mass {
  border-color: rgba(119, 183, 255, .24);
  background: linear-gradient(180deg, rgba(101,168,255,.10), rgba(101,168,255,.035));
}

.network-card-v1.net-shared,
.match-row-v1.match-strong {
  border-color: rgba(76, 221, 160, .20);
  background: linear-gradient(180deg, rgba(76,221,160,.075), rgba(76,221,160,.025));
}

.net-clients-v1 a,
.match-title-v1 a {
  color: #dfeaff;
}

.empty-v1,
.cr-empty {
  border-color: rgba(167, 195, 235, .16);
  background: rgba(7, 14, 25, .42);
}

@media (hover: hover) and (pointer: fine) {
  .shell-link:hover,
  .shell-logout-button:hover,
  .btn:hover,
  .softButton:hover,
  .create-back-link:hover,
  .networks-actions-v1 a:hover {
    color: #fff;
    border-color: rgba(119, 183, 255, .28);
    background: rgba(119, 183, 255, .10);
  }

  .home-check-row:hover,
  .access-device-card:hover,
  .access-card:hover,
  .person-card:hover,
  .person-device:hover,
  .network-card-v1:hover,
  .match-row-v1:hover {
    transform: translateY(-2px);
    border-color: rgba(119, 183, 255, .24);
    box-shadow: 0 20px 46px rgba(0,0,0,.20), inset 0 1px 0 rgba(255,255,255,.04);
  }
}

@media (max-width: 760px) {
  body::before {
    opacity: .13;
    background-size: 32px 32px;
  }

  .wrap {
    padding: 18px 14px 38px;
  }

  .shell-topline {
    align-items: flex-start;
  }

  .shell-user {
    max-width: 100%;
    white-space: normal;
  }

  .shell-user-name {
    max-width: min(62vw, 280px);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .shell-nav {
    margin-bottom: 18px;
    border-radius: 19px;
  }

  .shell-title h1 {
    font-size: clamp(34px, 11vw, 44px);
  }

  .shell-subtitle {
    font-size: 16px;
  }

  .card {
    margin: 11px 0;
    padding: 16px;
    border-radius: 20px;
  }

  .grid {
    gap: 10px;
  }

  button,
  .btn,
  .softButton,
  .primaryButton,
  .dangerButton,
  .create-back-link,
  .networks-actions-v1 a {
    min-height: 42px;
  }

  .access-card,
  .person-card,
  .network-card-v1,
  .match-row-v1 {
    border-radius: 17px;
  }

  .channel-hero {
    padding: 18px;
    border-radius: 22px;
  }

  .channel-now b {
    font-size: clamp(38px, 13vw, 48px);
  }

  .networks-actions-v1 {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
  }

  .networks-actions-v1 a {
    justify-content: center;
    padding: 8px;
    text-align: center;
  }
}

@media (max-width: 420px) {
  .wrap {
    padding-inline: 12px;
  }

  .shell-user-name {
    max-width: 58vw;
  }

  .shell-link {
    font-size: 12px;
    padding-inline: 5px;
  }

  .card {
    padding: 14px;
  }

  .networks-actions-v1 {
    grid-template-columns: 1fr;
  }
}

@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    scroll-behavior: auto !important;
    transition-duration: .01ms !important;
    animation-duration: .01ms !important;
    animation-iteration-count: 1 !important;
  }
}
/* /vpn-design-v2 */
"""
