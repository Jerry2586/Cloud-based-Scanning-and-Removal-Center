export const dashboardTheme = `
:root{color-scheme:dark;--bg:#090d16;--panel:#111722;--line:#232d3d;--text:#e6ecf4;--muted:#8997aa;--cyan:#6adbd1;--purple:#a9a2e9}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.6 "Segoe UI","Microsoft YaHei",sans-serif}
a{color:inherit;text-decoration:none}
button,a{-webkit-tap-highlight-color:transparent}
a:focus-visible{outline:2px solid var(--cyan);outline-offset:5px}
svg{width:22px;height:22px;flex-shrink:0}
h1,h2,h3,p{margin:0}
h1{font-size:27px;font-weight:650;letter-spacing:-.7px}
h2{font-size:17px;font-weight:600}
h3{font-size:17px;font-weight:600}
p{color:var(--muted)}
.xc-shell{display:grid;grid-template-columns:230px minmax(0,1fr);min-height:100vh}
.xc-sidebar{position:sticky;top:0;height:100vh;border-right:1px solid #202938;background:linear-gradient(180deg,#101722,#0d131d);padding:29px 16px;display:flex;flex-direction:column}
.brand{display:flex;align-items:center;gap:12px;padding:0 9px}
.brand-symbol{display:grid;place-items:center;width:40px;height:44px;border:1px solid #537e88;border-radius:12px;background:linear-gradient(145deg,#253c48,#15212f);box-shadow:inset 0 1px 0 #81c9cc40,0 0 20px #5bd6cf0a;color:var(--cyan)}
.brand-symbol svg{width:25px;height:25px}
.brand strong{display:block;font-size:21px;letter-spacing:1px}
.brand small{font-size:9px;letter-spacing:1.65px;color:#7f96ad}
.platform-label{font-size:11px;letter-spacing:3px;margin:18px 11px 21px;color:#687c93}
.nav-group{font-size:10px;letter-spacing:1px;color:#62758c;padding:14px 13px 8px}
.nav-item{display:flex;align-items:center;gap:12px;padding:11px 13px;margin:4px 0;border:1px solid transparent;border-radius:9px;color:#9baabd;transition:background .16s,color .16s}
.nav-item svg{width:18px;height:18px}
.nav-item:hover{background:#192431;color:#e7f0f8}
.nav-item i{font-style:normal;font-size:8px;margin-left:auto;letter-spacing:.5px;color:#94a0b4;border:1px solid #324154;border-radius:4px;padding:0 4px}
.xc-shell:not(:has(.xc-page:target)) .nav-overview,.xc-shell:has(#overview:target) .nav-overview,.xc-shell:has(#nodes:target) .nav-nodes,.xc-shell:has(#virus:target) .nav-virus,.xc-shell:has(#policy:target) .nav-policy,.xc-shell:has(#baseline:target) .nav-baseline,.xc-shell:has(#updates:target) .nav-updates,.xc-shell:has(#events:target) .nav-events,.xc-shell:has(#connection:target) .nav-connection{color:#84e4da;background:linear-gradient(90deg,#203838,#182830);border-color:#36514f;box-shadow:inset 3px 0 0 #72d7cc}
.sidebar-bottom{margin-top:auto;display:flex;align-items:center;gap:11px;padding:18px 9px 0;border-top:1px solid #223040;font-size:11px}
.sidebar-bottom strong{font-weight:500;color:#a0b0c2}
.sidebar-bottom small{display:block;font-size:10px;color:#596f88;margin-top:3px}
.status-dot{width:6px;height:6px;display:inline-block;border-radius:50%;background:var(--cyan);box-shadow:0 0 10px #6adbd155;flex-shrink:0}
.xc-workspace{min-width:0;background:radial-gradient(ellipse at 80% 0,#26314822,transparent 46%)}
.topbar{height:67px;border-bottom:1px solid #202938;display:flex;align-items:center;justify-content:space-between;padding:0 34px;font-size:12px;color:#8e9eb1}
.slash{color:#3d4b5e;margin:0 12px}
.topbar>div{display:flex;gap:22px;align-items:center}
.top-status{font-size:9px;letter-spacing:1.1px;color:#8c9bb1}
.top-action{display:flex;align-items:center;gap:7px;color:#bac7d7}
.top-action svg{width:15px;height:15px}
.preview-note{font-size:11px;color:#8793a8;padding:9px 34px;background:#18203466;border-bottom:1px solid #23304a55}
.xc-panels{padding:32px 34px 22px;max-width:1530px;margin:auto}
.xc-page{display:none;scroll-margin-top:145px}
.default-page{display:block}
.xc-page:target{display:block}
.xc-panels:has(.xc-page:target) .default-page:not(:target){display:none}
.page-heading{display:flex;justify-content:space-between;gap:18px;align-items:center;margin-bottom:25px}
.eyebrow{font-size:9px;letter-spacing:1.5px;color:#738399;font-weight:600;margin-bottom:6px}
.page-heading>div>p:last-child{font-size:12px;margin-top:6px}
.card{background:linear-gradient(145deg,#141c28,#101620);border:1px solid var(--line);border-radius:13px;padding:23px;box-shadow:0 5px 18px #0000000d;min-width:0}
.badge{display:inline-flex;align-items:center;gap:5px;white-space:nowrap;font-size:10px;padding:3px 8px;border-radius:5px;border:1px solid #344256;color:#9faec2;background:#192334}
.badge.ok{color:#86d5b6;border-color:#2b5145;background:#1a302b}
.badge.warning{color:#e6c688;border-color:#615438;background:#332d21}
.badge.danger{color:#ed9b9f;border-color:#613e49;background:#32212b}
.badge.muted{color:#8496ae;border-color:#2c3b50;background:#182132}
.engine-hero{position:relative;overflow:hidden;min-height:325px;display:grid;grid-template-columns:1.25fr 1fr;padding:33px 35px;background:radial-gradient(ellipse at 82% 60%,#35467544,transparent 50%),linear-gradient(120deg,#162332,#131b2a 56%,#182039);border-color:#35445a}
.engine-hero:after{content:"";position:absolute;inset:0;pointer-events:none;background:linear-gradient(transparent 97%,#8ea9da08 98%),linear-gradient(90deg,transparent 97%,#8ea9da08 98%);background-size:40px 40px;mask-image:linear-gradient(90deg,transparent,#000)}
.hero-copy{position:relative;z-index:1}
.hero-label{font-size:9px;font-weight:600;letter-spacing:1.55px;color:#8dadbd;display:flex;align-items:center;gap:9px;margin-bottom:18px}
.hero-copy h2{font-size:clamp(23px,2.05vw,33px);font-weight:600;line-height:1.55;letter-spacing:-.75px}
.hero-copy h2 span{color:var(--cyan)}
.hero-copy>p{font-size:12px;line-height:1.9;margin-top:13px;color:#92a5be}
.hero-actions{display:flex;gap:12px;margin:22px 0 18px}
.button{display:inline-flex;align-items:center;justify-content:center;gap:17px;font-size:11px;border:1px solid #36475c;border-radius:7px;padding:10px 14px;font-weight:600;transition:transform .15s,background .15s}
.button:hover{transform:translateY(-1px);background:#2b3c50}
.button.primary{color:#102523;background:linear-gradient(145deg,#93e9dc,#64c4bf);border-color:#a1ded0;box-shadow:inset 0 1px 0 #baf0e4}
.button.primary:hover{background:#a0ecdf}
.button.secondary{color:#bacbdf;background:#1a283c88}
.hero-status{display:flex;align-items:center;gap:10px;font-size:10px;color:#758aa3}
.engine-art{display:grid;place-items:center;position:relative;z-index:1;align-content:center;min-width:0}
.core-svg{width:100%;height:auto;max-width:380px;margin:-38px -20px -23px 0;filter:drop-shadow(0 20px 25px #080b2199)}
.art-label{font-size:8px;letter-spacing:3px;color:#6f84a9}
.stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:15px;margin:20px 0 27px}
.stats.three{grid-template-columns:repeat(3,minmax(0,1fr))}
.stat{padding:19px 22px}
.stat>span{color:#a5b4c6;font-size:11px}
.stat>strong{display:block;font-size:30px;line-height:1.4;letter-spacing:-1px;font-weight:500;margin:9px 0 5px;color:#dce6f4}
.stat strong small{font-size:11px;color:#708399;letter-spacing:0}
.stat>strong.unset{color:#6c7b92}
.stat>strong.small-value{font-size:22px}
.stat p{font-size:10px;color:#6e8098}
.section-heading{display:flex;justify-content:space-between;align-items:center;margin:0 0 14px}
.section-heading h2{font-size:15px}
.section-heading span{font-size:8px;color:#60738d;letter-spacing:1.7px}
.modules{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:15px}
.module-card{position:relative;padding:20px;transition:transform .18s,border-color .18s,background .18s}
.module-card:hover{transform:translateY(-3px);border-color:#4b727d;background:#172535}
.card-head{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:20px}
.card-head h2{font-size:15px}
.module-card .card-head{margin-bottom:21px}
.module-icon,.node-icon,.release-icon{display:grid;place-items:center;width:38px;height:38px;color:#82c9cd;border:1px solid #344a5b;background:linear-gradient(145deg,#283b4b,#1c2837);border-radius:9px}
.module-card:nth-child(2) .module-icon{color:#b2a4df;background:#302b43;border-color:#4c4260}
.module-card:nth-child(3) .module-icon{color:#9aace7;background:#252e49;border-color:#404d70}
.module-card:nth-child(4) .module-icon{color:#afc6d2}
.corner{color:#697d95;font-size:17px}
.module-card .eyebrow{font-size:8px;letter-spacing:1px}
.module-card h3{font-size:15px;margin:3px 0 9px}
.module-card>p:not(.eyebrow){font-size:11px;line-height:1.8;min-height:38px}
.module-state{display:block;font-size:9px;color:#748ea2;margin-top:19px;padding-top:13px;border-top:1px solid #283749}
.overview-lower{display:grid;grid-template-columns:1.15fr 1fr;gap:18px;margin-top:23px}
.endpoint-empty{display:flex;align-items:center;gap:16px;padding:15px 0}
.endpoint-empty>svg{width:28px;height:28px;color:#6a829b}
.endpoint-empty>div{flex:1}
.endpoint-empty strong{font-size:12px;font-weight:500}
.endpoint-empty p{font-size:10px;margin-top:6px}
.endpoint-empty .button{padding:8px 10px;white-space:nowrap}
.text-link{font-size:10px;color:#97c7cb;white-space:nowrap}
.events{list-style:none;padding:0;margin:0}
.events>li:not(.empty-state){display:flex;gap:12px;padding:18px 0;border-bottom:1px solid #273247}
.events li:last-child{border-bottom:0}
.events li>div{min-width:0;flex:1}
.events strong{font-size:12px;font-weight:500}
.events p{font-size:11px;overflow-wrap:anywhere;margin-top:4px}
.events time{font-size:9px;color:#667b94;max-width:150px;overflow-wrap:anywhere}
.event-dot{width:7px;height:7px;border-radius:50%;background:#b38d7f;flex-shrink:0;margin-top:7px}
.event-dot.ok{background:#78c8a8}
.event-dot.warning{background:#d8b074}
.events.compact{max-height:165px;overflow:auto}
.empty-state{text-align:center;display:flex;flex-direction:column;align-items:center;padding:18px 12px;color:#98a9bf}
.empty-state p{font-size:11px;margin-top:7px;max-width:430px}
.empty-symbol{display:grid;place-items:center;width:42px;height:42px;border:1px solid #334155;background:#1b283a;border-radius:11px;margin-bottom:12px;color:#6f8fa4}
.big-empty{padding:40px 15px 45px;min-height:225px}
.big-empty strong{font-size:15px;font-weight:500}
.big-empty .badge{margin-top:17px}
.node-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:20px;margin:0 0 23px}
.node-card h3{margin-top:6px}
.node-card>p{font-size:11px;margin-top:3px}
.empty-node{padding:21px 0;color:#70839c;font-size:12px}
.node-meta{border-top:1px solid #29384b;margin-top:18px;padding-top:14px;display:grid;gap:13px}
.node-meta>span{display:flex;justify-content:space-between;align-items:center;font-size:11px;color:#8c9eb5}
.node-meta b{font-weight:500}
.node-card>.text-link{display:flex;justify-content:space-between;margin-top:25px}
.details{margin:20px 0 0;display:grid;gap:11px}
.details>div{display:flex;justify-content:space-between;gap:15px;font-size:11px}
.details dt{color:#788ba4}
.details dd{margin:0;overflow-wrap:anywhere;text-align:right}
.next{padding-top:15px;font-size:11px}
.feature-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:19px;margin-top:23px;margin-bottom:23px}
.feature-grid h3{font-size:14px;margin-bottom:10px}
.feature-grid p{font-size:12px}
.feature-grid .badge{margin-top:18px}
.notice{color:#8f9fb7;font-size:11px;border:1px solid #2f4058;border-radius:8px;background:#192335;padding:13px 16px;margin-top:22px;overflow-wrap:anywhere}
.muted{color:var(--muted)}
.policy-banner{display:flex;align-items:center;justify-content:space-between;gap:15px}
.policy-banner>div{display:flex;gap:14px;align-items:center}
.policy-banner>div>svg{color:#9fa6d9}
.policy-banner h2 span{font-size:11px;color:#7288a2;margin-left:8px}
.strategy-flow{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:15px;padding:10px 0}
.strategy-flow>div{border-left:1px solid #36495f;padding-left:17px}
.strategy-flow b{display:block;color:#6b9ea7;font-size:11px;letter-spacing:1px;margin-bottom:12px}
.strategy-flow strong{font-size:13px;font-weight:500}
.strategy-flow p{font-size:10px;margin-top:5px}
.baseline-count{display:flex;align-items:baseline;gap:13px;margin:24px 0}
.baseline-count strong{font-weight:500;font-size:36px;color:#a6c9d0}
.baseline-count span{font-size:12px;color:#879ab2}
.node-grid>.card>p{font-size:11px;margin:8px 0}
.release-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:19px;margin-bottom:24px}
.release-card{padding:27px}
.release-icon{margin-bottom:25px;width:44px;height:44px}
.release-card h3{margin:8px 0 12px}
.release-card>p:not(.eyebrow){font-size:11px}
.release-card .details{padding-top:20px;border-top:1px solid #29394c;margin-top:23px;margin-bottom:24px}
.connection-grid{display:grid;grid-template-columns:1.08fr 1fr;gap:22px}
.guide-list{list-style:none;padding:0;margin:0}
.guide-step{display:flex;align-items:flex-start;gap:15px;padding:18px 0;border-bottom:1px solid #253348}
.guide-step>span{display:grid;place-items:center;width:28px;height:28px;border:1px solid #35465d;border-radius:7px;color:#7890aa;font-size:10px;flex-shrink:0}
.guide-step>div{flex:1}
.guide-step strong{font-size:12px;font-weight:500}
.guide-step p{font-size:11px;margin-top:4px}
.guide-step em{font-style:normal;font-size:10px;color:#5f748f;white-space:nowrap;margin-top:4px}
.guide-step.done>span{border-color:#386255;color:#88d7b6;background:#1e362f}
.guide-step.current>span{border-color:#63878a;color:#8cddd5;background:#20383d}
.guide-step.current em{color:#82c9cd}
.identity-row{display:flex;justify-content:space-between;gap:14px;padding:18px 0;border-bottom:1px solid #253348}
.identity-row strong{font-weight:500;font-size:12px}
.identity-row small{display:block;color:#6f849e;font-size:10px;margin-top:6px;overflow-wrap:anywhere}
.identity-row>div:last-child{display:flex;flex-wrap:wrap;justify-content:flex-end;align-content:center;gap:5px}
.xc-footer{max-width:1530px;padding:10px 34px 23px;margin:auto;display:flex;justify-content:space-between;gap:18px;font-size:9px;color:#586d88;letter-spacing:.5px}
.xc-footer i{font-style:normal;margin:0 9px}


@media(min-width:1600px){.hero-copy h2{font-size:35px}
.engine-hero{min-height:350px}
.core-svg{max-width:405px}
}

@media(max-width:1200px){.xc-shell{grid-template-columns:205px minmax(0,1fr)}
.xc-panels{padding:28px 25px}
.topbar,.preview-note{padding-left:25px;padding-right:25px}
.engine-hero{padding:28px}
.hero-copy h2{font-size:25px}
.modules{grid-template-columns:repeat(2,minmax(0,1fr))}
.overview-lower{grid-template-columns:1fr}
.module-card>p:not(.eyebrow){min-height:auto}
}

@media(max-width:900px){.xc-shell{grid-template-columns:180px minmax(0,1fr)}
.brand{gap:8px;padding:0}
.brand strong{font-size:18px}
.brand small{font-size:8px;letter-spacing:1px}
.xc-sidebar{padding:25px 10px}
.sidebar-bottom{gap:6px}
.sidebar-bottom strong{font-size:10px}
.nav-item{font-size:12px;gap:9px;padding:10px}
.stats{grid-template-columns:repeat(2,minmax(0,1fr))}
.engine-hero{grid-template-columns:1.5fr 1fr}
.core-svg{min-width:180px}
.hero-copy h2{font-size:22px}
.hero-label{font-size:8px;letter-spacing:.7px}
.hero-copy>p br{display:none}
.feature-grid,.release-grid{grid-template-columns:1fr}
.connection-grid{grid-template-columns:1fr}
.top-status{display:none}
.hero-actions{gap:8px;flex-wrap:wrap}
.strategy-flow{grid-template-columns:repeat(2,minmax(0,1fr));gap:25px}
.node-grid{grid-template-columns:1fr}
.stats.three{grid-template-columns:repeat(3,minmax(0,1fr))}
}

@media(max-width:650px){.xc-shell{display:block}
.xc-sidebar{position:relative;height:auto;padding:20px 18px 13px;border-bottom:1px solid #253447;border-right:0}
.brand{padding:0}
.brand strong{font-size:20px}
.brand small{font-size:9px}
.platform-label,.xc-sidebar>.nav-group,.sidebar-bottom,.nav-group{display:none}
.xc-sidebar nav{display:flex;gap:5px;overflow-x:auto;padding-top:15px;padding-bottom:3px;scrollbar-width:thin;scrollbar-color:#35495e transparent}
.nav-item{flex-shrink:0;margin:0;font-size:11px;padding:9px 10px;gap:7px;border-radius:7px}
.nav-item svg{width:15px;height:15px}
.nav-item i{display:none}
.topbar{height:48px;padding:0 19px;font-size:10px}
.topbar>div{gap:0}
.slash{margin:0 5px}
.top-action{font-size:10px;gap:4px}
.preview-note{padding:8px 19px;font-size:10px}
.xc-panels{padding:24px 18px 12px}
.page-heading{align-items:flex-start;margin-bottom:20px}
.page-heading>.badge{display:none}
h1{font-size:23px}
.page-heading>div>p:last-child{font-size:11px}
.engine-hero{padding:25px 23px;grid-template-columns:1fr;min-height:0}
.hero-copy h2{font-size:24px}
.hero-copy>p{font-size:11px}
.hero-label{font-size:8px;letter-spacing:1px}
.engine-art{display:none}
.hero-status{font-size:9px;gap:7px;flex-wrap:wrap}
.hero-actions{margin:21px 0 18px}
.stats,.stats.three{grid-template-columns:repeat(2,minmax(0,1fr));gap:10px;margin:15px 0 25px}
.stat{padding:15px}
.stat>strong{font-size:26px}
.stat p{font-size:9px}
.modules{gap:10px}
.module-card{padding:16px}
.module-card h3{font-size:14px}
.module-card .eyebrow{font-size:7px;letter-spacing:.6px}
.module-card>p:not(.eyebrow){font-size:10px}
.module-state{font-size:8px}
.module-icon{width:32px;height:32px}
.section-heading span{font-size:7px;letter-spacing:1px}
.card-head h2{font-size:14px}
.overview-lower{gap:15px;margin-top:20px}
.overview-lower>.card{padding:19px}
.endpoint-empty{flex-wrap:wrap;gap:10px}
.endpoint-empty>div{flex:1;min-width:190px}
.endpoint-empty .button{margin-left:38px}
.card{border-radius:10px}
.feature-grid{gap:12px}
.policy-banner{flex-wrap:wrap}
.policy-banner h2{font-size:14px}
.strategy-flow{gap:22px 8px}
.strategy-flow>div{padding-left:10px}
.strategy-flow p{font-size:9px}
.events li:not(.empty-state){flex-wrap:wrap}
.events li time{margin-left:19px;max-width:none}
.identity-row{flex-wrap:wrap}
.guide-step{gap:10px}
.guide-step em{font-size:9px}
.xc-footer{padding:15px 18px;flex-direction:column;gap:5px;font-size:8px}
.notice{font-size:10px;padding:12px}
}


@media(prefers-reduced-motion:reduce){html{scroll-behavior:auto}
*{transition:none!important}
}

`;
