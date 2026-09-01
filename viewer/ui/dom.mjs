// Building elements, and the small vocabulary every panel shares.
//
// `el` takes properties rather than an HTML string, so nothing a process can
// name — an executable path, a hostname, a command line — is ever parsed as
// markup. That is the whole XSS story for this interface, and it is why there
// is no innerHTML anywhere in it.

export const GRADE = { CRITICAL:["var(--crit)","var(--critbg)",4], HIGH:["var(--high)","var(--highbg)",3], MEDIUM:["var(--med)","var(--medbg)",2], LOW:["var(--low)","var(--lowbg)",1] };
export const CONF = { Confirmed:3, Probable:2, Possible:1 };

export const ROGUE_CODES = new Set(["RECON_FANOUT","SANDBOX_ESCAPE","EXPOSED_LISTENER","OFFENSIVE_TOOL","PROCESS_EXPLOSION","SUSPICIOUS_ENDPOINT","PRIVATE_PEER","METADATA_SERVICE","CREDENTIAL_ACCESS","PERSISTENCE_WRITE","SELF_TAMPERING","DISALLOWED_ASSET"]);

export const $ = (id) => document.getElementById(id);
export const el = (tag, props = {}, kids = []) => { const n = Object.assign(document.createElement(tag), props); for (const k of [].concat(kids)) if (k != null) n.append(k); return n; };
export const marks = (cls, total, on) => { const w = el("span", { className: cls }); for (let i=0;i<total;i++) w.append(el("i", { className: i<on?"":"off" })); return w; };
export const gradePill = (grade, score) => { const [fg,bg,n]=GRADE[grade]??GRADE.LOW; const p=el("span",{className:"pill"}); p.style.color=fg; p.style.background=bg; p.append(marks("pips",4,n), el("span",{textContent:grade}), el("span",{className:"mono",textContent:String(score),style:"opacity:.75"})); return p; };

export const rel = (ms) => { const s=Math.max(0,Math.round((Date.now()-ms)/1000)); if(s<60)return `${s}s`; if(s<3600)return `${Math.floor(s/60)}m`; if(s<86400)return `${Math.floor(s/3600)}h ${Math.floor(s%3600/60)}m`; return `${Math.floor(s/86400)}d`; };
export const clock = (ms) => { const d=new Date(ms); const today=new Date(); const hms=d.toLocaleTimeString([], {hour:"2-digit",minute:"2-digit",second:"2-digit"}); return d.toDateString()===today.toDateString()?hms:`${d.toLocaleDateString([], {day:"2-digit",month:"short"})} ${hms}`; };
