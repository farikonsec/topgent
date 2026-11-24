// Web settings. Desktop remains the product specification: the same three
// themes, from the same palettes (styles.css, from the desktop's theme.rs).
import { $, el } from "../dom.mjs";
import { save, session, view } from "../state.mjs";

export const THEMES = [["dark","Dark"],["light","Light"],["high-contrast","High contrast"]];
export const DENSITIES = [["compact","Compact"],["normal","Normal"],["comfortable","Comfortable"]];
export const REFRESHES = [[1500,"1.5s"],[5000,"5s"],[15000,"15s"],[30000,"30s"],[0,"Paused"]];

function choices(options, current, change, label) {
  return el("div", {className:"setting-choices", role:"group", ariaLabel:label}, options.map(([value, text]) => {
    const button=el("button", {className:"setting-choice", textContent:text, ariaPressed:String(value===current)});
    button.onclick=()=>change(value);
    return button;
  }));
}

function setting(name, detail, control) {
  return el("div",{className:"setting-row"},[el("div",{},[el("strong",{textContent:name}),el("p",{textContent:detail})]),control]);
}

export function renderSettings() {
  const host=$("settings");
  const change=(key,value)=>{ view[key]=value; save(); document.dispatchEvent(new CustomEvent("topgent-settings-change")); renderSettings(); };
  const notification=el("button",{className:"setting-choice",ariaPressed:String(session.alertsOn),textContent:session.alertsOn?"On":"Off"});
  notification.onclick=()=>document.dispatchEvent(new CustomEvent("topgent-alert-toggle"));
  host.replaceChildren(el("div",{className:"settings-list"},[
    setting("Theme","The desktop application's palettes, so a finding reads the same colour in both.",choices(THEMES,view.theme,value=>change("theme",value),"Theme")),
    setting("Density","Change spacing without hiding evidence.",choices(DENSITIES,view.density,value=>change("density",value),"Density")),
    setting("Refresh","Choose how often this host is scanned.",choices(REFRESHES,view.refreshMs,value=>change("refreshMs",value),"Refresh interval")),
    setting("Notifications","Sound, toast, and system notification. The event log is always retained.",notification),
  ]));
}
