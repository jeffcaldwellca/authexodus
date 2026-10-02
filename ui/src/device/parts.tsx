// Drawing primitives for the device illustrations: the iPhone and iPad bodies and the
// building blocks of a simplified iOS Settings screen. These are drawings, not screenshots.
// Colours come from CSS classes (`d-*` in styles.css) so the drawings follow light and dark mode.
import { useId, type ReactNode } from "react";
import type { Device } from "../api";
import { en } from "../strings/en";

const t = en.device;

export const ROW = 38;
const PAD = 10;

export type RowSpec = {
  label: string;
  value?: string;
  accessory?: "chevron" | "toggleOn" | "toggleOff" | "check" | "info";
  /** `row` marks the whole row as the thing to tap; `accessory` marks only the control at its end. */
  highlight?: "row" | "accessory";
  tone?: "link" | "danger";
  leadingCheck?: boolean;
  /** Draw the value as a live value the person has to type: bold, monospaced, marked. */
  live?: boolean;
  selected?: boolean;
};

export function Toggle({ x, y, on }: { x: number; y: number; on: boolean }) {
  return (
    <g>
      <rect x={x} y={y} width={34} height={20} rx={10} className={on ? "d-toggle-on" : "d-toggle-off"} />
      <circle cx={on ? x + 24 : x + 10} cy={y + 10} r={8} className="d-knob" />
    </g>
  );
}

/** A rounded group of rows, as in iOS Settings. Returns the drawing; use `groupHeight` to stack. */
export function Group({ y, w, rows, header }: { y: number; w: number; rows: RowSpec[]; header?: string }) {
  const gw = w - PAD * 2;
  const top = header ? y + 18 : y;
  return (
    <g>
      {header && <text x={PAD + 12} y={y + 11} className="d-text d-dim d-small">{header}</text>}
      <rect x={PAD} y={top} width={gw} height={rows.length * ROW} rx={9} className="d-card" />
      {rows.map((row, i) => {
        const ry = top + i * ROW;
        const mid = ry + ROW / 2;
        const end = PAD + gw - 12;
        const accW = row.accessory === "toggleOn" || row.accessory === "toggleOff" ? 42
          : row.accessory === "info" ? 26 : row.accessory ? 14 : 0;
        const labelX = PAD + 12 + (row.leadingCheck ? 14 : 0);
        const toneClass = row.tone === "link" ? "d-link" : row.tone === "danger" ? "d-danger" : "";
        return (
          <g key={row.label}>
            {row.selected && <rect x={PAD} y={ry} width={gw} height={ROW} rx={9} className="d-selected" />}
            {i > 0 && <line x1={labelX} x2={PAD + gw} y1={ry} y2={ry} className="d-sep" />}
            {row.highlight === "row" && (
              <rect x={PAD + 2} y={ry + 2} width={gw - 4} height={ROW - 4} rx={7} className="d-hl" />
            )}
            {row.leadingCheck && <text x={PAD + 10} y={mid + 4} className="d-text d-link d-bold">✓</text>}
            <text x={labelX} y={mid + 4} className={`d-text ${toneClass} ${row.selected ? "d-on-selected" : ""}`}>{row.label}</text>
            {row.value !== undefined && (row.live ? (
              <g>
                <rect x={end - accW - row.value.length * 7.4 - 8} y={mid - 10} width={row.value.length * 7.4 + 12} height={20} rx={5} className="d-live" />
                <text x={end - accW - 2} y={mid + 4} textAnchor="end" className="d-text d-mono d-bold">{row.value}</text>
              </g>
            ) : (
              <text x={end - accW} y={mid + 4} textAnchor="end" className="d-text d-dim">{row.value}</text>
            ))}
            {row.accessory === "chevron" && <text x={end} y={mid + 5} textAnchor="end" className="d-text d-dim d-chev">›</text>}
            {row.accessory === "check" && <text x={end} y={mid + 4} textAnchor="end" className="d-text d-link d-bold">✓</text>}
            {(row.accessory === "toggleOn" || row.accessory === "toggleOff") && (
              <Toggle x={end - 34} y={mid - 10} on={row.accessory === "toggleOn"} />
            )}
            {row.accessory === "info" && (
              <g>
                <circle cx={end - 9} cy={mid} r={8.5} className="d-info" />
                <text x={end - 9} y={mid + 4} textAnchor="middle" className="d-text d-link d-bold d-small">i</text>
              </g>
            )}
            {row.highlight === "accessory" && (
              <circle cx={row.accessory === "info" ? end - 9 : end - 17} cy={mid} r={row.accessory === "info" ? 14 : 22} className="d-hl d-ring" />
            )}
          </g>
        );
      })}
    </g>
  );
}

export function groupHeight(rows: number, header = false): number {
  return rows * ROW + (header ? 18 : 0) + 14;
}

/** Lays groups out top to bottom so scenes do not have to add up heights by hand. */
export function Stack({ y = 0, w, groups }: { y?: number; w: number; groups: { rows: RowSpec[]; header?: string }[] }) {
  let at = y;
  return (
    <g>
      {groups.map((g, i) => {
        const node = <Group key={i} y={at} w={w} rows={g.rows} header={g.header} />;
        at += groupHeight(g.rows.length, Boolean(g.header));
        return node;
      })}
    </g>
  );
}

export function NavBar({ w, title, back, action, actionHighlight, leading }: {
  w: number; title: string; back?: string | true; action?: string; actionHighlight?: boolean; leading?: string;
}) {
  const actionW = action ? action.length * 7 + 14 : 0;
  return (
    <g>
      {back !== undefined && (
        <text x={PAD} y={22} className="d-text d-link">
          <tspan className="d-chev">‹</tspan>{back === true ? "" : ` ${back}`}
        </text>
      )}
      {leading && <text x={PAD + 2} y={21} className="d-text d-link">{leading}</text>}
      <text x={w / 2} y={21} textAnchor="middle" className="d-text d-bold">{title}</text>
      {action && (
        <g>
          {actionHighlight && <rect x={w - PAD - actionW} y={6} width={actionW} height={24} rx={7} className="d-hl d-ring" />}
          <text x={w - PAD - 7} y={21} textAnchor="end" className="d-text d-link d-bold">{action}</text>
        </g>
      )}
    </g>
  );
}

export const NAV = 40;

/** The top level of Settings: the iPhone's first screen, and the iPad's sidebar. */
export function SettingsRoot({ w, active, profileRow, tapWifi }: Sidebar & { w: number }) {
  const wide = w > 200;
  const account: RowSpec[] = [{ label: t.yourName, accessory: "chevron" }];
  const groups: { rows: RowSpec[] }[] = [{ rows: account }];
  if (profileRow) groups.push({ rows: [{ label: t.profileDownloaded, accessory: wide ? "chevron" : undefined, highlight: "row" }] });
  groups.push({ rows: [
    { label: t.airplane, accessory: wide ? "toggleOff" : undefined },
    { label: t.wifi, value: wide ? t.homeNetwork : undefined, accessory: "chevron", selected: active === "wifi", highlight: tapWifi ? "row" : undefined },
    { label: t.bluetooth, value: wide ? t.on : undefined, accessory: "chevron" },
  ] });
  groups.push({ rows: [
    { label: t.general, accessory: "chevron", selected: active === "general" },
    { label: t.accessibility, accessory: "chevron" },
    { label: t.privacy, accessory: "chevron" },
  ] });
  return (
    <g>
      <text x={PAD + 4} y={26} className="d-text d-bold d-large">{t.settings}</text>
      <Stack y={40} w={w} groups={groups} />
    </g>
  );
}

/** `tapWifi` marks the Wi-Fi row as the thing to tap. */
export type Sidebar = { active?: "wifi" | "general"; profileRow?: boolean; tapWifi?: boolean };

const IPHONE = { vw: 260, vh: 372, full: 520, sx: 10, sy: 10, sw: 240, sh: 500, top: 44 };
const IPAD = { vw: 420, vh: 372, full: 540, sx: 12, sy: 12, sw: 396, sh: 516, top: 30, side: 142 };

/**
 * The device body with a clipped screen. `children` draws the main pane and is told how wide
 * it is. On an iPad with a `sidebar`, Settings' left column is drawn beside the pane.
 */
export function Frame({ device, label, sidebar, children }: {
  device: Device; label: string; sidebar?: Sidebar; children: (w: number) => ReactNode;
}) {
  const clip = useId();
  const fade = useId();
  if (device === "iphone") {
    const f = IPHONE;
    return (
      <svg className="device device-iphone" data-device="iphone" role="img" aria-label={label} viewBox={`0 0 ${f.vw} ${f.vh}`}>
        <rect x={1.5} y={1.5} width={f.vw - 3} height={f.full - 3} rx={42} className="d-body" />
        <clipPath id={clip}><rect x={f.sx} y={f.sy} width={f.sw} height={f.sh} rx={33} /></clipPath>
        <g clipPath={`url(#${clip})`}>
          <rect x={f.sx} y={f.sy} width={f.sw} height={f.sh} className="d-screen" />
          <text x={f.sx + 28} y={f.sy + 24} className="d-text d-bold d-small">{t.time}</text>
          <rect x={f.vw / 2 - 34} y={f.sy + 9} width={68} height={20} rx={10} className="d-island" />
          <g transform={`translate(${f.sx} ${f.sy + f.top})`}>{children(f.sw)}</g>
        </g>
        <Fade id={fade} w={f.vw} h={f.vh} />
      </svg>
    );
  }
  const f = IPAD;
  const paneX = sidebar ? f.sx + f.side : f.sx;
  const paneW = sidebar ? f.sw - f.side : f.sw;
  return (
    <svg className="device device-ipad" data-device="ipad" role="img" aria-label={label} viewBox={`0 0 ${f.vw} ${f.vh}`}>
      <rect x={1.5} y={1.5} width={f.vw - 3} height={f.full - 3} rx={24} className="d-body" />
      <clipPath id={clip}><rect x={f.sx} y={f.sy} width={f.sw} height={f.sh} rx={13} /></clipPath>
      <g clipPath={`url(#${clip})`}>
        <rect x={f.sx} y={f.sy} width={f.sw} height={f.sh} className="d-screen" />
        <text x={f.sx + 14} y={f.sy + 18} className="d-text d-bold d-small">{t.time}</text>
        {sidebar && (
          <g data-part="sidebar">
            <g transform={`translate(${f.sx} ${f.sy + f.top})`}><SettingsRoot w={f.side} {...sidebar} /></g>
            <line x1={paneX} x2={paneX} y1={f.sy} y2={f.sy + f.sh} className="d-sep" />
          </g>
        )}
        <g transform={`translate(${paneX} ${f.sy + f.top})`}>{children(paneW)}</g>
      </g>
      <Fade id={fade} w={f.vw} h={f.vh} />
    </svg>
  );
}

/** The drawings show only the top of the device; the bottom edge fades into the page. */
function Fade({ id, w, h }: { id: string; w: number; h: number }) {
  return (
    <>
      <linearGradient id={id} x1="0" y1="0" x2="0" y2="1">
        <stop offset="0" className="d-fade-from" />
        <stop offset="1" className="d-fade-to" />
      </linearGradient>
      <rect x={0} y={h - 44} width={w} height={44} fill={`url(#${id})`} />
    </>
  );
}
