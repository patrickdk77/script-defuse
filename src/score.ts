import { findingSpec } from './findings';
import { ScriptCategory as C, type DefuseFinding, type ScriptOptions, ScriptRisk, type ScriptScoreBands } from './types';

export const DEFAULT_BANDS: ScriptScoreBands = { low: 1, medium: 25, high: 50, critical: 80 };

interface Combination {
  name: string;
  weight: number;
  test(has: (c: C) => boolean): boolean;
}

export const COMBINATIONS: Combination[] = [
  { name: 'obfuscation with a way out of the form', weight: 20, test: has => has(C.Obfuscation) && (has(C.External) || has(C.DynamicCode)) },
  { name: 'obfuscation with a viewer API known from exploits', weight: 20, test: has => has(C.Obfuscation) && has(C.Api) },
];

/** The caller's weights first, then the built-in table. */
export function weightOf(f: DefuseFinding, options: ScriptOptions): number {
  const w = options.scoreWeights ?? [];
  const exact = w.find(x => x.category === f.category && x.detail === f.detail);
  if (exact) return exact.weight;
  const cat = w.find(x => x.category === f.category && x.detail === undefined);
  if (cat) return cat.weight;
  return findingSpec(f.category, f.detail)?.weight ?? f.weight ?? 0;
}

/** Highest weight in full, a quarter of each other kind's weight, plus combinations, capped at 100. */
export function scoreFindings(findings: DefuseFinding[], options: ScriptOptions): { score: number; risk: ScriptRisk } {
  const byKind = new Map<string, number>();
  for (const f of findings) {
    const k = `${f.category}/${f.detail}`;
    byKind.set(k, Math.max(byKind.get(k) ?? 0, weightOf(f, options)));
  }
  const weights = [...byKind.values()].sort((a, b) => b - a);
  let score = weights.length ? weights[0] + weights.slice(1).reduce((s, w) => s + w / 4, 0) : 0;
  const has = (c: C) => findings.some(f => f.category === c && weightOf(f, options) > 0);
  for (const combo of COMBINATIONS) if (combo.test(has)) score += combo.weight;
  score = Math.min(100, Math.round(score));
  return { score, risk: riskFor(score, options.scoreBands ?? DEFAULT_BANDS) };
}

export function riskFor(score: number, bands: ScriptScoreBands): ScriptRisk {
  if (score >= bands.critical) return ScriptRisk.Critical;
  if (score >= bands.high) return ScriptRisk.High;
  if (score >= bands.medium) return ScriptRisk.Medium;
  if (score >= bands.low) return ScriptRisk.Low;
  return ScriptRisk.None;
}
