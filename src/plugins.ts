import { inspectScript } from './engine';
import { weightOf } from './score';
import type { ScriptContext, ScriptFinding, ScriptOptions } from './types';

/** The script a container hands its plugins, as pdf-defuse's ContainedScript gives it. */
export interface PluginScript extends ScriptContext {
  text: string;
}

/** A script plugin in the shape pdf-defuse's `scriptPlugins` takes. */
export interface FormScriptPlugin {
  kind: 'script';
  name: string;
  accepts(script: PluginScript): boolean;
  process(script: PluginScript): Promise<{ result: 'passed' | 'removed'; findings?: ScriptFinding[] }>;
  /** Every script this plugin decided, with what it found, in the order it saw them. */
  readonly decisions: ReadonlyArray<{ script: PluginScript; result: 'passed' | 'removed'; findings: ScriptFinding[] }>;
}

/**
 * A plugin that keeps a script only when inspectScript calls it a form script, and removes every other one.
 *
 * It remembers the globals of the scripts it kept, so a field script may call a helper or read a value a
 * document-level script defined. pdf-defuse hands document-level scripts over first. Make one plugin per document.
 */
export function formScriptPlugin(options: ScriptOptions = {}): FormScriptPlugin {
  const known = new Set<string>();
  const decisions: Array<{ script: PluginScript; result: 'passed' | 'removed'; findings: ScriptFinding[] }> = [];
  return {
    kind: 'script',
    name: 'script-defuse',
    decisions,
    accepts: () => true,
    async process(script) {
      const r = inspectScript(script.text, { ...options, context: script, knownGlobals: known });
      const result = r.verdict === 'form' ? 'passed' : 'removed';
      if (result === 'passed') for (const name of r.definedGlobals) known.add(name);
      // The container scores the script by these weights alone, so they are the ones this script's score counted:
      // a finding that strips, at the caller's weight, and nothing for one that only describes the script.
      const findings = r.findings.map(f => ({ ...f, weight: f.action === 'strip' ? weightOf(f, options) : 0 }));
      decisions.push({ script, result, findings });
      return { result, findings };
    },
  };
}
