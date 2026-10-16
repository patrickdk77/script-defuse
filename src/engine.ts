import { analyzeScript } from './analyze';
import { analyzeFormCalc } from './formcalc';
import { scoreFindings } from './score';
import type { ScriptContext, ScriptInspection, ScriptOptions } from './types';

export interface InspectScriptOptions extends ScriptOptions {
  /** Where the script runs, for the findings' locations. */
  context?: ScriptContext;
  /** Global names scripts that ran before this one defined and kept, which this one may use. */
  knownGlobals?: Iterable<string>;
}

/**
 * Inspect one script, in JavaScript or, when the context says so, in FormCalc. The verdict is 'form' when no finding strips it: every call and property it uses formats,
 * checks or calculates form fields, and nothing in it hides what it does.
 */
export function inspectScript(text: string, options: InspectScriptOptions = {}): ScriptInspection {
  const { findings, definedGlobals } =
    options.context?.language === 'formcalc'
      ? analyzeFormCalc({ text, context: options.context, options })
      : analyzeScript({ text, context: options.context, options, known: new Set(options.knownGlobals ?? []) });
  const counted = findings.filter(f => f.action === 'strip');
  const { score, risk } = scoreFindings(counted, options);
  return { verdict: counted.length ? 'unsafe' : 'form', score, risk, findings, definedGlobals };
}
