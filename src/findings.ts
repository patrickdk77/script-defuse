import { ScriptCategory as C, ScriptDetail as D, type ScriptActionOverride, type ScriptFinding, type ScriptFindingAction } from './types';

interface Spec {
  action: ScriptFindingAction;
  /** May contain <key> placeholders filled from data. A filled value has control characters replaced by "?" and is cut to 60 characters. */
  description: string;
  weight: number;
}

const specs = new Map<string, Spec>();
function def(c: C, d: D, action: ScriptFindingAction, weight: number, description: string): void {
  specs.set(`${c}/${d}`, { action, weight, description });
}

// FORM
def(C.Form, D.Computation, 'info', 0, 'The script only formats, checks or calculates form fields');
def(C.Form, D.DocumentMacro, 'info', 0, 'The macro calls nothing script-defuse knows to reach outside its document');
// EXTERNAL
def(C.External, D.Url, 'strip', 60, '<api> opens a web address');
def(C.External, D.Submit, 'strip', 50, '<api> sends the form data somewhere');
def(C.External, D.Mail, 'strip', 50, '<api> sends mail');
def(C.External, D.OpenDocument, 'strip', 60, '<api> opens or creates another document');
def(C.External, D.DataObject, 'strip', 70, '<api> reads, writes or opens a file attached to the document');
def(C.External, D.ImportExport, 'strip', 50, '<api> reads or writes form data or files outside the document');
def(C.External, D.Network, 'strip', 70, '<api> talks to a network service');
def(C.External, D.MenuCommand, 'strip', 60, '<api> runs a viewer menu command');
def(C.External, D.Print, 'strip', 20, '<api> prints');
def(C.External, D.Save, 'strip', 30, '<api> saves or closes the document');
def(C.External, D.FileSystem, 'strip', 70, '<api> reads, writes or lists files and folders');
def(C.External, D.Process, 'strip', 90, '<api> starts a program or sends keystrokes to one');
def(C.External, D.Registry, 'strip', 60, '<api> reads or writes the registry or settings files');
def(C.External, D.Dde, 'strip', 80, '<api> talks to another program over DDE');
def(C.External, D.ComObject, 'strip', 80, '<api> creates or gets an object from outside the document, such as a shell or a web request');
def(C.External, D.NativeCode, 'strip', 90, '<api> calls native code in a library');
def(C.External, D.Environment, 'strip', 30, '<api> reads the environment of the computer it runs on');
def(C.External, D.Reference, 'strip', 60, 'The project refers to <api>, a library or project from outside the document');
// DYNAMIC_CODE
def(C.DynamicCode, D.Eval, 'strip', 80, '<api> runs code built from a string');
def(C.DynamicCode, D.Timer, 'strip', 70, '<api> runs code later, from a string');
def(C.DynamicCode, D.InstallScript, 'strip', 70, '<api> installs another script or action');
def(C.DynamicCode, D.Privilege, 'strip', 80, '<api> asks for privileged execution');
def(C.DynamicCode, D.ComputedAccess, 'strip', 40, 'A property is read by a name computed at run time, so what it reaches cannot be told');
def(C.DynamicCode, D.Prototype, 'strip', 60, '<api> reaches the language machinery behind objects and functions');
def(C.DynamicCode, D.With, 'strip', 40, 'A with statement changes what names refer to');
def(C.DynamicCode, D.SelfReference, 'strip', 60, '<api> reads the source of the running code, the way self-decrypting scripts do');
def(C.DynamicCode, D.LegacyMacro, 'strip', 80, '<api> runs a command of an older macro language, which reaches outside the document');
// OBFUSCATION
def(C.Obfuscation, D.CharCodes, 'strip', 50, 'Text is built from character codes');
def(C.Obfuscation, D.Decode, 'strip', 60, '<api> decodes hidden text');
def(C.Obfuscation, D.Concatenation, 'strip', 40, 'A string is joined from many short pieces');
def(C.Obfuscation, D.Escapes, 'strip', 40, 'A string writes ordinary letters as escape sequences');
def(C.Obfuscation, D.EncodedString, 'strip', 50, 'A string holds encoded data');
def(C.Obfuscation, D.LongString, 'strip', 40, 'A string far longer than form text');
def(C.Obfuscation, D.NumberExpression, 'strip', 30, 'A number is written as arithmetic on hex constants');
def(C.Obfuscation, D.BracketName, 'strip', 30, '<api> is reached by a quoted name where a form script names it plainly');
// API
def(C.Api, D.Exploited, 'strip', 80, '<api> is a viewer API known from exploits');
def(C.Api, D.Unknown, 'strip', 30, '<api> is not a form calculation, format or check');
def(C.Api, D.PasswordPrompt, 'strip', 50, '<api> asks for a password in a prompt, as a fake sign-in does. A form takes a password in a field of its own');
// SYNTAX
def(C.Syntax, D.Unparseable, 'strip', 50, 'The script does not parse, so what it does cannot be told');
// LIMIT
def(C.Limit, D.Size, 'strip', 30, 'The script is longer than limits.scriptSize');
def(C.Limit, D.Depth, 'strip', 30, 'The script nests deeper than limits.depth');

export function findingSpec(c: string, d: string): Spec | undefined {
  return specs.get(`${c}/${d}`);
}

const clip = (v: string | number) =>
  String(v)
    .replace(/[\p{Cc}\p{Cf}]/gu, '?')
    .slice(0, 60);

/** A finding with its default action, after the caller's overrides. */
export function makeFinding(c: C, d: D, overrides: ScriptActionOverride[] = [], location?: string, data?: Record<string, string | number>): ScriptFinding {
  const spec = specs.get(`${c}/${d}`);
  if (!spec) throw new Error(`no finding spec for ${c}/${d}`);
  const exact = overrides.find(o => o.category === c && o.detail === d);
  const byCategory = overrides.find(o => o.category === c && o.detail === undefined);
  const action = exact?.action ?? byCategory?.action ?? spec.action;
  const description = spec.description.replace(/<(\w+)>/g, (_m, key: string) => (data?.[key] === undefined ? key : clip(data[key])));
  const f: ScriptFinding = { category: c, detail: d, description, action, weight: spec.weight };
  if (location) f.location = location;
  if (data) f.data = data;
  return f;
}

/** Every finding kind this package can report, with its default action, weight and description. */
export function allFindingSpecs(): Array<{ category: C; detail: D; action: ScriptFindingAction; weight: number; description: string }> {
  return [...specs].map(([key, spec]) => {
    const [category, detail] = key.split('/') as [C, D];
    return { category, detail, ...spec };
  });
}
