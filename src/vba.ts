import { ENCODED, isLongBlob } from './analyze';
import { makeFinding } from './findings';
import { ScriptCategory as C, ScriptDetail as D, type ScriptContext, type ScriptFinding, type ScriptOptions, type ScriptReference } from './types';

/**
 * VBA, as Office stores a module's source. A module stays when it calls nothing on the lists below: the VBA library's
 * file, process, registry and DDE functions, Declare, objects from outside the document, the Office object model's
 * members that open files, URLs and mail or run other code, and the VBA editor's objects. The lists cannot prove a
 * module safe the way the PDF allowlists can, since a macro's own names and the document's controls are names no list
 * holds. What makes them hold is that a macro reaches outside its document only through one of these, through a
 * library the project refers to, or through a class it creates, and references and classes are checked too.
 */

type Finding = readonly [C, D];
const EXT = (d: D): Finding => [C.External, d];
const DYN = (d: D): Finding => [C.DynamicCode, d];

/** Names that reach outside the document wherever they appear, bare or as a member. */
const DENY: ReadonlyMap<string, Finding> = new Map<string, Finding>([
  // VBA's own library.
  ...['kill', 'filecopy', 'mkdir', 'rmdir', 'chdir', 'chdrive', 'setattr', 'dir', 'curdir', 'filelen', 'filedatetime', 'getattr', 'fileattr', 'loadpicture', 'savepicture'].map(
    (n): [string, Finding] => [n, EXT(D.FileSystem)],
  ),
  ...['shell', 'sendkeys', 'appactivate', 'macscript', 'applescripttask'].map((n): [string, Finding] => [n, EXT(D.Process)]),
  ...['savesetting', 'getsetting', 'getallsettings', 'deletesetting'].map((n): [string, Finding] => [n, EXT(D.Registry)]),
  ...['ddeinitiate', 'ddeexecute', 'ddepoke', 'dderequest', 'ddeterminate', 'ddeterminateall'].map((n): [string, Finding] => [n, EXT(D.Dde)]),
  ['createobject', EXT(D.ComObject)],
  ['getobject', EXT(D.ComObject)],
  ['callbyname', DYN(D.ComputedAccess)],
  ...['varptr', 'strptr', 'objptr'].map((n): [string, Finding] => [n, DYN(D.Privilege)]),
  ['strreverse', [C.Obfuscation, D.Decode]],
  // The Office object model.
  ...['executeexcel4macro', 'runautomacros'].map((n): [string, Finding] => [n, DYN(D.Eval)]),
  ['wordbasic', DYN(D.LegacyMacro)],
  ['ontime', DYN(D.Timer)],
  ...[
    'vbe',
    'vbproject',
    'vbcomponents',
    'codemodule',
    'addfromstring',
    'addfromfile',
    'addfromguid',
    'insertlines',
    'replaceline',
    'deletelines',
    'addins',
    'addins2',
    'comaddins',
    'excel4macrosheets',
    'excel4intlmacrosheets',
  ].map((n): [string, Finding] => [n, DYN(D.InstallScript)]),
  ['registerxll', EXT(D.NativeCode)],
  ['automationsecurity', DYN(D.Privilege)],
  ...['followhyperlink', 'navigate', 'navigate2'].map((n): [string, Finding] => [n, EXT(D.Url)]),
  ...[
    'opentext',
    'openxml',
    'opendatabase',
    'opencurrentdatabase',
    'insertfile',
    'insertfromfile',
    'addpicture',
    'addpicture2',
    'addmediaobject',
    'addmediaobject2',
    'attachedtemplate',
    'sourcefullname',
    'changelink',
    'updatelink',
    'opendatasource',
    'insertdatabase',
    'changefileopendirectory',
  ].map((n): [string, Finding] => [n, EXT(D.OpenDocument)]),
  ['addoleobject', EXT(D.DataObject)],
  ['querytables', EXT(D.Network)],
  ...['sendmail', 'sendforreview', 'route', 'mailenvelope', 'sendfaxoverinternet'].map((n): [string, Finding] => [n, EXT(D.Mail)]),
  ['printout', EXT(D.Print)],
  ...['saveas', 'saveas2', 'savecopyas', 'exportasfixedformat', 'exportasfixedformat2', 'exportasfixedformat3', 'saveasxmldata', 'publishobjects'].map((n): [string, Finding] => [n, EXT(D.Save)]),
  ...['importxml', 'xmlimport', 'xmlimportxml', 'exportxml'].map((n): [string, Finding] => [n, EXT(D.ImportExport)]),
  ['privateprofilestring', EXT(D.Registry)],
  ['profilestring', EXT(D.Registry)],
  ['activatemicrosoftapp', EXT(D.Process)],
  // What the objects CreateObject and GetObject return offer. They only come from those, which are denied anyway.
  ...['createtextfile', 'opentextfile', 'openastextstream', 'copyfile', 'movefile', 'deletefile', 'copyfolder', 'movefolder', 'deletefolder', 'createfolder', 'savetofile', 'loadfromfile'].map(
    (n): [string, Finding] => [n, EXT(D.FileSystem)],
  ),
  ...['exec', 'shellexecute'].map((n): [string, Finding] => [n, EXT(D.Process)]),
  ...['regwrite', 'regread', 'regdelete'].map((n): [string, Finding] => [n, EXT(D.Registry)]),
  ...['executeglobal', 'executestatement', 'addcode'].map((n): [string, Finding] => [n, DYN(D.Eval)]),
]);

/** Names that reach outside only when written bare, since as a member they are common and harmless. */
const BARE: ReadonlyMap<string, Finding> = new Map<string, Finding>([
  ['environ', EXT(D.Environment)],
  ['command', EXT(D.Environment)],
  ['input', EXT(D.FileSystem)],
  ['tasks', EXT(D.Process)],
]);

/** Names that reach outside only as a member, since bare they are statements or the macro's own names. */
const MEMBER: ReadonlyMap<string, Finding> = new Map<string, Finding>([
  ['open', EXT(D.OpenDocument)],
  ['follow', EXT(D.Url)],
  ['send', EXT(D.Mail)],
  ['import', EXT(D.ImportExport)],
  ['export', EXT(D.ImportExport)],
  ['compare', EXT(D.OpenDocument)],
]);

/** A member that reaches outside after a particular collection: Hyperlinks.Add adds a link the document did not have. */
const AFTER: ReadonlyMap<string, ReadonlyMap<string, Finding>> = new Map([
  ['hyperlinks', new Map([['add', EXT(D.Url)]])],
  ['oleobjects', new Map([['add', EXT(D.DataObject)]])],
  [
    'connections',
    new Map([
      ['add', EXT(D.Network)],
      ['add2', EXT(D.Network)],
    ]),
  ],
  ['xmlmaps', new Map([['add', EXT(D.ImportExport)]])],
  ['pictures', new Map([['insert', EXT(D.OpenDocument)]])],
]);

/** Collections whose Add opens a template or file when given one. Without arguments, Add makes an empty document. */
const ADD_WITH_FILE = new Set(['workbooks', 'documents', 'presentations']);

/** Classes `New` may create: VBA's own, the Scripting runtime's dictionary, VBScript's regular expressions. */
const NEW_ALLOWED = new Set(['collection', 'dictionary', 'regexp']);
/** Classes of the allowed libraries that reach outside: the file system object, and another Office instance. */
const NEW_DENIED: ReadonlyMap<string, Finding> = new Map<string, Finding>([
  ['filesystemobject', EXT(D.FileSystem)],
  ['application', EXT(D.Process)],
]);

/**
 * Type libraries a project may refer to: VBA, OLE Automation, Office, the Office applications, Forms 2.0, the Ref Edit
 * control, the Scripting runtime and VBScript regular expressions. Every other library, and every other project but
 * Word's Normal template, adds code or objects from outside the document.
 */
const LIBRARIES = new Set(
  [
    '000204EF-0000-0000-C000-000000000046',
    '00020430-0000-0000-C000-000000000046',
    '2DF8D04C-5BFA-101B-BDE5-00AA0044DE52',
    '00020813-0000-0000-C000-000000000046',
    '00020905-0000-0000-C000-000000000046',
    '91493440-5A91-11CF-8700-00AA0060263B',
    '00021A98-0000-0000-C000-000000000046',
    '0002123C-0000-0000-C000-000000000046',
    'A7107640-94DF-1068-855E-00DD01075445',
    '0D452EE1-E08F-101A-852E-02608C4D0BB4',
    '00024517-0000-0000-C000-000000000046',
    '420B2830-E718-11CF-893D-00A0C9054228',
    '3F4DACA7-160D-11D2-A8E9-00104B365C9F',
  ].map(g => g.toUpperCase()),
);

/** A worksheet formula that reaches outside when Excel calculates it, by the function it calls. */
const FORMULA_FUNCTIONS: ReadonlyMap<string, Finding> = new Map<string, Finding>([
  ...['webservice', 'importdata', 'importxml', 'importhtml', 'importfeed', 'importrange', 'rtd'].map((n): [string, Finding] => [n, EXT(D.Network)]),
  ...['call', 'register', 'register.id'].map((n): [string, Finding] => [n, EXT(D.NativeCode)]),
  ['exec', EXT(D.Process)],
  ['hyperlink', EXT(D.Url)],
]);
const FORMULA_CALL = /([A-Za-z][A-Za-z0-9.]*)\s*\(/g;
/** A DDE formula, application|topic!item, as `=cmd|' /c calc'!A0`. */
const DDE_FORMULA = /^[=+\-@][^"]*\w\s*\|[^!]*!/;
/** A macro name that names another file, as `'other.xlsm'!Macro`, which Excel opens to run it. */
const EXTERNAL_MACRO = /\.(?:xl[a-z]{1,2}|do[ct][a-z]?|pp[a-z]{1,2})'?!/i;

interface Token {
  t: 'id' | 'str' | 'num' | 'op' | 'nl' | 'bracket' | 'date';
  /** An identifier in lower case without its type character; the text of a string or a bracketed name. */
  v: string;
  pos: number;
}

class VbaSyntaxError extends Error {}

/** The tokens of a module. A comment that ends in " _" is not taken to go on, so the line after it is read as code. */
function tokenize(text: string): Token[] {
  const out: Token[] = [];
  let i = 0;
  let lineStart = true;
  const push = (t: Token['t'], v: string, pos: number) => {
    out.push({ t, v, pos });
    lineStart = t === 'nl';
  };
  const idStart = (c: string) => /[\p{L}_]/u.test(c);
  const idPart = (c: string) => /[\p{L}\p{N}_]/u.test(c);
  while (i < text.length) {
    const c = text[i];
    if (c === '\r' || c === '\n') {
      if (out.length && out[out.length - 1].t !== 'nl') push('nl', '', i);
      lineStart = true;
      i++;
      continue;
    }
    if (c === ' ' || c === '\t' || c === '\f' || c === '\v' || c === '\u00a0') {
      i++;
      continue;
    }
    if (c === '_' && /^_[ \t]*\r?\n/.test(text.slice(i, i + 64)) && (i === 0 || /[ \t]/.test(text[i - 1]))) {
      // A line continuation: the statement goes on on the next line.
      i = text.indexOf('\n', i) + 1;
      continue;
    }
    if (c === "'") {
      while (i < text.length && text[i] !== '\n' && text[i] !== '\r') i++;
      continue;
    }
    if (c === '"') {
      const start = i;
      let s = '';
      i++;
      for (;;) {
        if (i >= text.length || text[i] === '\n' || text[i] === '\r') throw new VbaSyntaxError(`a string that does not end on its line, at offset ${start}`);
        if (text[i] === '"') {
          if (text[i + 1] === '"') {
            s += '"';
            i += 2;
            continue;
          }
          i++;
          break;
        }
        s += text[i++];
      }
      push('str', s, start);
      continue;
    }
    if (c === '[') {
      const end = text.indexOf(']', i);
      const nl = text.slice(i, end < 0 ? text.length : end).search(/[\r\n]/);
      if (end < 0 || nl >= 0) throw new VbaSyntaxError(`a bracketed name that does not end on its line, at offset ${i}`);
      push('bracket', text.slice(i + 1, end), i);
      i = end + 1;
      continue;
    }
    if (c === '#') {
      const date = /^#[0-9/:\- ,.APMapm]+#/.exec(text.slice(i, i + 64));
      if (date && /\d/.test(date[0])) {
        push('date', date[0], i);
        i += date[0].length;
        continue;
      }
      push('op', '#', i);
      i++;
      continue;
    }
    if (/[0-9]/.test(c) || (c === '.' && /[0-9]/.test(text[i + 1] ?? '')) || (c === '&' && /[hHoO]/.test(text[i + 1] ?? '') && /[0-9a-fA-F]/.test(text[i + 2] ?? ''))) {
      const m = /^(?:&[hH][0-9a-fA-F]+|&[oO][0-7]+|(?:\d+\.?\d*|\.\d+)(?:[eEdD][+-]?\d+)?)[%&!#@^]?/.exec(text.slice(i, i + 64));
      const n = m ? m[0] : c;
      push('num', n, i);
      i += n.length;
      continue;
    }
    if (idStart(c)) {
      const start = i;
      while (i < text.length && idPart(text[i])) i++;
      const name = text.slice(start, i);
      // A type character: $ always; the others only where no operand follows.
      if (text[i] === '$' || (/[%&!#@]/.test(text[i] ?? '') && !idStart(text[i + 1] ?? '') && !/[0-9"(]/.test(text[i + 1] ?? ''))) i++;
      const lower = name.toLowerCase();
      if (lower === 'rem' && (lineStart || out[out.length - 1]?.t === 'nl')) {
        while (i < text.length && text[i] !== '\n' && text[i] !== '\r') i++;
        continue;
      }
      push('id', lower, start);
      continue;
    }
    if (c === ':' && text[i + 1] === '=') {
      push('op', ':=', i);
      i += 2;
      continue;
    }
    if (c === ':') {
      push('nl', ':', i);
      i++;
      continue;
    }
    const two = text.slice(i, i + 2);
    if (two === '<>' || two === '<=' || two === '>=') {
      push('op', two, i);
      i += 2;
      continue;
    }
    if ('=<>+-*/\\^&(),.!;'.includes(c)) {
      push('op', c, i);
      i++;
      continue;
    }
    throw new VbaSyntaxError(`a character VBA does not have, ${JSON.stringify(c)}, at offset ${i}`);
  }
  return out;
}

/** Statement keywords after which a new statement starts on the same line. */
const STATEMENT_AFTER = new Set(['then', 'else']);
/** Keywords that may come before Declare and the other statements a rule looks for. */
const MODIFIERS = new Set(['public', 'private', 'friend', 'static', 'global']);
/** Statements that declare the names after them. */
const DECLARES = new Set(['dim', 'const', 'sub', 'function', 'property', 'type', 'enum', 'static', 'redim', 'global', 'public', 'private', 'friend', 'event']);
/** Keywords inside a declaration that are not names it declares. */
const DECLARATION_WORDS = new Set([...DECLARES, 'get', 'let', 'set', 'withevents', 'as', 'new', 'optional', 'byval', 'byref', 'paramarray', 'preserve', 'to', 'declare', 'ptrsafe', 'lib', 'alias']);
/** Where a procedure starts and ends, for names declared inside it. */
const PROCEDURES = new Set(['sub', 'function', 'property']);
/** Constants an Add of a new workbook, document or presentation takes in place of a template file. */
const BUILTIN_CONSTANT = /^(?:xl|wd|pp|mso|vb)/;

export interface VbaInput {
  text: string;
  context?: ScriptContext;
  options?: ScriptOptions;
}

/** Inspects one VBA module. Its findings say what it calls that reaches outside the document, and what it hides. */
export function analyzeVba(input: VbaInput): { findings: ScriptFinding[]; definedGlobals: string[] } {
  const options = input.options ?? {};
  const overrides = options.actionOverrides ?? [];
  const findings: ScriptFinding[] = [];
  const reported = new Set<string>();
  const lines: number[] = [0];
  for (let i = 0; i < input.text.length; i++) if (input.text[i] === '\n') lines.push(i + 1);
  const lineOf = (pos: number) => {
    let lo = 0;
    let hi = lines.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (lines[mid] <= pos) lo = mid;
      else hi = mid - 1;
    }
    return lo + 1;
  };
  const where = (pos?: number) => [input.context?.location ?? input.context?.trigger, pos === undefined ? '' : `line ${lineOf(pos)}`].filter(Boolean).join(', ') || undefined;
  const report = (f: Finding, pos?: number, data?: Record<string, string | number>) => {
    const key = `${f[0]}/${f[1]}/${String(data?.api ?? '')}`;
    if (reported.has(key)) return;
    reported.add(key);
    findings.push(makeFinding(f[0], f[1], overrides, where(pos), data));
  };
  const done = () => {
    if (!findings.some(f => f.action === 'strip')) report([C.Form, D.DocumentMacro]);
    return { findings, definedGlobals: [] };
  };

  for (const r of input.context?.references ?? []) checkReference(r, report);

  const limits = options.limits ?? {};
  if (limits.scriptSize !== undefined && input.text.length > limits.scriptSize) {
    report([C.Limit, D.Size], undefined, { length: input.text.length });
    return done();
  }
  let tokens: Token[];
  try {
    tokens = tokenize(input.text);
  } catch (err) {
    report([C.Syntax, D.Unparseable], undefined, { reason: err instanceof Error ? err.message : String(err) });
    return done();
  }

  // Names the module declares at its top and inside each procedure, which a bare name may mean in place of VBA's or
  // Office's. A name declared in one procedure means nothing in another.
  const moduleNames = new Set<string>();
  const scopeOf: Array<ReadonlySet<string>> = new Array(tokens.length);
  {
    let scope: Set<string> = moduleNames;
    let inProcedure = false;
    for (let i = 0; i < tokens.length; i++) {
      const tok = tokens[i];
      const prev = tokens[i - 1];
      const startsStatement = !prev || prev.t === 'nl';
      if (tok.t === 'id' && tok.v === 'end' && tokens[i + 1]?.t === 'id' && PROCEDURES.has(tokens[i + 1].v)) {
        scopeOf[i] = scope;
        inProcedure = false;
        scope = moduleNames;
        continue;
      }
      if (startsStatement && tok.t === 'id' && (DECLARES.has(tok.v) || tok.v === 'declare')) {
        let j = i;
        while (tokens[j]?.t === 'id' && DECLARATION_WORDS.has(tokens[j].v)) j++;
        const procedure = tokens.slice(i, j).some(x => PROCEDURES.has(x.v) && tokens[i].v !== 'declare');
        // The procedure's own name belongs to the module; its parameters and locals to the procedure.
        if (procedure && tokens[j]?.t === 'id') moduleNames.add(tokens[j].v);
        if (procedure && !inProcedure) {
          scope = new Set(moduleNames);
          inProcedure = true;
        }
        for (let k = procedure ? j + 1 : j; k < tokens.length && tokens[k].t !== 'nl'; k++) {
          // Every name of a declaration list but types and the parts of qualified names: Dim a, b As Long; Sub F(x As Long).
          const x = tokens[k];
          if (x.t === 'id' && !DECLARATION_WORDS.has(x.v) && tokens[k - 1]?.v !== 'as' && tokens[k - 1]?.v !== '.' && tokens[k - 1]?.v !== 'new') scope.add(x.v);
        }
      }
      scopeOf[i] = scope;
    }
  }
  const declaredAt = (pos: number) => scopeOf[pos] ?? moduleNames;
  const indexOf = new Map<Token, number>(tokens.map((t, i) => [t, i]));

  // Statements, split at line ends, colons, and after Then and Else.
  const statements: Token[][] = [];
  let current: Token[] = [];
  for (const tok of tokens) {
    if (tok.t === 'nl') {
      if (current.length) statements.push(current);
      current = [];
      continue;
    }
    current.push(tok);
    if (tok.t === 'id' && STATEMENT_AFTER.has(tok.v)) {
      statements.push(current);
      current = [];
    }
  }
  if (current.length) statements.push(current);

  const appends = new Map<string, Joined>();
  for (const st of statements) {
    let k = 0;
    // A line number, as old macros carry, comes before the statement.
    if (st[0].t === 'num') k++;
    while (st[k]?.t === 'id' && MODIFIERS.has(st[k].v)) k++;
    const first = st[k];
    const second = st[k + 1];
    const head = first?.t === 'id' && st[k - 1]?.v !== '.' ? first.v : undefined;
    if (head === 'declare') report(EXT(D.NativeCode), first.pos, { api: `Declare ${second?.t === 'id' ? second.v : ''}`.trim() });
    // The file statements: Open ... For, Print #, Write #, Input #, Line Input #, Get, Put, Lock, Unlock, Seek, Name ... As.
    if (head === 'open' || head === 'print' || head === 'write' || head === 'lock' || head === 'unlock' || (head === 'line' && second?.v === 'input'))
      report(EXT(D.FileSystem), first.pos, { api: head === 'line' ? 'Line Input' : cap(head) });
    if ((head === 'get' || head === 'put' || head === 'seek' || head === 'width') && second?.v === '#') report(EXT(D.FileSystem), first.pos, { api: cap(head) });
    if ((head === 'get' || head === 'put') && st[k - 1]?.v !== 'property' && second && second.t !== 'id' && second.v !== '(') report(EXT(D.FileSystem), first.pos, { api: cap(head) });
    if (head === 'name' && second && !['=', '.', '(', '!'].includes(second.v) && st.some((x, n) => n > k + 1 && x.t === 'id' && x.v === 'as')) report(EXT(D.FileSystem), first.pos, { api: 'Name' });
    statementRules(st, k, declaredAt(indexOf.get(st[0]) ?? 0), report, appends);
  }
  for (const [name, j] of appends) joinedRules(j, undefined, report, name);
  return done();
}

type Report = (f: Finding, pos?: number, data?: Record<string, string | number>) => void;

const cap = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);

function checkReference(r: ScriptReference, report: Report): void {
  const api = r.name || r.libid.slice(0, 60);
  if (r.kind === 'project') {
    // *\C or *\D, then the path; Word's Normal template is named without one.
    const path = r.libid.replace(/^\*\\[A-Za-z]/, '');
    if (path.toLowerCase() !== 'normal') report(EXT(D.Reference), undefined, { api });
    return;
  }
  const guid = /\{([0-9A-Fa-f-]{36})\}/.exec(r.libid)?.[1]?.toUpperCase();
  if (!guid || !LIBRARIES.has(guid)) report(EXT(D.Reference), undefined, { api });
}

/** The checks that look at the names, strings and calls of one statement. */
function statementRules(st: Token[], start: number, declared: ReadonlySet<string>, report: Report, appends: Map<string, Joined>): void {
  let charCodes = 0;
  for (let i = start; i < st.length; i++) {
    const tok = st[i];
    const prev = st[i - 1];
    const next = st[i + 1];
    if (tok.t === 'str') {
      stringRules(tok.v, tok.pos, report);
      continue;
    }
    if (tok.t === 'bracket') {
      // In Excel, [A1] and [SUM(A1:A3)] are Evaluate written short.
      formulaRules(`=${tok.v}`, tok.pos, report);
      continue;
    }
    if (tok.t !== 'id') continue;
    const member = prev?.v === '.' || prev?.v === '!';
    const name = tok.v;
    // VBA's and Office's names are taken as theirs even where the module declares the same name, since a declaration
    // in one procedure does not change what the name means in the next.
    const denied = DENY.get(name) ?? (member ? MEMBER.get(name) : declared.has(name) ? undefined : BARE.get(name));
    if (denied) report(denied, tok.pos, { api: apiName(st, i) });
    if (member && prev && st[i - 2]?.t === 'id') {
      const before = st[i - 2].v;
      const after = AFTER.get(before)?.get(name);
      if (after) report(after, tok.pos, { api: `${cap(before)}.${cap(name)}` });
      if (name === 'add' && ADD_WITH_FILE.has(before) && takesArguments(next, st[i + 2]) && namesFile(st.slice(i + 1))) report(EXT(D.OpenDocument), tok.pos, { api: `${cap(before)}.Add` });
    }
    if (name === 'new' && next?.t === 'id') {
      let j = i + 1;
      while (st[j + 1]?.v === '.' && st[j + 2]?.t === 'id') j += 2;
      const cls = st[j].v;
      const deniedClass = NEW_DENIED.get(cls);
      if (deniedClass) report(deniedClass, tok.pos, { api: `New ${st[j].v}` });
      else if (j > i + 1 && !NEW_ALLOWED.has(cls)) report(EXT(D.ComObject), tok.pos, { api: `New ${st[i + 1].v}.${cls}` });
    }
    if (name === 'addressof') report(DYN(D.Privilege), tok.pos, { api: 'AddressOf' });
    // Run "Macro" and Application.Run name, args run the macro a string names. Run alone, as SlideShowSettings.Run, runs a show.
    if (name === 'run' && (member || !declared.has(name)) && takesArguments(next, st[i + 2])) report(DYN(D.Eval), tok.pos, { api: member ? `${cap(st[i - 2]?.v ?? '')}.Run` : 'Run' });
    if (name === 'evaluate') {
      const arg = next?.v === '(' ? st[i + 2] : next;
      const close = next?.v === '(' ? st[i + 3] : st[i + 2];
      if (arg?.t === 'str' && (!close || close.v === ')' || close.t === 'nl')) formulaRules(arg.v.startsWith('=') ? arg.v : `=${arg.v}`, arg.pos, report);
      else report(DYN(D.Eval), tok.pos, { api: 'Evaluate' });
    }
    if (CHR.has(name) && next?.v === '(') {
      const inner = argumentTokens(st, i + 1);
      if (hidesLetter(inner)) charCodes++;
      const ids = new Set(inner.filter(x => x.t === 'id').map(x => x.v));
      // Chr(Asc(Mid(s, i, 1)) Xor k): a string decoded one character at a time.
      if (ids.has('xor') || ((ids.has('asc') || ids.has('ascw') || ids.has('ascb')) && (ids.has('mid') || ids.has('mid$')))) report([C.Obfuscation, D.Decode], tok.pos, { api: 'Chr(Asc(...))' });
    }
    if (name === 'replace' && next?.v === '(') {
      const args = splitArguments(argumentTokens(st, i + 1));
      const [text, find, by] = args.map(a => (a.length === 1 && a[0].t === 'str' ? a[0].v : undefined));
      // Replace("pXoXwXeXr", "X", ""): text hidden among filler in a string the macro wrote itself.
      if (text !== undefined && find && by === '' && text.split(find).length - 1 >= 3) report([C.Obfuscation, D.Decode], tok.pos, { api: 'Replace("...")' });
    }
  }
  if (charCodes >= 6) report([C.Obfuscation, D.CharCodes], st[start]?.pos, { api: 'Chr', count: charCodes });
  const chains = literalChains(st, start);
  for (const c of chains) if (c.pieces.length > 1) joinedRules(c, c.pos, report);
  // x = x & "...": a string built up one piece per statement, judged on what it holds once joined.
  const [target, eq, again, amp] = st.slice(start);
  const first = chains[0];
  if (target?.t === 'id' && eq?.v === '=' && again?.t === 'id' && again.v === target.v && (amp?.v === '&' || amp?.v === '+') && first?.start === start + 4) {
    const j = appends.get(target.v) ?? { pieces: [], pos: target.pos };
    if (j.pieces.length < 100000) j.pieces.push(...first.pieces);
    appends.set(target.v, j);
  }
}

/** String literals and Chr calls joined by & or +, with the text they make. */
interface Joined {
  pieces: string[];
  pos: number;
  /** The index of the chain's first token in its statement. */
  start?: number;
}

/** Words of a payload: programs, script hosts, URLs, file types that run, and the objects that fetch and write files. */
const PAYLOAD_WORDS = [
  'powershell',
  'cmd.exe',
  'cmd /c',
  'wscript',
  'cscript',
  'mshta',
  'rundll32',
  'regsvr32',
  'certutil',
  'bitsadmin',
  'schtasks',
  'wmic',
  'http://',
  'https://',
  'ftp://',
  '.exe',
  '.dll',
  '.vbs',
  '.hta',
  '.ps1',
  '.bat',
  '.scr',
  '.lnk',
  'createobject',
  'getobject',
  'msxml2',
  'xmlhttp',
  'winhttp',
  'adodb',
  'savetofile',
  'responsebody',
  'shell.application',
  'wscript.shell',
  'filesystemobject',
  'winmgmts',
  'win32_process',
  'frombase64string',
  'downloadfile',
  'downloadstring',
  'webclient',
  'invoke-expression',
  'start-process',
  '-encodedcommand',
  'executionpolicy',
  'urldownloadtofile',
  'kernel32',
  'virtualalloc',
  'createthread',
  'rtlmovememory',
  '%temp%',
  '%appdata%',
];

/**
 * A joined string is obfuscation when it spells a payload word no piece holds on its own, as "pow" & "ersh" & "ell",
 * and is checked as any string literal is: encoded data, a long blob, a formula.
 */
function joinedRules(j: Joined, pos: number | undefined, report: Report, api?: string): void {
  const text = j.pieces.join('');
  const lower = text.toLowerCase();
  const pieces = j.pieces.map(p => p.toLowerCase());
  const hidden = PAYLOAD_WORDS.find(w => lower.includes(w) && !pieces.some(p => p.includes(w)));
  if (hidden) report([C.Obfuscation, D.Concatenation], pos ?? j.pos, { count: j.pieces.length, ...(api ? { api } : {}), word: hidden });
  if (j.pieces.length > 1) {
    if (ENCODED.some(re => re.test(text))) report([C.Obfuscation, D.EncodedString], pos ?? j.pos, { length: text.length });
    else if (isLongBlob(text)) report([C.Obfuscation, D.LongString], pos ?? j.pos, { length: text.length });
    if (/^[=+\-@]/.test(text)) formulaRules(text, pos ?? j.pos, report);
  }
}

const CHR = new Set(['chr', 'chrw', 'chrb']);

/**
 * Whether a Chr argument writes a character a string literal could hold as it is, which only hiding it explains:
 * Chr(112) or Chr(115 - 3). Macros write control characters, the quote, the non-breaking space and smart quotes with
 * Chr, and Chr(i) of a variable is a loop's work.
 */
function hidesLetter(arg: Token[]): boolean {
  if (!arg.length || !arg.every(t => t.t === 'num' || (t.t === 'op' && '+-*/\\()'.includes(t.v)))) return false;
  if (arg.length === 1) {
    const code = numberOf(arg[0].v);
    return code >= 33 && code <= 126 && code !== 34;
  }
  return true;
}

/**
 * The chains of string literals and Chr calls joined by & or +, as "p" & "ow" & Chr(101) & "r". Pieces joined around
 * variables, as a & "," & b, are separate chains. A Chr of a computed code stands for a character no one can tell.
 */
function literalChains(st: Token[], start: number): Joined[] {
  const chains: Joined[] = [];
  let cur: Joined | undefined;
  let i = start;
  while (i < st.length) {
    const tok = st[i];
    let end = -1;
    let piece = '';
    if (tok.t === 'str') {
      end = i + 1;
      piece = tok.v;
    } else if (tok.t === 'id' && CHR.has(tok.v) && st[i + 1]?.v === '(') {
      const arg = argumentTokens(st, i + 1);
      end = i + 2 + arg.length + 1;
      const code = arg.length === 1 && arg[0].t === 'num' ? numberOf(arg[0].v) : undefined;
      piece = code !== undefined && code >= 0 && code < 0x110000 ? String.fromCodePoint(code) : '\ufffd';
    }
    if (end < 0) {
      cur = undefined;
      i++;
      continue;
    }
    if (!cur) {
      cur = { pieces: [], pos: tok.pos, start: i };
      chains.push(cur);
    }
    cur.pieces.push(piece);
    if (st[end]?.v === '&' || st[end]?.v === '+') i = end + 1;
    else {
      cur = undefined;
      i = end;
    }
  }
  return chains;
}

/** A VBA number literal's value: decimal, &H hex or &O octal, with any type character. */
function numberOf(v: string): number {
  const m = /^&([hHoO])([0-9a-fA-F]+)/.exec(v);
  return m ? Number.parseInt(m[2], /[hH]/.test(m[1]) ? 16 : 8) : Number.parseFloat(v);
}

/** Whether the arguments of an Add name a file or template: anything but Office's constants, numbers and named-argument names. */
function namesFile(args: Token[]): boolean {
  return args.some((t, k) => (t.t === 'str' && t.v !== '') || (t.t === 'id' && !BUILTIN_CONSTANT.test(t.v) && args[k + 1]?.v !== ':=' && !['true', 'false'].includes(t.v)));
}

/** Whether a call's next tokens pass it arguments: anything but the end of the statement, "=", ")" or ",". */
function takesArguments(next: Token | undefined, after: Token | undefined): boolean {
  if (!next || next.t === 'nl') return false;
  if (next.v === '(') return after !== undefined && after.v !== ')';
  if (next.t === 'op' && ['=', ')', ',', '.', ':=', '&', '+', '-', '*', '/', '<>', '<', '>', '<=', '>='].includes(next.v)) return false;
  return !(next.t === 'id' && ['then', 'else', 'and', 'or', 'xor', 'mod', 'is', 'to', 'step'].includes(next.v));
}

/** The tokens inside the parentheses that open at `open`. */
function argumentTokens(st: Token[], open: number): Token[] {
  let depth = 0;
  for (let j = open; j < st.length; j++) {
    if (st[j].v === '(' && st[j].t === 'op') depth++;
    else if (st[j].v === ')' && st[j].t === 'op' && --depth === 0) return st.slice(open + 1, j);
  }
  return st.slice(open + 1);
}

function splitArguments(tokens: Token[]): Token[][] {
  const args: Token[][] = [[]];
  let depth = 0;
  for (const tok of tokens) {
    if (tok.t === 'op' && tok.v === '(') depth++;
    if (tok.t === 'op' && tok.v === ')') depth--;
    if (tok.t === 'op' && tok.v === ',' && depth === 0) args.push([]);
    else args[args.length - 1].push(tok);
  }
  return args;
}

/** The name a finding shows: the member with what it is a member of, as Workbooks.Open. */
function apiName(st: Token[], i: number): string {
  const own = cap(st[i].v);
  return (st[i - 1]?.v === '.' || st[i - 1]?.v === '!') && st[i - 2]?.t === 'id' ? `${cap(st[i - 2].v)}.${own}` : own;
}

function stringRules(s: string, pos: number, report: Report): void {
  if (ENCODED.some(re => re.test(s))) report([C.Obfuscation, D.EncodedString], pos, { length: s.length });
  else if (isLongBlob(s)) report([C.Obfuscation, D.LongString], pos, { length: s.length });
  if (/^[=+\-@]/.test(s)) formulaRules(s, pos, report);
  if (EXTERNAL_MACRO.test(s)) report(EXT(D.OpenDocument), pos, { api: 'a macro in another file' });
}

/** A formula a macro writes into a cell or evaluates, checked for the functions and DDE links that reach outside. */
function formulaRules(formula: string, pos: number, report: Report): void {
  if (DDE_FORMULA.test(formula)) report(EXT(D.Dde), pos, { api: 'a DDE formula' });
  for (const m of formula.matchAll(FORMULA_CALL)) {
    const f = FORMULA_FUNCTIONS.get(m[1].toLowerCase().replace(/^_xlfn\./, ''));
    if (f) report(f, pos, { api: m[1].toUpperCase() });
  }
}
