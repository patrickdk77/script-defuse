import { ENCODED, isLongBlob } from './analyze';
import { CODE_NODES, DOC, HOST_DENY, type Kind, type Member, NODE_DENY, NODE_VALUES, SOM_ROOTS, URL_ATTRIBUTES, XFA_EVENT, XFA_HOST, XFA_LAYOUT, XFA_ROOT } from './api';
import { makeFinding } from './findings';
import { ScriptCategory as C, ScriptDetail as D, type ScriptContext, type ScriptFinding, type ScriptOptions } from './types';

/**
 * FormCalc, the calculation language of XFA forms. A script is a list of expressions: arithmetic, comparisons, the
 * built-in functions, and references to form nodes written in the SOM, such as `$.rawValue` or `Total[0]`. The rules
 * are the JavaScript rules for an XFA script, applied to what FormCalc can say.
 */

interface Tok {
  t: 'num' | 'str' | 'id' | 'op' | 'kw' | 'eof';
  v: string;
  pos: number;
  /** A string as written, escapes and all. */
  raw?: string;
}

interface Seg {
  name: string;
  pos: number;
  /** `..name`, `.*` or `.[predicate]`, which select among a node's descendants. */
  select?: boolean;
  index?: Expr;
  call?: Expr[];
}

type Expr =
  | { t: 'num'; value: number; pos: number }
  | { t: 'str'; value: string; raw: string; pos: number }
  | { t: 'lit'; pos: number }
  | { t: 'ref'; base?: Expr; segs: Seg[]; pos: number }
  | { t: 'call'; name: string; args: Expr[]; pos: number }
  | { t: 'un'; arg: Expr; pos: number }
  | { t: 'bin'; l: Expr; r: Expr; pos: number }
  | { t: 'assign'; target: Extract<Expr, { t: 'ref' }>; value: Expr; pos: number }
  | { t: 'var'; name: string; init?: Expr; pos: number }
  | { t: 'func'; name: string; params: string[]; body: Expr[]; pos: number }
  | { t: 'block'; parts: Expr[]; pos: number };

const KEYWORDS = new Set([
  'and',
  'break',
  'continue',
  'do',
  'downto',
  'else',
  'elseif',
  'end',
  'endfor',
  'endfunc',
  'endif',
  'endwhile',
  'eq',
  'for',
  'foreach',
  'func',
  'ge',
  'gt',
  'if',
  'in',
  'infinity',
  'le',
  'lt',
  'nan',
  'ne',
  'not',
  'null',
  'or',
  'return',
  'step',
  'then',
  'this',
  'throw',
  'upto',
  'var',
  'while',
]);

/** The built-in functions, by lower-case name. FormCalc names are case-insensitive. */
const FUNCTIONS = new Set(
  [
    'Abs',
    'Avg',
    'Ceil',
    'Count',
    'Floor',
    'Max',
    'Min',
    'Mod',
    'Round',
    'Sum',
    'Date',
    'Date2Num',
    'DateFmt',
    'IsoDate2Num',
    'IsoTime2Num',
    'LocalDateFmt',
    'LocalTimeFmt',
    'Num2Date',
    'Num2GMTime',
    'Num2Time',
    'Time',
    'Time2Num',
    'TimeFmt',
    'Apr',
    'CTerm',
    'FV',
    'IPmt',
    'NPV',
    'Pmt',
    'PPmt',
    'PV',
    'Rate',
    'Term',
    'Choose',
    'Exists',
    'HasValue',
    'Oneof',
    'Within',
    'Null',
    'Ref',
    'UnitType',
    'UnitValue',
    'At',
    'Concat',
    'Encode',
    'Format',
    'Left',
    'Len',
    'Lower',
    'Ltrim',
    'Parse',
    'Replace',
    'Right',
    'Rtrim',
    'Space',
    'Str',
    'Stuff',
    'Substr',
    'Uuid',
    'Upper',
    'WordNum',
  ].map(s => s.toLowerCase()),
);

/** Built-in functions that reach outside the form, run text as code, or uncover hidden text. */
const DENIED_FUNCTIONS: ReadonlyMap<string, [C, D]> = new Map<string, [C, D]>([
  ['get', [C.External, D.Network]],
  ['post', [C.External, D.Network]],
  ['put', [C.External, D.Network]],
  ['eval', [C.DynamicCode, D.Eval]],
  ['decode', [C.Obfuscation, D.Decode]],
]);

const TABLES: ReadonlyMap<Kind, ReadonlyMap<string, Member>> = new Map<Kind, ReadonlyMap<string, Member>>([
  ['xfa', XFA_ROOT],
  ['xfahost', XFA_HOST],
  ['xfalayout', XFA_LAYOUT],
  ['xfaevent', XFA_EVENT],
  ['doc', DOC],
]);

/** Node methods that change the form's own trees, which only data may go through. */
const DATA_ONLY = new Set(['loadXML', 'assignNode']);
const DATA_PATH = /^(?:xfa\.(?:datasets|data|record)|\$data|\$record|!)/;
/** \u00XX escapes of printable ASCII, which a script has no reason to write. */
const NEEDLESS_ESCAPE = /\\u00(?:[2-7][0-9a-fA-F])/g;

class FormCalcSyntaxError extends Error {}

/** Space, tab, CR, LF, form feed, vertical tab, no-break space and the byte order mark. */
const WHITESPACE = new Set([0x20, 0x09, 0x0d, 0x0a, 0x0c, 0x0b, 0xa0, 0xfeff]);

function tokenize(text: string): Tok[] {
  const out: Tok[] = [];
  let i = 0;
  const n = text.length;
  const isIdStart = (c: string) => /[A-Za-z_$!#]/.test(c) || c.charCodeAt(0) >= 0x80;
  const isId = (c: string) => /[A-Za-z0-9_$]/.test(c) || c.charCodeAt(0) >= 0x80;
  const isDigit = (c: string | undefined) => c !== undefined && c >= '0' && c <= '9';
  while (i < n) {
    const c = text[i];
    if (WHITESPACE.has(c.charCodeAt(0))) {
      i++;
      continue;
    }
    if (c === ';' || (c === '/' && text[i + 1] === '/')) {
      while (i < n && text[i] !== '\n' && text[i] !== '\r') i++;
      continue;
    }
    const pos = i;
    if (c === '"') {
      let value = '';
      i++;
      for (;;) {
        if (i >= n) throw new FormCalcSyntaxError(`unterminated string at ${pos}`);
        const d = text[i];
        if (d === '"') {
          if (text[i + 1] === '"') {
            value += '"';
            i += 2;
            continue;
          }
          i++;
          break;
        }
        if (d === '\\' && (text[i + 1] === 'u' || text[i + 1] === 'U') && /^[0-9a-fA-F]{4}$/.test(text.slice(i + 2, i + 6))) {
          value += String.fromCharCode(Number.parseInt(text.slice(i + 2, i + 6), 16));
          i += 6;
          continue;
        }
        value += d;
        i++;
      }
      out.push({ t: 'str', v: value, pos, raw: text.slice(pos, i) });
      continue;
    }
    const prev = out[out.length - 1];
    const operand = !prev || (prev.t === 'op' && prev.v !== ')' && prev.v !== ']') || (prev.t === 'kw' && !['null', 'infinity', 'nan', 'this'].includes(prev.v));
    if (isDigit(c) || (c === '.' && isDigit(text[i + 1]) && operand)) {
      const m = /^(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?/.exec(text.slice(i, i + 400));
      if (!m) throw new FormCalcSyntaxError(`bad number at ${pos}`);
      out.push({ t: 'num', v: m[0], pos });
      i += m[0].length;
      continue;
    }
    if (isIdStart(c)) {
      i++;
      while (i < n && isId(text[i])) i++;
      const v = text.slice(pos, i);
      const lower = v.toLowerCase();
      if (KEYWORDS.has(lower)) out.push({ t: 'kw', v: lower, pos });
      else out.push({ t: 'id', v, pos });
      continue;
    }
    const two = text.slice(i, i + 2);
    if (two === '==' || two === '<>' || two === '<=' || two === '>=' || two === '..') {
      out.push({ t: 'op', v: two, pos });
      i += 2;
      continue;
    }
    if ('=<>+-*/&|()[],.'.includes(c)) {
      out.push({ t: 'op', v: c, pos });
      i++;
      continue;
    }
    throw new FormCalcSyntaxError(`unexpected ${JSON.stringify(c)} at ${pos}`);
  }
  out.push({ t: 'eof', v: '', pos: n });
  return out;
}

class Parser {
  private i = 0;
  private depth = 0;
  deepest = 0;
  constructor(
    private readonly toks: Tok[],
    private readonly maxDepth: number,
  ) {}

  private get tok(): Tok {
    return this.toks[this.i];
  }
  private next(): Tok {
    return this.toks[this.i++];
  }
  private isOp(v: string): boolean {
    return this.tok.t === 'op' && this.tok.v === v;
  }
  private isKw(...v: string[]): boolean {
    return this.tok.t === 'kw' && v.includes(this.tok.v);
  }
  private expectOp(v: string): void {
    if (!this.isOp(v)) this.fail(`expected ${v}`);
    this.i++;
  }
  private expectKw(v: string): void {
    if (!this.isKw(v)) this.fail(`expected ${v}`);
    this.i++;
  }
  private fail(msg: string): never {
    throw new FormCalcSyntaxError(`${msg} at ${this.tok.pos}${this.tok.v ? ` (${JSON.stringify(this.tok.v)})` : ''}`);
  }
  private enter(): void {
    this.depth++;
    if (this.depth > this.deepest) this.deepest = this.depth;
    if (this.depth > this.maxDepth) throw new DepthError();
  }
  private leave(): void {
    this.depth--;
  }

  program(): Expr[] {
    const list = this.list([]);
    if (this.tok.t !== 'eof') this.fail('unexpected');
    return list;
  }

  /** Expressions up to one of the keywords that close the construct, which is left for the caller. */
  private list(stop: string[]): Expr[] {
    const out: Expr[] = [];
    while (this.tok.t !== 'eof' && !this.isKw(...stop)) out.push(this.expression());
    if (stop.length && this.tok.t === 'eof') this.fail(`expected ${stop.join(' or ')}`);
    return out;
  }

  private ident(): string {
    if (this.tok.t !== 'id') this.fail('expected a name');
    return this.next().v;
  }

  private expression(): Expr {
    this.enter();
    try {
      const t = this.tok;
      if (t.t === 'kw') {
        switch (t.v) {
          case 'if': {
            this.i++;
            const parts: Expr[] = [];
            this.expectOp('(');
            parts.push(this.simple());
            this.expectOp(')');
            this.expectKw('then');
            parts.push(...this.list(['elseif', 'else', 'endif']));
            while (this.isKw('elseif')) {
              this.i++;
              this.expectOp('(');
              parts.push(this.simple());
              this.expectOp(')');
              this.expectKw('then');
              parts.push(...this.list(['elseif', 'else', 'endif']));
            }
            if (this.isKw('else')) {
              this.i++;
              parts.push(...this.list(['endif']));
            }
            this.expectKw('endif');
            return { t: 'block', parts, pos: t.pos };
          }
          case 'while': {
            this.i++;
            this.expectOp('(');
            const parts = [this.simple()];
            this.expectOp(')');
            this.expectKw('do');
            parts.push(...this.list(['endwhile']));
            this.expectKw('endwhile');
            return { t: 'block', parts, pos: t.pos };
          }
          case 'for': {
            this.i++;
            if (this.isKw('var')) this.i++;
            const name = this.ident();
            this.expectOp('=');
            const parts: Expr[] = [{ t: 'var', name, init: this.simple(), pos: t.pos }];
            if (!this.isKw('upto', 'downto')) this.fail('expected upto or downto');
            this.i++;
            parts.push(this.simple());
            if (this.isKw('step')) {
              this.i++;
              parts.push(this.simple());
            }
            this.expectKw('do');
            parts.push(...this.list(['endfor']));
            this.expectKw('endfor');
            return { t: 'block', parts, pos: t.pos };
          }
          case 'foreach': {
            this.i++;
            const name = this.ident();
            this.expectKw('in');
            this.expectOp('(');
            const parts: Expr[] = [{ t: 'var', name, pos: t.pos }, ...this.args()];
            this.expectKw('do');
            parts.push(...this.list(['endfor']));
            this.expectKw('endfor');
            return { t: 'block', parts, pos: t.pos };
          }
          case 'do': {
            this.i++;
            const parts = this.list(['end']);
            this.expectKw('end');
            return { t: 'block', parts, pos: t.pos };
          }
          case 'var': {
            this.i++;
            const name = this.ident();
            if (this.isOp('=')) {
              this.i++;
              return { t: 'var', name, init: this.simple(), pos: t.pos };
            }
            return { t: 'var', name, pos: t.pos };
          }
          case 'func': {
            this.i++;
            const name = this.ident();
            this.expectOp('(');
            const params: string[] = [];
            if (!this.isOp(')')) {
              params.push(this.ident());
              while (this.isOp(',')) {
                this.i++;
                params.push(this.ident());
              }
            }
            this.expectOp(')');
            this.expectKw('do');
            const body = this.list(['endfunc']);
            this.expectKw('endfunc');
            return { t: 'func', name, params, body, pos: t.pos };
          }
          case 'break':
          case 'continue':
            this.i++;
            return { t: 'lit', pos: t.pos };
          case 'return':
          case 'throw': {
            this.i++;
            const ends = this.tok.t === 'eof' || (this.tok.t === 'kw' && ['end', 'endif', 'endfor', 'endfunc', 'endwhile', 'else', 'elseif'].includes(this.tok.v));
            return ends ? { t: 'lit', pos: t.pos } : { t: 'block', parts: [this.simple()], pos: t.pos };
          }
          default:
            break;
        }
      }
      const e = this.simple();
      if (this.isOp('=')) {
        if (e.t !== 'ref' || e.segs[e.segs.length - 1]?.call) this.fail('cannot assign to this');
        this.i++;
        return { t: 'assign', target: e, value: this.simple(), pos: e.pos };
      }
      return e;
    } finally {
      this.leave();
    }
  }

  private simple(): Expr {
    return this.binary(0);
  }

  private static readonly LEVELS: ReadonlyArray<ReadonlyArray<string>> = [
    ['|', 'or'],
    ['&', 'and'],
    ['==', '<>', 'eq', 'ne'],
    ['<', '>', '<=', '>=', 'lt', 'gt', 'le', 'ge'],
    ['+', '-'],
    ['*', '/'],
  ];

  private binary(level: number): Expr {
    if (level >= Parser.LEVELS.length) return this.unary();
    this.enter();
    try {
      let l = this.binary(level + 1);
      const ops = Parser.LEVELS[level];
      while ((this.tok.t === 'op' || this.tok.t === 'kw') && ops.includes(this.tok.v)) {
        const pos = this.next().pos;
        l = { t: 'bin', l, r: this.binary(level + 1), pos };
      }
      return l;
    } finally {
      this.leave();
    }
  }

  private unary(): Expr {
    this.enter();
    try {
      if (this.isOp('-') || this.isOp('+') || this.isKw('not')) {
        const pos = this.next().pos;
        return { t: 'un', arg: this.unary(), pos };
      }
      return this.primary();
    } finally {
      this.leave();
    }
  }

  private args(): Expr[] {
    const out: Expr[] = [];
    if (!this.isOp(')')) {
      out.push(this.simple());
      while (this.isOp(',')) {
        this.i++;
        out.push(this.simple());
      }
    }
    this.expectOp(')');
    return out;
  }

  private primary(): Expr {
    const t = this.tok;
    if (t.t === 'num') {
      this.i++;
      return { t: 'num', value: Number(t.v), pos: t.pos };
    }
    if (t.t === 'str') {
      this.i++;
      return this.postfix({ t: 'str', value: t.v, raw: t.raw ?? '', pos: t.pos });
    }
    if (t.t === 'kw' && (t.v === 'null' || t.v === 'infinity' || t.v === 'nan')) {
      this.i++;
      return { t: 'lit', pos: t.pos };
    }
    if (this.isOp('(')) {
      this.i++;
      const e = this.simple();
      this.expectOp(')');
      return this.postfix(e);
    }
    if (t.t === 'id' || (t.t === 'kw' && t.v === 'this')) {
      this.i++;
      if (t.t === 'id' && this.isOp('(') && !/^[$!#]/.test(t.v)) {
        this.i++;
        return this.postfix({ t: 'call', name: t.v, args: this.args(), pos: t.pos });
      }
      const root: Seg = { name: t.v, pos: t.pos };
      const ref: Extract<Expr, { t: 'ref' }> = { t: 'ref', segs: [root], pos: t.pos };
      this.segments(ref);
      return ref;
    }
    return this.fail('unexpected');
  }

  /** Accessors after a value that is not a name, such as a call's result. */
  private postfix(e: Expr): Expr {
    if (!this.isOp('.') && !this.isOp('..') && !this.isOp('[')) return e;
    const ref: Extract<Expr, { t: 'ref' }> = { t: 'ref', base: e, segs: [], pos: e.pos };
    this.segments(ref);
    return ref;
  }

  private segments(ref: Extract<Expr, { t: 'ref' }>): void {
    for (;;) {
      const last = ref.segs[ref.segs.length - 1];
      if (this.isOp('[')) {
        this.i++;
        let index: Expr;
        if (this.isOp('*')) {
          index = { t: 'lit', pos: this.next().pos };
        } else index = this.simple();
        this.expectOp(']');
        if (last) last.index = index;
        else ref.segs.push({ name: '[]', pos: index.pos, index, select: true });
        continue;
      }
      if (this.isOp('.') || this.isOp('..')) {
        const descend = this.next().v === '..';
        const pos = this.tok.pos;
        if (this.isOp('*')) {
          this.i++;
          ref.segs.push({ name: '*', pos, select: true });
          continue;
        }
        if (this.isOp('[')) {
          this.i++;
          const index = this.simple();
          this.expectOp(']');
          ref.segs.push({ name: '[]', pos, index, select: true });
          continue;
        }
        if (this.tok.t !== 'id' && this.tok.t !== 'kw') this.fail('expected a name');
        const seg: Seg = { name: this.next().v, pos, select: descend };
        if (this.isOp('(')) {
          this.i++;
          seg.call = this.args();
        }
        ref.segs.push(seg);
        continue;
      }
      return;
    }
  }
}

class DepthError extends Error {}

export interface FormCalcInput {
  text: string;
  context?: ScriptContext;
  options?: ScriptOptions;
}

export function analyzeFormCalc(input: FormCalcInput): { findings: ScriptFinding[]; definedGlobals: string[] } {
  const options = input.options ?? {};
  const overrides = options.actionOverrides ?? [];
  const findings: ScriptFinding[] = [];
  const reported = new Set<string>();
  const where = (pos?: number) => {
    const line = pos === undefined ? '' : `line ${lineOf(input.text, pos)}`;
    const ctx = input.context?.location ?? (input.context?.fieldName ? `field ${JSON.stringify(input.context.fieldName)}` : input.context?.trigger);
    return [ctx, line].filter(Boolean).join(', ') || undefined;
  };
  const report = (c: C, d: D, pos?: number, data?: Record<string, string | number>) => {
    const key = `${c}/${d}/${String(data?.api ?? '')}`;
    if (reported.has(key)) return;
    reported.add(key);
    findings.push(makeFinding(c, d, overrides, where(pos), data));
  };
  const reportMember = (m: Member | undefined, api: string, pos: number) => {
    if (m && 'finding' in m) report(m.finding[0], m.finding[1], pos, { api });
  };
  const done = () => {
    if (!findings.some(f => f.action === 'strip')) report(C.Form, D.Computation);
    return { findings, definedGlobals: [] };
  };

  const limits = options.limits ?? {};
  if (limits.scriptSize !== undefined && input.text.length > limits.scriptSize) {
    report(C.Limit, D.Size, undefined, { length: input.text.length });
    return { findings, definedGlobals: [] };
  }
  let program: Expr[];
  try {
    const parser = new Parser(tokenize(input.text), limits.depth ?? Number.POSITIVE_INFINITY);
    program = parser.program();
  } catch (err) {
    if (err instanceof DepthError) report(C.Limit, D.Depth, undefined, { depth: limits.depth ?? 0 });
    else report(C.Syntax, D.Unparseable, undefined, { reason: err instanceof Error ? err.message : String(err) });
    return { findings, definedGlobals: [] };
  }

  // Names the script declares: functions, variables, parameters and loop variables. They hold values, not nodes.
  const funcs = new Set<string>();
  const vars = new Set<string>();
  const declare = (e: Expr) => {
    if (e.t === 'func') {
      funcs.add(e.name.toLowerCase());
      for (const p of e.params) vars.add(p);
      e.body.forEach(declare);
    } else if (e.t === 'var') {
      vars.add(e.name);
      if (e.init) declare(e.init);
    } else for (const c of childrenOf(e)) declare(c);
  };
  program.forEach(declare);

  const describe = (ref: Extract<Expr, { t: 'ref' }>, upTo = ref.segs.length): string => {
    const head = ref.base ? (ref.base.t === 'call' ? `${ref.base.name}()` : '(...)') : '';
    const parts = ref.segs.slice(0, upTo).map((s, i) => `${i === 0 && !ref.base ? '' : '.'}${s.name}${s.call ? '()' : ''}`);
    return head + parts.join('');
  };

  /** The kind of a member of a value of `kind`, reporting what the member reaches. */
  const member = (kind: Kind, name: string, api: string, pos: number, write: boolean): Kind => {
    const t = TABLES.get(kind);
    if (t) {
      const m = t.get(name);
      if (!m) {
        report(C.Api, D.Unknown, pos, { api });
        return 'node';
      }
      if ('finding' in m) {
        reportMember(m, api, pos);
        return 'node';
      }
      if (write && !m.write) report(C.Api, D.Unknown, pos, { api: `${api} =` });
      return m.kind;
    }
    const deny = HOST_DENY.get(name) ?? NODE_DENY.get(name);
    if (deny) reportMember(deny, api, pos);
    else if (write && URL_ATTRIBUTES.has(name)) report(C.External, D.Url, pos, { api: `${api} =` });
    return NODE_VALUES.get(name) ?? 'node';
  };

  const rootKind = (name: string, pos: number): Kind => {
    if (vars.has(name)) return 'data';
    if (name === 'xfa') return 'xfa';
    if (name === 'this') return 'node';
    const som = SOM_ROOTS.get(name);
    if (som !== undefined) {
      if (typeof som === 'string') return som;
      reportMember(som, name, pos);
      return 'node';
    }
    if (name.startsWith('!')) return 'node';
    if (name.startsWith('$')) {
      report(C.Api, D.Unknown, pos, { api: name });
      return 'node';
    }
    // A form node by name, unless it is a name a viewer object has that leaves the form.
    const deny = HOST_DENY.get(name) ?? NODE_DENY.get(name);
    if (deny) reportMember(deny, name, pos);
    return 'node';
  };

  const checkStrings = (e: Extract<Expr, { t: 'str' }>) => {
    const s = e.value;
    if (ENCODED.some(re => re.test(s)) || ENCODED.some(re => re.test(e.raw))) report(C.Obfuscation, D.EncodedString, e.pos, { length: s.length });
    else if (isLongBlob(s)) report(C.Obfuscation, D.LongString, e.pos, { length: s.length });
    const escapes = e.raw.match(NEEDLESS_ESCAPE)?.length ?? 0;
    if (escapes >= 3) report(C.Obfuscation, D.Escapes, e.pos, { count: escapes });
  };

  const literalOf = (e: Expr | undefined) => (e?.t === 'str' ? e.value : undefined);

  const visitRef = (ref: Extract<Expr, { t: 'ref' }>, write: boolean) => {
    let kind: Kind = 'data';
    if (ref.base) visit(ref.base);
    ref.segs.forEach((seg, i) => {
      if (seg.index) visit(seg.index);
      for (const a of seg.call ?? []) visit(a);
      const api = describe(ref, i + 1);
      const isWrite = write && i === ref.segs.length - 1;
      if (i === 0 && !ref.base) kind = rootKind(seg.name, seg.pos);
      else if (seg.select) kind = 'node';
      else {
        const parent = kind;
        kind = member(parent, seg.name, api.replace(/\(\)$/, ''), seg.pos, isWrite);
        // $host.response(question, title, default, 1): a password asked for in a prompt.
        if (seg.call && parent === 'xfahost' && seg.name === 'response') {
          const flag = seg.call[3];
          if (flag && !(flag.t === 'num' && flag.value === 0) && flag.t !== 'lit') report(C.Api, D.PasswordPrompt, seg.pos, { api: api.replace(/\(\)$/, '') });
        }
        if (seg.call && (parent === 'node' || parent === 'data' || parent === 'xfa')) {
          const receiver = describe(ref, i);
          const first = literalOf(seg.call[0]);
          if (seg.name === 'createNode' && (first === undefined || CODE_NODES.has(first)))
            report(C.DynamicCode, D.InstallScript, seg.pos, { api: `${api.replace(/\(\)$/, '')}(${first === undefined ? '...' : JSON.stringify(first)})` });
          if (DATA_ONLY.has(seg.name) && !DATA_PATH.test(receiver)) report(C.DynamicCode, D.InstallScript, seg.pos, { api: api.replace(/\(\)$/, '') });
          if (seg.name === 'setAttribute') {
            const attr = literalOf(seg.call[1]);
            if (attr === undefined || URL_ATTRIBUTES.has(attr)) report(C.External, D.Url, seg.pos, { api: `${api.replace(/\(\)$/, '')}(..., ${attr === undefined ? '...' : JSON.stringify(attr)})` });
          }
        }
      }
    });
  };

  const visit = (e: Expr): void => {
    switch (e.t) {
      case 'str':
        checkStrings(e);
        return;
      case 'ref':
        visitRef(e, false);
        return;
      case 'assign':
        visitRef(e.target, true);
        visit(e.value);
        return;
      case 'call': {
        const name = e.name.toLowerCase();
        e.args.forEach(visit);
        const denied = DENIED_FUNCTIONS.get(name);
        if (denied) report(denied[0], denied[1], e.pos, { api: e.name });
        else if (!FUNCTIONS.has(name) && !funcs.has(name)) report(C.Api, D.Unknown, e.pos, { api: e.name });
        if (name === 'concat') {
          const literals = e.args.filter(a => a.t === 'str');
          const tiny = literals.filter(a => a.t === 'str' && a.value.length <= 2).length;
          if (tiny >= 6 || literals.length >= 25) report(C.Obfuscation, D.Concatenation, e.pos, { count: e.args.length });
        }
        // Replace("qwqoqrqd", "q", ""): text hidden among filler in a string the script wrote itself.
        if (name === 'replace' && (literalOf(e.args[0])?.length ?? 0) > 3) report(C.Obfuscation, D.Decode, e.pos, { api: 'Replace("...")' });
        return;
      }
      default:
        for (const c of childrenOf(e)) visit(c);
    }
  };
  program.forEach(visit);
  return done();
}

function childrenOf(e: Expr): Expr[] {
  switch (e.t) {
    case 'ref':
      return [...(e.base ? [e.base] : []), ...e.segs.flatMap(s => [...(s.index ? [s.index] : []), ...(s.call ?? [])])];
    case 'call':
      return e.args;
    case 'un':
      return [e.arg];
    case 'bin':
      return [e.l, e.r];
    case 'assign':
      return [e.target, e.value];
    case 'var':
      return e.init ? [e.init] : [];
    case 'func':
      return e.body;
    case 'block':
      return e.parts;
    default:
      return [];
  }
}

function lineOf(text: string, offset: number): number {
  let line = 1;
  for (let i = 0; i < offset && i < text.length; i++) if (text.charCodeAt(i) === 10) line++;
  return line;
}
