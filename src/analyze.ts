import { type AnyNode, type Expression, type Node, type Pattern, parse } from 'acorn';
import {
  AFORM,
  APP,
  BUILTIN_DENY,
  BUILTIN_FUNCTIONS,
  BUILTIN_NAMESPACES,
  CODE_NODES,
  COLOR,
  CONSOLE,
  CONSTANT_ROOTS,
  DENIED_GLOBALS,
  DOC,
  DOC_ALL,
  EVENT,
  FIELD,
  HOST_DENY,
  HOST_KINDS,
  type Kind,
  MACHINERY,
  type Member,
  NODE_DENY,
  NODE_VALUES,
  SOM_ROOTS,
  URL_ATTRIBUTES,
  UTIL,
  XFA_EVENT,
  XFA_HOST,
  XFA_LAYOUT,
  XFA_ROOT,
  XMLDATA,
} from './api';
import { makeFinding } from './findings';
import { ScriptCategory as C, ScriptDetail as D, type ScriptContext, type ScriptFinding, type ScriptOptions } from './types';

/** Functions a script defines at its top level, and a script run after it may call. */
export interface AnalyzeInput {
  text: string;
  context?: ScriptContext;
  options?: ScriptOptions;
  /** Global names earlier scripts of the same document defined, and that were kept. */
  known?: ReadonlySet<string>;
}

export interface AnalyzeResult {
  findings: ScriptFinding[];
  /** Global names the script defines: functions, top-level variables, and properties it sets on `this`. */
  definedGlobals: string[];
}

const PLAIN: ReadonlySet<Kind> = new Set<Kind>(['data', 'string', 'number']);
const HOST_TABLES: ReadonlyMap<Kind, ReadonlyMap<string, Member>> = new Map<Kind, ReadonlyMap<string, Member>>([
  ['doc', DOC],
  ['field', FIELD],
  ['event', EVENT],
  ['app', APP],
  ['util', UTIL],
  ['color', COLOR],
  ['console', CONSOLE],
  ['xmldata', XMLDATA],
  ['xfa', XFA_ROOT],
  ['xfahost', XFA_HOST],
  ['xfalayout', XFA_LAYOUT],
  ['xfaevent', XFA_EVENT],
]);
const ACROFORM_ROOTS: ReadonlyMap<string, Kind> = new Map<string, Kind>([
  ['event', 'event'],
  ['app', 'app'],
  ['util', 'util'],
  ['color', 'color'],
  ['console', 'console'],
  ['XMLData', 'xmldata'],
]);
/** An XFA script sees Acrobat's objects too, but its event is the XFA event and `xfa` is the form's object model. */
const XFA_ROOTS: ReadonlyMap<string, Kind> = new Map<string, Kind>([
  ...ACROFORM_ROOTS,
  ['event', 'xfaevent'],
  ['xfa', 'xfa'],
  ...[...SOM_ROOTS].flatMap(([name, v]): Array<[string, Kind]> => (typeof v === 'string' ? [[name, v]] : [])),
]);
const VALUES: ReadonlySet<string> = new Set(['undefined', 'NaN', 'Infinity', 'arguments']);
/** Acrobat objects an XFA form's script object of the same name may stand for. */
const SHADOWED: ReadonlySet<Kind> = new Set<Kind>(['util', 'color', 'console']);
/** Node methods that change the form's own trees, which only data may go through. */
const DATA_ONLY = new Set(['loadXML', 'assignNode']);
const DATA_PATH = /^(?:xfa\.(?:datasets|data|record)|\$data|\$record|!)/;
const ARITHMETIC: ReadonlySet<string> = new Set(['-', '*', '/', '%', '**', '|', '&', '^', '<<', '>>', '>>>']);

/** A string of base64, hex, or %u and \x escapes long enough to carry a payload. */
export const ENCODED = [/^[A-Za-z0-9+/]{120,}={0,2}$/, /^(?:[0-9a-fA-F]{2}){60,}$/, /(?:%u[0-9a-fA-F]{4}){8,}/, /(?:%[0-9a-fA-F]{2}){30,}/, /(?:\\x[0-9a-fA-F]{2}){20,}/];
/** An escape that writes a printable ASCII character, which a script has no reason to escape. */
const NEEDLESS_ESCAPE = /\\x(?:[2-7][0-9a-fA-F])|\\u00(?:[2-7][0-9a-fA-F])/g;

interface Binding {
  name: string;
  kinds: Set<Kind>;
  sources: Array<{ expr: Expression; scope: Scope }>;
  param: boolean;
  /** Declared by a function declaration, so it holds a function whose source toString reads. */
  fn?: boolean;
}

class Scope {
  readonly bindings = new Map<string, Binding>();
  constructor(readonly parent?: Scope) {}
  lookup(name: string): Binding | undefined {
    for (let s: Scope | undefined = this; s; s = s.parent) {
      const b = s.bindings.get(name);
      if (b) return b;
    }
    return undefined;
  }
  declare(name: string, param = false): Binding {
    const found = this.bindings.get(name);
    if (found) return found;
    const b: Binding = { name, kinds: new Set(), sources: [], param };
    this.bindings.set(name, b);
    return b;
  }
}

type FunctionNode = Extract<AnyNode, { type: 'FunctionDeclaration' | 'FunctionExpression' | 'ArrowFunctionExpression' }>;

function isNode(v: unknown): v is AnyNode {
  return typeof v === 'object' && v !== null && typeof (v as { type?: unknown }).type === 'string';
}

function children(n: AnyNode): AnyNode[] {
  const out: AnyNode[] = [];
  for (const [key, v] of Object.entries(n as unknown as Record<string, unknown>)) {
    if (key === 'loc' || key === 'range') continue;
    if (Array.isArray(v)) {
      for (const x of v) if (isNode(x)) out.push(x);
    } else if (isNode(v)) out.push(v);
  }
  return out;
}

const isFunction = (n: AnyNode): n is FunctionNode => n.type === 'FunctionDeclaration' || n.type === 'FunctionExpression' || n.type === 'ArrowFunctionExpression';

function patternNames(p: Pattern, out: string[] = []): string[] {
  if (p.type === 'Identifier') out.push(p.name);
  else if (p.type === 'ObjectPattern') for (const prop of p.properties) patternNames(prop.type === 'RestElement' ? prop.argument : prop.value, out);
  else if (p.type === 'ArrayPattern') {
    for (const e of p.elements) if (e) patternNames(e, out);
  } else if (p.type === 'RestElement') patternNames(p.argument, out);
  else if (p.type === 'AssignmentPattern') patternNames(p.left, out);
  return out;
}

export function analyzeScript(input: AnalyzeInput): AnalyzeResult {
  const options = input.options ?? {};
  const xfa = input.context?.form === 'xfa';
  const roots = xfa ? XFA_ROOTS : ACROFORM_ROOTS;
  const overrides = options.actionOverrides ?? [];
  const known = input.known ?? new Set<string>();
  const findings: ScriptFinding[] = [];
  const reported = new Set<string>();
  const where = (n?: Node) => {
    const line = n ? `line ${lineOf(input.text, n.start)}` : '';
    const ctx = input.context?.location ?? (input.context?.fieldName ? `field ${JSON.stringify(input.context.fieldName)}` : input.context?.trigger);
    return [ctx, line].filter(Boolean).join(', ') || undefined;
  };
  const report = (c: C, d: D, n?: Node, data?: Record<string, string | number>) => {
    const key = `${c}/${d}/${String(data?.api ?? '')}`;
    if (reported.has(key)) return;
    reported.add(key);
    findings.push(makeFinding(c, d, overrides, where(n), data));
  };
  const reportMember = (m: Member, api: string, n: Node) => {
    if ('finding' in m) report(m.finding[0], m.finding[1], n, { api });
  };

  const limits = options.limits ?? {};
  if (limits.scriptSize !== undefined && input.text.length > limits.scriptSize) {
    report(C.Limit, D.Size, undefined, { length: input.text.length });
    return { findings, definedGlobals: [] };
  }

  let program: AnyNode;
  try {
    program = parse(input.text, { ecmaVersion: 'latest', sourceType: 'script', allowReturnOutsideFunction: true, allowHashBang: true }) as AnyNode;
  } catch (err) {
    report(C.Syntax, D.Unparseable, undefined, { reason: err instanceof Error ? err.message : String(err) });
    return { findings, definedGlobals: [] };
  }

  // Nesting, checked before anything recursive walks the tree.
  if (limits.depth !== undefined) {
    let deepest = 0;
    const stack: Array<[AnyNode, number]> = [[program, 1]];
    while (stack.length) {
      const [n, d] = stack.pop() as [AnyNode, number];
      deepest = Math.max(deepest, d);
      if (d > limits.depth) break;
      for (const c of children(n)) stack.push([c, d + 1]);
    }
    if (deepest > limits.depth) {
      report(C.Limit, D.Depth, undefined, { depth: limits.depth });
      return { findings, definedGlobals: [] };
    }
  }

  const top = new Scope();
  const scopeOf = new Map<AnyNode, Scope>();

  // 1. Declarations: functions, parameters, var, let, const and catch parameters, hoisted to their function.
  const declare = (n: AnyNode, scope: Scope) => {
    if (isFunction(n)) {
      if (n.type === 'FunctionDeclaration' && n.id) {
        const b = scope.declare(n.id.name);
        b.kinds.add('data');
        b.fn = true;
      }
      const inner = new Scope(scope);
      scopeOf.set(n, inner);
      if (n.type === 'FunctionExpression' && n.id) inner.declare(n.id.name).kinds.add('data');
      for (const p of n.params) for (const name of patternNames(p)) inner.declare(name, true).kinds.add('unknown');
      declare(n.body as AnyNode, inner);
      return;
    }
    if (n.type === 'VariableDeclaration') for (const d of n.declarations) for (const name of patternNames(d.id)) scope.declare(name);
    if (n.type === 'CatchClause' && n.param) for (const name of patternNames(n.param)) scope.declare(name).kinds.add('unknown');
    if (n.type === 'ClassDeclaration' && n.id) scope.declare(n.id.name).kinds.add('data');
    for (const c of children(n)) declare(c, scope);
  };
  declare(program, top);

  // 2. What each binding is given: initializers and assignments. An assignment to a name nothing declares makes a
  // global, unless it is a property of the document, which an AcroForm script's bare names reach.
  const declareGlobal = (name: string): Binding | undefined => (!xfa && DOC_ALL.has(name) ? undefined : top.declare(name));
  const assign = (target: Pattern, expr: Expression | undefined, scope: Scope) => {
    for (const name of patternNames(target)) {
      const b = scope.lookup(name) ?? declareGlobal(name);
      if (!b) continue;
      if (expr && target.type === 'Identifier') b.sources.push({ expr, scope });
      else b.kinds.add('unknown');
    }
  };
  const collect = (n: AnyNode, scope: Scope) => {
    const inner = scopeOf.get(n) ?? scope;
    // A declaration without a value holds undefined until an assignment gives it one, so it adds no kind.
    if (n.type === 'VariableDeclarator') {
      if (n.init || n.id.type !== 'Identifier') assign(n.id, n.init ?? undefined, scope);
    } else if (!xfa && n.type === 'AssignmentExpression' && n.left.type === 'MemberExpression' && n.left.object.type === 'ThisExpression') {
      // A property set on the document is a global the viewer resolves unqualified names to.
      const name = memberName(n.left);
      if (name !== undefined && !DOC_ALL.has(name)) {
        const b = top.declare(name);
        if (n.operator === '=') b.sources.push({ expr: n.right, scope });
        else b.kinds.add(n.operator === '+=' ? 'data' : 'number');
      }
    } else if (n.type === 'AssignmentExpression' && n.left.type !== 'MemberExpression') {
      if (n.operator === '=') assign(n.left, n.right, scope);
      else for (const name of patternNames(n.left)) (scope.lookup(name) ?? declareGlobal(name))?.kinds.add(n.operator === '+=' ? 'data' : 'number');
    } else if ((n.type === 'ForInStatement' || n.type === 'ForOfStatement') && n.left.type !== 'VariableDeclaration' && n.left.type !== 'MemberExpression') {
      for (const name of patternNames(n.left)) (scope.lookup(name) ?? declareGlobal(name))?.kinds.add(n.type === 'ForInStatement' ? 'string' : 'unknown');
    } else if ((n.type === 'ForInStatement' || n.type === 'ForOfStatement') && n.left.type === 'VariableDeclaration') {
      for (const d of n.left.declarations) for (const name of patternNames(d.id)) (scope.lookup(name) ?? scope.declare(name)).kinds.add(n.type === 'ForInStatement' ? 'string' : 'unknown');
    } else if (n.type === 'UpdateExpression' && n.argument.type === 'Identifier') (scope.lookup(n.argument.name) ?? declareGlobal(n.argument.name))?.kinds.add('number');
    for (const c of children(n)) collect(c, inner);
  };
  collect(program, top);

  // 3. Kinds, to a fixpoint: a binding is everything it is ever given.
  const kindOf = (e: AnyNode, scope: Scope): Set<Kind> => {
    switch (e.type) {
      case 'Literal':
        return new Set<Kind>([typeof e.value === 'number' ? 'number' : typeof e.value === 'string' ? 'string' : 'data']);
      case 'TemplateLiteral':
        return new Set<Kind>(['string']);
      case 'ArrayExpression':
      case 'ObjectExpression':
      case 'FunctionExpression':
      case 'ArrowFunctionExpression':
      case 'ClassExpression':
      case 'NewExpression':
        return new Set<Kind>(['data']);
      case 'ThisExpression':
        return new Set<Kind>([xfa ? 'node' : 'doc']);
      case 'Identifier': {
        const b = scope.lookup(e.name);
        if (b) return new Set(b.kinds);
        const root = roots.get(e.name);
        if (root) return new Set([root]);
        if (CONSTANT_ROOTS.has(e.name)) return new Set<Kind>(['constant']);
        if (e.name === 'Math') return new Set<Kind>(['math']);
        if (BUILTIN_NAMESPACES.has(e.name)) return new Set<Kind>(['builtin']);
        if (VALUES.has(e.name) || AFORM.has(e.name) || known.has(e.name) || BUILTIN_FUNCTIONS.has(e.name)) return new Set<Kind>(['data']);
        // An XFA script reaches the form's nodes by name.
        if (xfa) return new Set<Kind>(['node']);
        const docMember = DOC.get(e.name);
        if (docMember && 'kind' in docMember) return new Set<Kind>([docMember.kind]);
        return new Set<Kind>(['unknown']);
      }
      case 'MemberExpression': {
        const obj = kindOf(e.object as AnyNode, scope);
        const name = memberName(e);
        const out = new Set<Kind>();
        for (const k of obj) {
          const t = HOST_TABLES.get(k);
          const own = k === 'doc' && name !== undefined && !DOC.has(name) ? top.bindings.get(name) : undefined;
          if (own) for (const x of own.kinds) out.add(x);
          else if (t && name !== undefined) {
            const m = t.get(name);
            out.add(m && 'kind' in m ? m.kind : xfa && SHADOWED.has(k) ? 'node' : 'unknown');
          } else if (k === 'fields') out.add(name === 'length' ? 'number' : 'field');
          else if (k === 'node') out.add((name !== undefined && NODE_VALUES.get(name)) || 'node');
          else if (k === 'constant' || k === 'math') out.add(name === undefined ? 'unknown' : 'data');
          else if (k === 'builtin') out.add('data');
          else if (name === 'length') out.add('number');
          else out.add('unknown');
        }
        return out;
      }
      case 'CallExpression': {
        if (e.callee.type === 'MemberExpression') return kindOf(e.callee as AnyNode, scope);
        if (e.callee.type === 'Identifier') {
          const builtin = BUILTIN_FUNCTIONS.get(e.callee.name);
          if (builtin) return new Set([builtin]);
          const docMember = !xfa && !scope.lookup(e.callee.name) && DOC.get(e.callee.name);
          if (docMember && 'kind' in docMember) return new Set<Kind>([docMember.kind]);
        }
        return new Set<Kind>(['unknown']);
      }
      case 'BinaryExpression': {
        if (ARITHMETIC.has(e.operator)) return new Set<Kind>(['number']);
        if (e.operator !== '+') return new Set<Kind>(['data']);
        const l = kindOf(e.left as AnyNode, scope);
        const r = kindOf(e.right, scope);
        if (l.has('string') || r.has('string')) return new Set<Kind>(['string']);
        if ([...l, ...r].every(k => k === 'number')) return new Set<Kind>(['number']);
        return new Set<Kind>(['data']);
      }
      case 'UnaryExpression':
        return new Set<Kind>([e.operator === '-' || e.operator === '+' || e.operator === '~' ? 'number' : e.operator === 'typeof' ? 'string' : 'data']);
      case 'UpdateExpression':
        return new Set<Kind>(['number']);
      case 'LogicalExpression':
        return new Set([...kindOf(e.left, scope), ...kindOf(e.right, scope)]);
      case 'ConditionalExpression':
        return new Set([...kindOf(e.consequent, scope), ...kindOf(e.alternate, scope)]);
      case 'AssignmentExpression':
        return e.operator === '=' ? kindOf(e.right, scope) : new Set<Kind>([e.operator === '+=' ? 'data' : 'number']);
      case 'SequenceExpression':
        return kindOf(e.expressions[e.expressions.length - 1], scope);
      case 'ParenthesizedExpression':
        return kindOf(e.expression, scope);
      default:
        return new Set<Kind>(['unknown']);
    }
  };
  const all: Binding[] = [];
  const gather = (s: Scope) => all.push(...s.bindings.values());
  gather(top);
  for (const s of scopeOf.values()) gather(s);
  for (let round = 0; round < 10; round++) {
    let changed = false;
    for (const b of all)
      for (const src of b.sources)
        for (const k of kindOf(src.expr as AnyNode, src.scope)) {
          if (!b.kinds.has(k)) {
            b.kinds.add(k);
            changed = true;
          }
        }
    if (!changed) break;
  }
  for (const b of all) if (b.kinds.size === 0) b.kinds.add('unknown');

  // 4. The rules.
  const isPlainLocal = (e: AnyNode, scope: Scope) => {
    if (e.type !== 'Identifier') return false;
    const b = scope.lookup(e.name);
    return b !== undefined && !b.param && [...b.kinds].every(k => PLAIN.has(k));
  };
  const checkName = (name: string, objKinds: Set<Kind>, api: string, n: Node, write: boolean) => {
    for (const k of objKinds) {
      const t = HOST_TABLES.get(k);
      if (t) {
        const m = t.get(name);
        if (!m && k === 'doc' && (top.bindings.has(name) || known.has(name))) continue;
        // An XFA form's script objects are often named util or color, so another name on them is the form's own.
        if (!m && xfa && SHADOWED.has(k) && !MACHINERY.has(name)) {
          const host = HOST_DENY.get(name) ?? NODE_DENY.get(name);
          if (host) reportMember(host, api, n);
          continue;
        }
        // A field holds every Field member, so another name is the form's own data, unless a viewer object has it.
        if (!m && k === 'field' && !MACHINERY.has(name)) {
          const host = HOST_DENY.get(name);
          if (host) reportMember(host, api, n);
          continue;
        }
        if (!m) report(C.Api, D.Unknown, n, { api });
        else if ('finding' in m) reportMember(m, api, n);
        else if (write && !m.write) report(C.Api, D.Unknown, n, { api: `${api} =` });
        continue;
      }
      if (k === 'math' || k === 'builtin') {
        const deny = BUILTIN_DENY.get(name);
        if (deny) reportMember(deny, api, n);
        else if (MACHINERY.has(name)) report(C.DynamicCode, D.Prototype, n, { api });
        continue;
      }
      if (k === 'constant' || k === 'fields') continue;
      if (MACHINERY.has(name)) report(C.DynamicCode, D.Prototype, n, { api });
      const host = HOST_DENY.get(name) ?? (xfa || k === 'node' ? NODE_DENY.get(name) : undefined);
      if (host) reportMember(host, api, n);
      // A node's href or prototype reference set at run time loads what it names.
      else if (write && k === 'node' && URL_ATTRIBUTES.has(name)) report(C.External, D.Url, n, { api: `${api} =` });
    }
  };
  const describe = (e: AnyNode): string => {
    if (e.type === 'Identifier') return e.name;
    if (e.type === 'ThisExpression') return 'this';
    if (e.type === 'MemberExpression') {
      const name = memberName(e);
      return `${describe(e.object as AnyNode)}${name === undefined ? '[...]' : e.computed ? `[${JSON.stringify(name)}]` : `.${name}`}`;
    }
    if (e.type === 'CallExpression') return `${describe(e.callee as AnyNode)}()`;
    return e.type;
  };
  const concatPieces = (e: AnyNode): AnyNode[] => (e.type === 'BinaryExpression' && e.operator === '+' ? [...concatPieces(e.left as AnyNode), ...concatPieces(e.right)] : [e]);
  const inConcat = new Set<AnyNode>();
  const inArithmetic = new Set<AnyNode>();
  const defined: string[] = [];

  const visit = (n: AnyNode, scope: Scope, parent: AnyNode | undefined, write: boolean) => {
    const inner = scopeOf.get(n) ?? scope;
    switch (n.type) {
      case 'WithStatement':
        report(C.DynamicCode, D.With, n);
        break;
      case 'ImportExpression':
        report(C.DynamicCode, D.Eval, n, { api: 'import()' });
        break;
      case 'TaggedTemplateExpression':
        report(C.Api, D.Unknown, n, { api: `${describe(n.tag as AnyNode)}\`...\`` });
        break;
      case 'Identifier': {
        if (!parent || !isReference(n, parent)) break;
        // typeof on a name is a feature check: it reads nothing and never throws, whatever the name is.
        if (parent.type === 'UnaryExpression' && parent.operator === 'typeof') break;
        const b = scope.lookup(n.name);
        if (b) break;
        const denied = DENIED_GLOBALS.get(n.name);
        if (denied) {
          reportMember(denied, n.name, n);
          break;
        }
        const som = xfa ? SOM_ROOTS.get(n.name) : undefined;
        if (som !== undefined && typeof som !== 'string') {
          reportMember(som, n.name, n);
          break;
        }
        if (roots.has(n.name) || CONSTANT_ROOTS.has(n.name) || BUILTIN_NAMESPACES.has(n.name) || VALUES.has(n.name) || AFORM.has(n.name) || known.has(n.name) || BUILTIN_FUNCTIONS.has(n.name)) break;
        if (xfa) {
          // A form node by name, unless it is a name a viewer object has that leaves the form.
          const host = HOST_DENY.get(n.name) ?? NODE_DENY.get(n.name);
          if (host) reportMember(host, n.name, n);
          break;
        }
        const docMember = DOC.get(n.name);
        if (docMember) {
          reportMember(docMember, n.name, n);
          if (write && 'kind' in docMember && !docMember.write) report(C.Api, D.Unknown, n, { api: `${n.name} =` });
          break;
        }
        report(C.Api, D.Unknown, n, { api: n.name });
        break;
      }
      case 'MemberExpression': {
        const objKinds = kindOf(n.object as AnyNode, scope);
        const api = describe(n);
        const own = memberName(n);
        if ((own === 'callee' || own === 'caller') && n.object.type === 'Identifier' && n.object.name === 'arguments' && !scope.lookup('arguments')) {
          report(C.DynamicCode, D.SelfReference, n, { api });
          break;
        }
        if (n.computed) {
          const p = n.property;
          if (p.type === 'Literal' && typeof p.value === 'string') {
            // A form node is reached by quoted name when its name is not an identifier, so only its members are checked.
            if ([...objKinds].some(k => HOST_KINDS.has(k) && k !== 'node')) report(C.Obfuscation, D.BracketName, n, { api });
            checkName(p.value, objKinds, api, n, write);
          } else if (p.type === 'Literal' && typeof p.value === 'number') {
            if ([...objKinds].some(k => HOST_TABLES.has(k))) report(C.Api, D.Unknown, n, { api });
          } else {
            const keyKinds = kindOf(p as AnyNode, scope);
            const numericKey = [...keyKinds].every(k => k === 'number');
            const onHost = [...objKinds].some(k => HOST_TABLES.has(k) || k === 'math' || k === 'builtin' || k === 'constant');
            if (onHost || (!numericKey && !isPlainLocal(n.object as AnyNode, scope))) report(C.DynamicCode, D.ComputedAccess, n, { api });
          }
        } else if (n.property.type === 'Identifier') checkName(n.property.name, objKinds, api, n, write);
        break;
      }
      case 'CallExpression': {
        const callee = describe(n.callee as AnyNode);
        if (callee === 'util.printf') checkPrintf(n.arguments[0] as AnyNode | undefined, report, n);
        if (callee === 'String.fromCharCode' || callee === 'String.fromCodePoint') report(C.Obfuscation, D.CharCodes, n, { api: callee, count: n.arguments.length });
        const method = n.callee.type === 'MemberExpression' ? memberName(n.callee) : undefined;
        const receiver = n.callee.type === 'MemberExpression' ? n.callee.object : undefined;
        if (method && receiver) {
          const on = kindOf(receiver as AnyNode, scope);
          const first = n.arguments[0];
          const literal = first?.type === 'Literal' && typeof first.value === 'string' ? first.value : undefined;
          // app.response(q, title, default, true), or with bPassword set: a password asked for in a prompt.
          if ((on.has('app') || on.has('xfahost')) && method === 'response') {
            const opts = first?.type === 'ObjectExpression' ? first : undefined;
            const flag = opts
              ? opts.properties.find(
                  p => p.type === 'Property' && !p.computed && ((p.key.type === 'Identifier' && p.key.name === 'bPassword') || (p.key.type === 'Literal' && p.key.value === 'bPassword')),
                )
              : n.arguments[3];
            const value = flag?.type === 'Property' ? flag.value : flag;
            const off = !value || (value.type === 'Literal' && (value.value === false || value.value === 0 || value.value === null));
            if (!off) report(C.Api, D.PasswordPrompt, n, { api: callee });
          }
          if (on.has('xmldata') && method === 'parse') {
            const allow = n.arguments[1];
            if (!(allow?.type === 'Literal' && allow.value === false)) report(C.External, D.ImportExport, n, { api: 'XMLData.parse with entities' });
          }
          const nodeLike = on.has('node') || on.has('xfa') || on.has('unknown');
          if (nodeLike && method === 'createNode' && (literal === undefined || CODE_NODES.has(literal)))
            report(C.DynamicCode, D.InstallScript, n, { api: `${callee}(${literal === undefined ? '...' : JSON.stringify(literal)})` });
          if (nodeLike && DATA_ONLY.has(method) && !DATA_PATH.test(describe(receiver as AnyNode))) report(C.DynamicCode, D.InstallScript, n, { api: callee });
          if (nodeLike && method === 'setAttribute') {
            const name = n.arguments[1];
            const attr = name?.type === 'Literal' && typeof name.value === 'string' ? name.value : undefined;
            if (attr === undefined || URL_ATTRIBUTES.has(attr)) report(C.External, D.Url, n, { api: `${callee}(..., ${attr === undefined ? '...' : JSON.stringify(attr)})` });
          }
        }
        // (1525081).toString(36) spells "word": text written as a number in a base past 10.
        if (method === 'toString' && receiver) {
          const radix = n.arguments[0];
          const big = radix?.type === 'Literal' && typeof radix.value === 'number' && (radix.value > 16 || (radix.value > 10 && receiver.type === 'Literal'));
          if (big || (radix && radix.type !== 'Literal' && receiver.type === 'Literal')) report(C.Obfuscation, D.Decode, n, { api: `${describe(receiver as AnyNode)}.toString(radix)` });
        }
        // "qwqoqrqd".replace(/q/g, ""): text hidden among filler in a string the script wrote itself.
        if ((method === 'replace' || method === 'replaceAll' || method === 'split') && receiver?.type === 'Literal' && typeof receiver.value === 'string' && receiver.value.length > 3) {
          report(C.Obfuscation, D.Decode, n, { api: `"...".${method}()` });
        }
        if (n.callee.type === 'MemberExpression' && memberName(n.callee) === 'repeat') {
          const count = n.arguments[0];
          if (count?.type === 'Literal' && typeof count.value === 'number' && count.value > 1000) report(C.Obfuscation, D.LongString, n, { length: count.value });
        }
        if (n.callee.type === 'MemberExpression' && memberName(n.callee) === 'toString' && n.callee.object.type !== 'Literal') {
          const k = kindOf(n.callee.object as AnyNode, scope);
          const target = n.callee.object;
          const isFn = target.type === 'Identifier' && isFunctionBinding(target.name, scope);
          if (isFn || target.type === 'FunctionExpression' || target.type === 'ArrowFunctionExpression' || (k.has('data') && target.type === 'MemberExpression' && memberName(target) === 'callee')) {
            report(C.DynamicCode, D.SelfReference, n, { api: `${describe(target as AnyNode)}.toString()` });
          }
        }
        break;
      }
      case 'Literal': {
        if (typeof n.value !== 'string') break;
        const s = n.value;
        if (ENCODED.some(re => re.test(s)) || ENCODED.some(re => re.test(n.raw ?? ''))) report(C.Obfuscation, D.EncodedString, n, { length: s.length });
        else if (isLongBlob(s)) report(C.Obfuscation, D.LongString, n, { length: s.length });
        const escapes = (n.raw ?? '').match(NEEDLESS_ESCAPE)?.length ?? 0;
        if (escapes >= 3) report(C.Obfuscation, D.Escapes, n, { count: escapes });
        break;
      }
      case 'TemplateElement': {
        const s = n.value.cooked ?? n.value.raw;
        if (ENCODED.some(re => re.test(s))) report(C.Obfuscation, D.EncodedString, n, { length: s.length });
        else if (isLongBlob(s)) report(C.Obfuscation, D.LongString, n, { length: s.length });
        break;
      }
      case 'BinaryExpression': {
        if ((n.operator === '+' || n.operator === '-' || n.operator === '*') && !inArithmetic.has(n)) {
          // 0x1a2+0x3b4+-0x556 is 0: a number hidden as arithmetic on hex constants.
          const leaves: AnyNode[] = [];
          const walk = (x: AnyNode) => {
            if (x.type === 'BinaryExpression' && (x.operator === '+' || x.operator === '-' || x.operator === '*')) {
              inArithmetic.add(x);
              walk(x.left as AnyNode);
              walk(x.right);
            } else leaves.push(x.type === 'UnaryExpression' && x.operator === '-' ? (x.argument as AnyNode) : x);
          };
          walk(n);
          const numbers = leaves.filter(l => l.type === 'Literal' && typeof l.value === 'number');
          if (numbers.length === leaves.length && numbers.length >= 3 && numbers.some(l => l.type === 'Literal' && /^0x/i.test(l.raw ?? '')))
            report(C.Obfuscation, D.NumberExpression, n, { count: numbers.length });
        }
        if (n.operator !== '+' || inConcat.has(n)) break;
        const pieces = concatPieces(n);
        // The nested + nodes of this chain are counted here, not again on their own.
        const mark = (x: AnyNode) => {
          if (x.type === 'BinaryExpression' && x.operator === '+') {
            inConcat.add(x);
            mark(x.left as AnyNode);
            mark(x.right);
          }
        };
        mark(n);
        const tiny = pieces.filter(
          p => (p.type === 'Literal' && typeof p.value === 'string' && p.value.length <= 2) || (p.type === 'CallExpression' && /fromCharCode$/.test(describe(p.callee as AnyNode))),
        ).length;
        const literals = pieces.filter(p => p.type === 'Literal' && typeof p.value === 'string').length;
        if (tiny >= 6 || literals >= 25) report(C.Obfuscation, D.Concatenation, n, { count: pieces.length });
        break;
      }
      default:
        break;
    }
    for (const c of children(n)) {
      const isWriteTarget = (n.type === 'AssignmentExpression' && c === n.left) || (n.type === 'UpdateExpression' && c === n.argument);
      visit(c, inner, n, isWriteTarget);
    }
  };
  visit(program, top, undefined, false);
  // Every name the top scope holds is global: declared there, assigned without a declaration, or set on `this`.
  // An XFA script's names stay in its own script; other scripts reach them through the node that holds it.
  if (!xfa) for (const name of top.bindings.keys()) defined.push(name);

  if (!findings.some(f => f.action === 'strip')) report(C.Form, D.Computation);
  return { findings, definedGlobals: [...new Set(defined)] };
}

/**
 * A string over 64KB, or over 1000 characters with a stretch of 64 or more that has no whitespace: a payload or an
 * encoded blob. Text and tables of numbers break into words; the forms sampled never ran past 18.
 */
export function isLongBlob(s: string): boolean {
  if (s.length <= 1000) return false;
  if (s.length > 65536) return true;
  let run = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    run = c === 32 || c === 9 || c === 10 || c === 13 ? 0 : run + 1;
    if (run >= 64) return true;
  }
  return false;
}

function memberName(e: Extract<AnyNode, { type: 'MemberExpression' }>): string | undefined {
  if (!e.computed && e.property.type === 'Identifier') return e.property.name;
  if (e.computed && e.property.type === 'Literal' && (typeof e.property.value === 'string' || typeof e.property.value === 'number')) return String(e.property.value);
  return undefined;
}

/** Whether an identifier is read or written as a variable, not a property name, label or declaration. */
function isReference(n: Extract<AnyNode, { type: 'Identifier' }>, parent: AnyNode): boolean {
  switch (parent.type) {
    case 'MemberExpression':
      return parent.object === n || (parent.computed && parent.property === n);
    case 'Property':
      return parent.value === n || (parent.computed && parent.key === n);
    case 'PropertyDefinition':
    case 'MethodDefinition':
      return parent.computed && parent.key === n;
    case 'VariableDeclarator':
      return parent.init === n;
    case 'FunctionDeclaration':
    case 'FunctionExpression':
    case 'ArrowFunctionExpression':
      return false;
    case 'LabeledStatement':
    case 'BreakStatement':
    case 'ContinueStatement':
      return false;
    case 'CatchClause':
      return false;
    case 'ClassDeclaration':
    case 'ClassExpression':
      return parent.superClass === n;
    case 'AssignmentPattern':
      return parent.right === n;
    case 'ArrayPattern':
    case 'ObjectPattern':
    case 'RestElement':
      return false;
    case 'ExportSpecifier':
    case 'ImportSpecifier':
    case 'ImportDefaultSpecifier':
    case 'ImportNamespaceSpecifier':
      return false;
    case 'MetaProperty':
      return false;
    default:
      return true;
  }
}

function isFunctionBinding(name: string, scope: Scope): boolean {
  const b = scope.lookup(name);
  return b !== undefined && !b.param && (b.fn === true || b.sources.some(s => s.expr.type === 'FunctionExpression' || s.expr.type === 'ArrowFunctionExpression'));
}

/** util.printf with a format a script did not write out, or with a field width past 100: the CVE-2008-2992 overflow. */
function checkPrintf(format: AnyNode | undefined, report: (c: C, d: D, n?: Node, data?: Record<string, string | number>) => void, n: Node): void {
  if (format?.type !== 'Literal' || typeof format.value !== 'string') {
    report(C.Api, D.Exploited, n, { api: 'util.printf with a computed format' });
    return;
  }
  for (const m of format.value.matchAll(/%[-+ #0,]*(\d+)?(?:\.(\d+))?[a-zA-Z]/g)) {
    if (Number(m[1] ?? 0) > 100 || Number(m[2] ?? 0) > 100) {
      report(C.Api, D.Exploited, n, { api: 'util.printf with a field width past 100' });
      return;
    }
  }
}

function lineOf(text: string, offset: number): number {
  let line = 1;
  for (let i = 0; i < offset && i < text.length; i++) if (text.charCodeAt(i) === 10) line++;
  return line;
}
