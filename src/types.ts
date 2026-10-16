/** Prefixed with SCRIPT_, so they never read as another package's kinds in a shared report, such as pdf-defuse's FORM. */
export enum ScriptCategory {
  /** The script only formats, checks or calculates form fields, or a macro calls nothing known to reach outside its document. */
  Form = 'SCRIPT_FORM',
  /** The script reaches outside the form or document: a URL, mail, a submit, another file, the network, a program, a library. */
  External = 'SCRIPT_EXTERNAL',
  /** The script runs code it builds at run time, installs scripts, or reaches the language's own machinery. */
  DynamicCode = 'SCRIPT_DYNAMIC_CODE',
  /** The script hides what it does: decoded strings, character codes, long concatenations, escapes. */
  Obfuscation = 'SCRIPT_OBFUSCATION',
  /** The script uses a viewer API that is not form computation. */
  Api = 'SCRIPT_API',
  Syntax = 'SCRIPT_SYNTAX',
  Limit = 'SCRIPT_LIMIT',
}

export enum ScriptDetail {
  // FORM
  Computation = 'COMPUTATION',
  DocumentMacro = 'DOCUMENT_MACRO',
  // EXTERNAL
  Url = 'URL',
  Submit = 'SUBMIT',
  Mail = 'MAIL',
  OpenDocument = 'OPEN_DOCUMENT',
  DataObject = 'DATA_OBJECT',
  ImportExport = 'IMPORT_EXPORT',
  Network = 'NETWORK',
  MenuCommand = 'MENU_COMMAND',
  Print = 'PRINT',
  Save = 'SAVE',
  FileSystem = 'FILE_SYSTEM',
  Process = 'PROCESS',
  Registry = 'REGISTRY',
  Dde = 'DDE',
  ComObject = 'COM_OBJECT',
  NativeCode = 'NATIVE_CODE',
  Environment = 'ENVIRONMENT',
  Reference = 'REFERENCE',
  // DYNAMIC_CODE
  Eval = 'EVAL',
  Timer = 'TIMER',
  InstallScript = 'INSTALL_SCRIPT',
  Privilege = 'PRIVILEGE',
  ComputedAccess = 'COMPUTED_ACCESS',
  Prototype = 'PROTOTYPE',
  With = 'WITH',
  SelfReference = 'SELF_REFERENCE',
  LegacyMacro = 'LEGACY_MACRO',
  // OBFUSCATION
  CharCodes = 'CHAR_CODES',
  Decode = 'DECODE',
  Concatenation = 'CONCATENATION',
  Escapes = 'ESCAPES',
  EncodedString = 'ENCODED_STRING',
  LongString = 'LONG_STRING',
  BracketName = 'BRACKET_NAME',
  NumberExpression = 'NUMBER_EXPRESSION',
  // API
  Exploited = 'EXPLOITED',
  Unknown = 'UNKNOWN',
  PasswordPrompt = 'PASSWORD_PROMPT',
  // SYNTAX
  Unparseable = 'UNPARSEABLE',
  // LIMIT
  Size = 'SIZE',
  Depth = 'DEPTH',
}

export type ScriptFindingAction = 'strip' | 'info';

export enum ScriptRisk {
  None = 'NONE',
  Low = 'LOW',
  Medium = 'MEDIUM',
  High = 'HIGH',
  Critical = 'CRITICAL',
}

/** The finding shape every package of the defuse family shares. */
export interface DefuseFinding {
  category: string;
  detail: string;
  /** Plain sentence, safe to show the uploader. */
  description: string;
  /** Default action after any caller override. */
  action: 'reject' | 'strip' | 'info';
  /** Where in the script: "line 3", with the trigger and field when the caller gave them. */
  location?: string;
  /** Extra values: the API name, the count, the length. */
  data?: Record<string, string | number>;
  /** Set when the finding comes from inside a contained file. */
  attachment?: string;
  /** How much the finding adds to a score. */
  weight?: number;
}

export interface ScriptFinding extends DefuseFinding {
  category: ScriptCategory;
  detail: ScriptDetail;
  action: ScriptFindingAction;
}

export interface ScriptActionOverride {
  category: ScriptCategory;
  detail?: ScriptDetail;
  action: ScriptFindingAction;
}

export interface ScriptScoreWeight {
  category: ScriptCategory;
  detail?: ScriptDetail;
  weight: number;
}

/** Lower bound of each band. */
export interface ScriptScoreBands {
  low: number;
  medium: number;
  high: number;
  critical: number;
}

export interface ScriptLimits {
  /** Characters in one script. A script past it is LIMIT/SIZE and is not parsed. */
  scriptSize?: number;
  /** Nesting of the syntax tree. A script past it is LIMIT/DEPTH. */
  depth?: number;
}

export interface ScriptOptions {
  /** A limit left out is not enforced. */
  limits?: ScriptLimits;
  actionOverrides?: ScriptActionOverride[];
  scoreWeights?: ScriptScoreWeight[];
  scoreBands?: ScriptScoreBands;
}

/** A type library or another VBA project a VBA project refers to, as office-defuse reads it from the dir stream. */
export interface ScriptReference {
  name: string;
  kind: 'registered' | 'control' | 'project';
  /** A type library's LibidReference, such as `*\G{...}#2.0#0#path#description`, or a project's path. */
  libid: string;
}

/** Where a script runs, as a container reports it. pdf-defuse's and office-defuse's ContainedScript fit. */
export interface ScriptContext {
  /** "document", "open", "field-format", "field-calculate", "click", ...; for a VBA module "vba-" and its kind. */
  trigger?: string;
  location?: string;
  fieldName?: string;
  /** 'javascript' unless the script is FormCalc, which only XFA forms carry, or a VBA module. */
  language?: 'javascript' | 'formcalc' | 'vba';
  /** 'xfa' for a script in an XFA form, which runs against the XFA object model; 'office' for a VBA module. */
  form?: 'acroform' | 'xfa' | 'office';
  /** For a VBA module, the references of its project. office-defuse gives them with the project's first module. */
  references?: ScriptReference[];
}

export interface ScriptInspection {
  /** 'form' when no finding strips the script: it only formats, checks or calculates form fields, or a VBA module calls nothing known to reach outside its document. */
  verdict: 'form' | 'unsafe';
  score: number;
  risk: ScriptRisk;
  findings: ScriptFinding[];
  /** Global names the script defines, for scripts that run after it and use them. */
  definedGlobals: string[];
}
