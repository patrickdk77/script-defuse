import { ScriptCategory as C, ScriptDetail as D } from './types';

/**
 * What a value is, as far as the rules need to know. Host kinds are the viewer's objects; the rest are plain data,
 * which can reach nothing outside the script.
 */
export type Kind =
  | 'doc'
  | 'field'
  | 'fields'
  | 'event'
  | 'app'
  | 'util'
  | 'color'
  | 'console'
  | 'constant'
  | 'math'
  | 'builtin'
  | 'xmldata'
  | 'xfa'
  | 'xfahost'
  | 'xfalayout'
  | 'xfaevent'
  | 'node'
  | 'number'
  | 'string'
  | 'data'
  | 'unknown';

export const HOST_KINDS: ReadonlySet<Kind> = new Set<Kind>([
  'doc',
  'field',
  'fields',
  'event',
  'app',
  'util',
  'color',
  'console',
  'constant',
  'math',
  'builtin',
  'xmldata',
  'xfa',
  'xfahost',
  'xfalayout',
  'xfaevent',
  'node',
]);

/** A member of a host object: allowed, giving a value of `kind`, or a finding. */
export type Member = { kind: Kind; write?: boolean } | { finding: [C, D] };

const ok = (kind: Kind, write = false): Member => ({ kind, write });
const bad = (c: C, d: D): Member => ({ finding: [c, d] });

function table(entries: Record<string, Member>): ReadonlyMap<string, Member> {
  return new Map(Object.entries(entries));
}

const url = bad(C.External, D.Url);
const submit = bad(C.External, D.Submit);
const mail = bad(C.External, D.Mail);
const openDoc = bad(C.External, D.OpenDocument);
const dataObject = bad(C.External, D.DataObject);
const importExport = bad(C.External, D.ImportExport);
const network = bad(C.External, D.Network);
const menu = bad(C.External, D.MenuCommand);
const print = bad(C.External, D.Print);
const save = bad(C.External, D.Save);
const timer = bad(C.DynamicCode, D.Timer);
const install = bad(C.DynamicCode, D.InstallScript);
const privilege = bad(C.DynamicCode, D.Privilege);
const exploited = bad(C.Api, D.Exploited);

/** The document: `this`, and what an unqualified name falls back to in a viewer. */
export const DOC = table({
  getField: ok('field'),
  getNthFieldName: ok('string'),
  numFields: ok('number'),
  calculateNow: ok('data'),
  resetForm: ok('data'),
  dirty: ok('data', true),
  calculate: ok('data', true),
  pageNum: ok('number', true),
  numPages: ok('number'),
  // Privacy and view settings: no cached or autocompleted form data, the zoom, the page layout, deferred redraws.
  nocache: ok('data', true),
  noautocomplete: ok('data', true),
  zoom: ok('number', true),
  zoomType: ok('string', true),
  layout: ok('string', true),
  delay: ok('data', true),
  scroll: ok('data'),
  // An XFA document's form model, which bookmarks and other PDF-side scripts reach. The XFA tables check it.
  xfa: ok('xfa'),
  // Ways out of the form.
  getURL: url,
  submitForm: submit,
  mailDoc: mail,
  mailForm: mail,
  openDataObject: dataObject,
  exportDataObject: dataObject,
  importDataObject: dataObject,
  createDataObject: dataObject,
  getDataObject: dataObject,
  getDataObjectContents: dataObject,
  setDataObjectContents: dataObject,
  removeDataObject: dataObject,
  dataObjects: dataObject,
  embedDocAsDataObject: dataObject,
  importAnFDF: importExport,
  importAnXFDF: importExport,
  importTextData: importExport,
  importXFAData: importExport,
  importIcon: importExport,
  importSound: importExport,
  exportAsFDF: importExport,
  exportAsFDFStr: importExport,
  exportAsXFDF: importExport,
  exportAsXFDFStr: importExport,
  exportAsText: importExport,
  exportXFAData: importExport,
  insertPages: importExport,
  replacePages: importExport,
  extractPages: importExport,
  addWatermarkFromFile: importExport,
  newPage: importExport,
  print: print,
  saveAs: save,
  closeDoc: save,
  addScript: install,
  setAction: install,
  setPageAction: install,
  removeScript: install,
  getAnnots: exploited,
  getAnnot: exploited,
  syncAnnotScan: exploited,
  getIcon: exploited,
  media: exploited,
  Collab: network,
});

/**
 * Every member Acrobat's Doc object has, form or not. A script that sets one of these on the document, or assigns to
 * it as a bare name, sets the document's own property; any other name it sets is a global of its own.
 */
export const DOC_ALL: ReadonlySet<string> = new Set([
  ...DOC.keys(),
  'alternatePresentations',
  'author',
  'baseURL',
  'bookmarkRoot',
  'creationDate',
  'creator',
  'disclosed',
  'docID',
  'documentFileName',
  'dynamicXFAForm',
  'external',
  'filesize',
  'hidden',
  'hostContainer',
  'icons',
  'info',
  'innerAppWindowRect',
  'innerDocWindowRect',
  'isModal',
  'keywords',
  'metadata',
  'modDate',
  'mouseX',
  'mouseY',
  'numTemplates',
  'outerAppWindowRect',
  'outerDocWindowRect',
  'pageWindowRect',
  'path',
  'permStatusReady',
  'producer',
  'requiresFullSave',
  'securityHandler',
  'selectedAnnots',
  'sounds',
  'spellDictionaryOrder',
  'spellLanguageOrder',
  'subject',
  'templates',
  'title',
  'URL',
  'viewState',
  'XFAForeground',
  'addAnnot',
  'addField',
  'addIcon',
  'addLink',
  'addRecipientListCryptFilter',
  'addRequirement',
  'addThumbnails',
  'addWatermarkFromText',
  'addWeblinks',
  'applyRedactions',
  'bringToFront',
  'certifyInvisibleSign',
  'colorConvertPage',
  'createTemplate',
  'deletePages',
  'deleteSound',
  'embedOutputIntent',
  'encryptForRecipients',
  'encryptUsingPolicy',
  'flattenPages',
  'getAnnot3D',
  'getAnnots3D',
  'getColorConvertAction',
  'getLegalWarnings',
  'getLinks',
  'getNthTemplate',
  'getOCGs',
  'getOCGOrder',
  'getPageBox',
  'getPageLabel',
  'getPageNthWord',
  'getPageNthWordQuads',
  'getPageNumWords',
  'getPageRotation',
  'getPageTransition',
  'getPrintParams',
  'getSound',
  'getTemplate',
  'gotoNamedDest',
  'movePage',
  'preflight',
  'removeField',
  'removeIcon',
  'removeLinks',
  'removeRequirement',
  'removeTemplate',
  'removeThumbnails',
  'removeWeblinks',
  'selectPageNthWord',
  'setOCGOrder',
  'setPageBoxes',
  'setPageLabels',
  'setPageRotations',
  'setPageTabOrder',
  'setPageTransitions',
  'spawnPageFromTemplate',
  'timestampSign',
  'validatePreflightAudit',
]);

/**
 * A form field, from getField, event.target or event.source: Acrobat's whole Field object. Since every member it has
 * is here, any other name on a field is one the form set itself, such as event.target.oldVal.
 */
export const FIELD = table({
  doc: ok('doc'),
  multipleSelection: ok('data', true),
  print: ok('data', true),
  buttonGetIcon: ok('data'),
  buttonSetIcon: ok('data'),
  getLock: ok('data'),
  setLock: ok('data'),
  value: ok('data', true),
  valueAsString: ok('string'),
  name: ok('string'),
  type: ok('string'),
  display: ok('number', true),
  hidden: ok('data', true),
  readonly: ok('data', true),
  required: ok('data', true),
  textColor: ok('data', true),
  fillColor: ok('data', true),
  bgColor: ok('data', true),
  fgColor: ok('data', true),
  borderColor: ok('data', true),
  strokeColor: ok('data', true),
  textSize: ok('number', true),
  textFont: ok('data', true),
  alignment: ok('string', true),
  charLimit: ok('number', true),
  defaultValue: ok('data', true),
  exportValues: ok('data', true),
  numItems: ok('number'),
  currentValueIndices: ok('data', true),
  getItemAt: ok('string'),
  setItems: ok('data'),
  insertItemAt: ok('data'),
  deleteItemAt: ok('data'),
  clearItems: ok('data'),
  isBoxChecked: ok('data'),
  isDefaultChecked: ok('data'),
  checkThisBox: ok('data'),
  defaultIsChecked: ok('data'),
  page: ok('data'),
  rect: ok('data', true),
  setFocus: ok('data'),
  buttonGetCaption: ok('string'),
  buttonSetCaption: ok('data'),
  editable: ok('data', true),
  multiline: ok('data', true),
  comb: ok('data', true),
  doNotScroll: ok('data', true),
  doNotSpellCheck: ok('data', true),
  password: ok('data', true),
  userName: ok('string', true),
  rotation: ok('number', true),
  lineWidth: ok('number', true),
  borderStyle: ok('data', true),
  calcOrderIndex: ok('number', true),
  commitOnSelChange: ok('data', true),
  radiosInUnison: ok('data', true),
  richText: ok('data', true),
  richValue: ok('data', true),
  defaultStyle: ok('data', true),
  style: ok('data', true),
  highlight: ok('data', true),
  delay: ok('data', true),
  buttonAlignX: ok('number', true),
  buttonAlignY: ok('number', true),
  buttonFitBounds: ok('data', true),
  buttonPosition: ok('number', true),
  buttonScaleHow: ok('number', true),
  buttonScaleWhen: ok('number', true),
  getArray: ok('fields'),
  setAction: install,
  buttonImportIcon: importExport,
  browseForFileToSubmit: importExport,
  fileSelect: importExport,
  submitName: submit,
  signatureSign: exploited,
  signatureSetSeedValue: exploited,
  signatureValidate: exploited,
  signatureInfo: exploited,
  signatureGetSeedValue: exploited,
  signatureGetModifications: exploited,
});

/** `event`, the object a field or document script runs for. */
export const EVENT = table({
  value: ok('data', true),
  valueAsString: ok('string'),
  change: ok('string', true),
  changeEx: ok('data'),
  commitKey: ok('number'),
  fieldFull: ok('data'),
  keyDown: ok('data'),
  modifier: ok('data'),
  name: ok('string'),
  rc: ok('data', true),
  richChange: ok('data', true),
  richChangeEx: ok('data', true),
  richValue: ok('data', true),
  selEnd: ok('number', true),
  selStart: ok('number', true),
  shift: ok('data'),
  source: ok('field'),
  target: ok('field'),
  targetName: ok('string'),
  type: ok('string'),
  willCommit: ok('data'),
});

/** `app`, the viewer. Message boxes and version checks only. */
export const APP = table({
  alert: ok('data'),
  beep: ok('data'),
  response: ok('string'),
  viewerVersion: ok('number'),
  viewerType: ok('string'),
  viewerVariation: ok('string'),
  platform: ok('string'),
  language: ok('string'),
  formsVersion: ok('number'),
  calculate: ok('data', true),
  runtimeHighlight: ok('data', true),
  runtimeHighlightColor: ok('data', true),
  focusRect: ok('data', true),
  launchURL: url,
  openDoc: openDoc,
  newDoc: openDoc,
  openFDF: importExport,
  newFDF: importExport,
  browseForDoc: importExport,
  mailMsg: mail,
  mailGetAddrs: mail,
  execMenuItem: menu,
  execDialog: menu,
  addMenuItem: install,
  addSubMenu: install,
  addToolButton: install,
  setTimeOut: timer,
  setInterval: timer,
  clearTimeOut: timer,
  clearInterval: timer,
  trustedFunction: privilege,
  beginPriv: privilege,
  endPriv: privilege,
  trustPropagatorFunction: privilege,
  loadPolicyFile: privilege,
  activeDocs: openDoc,
  doc: openDoc,
  fs: importExport,
  media: exploited,
  printColorProfiles: exploited,
  printerNames: exploited,
  plugIns: exploited,
  plugins: exploited,
  monitors: exploited,
  getPath: importExport,
});

/** `util`: formatting and parsing text, numbers and dates. */
export const UTIL = table({
  printf: ok('string'),
  printd: ok('string'),
  printx: ok('string'),
  scand: ok('data'),
  stringFromStream: dataObject,
  streamFromString: dataObject,
  iconStreamFromIcon: dataObject,
  readFileIntoStream: importExport,
  spansToXML: ok('string'),
  xmlToSpans: ok('data'),
  crackURL: ok('data'),
});

export const COLOR = table({
  transparent: ok('data'),
  black: ok('data'),
  white: ok('data'),
  red: ok('data'),
  green: ok('data'),
  blue: ok('data'),
  cyan: ok('data'),
  magenta: ok('data'),
  yellow: ok('data'),
  dkGray: ok('data'),
  gray: ok('data'),
  ltGray: ok('data'),
  convert: ok('data'),
  equal: ok('data'),
});

export const CONSOLE = table({ println: ok('data'), show: ok('data'), hide: ok('data'), clear: ok('data') });

/** `XMLData`, which parses XML text a form holds and queries it. Its parse is checked for entities on its own. */
export const XMLDATA = table({ parse: ok('data'), applyXPath: ok('data') });

/** Namespaces of constants a form script reads, such as display.hidden. Any member of them is a constant. */
export const CONSTANT_ROOTS: ReadonlySet<string> = new Set(['display', 'border', 'style', 'font', 'highlight', 'position', 'scaleHow', 'scaleWhen', 'zoomtype', 'cursor', 'textures']);

/** Acrobat's AForm helpers, which format, check and calculate fields. */
export const AFORM: ReadonlySet<string> = new Set([
  'AFDate_Format',
  'AFDate_FormatEx',
  'AFDate_Keystroke',
  'AFDate_KeystrokeEx',
  'AFExactMatch',
  'AFExtractNums',
  'AFMakeArrayFromList',
  'AFMakeNumber',
  'AFMergeChange',
  'AFNumber_Format',
  'AFNumber_Keystroke',
  'AFParseDateEx',
  'AFPercent_Format',
  'AFPercent_Keystroke',
  'AFRange_Validate',
  'AFSimple',
  'AFSimple_Calculate',
  'AFSpecial_Format',
  'AFSpecial_Keystroke',
  'AFSpecial_KeystrokeEx',
  'AFTime_Format',
  'AFTime_FormatEx',
  'AFTime_Keystroke',
  'AFTime_KeystrokeEx',
  'AFParseTime',
  'AFParseDate',
  'AFGetMonthIndex',
  'AFMatchMonth',
  'AFDefineDateString',
]);

/** Global functions and namespaces of the language itself that compute on data. */
export const BUILTIN_FUNCTIONS: ReadonlyMap<string, Kind> = new Map<string, Kind>([
  ['parseInt', 'number'],
  ['parseFloat', 'number'],
  ['isNaN', 'data'],
  ['isFinite', 'data'],
  ['Number', 'number'],
  ['String', 'string'],
  ['Boolean', 'data'],
  ['Array', 'data'],
  ['Date', 'data'],
  ['RegExp', 'data'],
  ['Error', 'data'],
  ['TypeError', 'data'],
  ['RangeError', 'data'],
  ['encodeURIComponent', 'string'],
  ['encodeURI', 'string'],
]);

/** Namespaces whose members are pure computation, apart from the ones named in BUILTIN_DENY. */
export const BUILTIN_NAMESPACES: ReadonlySet<string> = new Set(['Math', 'Number', 'String', 'Date', 'JSON', 'Array', 'Object', 'Boolean']);

/** Members of those namespaces that hide text or reach the machinery behind objects. */
export const BUILTIN_DENY: ReadonlyMap<string, Member> = new Map<string, Member>([
  ['fromCharCode', bad(C.Obfuscation, D.CharCodes)],
  ['fromCodePoint', bad(C.Obfuscation, D.CharCodes)],
  ['defineProperty', bad(C.DynamicCode, D.Prototype)],
  ['defineProperties', bad(C.DynamicCode, D.Prototype)],
  ['setPrototypeOf', bad(C.DynamicCode, D.Prototype)],
  ['getPrototypeOf', bad(C.DynamicCode, D.Prototype)],
  ['getOwnPropertyDescriptor', bad(C.DynamicCode, D.Prototype)],
  ['create', bad(C.DynamicCode, D.Prototype)],
  ['assign', bad(C.DynamicCode, D.Prototype)],
]);

/** Global names that are themselves a finding, wherever they appear. */
export const DENIED_GLOBALS: ReadonlyMap<string, Member> = new Map<string, Member>([
  ['eval', bad(C.DynamicCode, D.Eval)],
  ['Function', bad(C.DynamicCode, D.Eval)],
  ['setTimeout', timer],
  ['setInterval', timer],
  ['unescape', bad(C.Obfuscation, D.Decode)],
  ['escape', bad(C.Obfuscation, D.Decode)],
  ['decodeURIComponent', bad(C.Obfuscation, D.Decode)],
  ['decodeURI', bad(C.Obfuscation, D.Decode)],
  ['atob', bad(C.Obfuscation, D.Decode)],
  ['btoa', bad(C.Obfuscation, D.Decode)],
  ['Net', network],
  ['SOAP', network],
  ['Collab', network],
  ['ADBC', network],
  ['Connection', network],
  ['RSS', network],
  ['identity', network],
  ['security', privilege],
  ['spell', exploited],
  ['media', exploited],
  ['search', exploited],
  ['getURL', url],
  ['submitForm', submit],
  ['mailDoc', mail],
  ['mailForm', mail],
  ['global', bad(C.Api, D.Unknown)],
  ['Proxy', bad(C.DynamicCode, D.Prototype)],
  ['Reflect', bad(C.DynamicCode, D.Prototype)],
  ['Symbol', bad(C.DynamicCode, D.Prototype)],
  ['Report', openDoc],
  ['catalog', importExport],
]);

/** Member names that reach the language machinery on any value. */
export const MACHINERY: ReadonlySet<string> = new Set(['constructor', '__proto__', 'prototype', '__defineGetter__', '__defineSetter__', '__lookupGetter__', '__lookupSetter__', 'caller', 'callee']);

/**
 * Member names a viewer object has that are not form computation. A plain value, such as a function's parameter,
 * might hold a viewer object, so one of these names on it gets the finding the object would have.
 */
export const HOST_DENY: ReadonlyMap<string, Member> = (() => {
  const m = new Map<string, Member>();
  for (const t of [DOC, FIELD, APP, UTIL])
    for (const [name, member] of t) {
      if ('finding' in member && !m.has(name)) m.set(name, member);
    }
  return m;
})();

// ---------- XFA ----------

/**
 * `xfa`, the root of an XFA form's object model. Its models are trees of form nodes, apart from the host, the
 * layout and the event, and the connections, sources and signatures that reach outside the form.
 */
export const XFA_ROOT = table({
  host: ok('xfahost'),
  layout: ok('xfalayout'),
  event: ok('xfaevent'),
  form: ok('node'),
  template: ok('node'),
  data: ok('node'),
  datasets: ok('node'),
  record: ok('node'),
  dataWindow: ok('node'),
  config: ok('node'),
  localeSet: ok('node'),
  context: ok('node'),
  log: ok('node'),
  resolveNode: ok('node'),
  resolveNodes: ok('node'),
  createNode: ok('node'),
  isCompatibleNS: ok('data'),
  isPropertySpecified: ok('data'),
  nodes: ok('node'),
  parent: ok('node'),
  all: ok('node'),
  oneOfChild: ok('node'),
  name: ok('string'),
  className: ok('string'),
  somExpression: ok('string'),
  connectionSet: network,
  sourceSet: network,
  signature: exploited,
});

/** `xfa.host`, the viewer as an XFA form sees it. Message boxes, focus, pages and version checks. */
export const XFA_HOST = table({
  appType: ok('string'),
  calculationsEnabled: ok('data', true),
  currentPage: ok('number', true),
  language: ok('string'),
  name: ok('string'),
  numPages: ok('number'),
  platform: ok('string'),
  title: ok('string', true),
  validationsEnabled: ok('data', true),
  variation: ok('string'),
  version: ok('string'),
  beep: ok('data'),
  documentCountInBatch: ok('number'),
  documentInBatch: ok('number'),
  getFocus: ok('node'),
  messageBox: ok('number'),
  pageDown: ok('data'),
  pageUp: ok('data'),
  resetData: ok('data'),
  response: ok('string'),
  setFocus: ok('data'),
  openList: ok('data'),
  gotoURL: url,
  exportData: importExport,
  importData: importExport,
  print: print,
});

/** `xfa.layout`: where nodes fall on pages. */
export const XFA_LAYOUT = table({
  absPage: ok('number'),
  absPageCount: ok('number'),
  absPageCountInBatch: ok('number'),
  absPageInBatch: ok('number'),
  absPageSpan: ok('number'),
  h: ok('number'),
  w: ok('number'),
  x: ok('number'),
  y: ok('number'),
  page: ok('number'),
  pageContent: ok('node'),
  pageCount: ok('number'),
  pageSpan: ok('number'),
  relayout: ok('data'),
  relayoutPageArea: ok('data'),
  sheet: ok('number'),
  sheetCount: ok('number'),
  sheetCountInBatch: ok('number'),
  sheetInBatch: ok('number'),
  ready: ok('data'),
});

/**
 * `event` in an XFA script, and `xfa.event`: the XFA event's members and those of Acrobat's event object. Its target
 * is the Acrobat document.
 */
export const XFA_EVENT: ReadonlyMap<string, Member> = new Map<string, Member>([
  ...EVENT,
  ['change', ok('string', true)],
  ['commitKey', ok('number')],
  ['fullText', ok('string')],
  ['keyDown', ok('data')],
  ['modifier', ok('data')],
  ['name', ok('string')],
  ['newContentType', ok('string')],
  ['newText', ok('string')],
  ['prevContentType', ok('string')],
  ['prevText', ok('string')],
  ['reenter', ok('data')],
  ['selEnd', ok('number', true)],
  ['selStart', ok('number', true)],
  ['shift', ok('data')],
  ['soapFaultCode', ok('string')],
  ['soapFaultString', ok('string')],
  ['cancelAction', ok('data', true)],
  ['target', ok('doc')],
]);

/** Members of a form node that hold its value, rather than another node. Any other member is a node. */
export const NODE_VALUES: ReadonlyMap<string, Kind> = new Map<string, Kind>([
  ['rawValue', 'data'],
  ['formattedValue', 'string'],
  ['editValue', 'string'],
  ['isNull', 'data'],
  ['length', 'number'],
  ['index', 'number'],
  ['classIndex', 'number'],
  ['name', 'string'],
  ['className', 'string'],
  ['somExpression', 'string'],
  ['value', 'node'],
]);

/**
 * Members of form nodes, and of XFA's host and connections reached through a node, that leave the form or run what
 * the form did not carry. A node can be any object of the model, so any of these names on one is a finding.
 */
export const NODE_DENY: ReadonlyMap<string, Member> = new Map<string, Member>([
  ['connectionSet', network],
  ['sourceSet', network],
  ['execute', network],
  ['signature', exploited],
  ['gotoURL', url],
  ['exportData', importExport],
  ['importData', importExport],
  ['applyXSL', bad(C.DynamicCode, D.Eval)],
]);

/** Node types a script may not create: they would carry script, actions or content from outside the form. */
export const CODE_NODES: ReadonlySet<string> = new Set([
  'script',
  'event',
  'calculate',
  'validate',
  'variables',
  'submit',
  'execute',
  'signData',
  'encryptData',
  'exObject',
  'connect',
  'image',
  'exData',
  'proto',
]);

/** Attributes of a node that name something outside the form. */
export const URL_ATTRIBUTES: ReadonlySet<string> = new Set(['href', 'usehref', 'use', 'target', 'url', 'server', 'codeBase', 'archive', 'classId']);

/** Roots of the SOM in an XFA script, written with `$`. `!` is the datasets model. */
export const SOM_ROOTS: ReadonlyMap<string, Kind | Member> = new Map<string, Kind | Member>([
  ['$', 'node'],
  ['$form', 'node'],
  ['$data', 'node'],
  ['$record', 'node'],
  ['$template', 'node'],
  ['$config', 'node'],
  ['$xfa', 'xfa'],
  ['$host', 'xfahost'],
  ['$layout', 'xfalayout'],
  ['$event', 'xfaevent'],
  ['$connectionSet', network],
  ['$sourceSet', network],
  ['$signature', exploited],
]);
