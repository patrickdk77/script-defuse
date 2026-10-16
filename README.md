# script-defuse

Tell a PDF form's scripts from the rest. script-defuse parses a script and calls it a form script when every call and every property it uses formats, checks or calculates form fields. It reads AcroForm JavaScript, and the JavaScript and FormCalc of XFA forms. Any other script is unsafe, and its findings name what it reaches and on which line: a web address, a form submit, mail, another document, an attached file, the network, code built from a string, or text it hides.

It plugs into [pdf-defuse](https://github.com/patrickdk77/pdf-defuse) as a script plugin, so a fillable form keeps its calculations, formats and checks while every other script goes. It parses with [acorn](https://github.com/acornjs/acorn), its one runtime dependency, and follows the shapes of the other defuse packages.

```
npm install @patrickdk77/script-defuse
```

Node 18 or later.

## Quick start

```js
const { inspectScript } = require('@patrickdk77/script-defuse');

const r = inspectScript('event.value = this.getField("Qty").value * this.getField("Price").value;');
r.verdict;  // 'form' or 'unsafe'
r.score;    // 0 to 100
r.risk;     // 'NONE', 'LOW', 'MEDIUM', 'HIGH' or 'CRITICAL'
r.findings; // [{ category, detail, description, action, location, data, weight }]
```

ES modules work too: `import { inspectScript } from '@patrickdk77/script-defuse'`.

### With pdf-defuse

```js
const { disarmPdf } = require('@patrickdk77/pdf-defuse');
const { formScriptPlugin } = require('@patrickdk77/script-defuse');

const result = await disarmPdf(bytes, { scriptPlugins: [formScriptPlugin()] });
```

pdf-defuse removes every script unless a plugin keeps it. This plugin keeps the form scripts and removes the rest. From pdf-defuse 0.2.4 the plugin's findings go into the PDF's report at each script's location.

Make one plugin per PDF. pdf-defuse hands it the document-level scripts first, and the plugin remembers the globals of the ones it kept, so a field script may call a helper they define. A field script that calls a helper from a document script the plugin removed is removed too.

With [file-defuse](https://github.com/patrickdk77/file-defuse), pass it in the pdf section: `disarmFile(bytes, { pdf: { scriptPlugins: [formScriptPlugin()] } })`.

## What a form script may use

An allowlist decides. A script that uses anything not on it is unsafe, a viewer API script-defuse does not know included.

- Fields: `this.getField(name)`, or `getField(name)`, `event.target` and `event.source`, and a field's value, display, colors, font, list items and check state. `this.numFields`, `getNthFieldName`, `calculateNow` and `resetForm`.
- The event: `event.value`, `change`, `rc`, `willCommit`, `selStart`, `selEnd` and the rest of what a format, keystroke, validate or calculate script reads and sets.
- Acrobat's form helpers, the AForm functions: `AFNumber_Format`, `AFSimple_Calculate`, `AFDate_FormatEx`, `AFRange_Validate`, `AFSpecial_Keystroke` and the others.
- Formatting: `util.printf`, `util.printd`, `util.printx` and `util.scand`, and the `color` and `display` constants.
- Messages: `app.alert`, `app.response` and `app.beep`, and reading `app.viewerVersion`, `viewerType`, `platform` and `language`. A prompt that asks for a password is SCRIPT_API/PASSWORD_PROMPT, since a form takes a password in a field of its own.
- The document's `nocache`, `noautocomplete`, `zoom`, `zoomType`, `layout`, `delay` and `pageNum`, which a script may set, and `scroll`.
- `this.xfa`, or `xfa` alone, in a document that has an XFA form. A bookmark can move to a part of the form that way, and the XFA rules below check everything it reaches.
- The language: `Math`, `Number`, `String`, `Date`, `RegExp`, `JSON`, arrays and objects, and the script's own functions and variables.

A form may store its own data on a field, such as `event.target.oldVal`. A name the script sets on `this` is a global, as a viewer resolves it, so `this.ADBE = new Object()` followed by `ADBE.x` is the script's own data too. So is a name it assigns without declaring it, unless the document has a property of that name. `viewState = s` and `this.viewState = s` set the document's property, so script-defuse checks them as writes to the document, and a property outside the list above is SCRIPT_API/UNKNOWN.

script-defuse follows each value through the script. A local that holds `this.getField("Total")` is a field wherever it is used, and one that holds `this` is the document. A value it cannot place, such as a function parameter, might hold a viewer object, so a viewer API name on it, such as `submitForm`, gets the finding the viewer object would.

## XFA forms

pdf-defuse 0.2.4 hands over an XFA form's scripts with `form: 'xfa'` and their `language`. Pass the same in `context` to `inspectScript`.

XFA JavaScript runs against the XFA object model, with Acrobat's objects beside it.

- `this` is the node that holds the script, and a bare name is a node the SOM finds, such as `Total.rawValue` or `form1.Page1.Name`. Any member of a node counts as the form's own, unless a viewer object has a member of that name that leaves the form.
- `xfa.resolveNode` and `resolveNodes` find nodes by SOM path, computed or not. `xfa.form`, `template`, `data`, `datasets` and `record` are trees of nodes.
- `xfa.host` gives message boxes, focus, pages, `resetData` and version checks, and `xfa.layout` gives pages and positions. `event` and `xfa.event` give the XFA event's members, such as `change`, `newText` and `prevText`. `event.target` is the Acrobat document.
- Forms often name a script object `util` or `color`. A name Acrobat's `util` or `color` lacks is then a function of the script object.
- `xfa.datasets.createNode`, `loadXML` and `assignNode` on the data, and `XMLData.parse` with entities turned off, build and read data.

These are removed wherever a node, a parameter or a variable reaches them:

- `xfa.host.gotoURL`, `exportData`, `importData` and `print`.
- `xfa.connectionSet`, `xfa.sourceSet` and any `execute`, which call a web service or a database.
- `xfa.signature`.
- A node created with a type that carries script, actions or outside content, such as `createNode("script")`, or with a type the script computes.
- `loadXML` and `assignNode` on anything but the data, since they can add script to the form.
- `applyXSL`, which runs a stylesheet.
- Setting a node's `href`, `usehref` or another attribute that names something outside the form, whether directly or with `setAttribute`.
- `XMLData.parse` with entities left on.

FormCalc has a parser of its own and the same rules. A FormCalc script keeps arithmetic, comparisons, `if`, `while`, `for` and `foreach`, the functions and variables it declares, and the built-in functions except these:

- `Get`, `Post` and `Put`, which reach a URL, are SCRIPT_EXTERNAL/NETWORK.
- `Eval` is SCRIPT_DYNAMIC_CODE/EVAL.
- `Decode` is SCRIPT_OBFUSCATION/DECODE.
- A function that FormCalc lacks and the script did not declare is SCRIPT_API/UNKNOWN.

References such as `$host.messageBox`, `$.rawValue`, `xfa.event.change` and `$record.Name` go through the tables the JavaScript rules use, so `$host.gotoURL` and `xfa.connectionSet` go in FormCalc too. `Concat` with many tiny pieces, `Replace` on a string the script wrote itself, encoded or long strings, and `\u` escapes of plain ASCII strip a FormCalc script as they strip a JavaScript one. A script FormCalc cannot parse is SCRIPT_SYNTAX/UNPARSEABLE. That includes JavaScript written in a script element with no content type, which XFA reads as FormCalc and a viewer cannot run.

An XFA script defines no globals for other scripts, which reach its functions through the node that holds it.

## Obfuscation

A form script has nothing to hide, so each of these strips the script:

- `String.fromCharCode` and `fromCodePoint`.
- `unescape`, `escape`, `decodeURIComponent`, `decodeURI`, `atob` and `btoa`.
- A number turned into text in a base past 10, as `(1525081).toString(36)` spells word.
- `replace` or `split` on a string the script wrote itself, as `"qwqoqrqd".replace(/q/g, "")` uncovers hidden text.
- A string joined from 6 or more pieces of one or two characters, or from 25 or more pieces.
- Three or more `\x` or `\u` escapes that write printable ASCII.
- A string of base64, hex, `%u` or `\x` escapes long enough to carry a payload.
- A string over 64 KB, or over 1000 characters with a run of 64 that has no whitespace, and `repeat` past 1000. Text and tables of numbers break into words, so a long message or a CRC table stays.
- Arithmetic on three or more number literals with one in hex, such as `0x1a2+0x3b4+-0x556`.
- A viewer API reached by a quoted name, such as `app["alert"]`.
- A property read by a name computed at run time, unless the object is the script's own data or the key can only be a number.
- `eval`, `Function`, timers that take a string, `arguments.callee` and a function's own `toString`.

## Findings

| Kind | Action | Weight | When |
|---|---|---|---|
| SCRIPT_FORM/COMPUTATION | info | 0 | The script only formats, checks or calculates form fields |
| SCRIPT_EXTERNAL/URL | strip | 60 | `app.launchURL`, `this.getURL`, `xfa.host.gotoURL`, setting a node's `href` |
| SCRIPT_EXTERNAL/SUBMIT | strip | 50 | `this.submitForm` |
| SCRIPT_EXTERNAL/MAIL | strip | 50 | `this.mailDoc`, `mailForm`, `app.mailMsg` |
| SCRIPT_EXTERNAL/OPEN_DOCUMENT | strip | 60 | `app.openDoc`, `app.newDoc`, `app.activeDocs` |
| SCRIPT_EXTERNAL/DATA_OBJECT | strip | 70 | `exportDataObject`, `importDataObject` and the other attached-file calls |
| SCRIPT_EXTERNAL/IMPORT_EXPORT | strip | 50 | FDF, XFDF and text import and export, page insertion, icon import, `xfa.host.exportData` and `importData`, `XMLData.parse` with entities |
| SCRIPT_EXTERNAL/NETWORK | strip | 70 | `Net`, `SOAP`, `Collab`, `ADBC`, `RSS`, XFA connections and `execute`, FormCalc's `Get`, `Post` and `Put` |
| SCRIPT_EXTERNAL/MENU_COMMAND | strip | 60 | `app.execMenuItem`, `app.execDialog` |
| SCRIPT_EXTERNAL/PRINT | strip | 20 | `this.print`, `xfa.host.print` |
| SCRIPT_EXTERNAL/SAVE | strip | 30 | `this.saveAs`, `closeDoc` |
| SCRIPT_DYNAMIC_CODE/EVAL | strip | 80 | `eval`, `Function`, `import()`, FormCalc's `Eval`, `applyXSL` |
| SCRIPT_DYNAMIC_CODE/TIMER | strip | 70 | `app.setTimeOut`, `setInterval` |
| SCRIPT_DYNAMIC_CODE/INSTALL_SCRIPT | strip | 70 | `addScript`, `setAction`, `setPageAction`, menu and toolbar items, XFA nodes created to carry script, `loadXML` and `assignNode` outside the data |
| SCRIPT_DYNAMIC_CODE/PRIVILEGE | strip | 80 | `app.trustedFunction`, `beginPriv`, `security` |
| SCRIPT_DYNAMIC_CODE/COMPUTED_ACCESS | strip | 40 | A property read by a name computed at run time |
| SCRIPT_DYNAMIC_CODE/PROTOTYPE | strip | 60 | `constructor`, `__proto__`, `prototype`, `Object.defineProperty`, `Proxy`, `Reflect` |
| SCRIPT_DYNAMIC_CODE/WITH | strip | 40 | A with statement |
| SCRIPT_DYNAMIC_CODE/SELF_REFERENCE | strip | 60 | `arguments.callee`, a function's own `toString` |
| SCRIPT_OBFUSCATION/CHAR_CODES | strip | 50 | `String.fromCharCode` |
| SCRIPT_OBFUSCATION/DECODE | strip | 60 | Decoders, number bases, text hidden among filler, FormCalc's `Decode` |
| SCRIPT_OBFUSCATION/CONCATENATION | strip | 40 | A string joined from many short pieces |
| SCRIPT_OBFUSCATION/ESCAPES | strip | 40 | Escapes that write printable ASCII |
| SCRIPT_OBFUSCATION/ENCODED_STRING | strip | 50 | A long base64, hex or escaped string |
| SCRIPT_OBFUSCATION/LONG_STRING | strip | 40 | A string over 64 KB, or over 1000 characters with a run of 64 and no whitespace |
| SCRIPT_OBFUSCATION/NUMBER_EXPRESSION | strip | 30 | Arithmetic on hex constants |
| SCRIPT_OBFUSCATION/BRACKET_NAME | strip | 30 | A viewer API reached by a quoted name |
| SCRIPT_API/EXPLOITED | strip | 80 | `getAnnots`, `syncAnnotScan`, `media`, `spell`, signature calls, `xfa.signature`, `util.printf` with a computed format or a field width past 100 |
| SCRIPT_API/UNKNOWN | strip | 30 | A viewer API or global name that is not form computation |
| SCRIPT_API/PASSWORD_PROMPT | strip | 50 | `app.response` or `xfa.host.response` with the password option set |
| SCRIPT_SYNTAX/UNPARSEABLE | strip | 50 | The script is not valid JavaScript, or FormCalc for a FormCalc script |
| SCRIPT_LIMIT/SIZE | strip | 30 | The script is longer than `limits.scriptSize` |
| SCRIPT_LIMIT/DEPTH | strip | 30 | The script nests deeper than `limits.depth` |

The categories start with `SCRIPT_` so they never read as another package's kinds in a shared report. pdf-defuse has a FORM category of its own.

Each finding carries the API in `data.api` where there is one, and its `location` gives the line, after the location the container gave. `allFindingSpecs()` returns this table.

## Scoring

The score takes the highest weight in full and a quarter of each other kind's weight, adds 20 for obfuscation together with a way out of the form or dynamic code, and 20 for obfuscation together with a viewer API known from exploits, and stops at 100. The risk bands start at 1 for LOW, 25 for MEDIUM, 50 for HIGH and 80 for CRITICAL.

## Options

| Option | Default | What it does |
|---|---|---|
| `limits.scriptSize` | none | Characters in one script. A longer script is SCRIPT_LIMIT/SIZE and is not parsed |
| `limits.depth` | none | Nesting of the syntax tree. A deeper script is SCRIPT_LIMIT/DEPTH |
| `actionOverrides` | none | `[{ category, detail?, action }]` sets a kind to `strip` or `info`. An `info` kind no longer makes a script unsafe |
| `scoreWeights` | none | `[{ category, detail?, weight }]` |
| `scoreBands` | above | `{ low, medium, high, critical }` |
| `context` | none | `inspectScript` only. `{ trigger, location, fieldName, language, form }`. The first three go into the findings' locations. `language: 'formcalc'` reads FormCalc, and `form: 'xfa'` reads JavaScript against the XFA object model |
| `knownGlobals` | none | `inspectScript` only. Global names scripts that ran before defined and kept |

A limit left out is not enforced. `formScriptPlugin(options)` takes the same options but `context` and `knownGlobals`, which it fills in itself, and keeps every decision it made in `plugin.decisions`.

## What it does not protect against

- A form script can loop forever. script-defuse does not decide whether a loop ends.
- pdf-defuse removes an XFA form's submits, connections, unsafe links and the images no plugin keeps. script-defuse sees only the scripts it is handed.
- A form that uses a viewer API outside the allowlist loses that script. An action override keeps a kind you accept.
- JavaScript files, and scripts in HTML, are not covered yet.

## Development

```
npm install
npm test
```

`npm test` runs the linter, builds, and runs the tests. The tests build each script they check. No sample from a real form or a malicious file goes in this repository.

## License

MIT
