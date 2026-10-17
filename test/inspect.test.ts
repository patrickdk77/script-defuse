import { expect } from 'chai';
import { ScriptCategory as C, ScriptDetail as D, formScriptPlugin, inspectScript, type ScriptInspection } from '../src';

const kinds = (r: ScriptInspection) => r.findings.filter(f => f.action === 'strip').map(f => `${f.category}/${f.detail}`);
const form = (text: string, knownGlobals?: string[]) => {
  const r = inspectScript(text, { knownGlobals });
  expect(kinds(r), text).to.deep.equal([]);
  expect(r.verdict).to.equal('form');
  return r;
};
const unsafe = (text: string, kind: string) => {
  const r = inspectScript(text);
  expect(r.verdict, text).to.equal('unsafe');
  expect(kinds(r), text).to.include(kind);
  return r;
};

describe('form scripts', () => {
  it('keeps the AForm format, keystroke, validate and calculate helpers', () => {
    form('AFNumber_Format(2, 0, 0, 0, "$", true);');
    form('AFNumber_Keystroke(2, 0, 0, 0, "$", true);');
    form('AFDate_FormatEx("mm/dd/yyyy");');
    form('AFRange_Validate(true, 0, true, 100);');
    form('AFSimple_Calculate("SUM", new Array("Line1", "Line2", "Line3"));');
    form('AFSpecial_Keystroke(1);');
  });

  it('keeps a calculation that reads fields and sets event.value', () => {
    form(`
      var a = this.getField("Qty").value;
      var b = this.getField("Price").value;
      event.value = Number(a) * Number(b);
    `);
    form('event.value = getField("Subtotal").value + getField("Tax").value;');
  });

  it('keeps a validation that checks the value and tells the user', () => {
    form(`
      if (event.value !== "" && !/^\\d{5}$/.test(event.value)) {
        app.alert("Enter a five digit ZIP code.");
        event.rc = false;
      }
    `);
  });

  it('keeps field styling, list handling and a loop over field names', () => {
    form(`
      var f = event.target;
      f.fillColor = event.value < 0 ? color.red : color.transparent;
      f.display = event.value ? display.visible : display.hidden;
      var names = ["A", "B", "C"];
      var total = 0;
      for (var i = 0; i < names.length; i++) total += Number(this.getField(names[i]).value);
      this.getField("Total").value = util.printf("%.2f", total);
    `);
  });

  it('keeps data a form stores on a field, and checks a viewer API reached through the field', () => {
    form('if (event.target.oldVal === event.target.value) { event.target.value = "Off"; } event.target.oldVal = event.target.value;');
    unsafe('event.target.doc.submitForm("http://example.com");', `${C.External}/${D.Submit}`);
    unsafe('event.target.submitForm("http://example.com");', `${C.External}/${D.Submit}`);
  });

  it('keeps a date check with util.scand and util.printd', () => {
    form('var d = util.scand("mm/dd/yyyy", event.value); if (d) event.value = util.printd("mmmm d, yyyy", d);');
  });

  it('keeps a typeof feature check on a name that does not exist', () => {
    form('if (typeof ADBE == "undefined") { var x = 1; }');
  });

  it('keeps a script that uses a global an earlier kept script defined, and one that sets it on the document', () => {
    form('total = sumFields(["A", "B"]);', ['sumFields', 'total']);
    form('this.Helpers = new Object(); Helpers.version = 2;');
  });
});

describe('ways out of the form', () => {
  it('strips web addresses, submits, mail and other documents', () => {
    unsafe('app.launchURL("http://example.com", true);', `${C.External}/${D.Url}`);
    unsafe('this.getURL("http://example.com");', `${C.External}/${D.Url}`);
    unsafe('this.submitForm({cURL: "http://example.com/collect", cSubmitAs: "PDF"});', `${C.External}/${D.Submit}`);
    unsafe('submitForm("http://example.com/collect");', `${C.External}/${D.Submit}`);
    unsafe('this.mailDoc({cTo: "a@example.com"});', `${C.External}/${D.Mail}`);
    unsafe('app.openDoc("/c/other.pdf");', `${C.External}/${D.OpenDocument}`);
  });

  it('strips attached files, imports and the network', () => {
    unsafe('this.exportDataObject({cName: "payload.exe", nLaunch: 2});', `${C.External}/${D.DataObject}`);
    unsafe('this.importAnFDF("data.fdf");', `${C.External}/${D.ImportExport}`);
    unsafe('Net.HTTP.request({cVerb: "GET", cURL: "http://example.com"});', `${C.External}/${D.Network}`);
    unsafe('SOAP.request({cURL: "http://example.com"});', `${C.External}/${D.Network}`);
    unsafe('app.execMenuItem("SaveAs");', `${C.External}/${D.MenuCommand}`);
  });

  it('strips a viewer API reached through a local or a function parameter', () => {
    unsafe('var d = this; d.submitForm("http://example.com");', `${C.External}/${D.Submit}`);
    unsafe('function go(doc) { doc.exportDataObject({cName: "x", nLaunch: 2}); } go(this);', `${C.External}/${D.DataObject}`);
    unsafe('var a = app; a.launchURL("http://example.com");', `${C.External}/${D.Url}`);
  });

  it('strips viewer APIs known from exploits', () => {
    unsafe('var a = this.getAnnots();', `${C.Api}/${D.Exploited}`);
    unsafe('util.printf("%45000f", 1);', `${C.Api}/${D.Exploited}`);
    unsafe('var fmt = "%" + "45000f"; util.printf(fmt, 1);', `${C.Api}/${D.Exploited}`);
    unsafe('Collab.getIcon("x");', `${C.External}/${D.Network}`);
    unsafe('media.newPlayer(null);', `${C.Api}/${D.Exploited}`);
  });

  it('strips any viewer member that is not form computation', () => {
    unsafe('var p = this.path;', `${C.Api}/${D.Unknown}`);
    unsafe('event.target.setAction("MouseUp", "app.alert(1)");', `${C.DynamicCode}/${D.InstallScript}`);
    unsafe('app.viewerVersion = 1;', `${C.Api}/${D.Unknown}`);
    unsafe('someHostThing();', `${C.Api}/${D.Unknown}`);
  });
});

describe('dynamic code', () => {
  it('strips eval, the Function constructor and timers', () => {
    unsafe('eval("app.alert(1)");', `${C.DynamicCode}/${D.Eval}`);
    unsafe('var f = new Function("return 1"); f();', `${C.DynamicCode}/${D.Eval}`);
    unsafe('app.setTimeOut("app.alert(1)", 100);', `${C.DynamicCode}/${D.Timer}`);
    unsafe('app.setInterval("tick()", 100);', `${C.DynamicCode}/${D.Timer}`);
  });

  it('strips privileged execution and installed scripts', () => {
    unsafe('var t = app.trustedFunction(function () { app.beginPriv(); });', `${C.DynamicCode}/${D.Privilege}`);
    unsafe('this.addScript("x", "app.alert(1)");', `${C.DynamicCode}/${D.InstallScript}`);
  });

  it('strips a property read by a computed name on a viewer object', () => {
    unsafe('var m = "launch" + "URL"; app[m]("http://example.com");', `${C.DynamicCode}/${D.ComputedAccess}`);
    unsafe('var k = event.value; this[k]();', `${C.DynamicCode}/${D.ComputedAccess}`);
  });

  it('keeps a numeric index into a local array, and an index into a parameter only when the key is a number', () => {
    form('var a = [1, 2, 3]; var s = 0; for (var i = 0; i < a.length; i++) s += a[i]; event.value = s;');
    form('function first(list) { return list[0]; } event.value = first([4]);');
    unsafe('function get(o, k) { return o[k]; } get(this, "submitForm")();', `${C.DynamicCode}/${D.ComputedAccess}`);
  });

  it('strips the machinery behind objects and functions', () => {
    unsafe('"".constructor.constructor("app.alert(1)")();', `${C.DynamicCode}/${D.Prototype}`);
    unsafe('var o = {}; o.__proto__.x = 1;', `${C.DynamicCode}/${D.Prototype}`);
    unsafe('Object.defineProperty(this, "x", {get: function () { return 1; }});', `${C.DynamicCode}/${D.Prototype}`);
    unsafe('with (app) { alert(1); }', `${C.DynamicCode}/${D.With}`);
  });

  it('strips a script that reads its own source', () => {
    unsafe('var src = arguments.callee.toString();', `${C.DynamicCode}/${D.SelfReference}`);
    unsafe('function f() {} var s = f.toString();', `${C.DynamicCode}/${D.SelfReference}`);
  });
});

describe('obfuscation', () => {
  it('strips text built from character codes and decoders', () => {
    unsafe('var s = String.fromCharCode(97, 112, 112);', `${C.Obfuscation}/${D.CharCodes}`);
    unsafe('var s = unescape("%61%70%70");', `${C.Obfuscation}/${D.Decode}`);
    unsafe('var s = decodeURIComponent("%61");', `${C.Obfuscation}/${D.Decode}`);
  });

  it('strips text written as numbers in another base, and text hidden among filler', () => {
    unsafe('app.alert((1525081).toString(36));', `${C.Obfuscation}/${D.Decode}`);
    unsafe('var n = 1; app.alert(n.toString(36));', `${C.Obfuscation}/${D.Decode}`);
    unsafe('app.alert("qwqoqrqdqs".replace(/q/g, ""));', `${C.Obfuscation}/${D.Decode}`);
    unsafe('var s = "a-p-p".split("-");', `${C.Obfuscation}/${D.Decode}`);
  });

  it('strips a string joined from many tiny pieces', () => {
    unsafe('var s = "s" + "u" + "b" + "m" + "i" + "t" + "F" + "o" + "r" + "m";', `${C.Obfuscation}/${D.Concatenation}`);
  });

  it('keeps a message joined from a few readable pieces', () => {
    form('app.alert("Total for " + event.value + " is " + this.getField("T").value + ".");');
  });

  it('strips needless escapes, encoded strings and very long strings', () => {
    unsafe('var s = "\\x61\\x70\\x70\\x2e\\x61";', `${C.Obfuscation}/${D.Escapes}`);
    unsafe(`var s = "${'QUJD'.repeat(40)}";`, `${C.Obfuscation}/${D.EncodedString}`);
    unsafe(`var s = "${'%u9090'.repeat(10)}";`, `${C.Obfuscation}/${D.EncodedString}`);
    unsafe(`var s = "${'x;'.repeat(600)}";`, `${C.Obfuscation}/${D.LongString}`);
    // Text and tables break into words, such as a CRC table a form computes a checksum with.
    form(`var table = "${'0A1B2C3D 4E5F6071 '.repeat(80)}";`);
    unsafe(`var xx = "${`${'01'.repeat(35)} `.repeat(20)}";`, `${C.Obfuscation}/${D.LongString}`);
    unsafe(`var xx = "${'0 1 '.repeat(16400)}";`, `${C.Obfuscation}/${D.LongString}`);
    unsafe('var s = "A".repeat(100000);', `${C.Obfuscation}/${D.LongString}`);
  });

  it('strips a number hidden as arithmetic on hex constants, and keeps ordinary arithmetic', () => {
    unsafe('AFSpecial_Format(0x1a2+0x3b4+-0x556);', `${C.Obfuscation}/${D.NumberExpression}`);
    form('event.value = 2 * 3 + this.getField("A").value;');
    form('var mask = 0xff; event.value = 1 + 2 + 3;');
  });

  it('strips a quoted name on a viewer object where a form script would name it plainly', () => {
    unsafe('app["alert"]("hi");', `${C.Obfuscation}/${D.BracketName}`);
  });
});

describe('scripts that cannot be read', () => {
  it('strips a script that does not parse', () => {
    unsafe('var = ;', `${C.Syntax}/${D.Unparseable}`);
  });

  it('strips a script past the size and depth limits', () => {
    const r = inspectScript('event.value = 1;', { limits: { scriptSize: 5 } });
    expect(kinds(r)).to.deep.equal([`${C.Limit}/${D.Size}`]);
    const deep = `event.value = ${'['.repeat(50)}1${']'.repeat(50)};`;
    expect(kinds(inspectScript(deep, { limits: { depth: 20 } }))).to.deep.equal([`${C.Limit}/${D.Depth}`]);
  });
});

describe('the document', () => {
  it('reads an assignment to a document property as a write to the document, not a new global', () => {
    // A large string written to a document property the allowlist does not have.
    unsafe('var big = new Array(4096).join("x"); viewState = big;', `${C.Api}/${D.Unknown}`);
    unsafe('this.viewState = "x";', `${C.Api}/${D.Unknown}`);
    unsafe('numPages = 1;', `${C.Api}/${D.Unknown}`);
    form('this.nocache = true; this.noautocomplete = true; this.zoom = 100; this.layout = "SinglePage";');
    form('myTotal = 0; myTotal += 5; event.value = myTotal;');
  });

  it('removes a prompt that asks for a password', () => {
    unsafe('var p = app.response({ cQuestion: "Enter your PIN", cTitle: "Verify", bPassword: true });', `${C.Api}/${D.PasswordPrompt}`);
    unsafe('var p = app.response("Enter your PIN", "Verify", "", true);', `${C.Api}/${D.PasswordPrompt}`);
    form('var name = app.response({ cQuestion: "Your name?", bPassword: false }); event.value = name;');
    form('var name = app.response("Your name?"); event.value = name;');
    const xfa = inspectScript('var p = xfa.host.response("Enter your PIN", "Verify", "", 1);', { context: { form: 'xfa' } });
    expect(kinds(xfa)).to.include(`${C.Api}/${D.PasswordPrompt}`);
    const fc = inspectScript('$ = $host.response("Enter your PIN", "Verify", "", 1)', { context: { form: 'xfa', language: 'formcalc' } });
    expect(kinds(fc)).to.include(`${C.Api}/${D.PasswordPrompt}`);
    expect(inspectScript('$ = $host.response("Name?", "Ask")', { context: { form: 'xfa', language: 'formcalc' } }).verdict).to.equal('form');
  });
});

describe('the report', () => {
  it('names the API and where it is', () => {
    const r = inspectScript('var x = 1;\napp.launchURL("http://example.com");', { context: { location: 'document script "init"' } });
    const f = r.findings.find(x => x.detail === D.Url);
    expect(f?.data?.api).to.equal('app.launchURL');
    expect(f?.location).to.equal('document script "init", line 2');
    expect(f?.description).to.equal('app.launchURL opens a web address');
    expect(r.score).to.be.greaterThan(0);
  });

  it('marks a form script with an info finding and a zero score', () => {
    const r = form('AFNumber_Format(2, 0, 0, 0, "", true);');
    expect(r.findings.map(f => `${f.category}/${f.detail}/${f.action}`)).to.deep.equal([`${C.Form}/${D.Computation}/info`]);
    expect(r.score).to.equal(0);
  });

  it('lets an override keep what a finding would strip', () => {
    const r = inspectScript('app.launchURL("http://example.com");', { actionOverrides: [{ category: C.External, detail: D.Url, action: 'info' }] });
    expect(r.verdict).to.equal('form');
  });
});

describe('formScriptPlugin', () => {
  it('keeps a field script that calls a helper a kept document script defined', async () => {
    const plugin = formScriptPlugin();
    const doc = await plugin.process({ text: 'function addUp(a, b) { return Number(a) + Number(b); }', trigger: 'document', location: 'document script "helpers"' });
    expect(doc.result).to.equal('passed');
    const field = await plugin.process({ text: 'event.value = addUp(getField("A").value, getField("B").value);', trigger: 'field-calculate', fieldName: 'Total' });
    expect(field.result).to.equal('passed');
  });

  it('does not let a field script call a helper from a document script it removed', async () => {
    const plugin = formScriptPlugin();
    const doc = await plugin.process({ text: 'function go() { app.launchURL("http://example.com"); }', trigger: 'document' });
    expect(doc.result).to.equal('removed');
    const field = await plugin.process({ text: 'go();', trigger: 'click' });
    expect(field.result).to.equal('removed');
    expect(plugin.decisions.map(d => d.result)).to.deep.equal(['removed', 'removed']);
  });

  it('hands back its findings for the container report', async () => {
    const r = await formScriptPlugin().process({ text: 'this.submitForm("http://example.com");', trigger: 'click' });
    expect(r.findings?.some(f => f.detail === D.Submit)).to.equal(true);
  });

  it('weighs its findings as the script score counts them, so a container scores the script by them alone', async () => {
    const kept = await formScriptPlugin().process({ text: 'var inertSum = Number(getField("InertLeft").value) + 7; event.value = inertSum;', trigger: 'field-calculate', fieldName: 'InertRight' });
    expect(kept.result).to.equal('passed');
    expect(kept.findings?.length).to.be.greaterThan(0);
    expect(kept.findings?.map(f => f.weight)).to.satisfy((w: number[]) => w.every(x => x === 0));
    const text = 'this.submitForm("http://example.com");';
    const removed = await formScriptPlugin({ scoreWeights: [{ category: C.External, weight: 33 }] }).process({ text, trigger: 'click' });
    const submit = removed.findings?.find(f => f.detail === D.Submit);
    expect([removed.result, submit?.weight]).to.deep.equal(['removed', 33]);
    const own = inspectScript(text, { context: { trigger: 'click' }, scoreWeights: [{ category: C.External, weight: 33 }] });
    expect(Math.max(...(removed.findings ?? []).map(f => f.weight ?? 0))).to.equal(own.score);
  });
});
