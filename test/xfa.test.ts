import { expect } from 'chai';
import { ScriptCategory as C, ScriptDetail as D, formScriptPlugin, type InspectScriptOptions, inspectScript, type ScriptInspection } from '../src';

const kinds = (r: ScriptInspection) => r.findings.filter(f => f.action === 'strip').map(f => `${f.category}/${f.detail}`);
const XFA_JS: InspectScriptOptions = { context: { form: 'xfa', language: 'javascript' } };
const FORMCALC: InspectScriptOptions = { context: { form: 'xfa', language: 'formcalc' } };

const keeps = (text: string, options: InspectScriptOptions) => {
  const r = inspectScript(text, options);
  expect(kinds(r), text).to.deep.equal([]);
  expect(r.verdict).to.equal('form');
  return r;
};
const removes = (text: string, kind: string, options: InspectScriptOptions) => {
  const r = inspectScript(text, options);
  expect(r.verdict, text).to.equal('unsafe');
  expect(kinds(r), text).to.include(kind);
  return r;
};

describe('XFA JavaScript', () => {
  const form = (text: string) => keeps(text, XFA_JS);
  const unsafe = (text: string, kind: string) => removes(text, kind, XFA_JS);

  it('keeps calculations on form nodes reached by name, by this, and by resolveNode', () => {
    form('this.rawValue = Qty.rawValue * Price.rawValue;');
    form('form1.Page1.Total.rawValue = Sub.rawValue + Tax.rawValue;');
    form('xfa.resolveNode("form1.Page1.Line" + i).rawValue = 0;');
    form('var rows = xfa.resolveNodes("Lines.Item[*]"); for (var i = 0; i < rows.length; i++) rows.item(i).Cost.rawValue = 0;');
    form('this.presence = (Married.rawValue == "1") ? "visible" : "hidden";');
    form('Lines._Item.addInstance(1); xfa.form.recalculate(1);');
  });

  it('keeps the host, layout and event members a form uses', () => {
    form('xfa.host.messageBox("Enter a five digit ZIP code.", "Check", 1);');
    form('xfa.host.setFocus(this.somExpression); xfa.host.beep(1);');
    form('Footer.Count.rawValue = xfa.layout.pageCount() - xfa.layout.page(this);');
    form('if (xfa.event.prevText != xfa.event.newText) Status.rawValue = xfa.event.newText.length;');
    form('if (xfa.host.version < 8) { xfa.host.messageBox("Upgrade your reader."); }');
    form('event.change = event.change.toUpperCase();');
  });

  it("keeps calls to the form's script objects, including ones named util or color", () => {
    form('utils.markRequired(this);');
    form('util.highlightRequired(this, true); color.shadeValid(this);');
    form('this.rawValue = util.printd("mm/dd/yyyy", new Date());');
    form('function check(f) { if (f.isNull) { f.mandatory = "error"; return false; } return true; }');
  });

  it('keeps data nodes a script builds and loads', () => {
    form('var group = xfa.datasets.createNode("dataGroup", "progress"); xfa.datasets.data.nodes.append(group);');
    form('var fill = xfa.form.createNode("color", "");');
    form('xfa.datasets.data.loadXML(Saved.rawValue, 0, 1);');
    form('xfa.datasets.data.order.assignNode("progress.step", "2", 0);');
    form('var doc = XMLData.parse(Store.rawValue, false); var labels = XMLData.applyXPath(doc, "//item/label");');
  });

  it('keeps a loop index declared before the loop', () => {
    form('function count(list, x) { var n = 0; var k; for (k = 0; k < list.length; k++) { if (list[k] === x) n++; } return n; }');
  });

  it('removes ways out of the form through the XFA host and its connections', () => {
    unsafe('xfa.host.gotoURL("https://example.com/");', `${C.External}/${D.Url}`);
    unsafe('xfa.host.exportData("", 0);', `${C.External}/${D.ImportExport}`);
    unsafe('xfa.host.importData("data.xml");', `${C.External}/${D.ImportExport}`);
    unsafe('xfa.host.print(0, "0", "2", 0, 1, 0, 0, 0);', `${C.External}/${D.Print}`);
    unsafe('xfa.connectionSet.LookupService.execute(0);', `${C.External}/${D.Network}`);
    unsafe('var h = xfa.resolveNode("$host"); h.gotoURL("https://example.com/");', `${C.External}/${D.Url}`);
    unsafe('$host.gotoURL("https://example.com/");', `${C.External}/${D.Url}`);
    unsafe('xfa.signature.sign("form1", "Sig", "");', `${C.Api}/${D.Exploited}`);
  });

  it('removes Acrobat calls an XFA script reaches through event.target and app', () => {
    unsafe('event.target.submitForm({ cURL: "https://example.com/" });', `${C.External}/${D.Submit}`);
    unsafe('event.target.mailDoc(true);', `${C.External}/${D.Mail}`);
    unsafe('app.launchURL("https://example.com/", true);', `${C.External}/${D.Url}`);
    unsafe('var r = new Report(); r.writeText("x"); r.open("x");', `${C.External}/${D.OpenDocument}`);
  });

  it('removes scripts that change the form to carry script or load from outside it', () => {
    unsafe('var s = xfa.template.createNode("script"); s.value = "x";', `${C.DynamicCode}/${D.InstallScript}`);
    unsafe('var n = xfa.form.createNode(kind);', `${C.DynamicCode}/${D.InstallScript}`);
    unsafe('this.resolveNode("#subform").loadXML(s, 0, 1);', `${C.DynamicCode}/${D.InstallScript}`);
    unsafe('xfa.form.form1.applyXSL(sheet);', `${C.DynamicCode}/${D.Eval}`);
    unsafe('ImageField1.value.image.href = "https://example.com/a.png";', `${C.External}/${D.Url}`);
    unsafe('Send.event__click.submit.target = "https://example.com/";', `${C.External}/${D.Url}`);
    unsafe('this.setAttribute("https://example.com/a.png", "href");', `${C.External}/${D.Url}`);
    unsafe('var doc = XMLData.parse(Store.rawValue);', `${C.External}/${D.ImportExport}`);
  });

  it('applies the obfuscation rules as in AcroForm scripts', () => {
    unsafe('eval(Hidden.rawValue);', `${C.DynamicCode}/${D.Eval}`);
    unsafe('var s = String.fromCharCode(104, 116, 116, 112);', `${C.Obfuscation}/${D.CharCodes}`);
    unsafe('xfa.host["gotoURL"]("https://example.com/");', `${C.Obfuscation}/${D.BracketName}`);
  });

  it("lets a PDF-side script reach the document's XFA form through the same tables", () => {
    keeps('xfa.form.order.variables.nav.jumpTo(xfa.form.order.part2.somExpression);', {});
    keeps('event.target.xfa.resolveNode("form1.Total").rawValue = 0; this.scroll(0, 100);', {});
    removes('xfa.host.gotoURL("https://example.com/");', `${C.External}/${D.Url}`, {});
    removes('xfa["host"].messageBox("x");', `${C.Obfuscation}/${D.BracketName}`, {});
  });

  it('reads this as the document and bare names as unknown in an AcroForm script', () => {
    removes('var v = this.rawValue;', `${C.Api}/${D.Unknown}`, {});
    removes('rawValue = 1; var y = rawValue + nonsense;', `${C.Api}/${D.Unknown}`, {});
  });

  it('defines no globals, since other scripts reach an XFA script through its node', () => {
    expect(inspectScript('function helper() { return 1; } var x = 2;', XFA_JS).definedGlobals).to.deep.equal([]);
  });
});

describe('FormCalc', () => {
  const form = (text: string) => keeps(text, FORMCALC);
  const unsafe = (text: string, kind: string) => removes(text, kind, FORMCALC);

  it('keeps calculations with the built-in functions', () => {
    form('Sum(Line1, Line2, Line3)');
    form('$ = Round(Price * Qty, 2)');
    form('Total = Sum(Lines.Item[*].Cost)');
    form('$.rawValue = Concat(First, " ", Last)');
    form('if (HasValue($) and Len($) > 9) then $host.messageBox("Too long") endif');
    form('$ = Num2Date(Date(), "MM/DD/YYYY")');
  });

  it('keeps control flow, variables and functions', () => {
    form(`
      ; running total
      var total = 0
      foreach item in (Lines.Item[*].Cost) do
        total = total + item
      endfor
      $ = total // done
    `);
    form('for i = 1 upto 10 step 1 do if (i > 5) then break endif endfor');
    form('var n = 0 while (n < 3) do n = n + 1 endwhile');
    form('func addTax(x) do x * 1.08 endfunc $ = addTax(Subtotal)');
    form('IF (A == 1) THEN B = 2 ELSEIF (A <> 2) THEN B = 3 ELSE B = 4 ENDIF');
    form('do var t = $.rawValue $.rawValue = Upper(t) end');
  });

  it('keeps node members, the event, and form methods', () => {
    form('$.presence = "hidden"');
    form('xfa.event.change = Upper(xfa.event.change)');
    form('$host.setFocus("Field1")');
    form('Lines._Item.addInstance(1)');
    form('$record.Customer.Name = Name');
    form('Page2.Field1.execInitialize()');
    form('$ = $.parent.Line[0] + $.parent.Line[-1]');
  });

  it('removes the URL functions, Eval and Decode', () => {
    unsafe('Get("https://example.com/")', `${C.External}/${D.Network}`);
    unsafe('Post("https://example.com/", $.rawValue)', `${C.External}/${D.Network}`);
    unsafe('put("https://example.com/", $.rawValue)', `${C.External}/${D.Network}`);
    unsafe('Eval("1 + 1")', `${C.DynamicCode}/${D.Eval}`);
    unsafe('$ = Decode("%41%42", "url")', `${C.Obfuscation}/${D.Decode}`);
  });

  it('removes ways out of the form through the host and connections', () => {
    unsafe('$host.gotoURL("https://example.com/")', `${C.External}/${D.Url}`);
    unsafe('xfa.host.exportData()', `${C.External}/${D.ImportExport}`);
    unsafe('$connectionSet.DataConnection.execute(0)', `${C.External}/${D.Network}`);
    unsafe('xfa.connectionSet.DataConnection.execute(0)', `${C.External}/${D.Network}`);
    unsafe('xfa.resolveNode("$host").gotoURL("https://example.com/")', `${C.External}/${D.Url}`);
    unsafe('xfa.template.createNode("script")', `${C.DynamicCode}/${D.InstallScript}`);
    unsafe('ImageField1.value.image.href = "https://example.com/a.png"', `${C.External}/${D.Url}`);
  });

  it('removes hidden text', () => {
    unsafe('$ = Concat("h", "t", "t", "p", ":", "/", "/")', `${C.Obfuscation}/${D.Concatenation}`);
    unsafe('$ = Replace("hzztzztzzp", "zz", "")', `${C.Obfuscation}/${D.Decode}`);
    unsafe(`$ = "${'QUJD'.repeat(40)}"`, `${C.Obfuscation}/${D.EncodedString}`);
    unsafe('$ = "\\u0068\\u0074\\u0074\\u0070"', `${C.Obfuscation}/${D.Escapes}`);
  });

  it('removes what it cannot parse and functions it does not know', () => {
    unsafe('$ = (Qty]*2)', `${C.Syntax}/${D.Unparseable}`);
    unsafe('if (a) { b = 1 }', `${C.Syntax}/${D.Unparseable}`);
    unsafe('if (a) then b = 1', `${C.Syntax}/${D.Unparseable}`);
    unsafe('Launch("calc.exe")', `${C.Api}/${D.Unknown}`);
  });

  it('enforces the size and depth limits', () => {
    const big = removes('Sum(A, B)', `${C.Limit}/${D.Size}`, { ...FORMCALC, limits: { scriptSize: 4 } });
    expect(big.findings.some(f => f.category === C.Syntax)).to.equal(false);
    removes(`$ = ${'('.repeat(50)}1${')'.repeat(50)}`, `${C.Limit}/${D.Depth}`, { ...FORMCALC, limits: { depth: 40 } });
  });
});

describe('formScriptPlugin with XFA scripts', () => {
  it('reads the language and form from the script pdf-defuse hands it', async () => {
    const plugin = formScriptPlugin();
    const base = { trigger: 'xfa-calculate', location: 'XFA template, form1.Total, calculate', keptDocumentScripts: [] };
    expect((await plugin.process({ ...base, text: 'Sum(A, B)', language: 'formcalc', form: 'xfa' })).result).to.equal('passed');
    expect((await plugin.process({ ...base, text: 'this.rawValue = A.rawValue;', language: 'javascript', form: 'xfa' })).result).to.equal('passed');
    expect((await plugin.process({ ...base, text: 'Get("https://example.com/")', language: 'formcalc', form: 'xfa' })).result).to.equal('removed');
    // FormCalc read as JavaScript is not valid JavaScript.
    expect((await plugin.process({ ...base, text: 'if (A) then B = 1 endif', form: 'xfa' })).result).to.equal('removed');
  });
});
