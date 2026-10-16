import { expect } from 'chai';
import { formScriptPlugin, inspectScript, type ScriptContext, type ScriptInspection, type ScriptReference } from '../src';

// Every module here is written for the test. The unsafe ones imitate how macros reach outside a document, with inert
// names and example.invalid hosts in place of real programs and servers.

const VBA: ScriptContext = { language: 'vba', form: 'office', trigger: 'vba-standard', location: 'VBA/Module1' };
const kinds = (r: ScriptInspection) => r.findings.filter(f => f.action === 'strip').map(f => `${f.category}/${f.detail}`);
const inspect = (text: string, context: ScriptContext = VBA) => inspectScript(text.replace(/\n/g, '\r\n'), { context });
const kept = (text: string, context?: ScriptContext) => {
  const r = inspect(text, context);
  expect(kinds(r), text).to.deep.equal([]);
  expect(r.verdict).to.equal('form');
  return r;
};
const removed = (text: string, kind: string, api?: string) => {
  const r = inspect(text);
  expect(r.verdict, text).to.equal('unsafe');
  expect(kinds(r), text).to.include(kind);
  if (api !== undefined)
    expect(
      r.findings.filter(f => `${f.category}/${f.detail}` === kind).map(f => f.data?.api),
      text,
    ).to.include(api);
  return r;
};

describe('VBA modules', () => {
  it('keeps macros that work on their own document', () => {
    const r = kept(`Attribute VB_Name = "Sums"
Option Explicit

' Fills a column and adds it up.
Public Sub AddTotals()
    Dim total As Double, r As Long
    For r = 2 To 10
        Cells(r, 2).Value = r * 1.5
        total = total + Cells(r, 2).Value
    Next r
    Range("B11").Formula = "=SUM(B2:B10)"
    MsgBox "Total: " & Format(total, "0.00") & vbCrLf & "Done", vbInformation
    Debug.Print total
End Sub

Private Function ColumnLetter(n As Long) As String
    ColumnLetter = Chr(64 + n)
End Function`);
    expect(r.findings.map(f => `${f.category}/${f.detail}`)).to.deep.equal(['SCRIPT_FORM/DOCUMENT_MACRO']);
  });

  it('keeps document events, forms, a slide show and the characters Chr writes for text', () => {
    kept(`Sub Workbook_Open()
    Worksheets(3).Activate
    Application.StatusBar = "Inert ready"
End Sub
Sub Worksheet_Change(ByVal changed As Range)
    If changed.Column = 2 Then changed.Offset(0, 1).Value = changed.Value * 2
End Sub`);
    kept(`Sub InertButton_Click()
    Me.Hide
    PickForm.Show
    Set deck = ActivePresentation
    deck.SlideShowSettings.Run
    quoted = Chr(34) & "x" & Chr(34) & Chr(13) & Chr(10) & Chr(9) & Chr(171) & Chr(187) & Chr(176)
End Sub`);
    kept(`Sub Fill()
    Dim d As New Collection, s As Object
    Set s = New Scripting.Dictionary
    Workbooks.Add
    ActiveWorkbook.Save
    x = Evaluate("SUM(A1:A3)") + [B1]
End Sub`);
  });

  it('removes a module that starts a program, sends keys, or talks to another program', () => {
    removed('Sub A()\n    Shell "inert-program.exe", vbHide\nEnd Sub', 'SCRIPT_EXTERNAL/PROCESS', 'Shell');
    removed('Sub A()\n    x = VBA.Interaction.Shell("inert-program.exe")\nEnd Sub', 'SCRIPT_EXTERNAL/PROCESS', 'Interaction.Shell');
    removed('Sub A()\n    SendKeys "%{F4}"\nEnd Sub', 'SCRIPT_EXTERNAL/PROCESS', 'Sendkeys');
    removed('Sub A()\n    ch = DDEInitiate("inert-app", "inert topic")\nEnd Sub', 'SCRIPT_EXTERNAL/DDE');
    removed('Sub A()\n    MacScript "inert"\nEnd Sub', 'SCRIPT_EXTERNAL/PROCESS');
  });

  it('removes objects from outside the document, native calls and the VBA editor', () => {
    removed('Sub A()\n    Set o = CreateObject("Inert.Object")\n    o.Run "x"\nEnd Sub', 'SCRIPT_EXTERNAL/COM_OBJECT', 'Createobject');
    removed('Sub A()\n    Set o = GetObject("winmgmts:")\nEnd Sub', 'SCRIPT_EXTERNAL/COM_OBJECT');
    removed('Sub A()\n    Set files = New FileSystemObject\nEnd Sub', 'SCRIPT_EXTERNAL/FILE_SYSTEM', 'New filesystemobject');
    removed('Sub A()\n    Dim h As New InertLib.Fetcher\nEnd Sub', 'SCRIPT_EXTERNAL/COM_OBJECT');
    removed('Declare PtrSafe Function InertCall Lib "inert.dll" (ByVal n As Long) As Long', 'SCRIPT_EXTERNAL/NATIVE_CODE');
    removed('Sub A()\n    Set p = target.VBProject\n    p.VBComponents(2).CodeModule.AddFromString "Sub B(): End Sub"\nEnd Sub', 'SCRIPT_DYNAMIC_CODE/INSTALL_SCRIPT');
    removed('Sub A()\n    p = VarPtr(x)\n    q = AddressOf Callback\nEnd Sub', 'SCRIPT_DYNAMIC_CODE/PRIVILEGE');
  });

  it('removes file statements and functions, the registry and the environment', () => {
    removed('Sub A()\n    Open "C:\\inert\\a.txt" For Append As #7\n    Print #7, total\n    Close #7\nEnd Sub', 'SCRIPT_EXTERNAL/FILE_SYSTEM', 'Open');
    removed('Sub A()\n10  Open path For Binary As #2\nEnd Sub', 'SCRIPT_EXTERNAL/FILE_SYSTEM', 'Open');
    removed('Sub A()\n    If Dir("C:\\inert\\a.txt") <> "" Then Kill "C:\\inert\\a.txt"\nEnd Sub', 'SCRIPT_EXTERNAL/FILE_SYSTEM', 'Kill');
    removed('Sub A()\n    Name "a.txt" As "b.txt"\nEnd Sub', 'SCRIPT_EXTERNAL/FILE_SYSTEM', 'Name');
    removed('Sub A()\n    SaveSetting "Inert", "Section", "Key", "1"\nEnd Sub', 'SCRIPT_EXTERNAL/REGISTRY');
    removed('Sub A()\n    t = Environ("TEMP")\nEnd Sub', 'SCRIPT_EXTERNAL/ENVIRONMENT', 'Environ');
    // A property named Name and a procedure's Property Get are not file statements.
    kept('Property Get Name() As String\n    Name = "x"\nEnd Property\nSub B()\n    ws.Name = "Inputs"\nEnd Sub');
  });

  it("removes Office's ways out: other files, URLs, mail, saving elsewhere, printing, code by name and timers", () => {
    removed('Sub A()\n    Workbooks.Open "https://example.invalid/book.xlsx"\nEnd Sub', 'SCRIPT_EXTERNAL/OPEN_DOCUMENT', 'Workbooks.Open');
    removed('Sub A()\n    With ThisWorkbook\n        .FollowHyperlink "https://example.invalid/"\n    End With\nEnd Sub', 'SCRIPT_EXTERNAL/URL');
    removed('Sub A()\n    Worksheets(2).Hyperlinks.Add Cells(4, 4), "https://example.invalid/"\nEnd Sub', 'SCRIPT_EXTERNAL/URL', 'Hyperlinks.Add');
    removed('Sub A()\n    With ActiveDocument\n        .AttachedTemplate = "\\\\inert\\share\\t.dotm"\n    End With\nEnd Sub', 'SCRIPT_EXTERNAL/OPEN_DOCUMENT');
    removed('Sub A()\n    Documents.Add Template:="\\\\inert\\share\\t.dotm"\nEnd Sub', 'SCRIPT_EXTERNAL/OPEN_DOCUMENT', 'Documents.Add');
    removed('Sub A()\n    ActiveWorkbook.SendMail "someone@example.invalid"\nEnd Sub', 'SCRIPT_EXTERNAL/MAIL');
    removed('Sub A()\n    ActiveWorkbook.SaveCopyAs "C:\\inert\\copy.xlsm"\nEnd Sub', 'SCRIPT_EXTERNAL/SAVE');
    removed('Sub A()\n    ActiveSheet.PrintOut\nEnd Sub', 'SCRIPT_EXTERNAL/PRINT');
    removed('Sub A()\n    Application.Run "Other" & name\nEnd Sub', 'SCRIPT_DYNAMIC_CODE/EVAL', 'Application.Run');
    removed('Sub A()\n    With Application\n        .Run "Other"\n    End With\nEnd Sub', 'SCRIPT_DYNAMIC_CODE/EVAL');
    removed('Sub A()\n    Application.ExecuteExcel4Macro "INERT()"\nEnd Sub', 'SCRIPT_DYNAMIC_CODE/EVAL');
    removed('Sub A()\n    Application.OnTime later, "B"\nEnd Sub', 'SCRIPT_DYNAMIC_CODE/TIMER');
    removed('Sub A()\n    WordBasic.FileOpen "x"\nEnd Sub', 'SCRIPT_DYNAMIC_CODE/LEGACY_MACRO');
    removed('Sub A()\n    x = CallByName(obj, name, VbMethod)\nEnd Sub', 'SCRIPT_DYNAMIC_CODE/COMPUTED_ACCESS');
    removed('Sub A()\n    x = Application.Evaluate(formula)\nEnd Sub', 'SCRIPT_DYNAMIC_CODE/EVAL', 'Evaluate');
  });

  it('removes formulas that reach outside, and macros that name another file', () => {
    removed('Sub A()\n    Range("A1").Formula = "=WEBSERVICE(""https://example.invalid/"")"\nEnd Sub', 'SCRIPT_EXTERNAL/NETWORK', 'WEBSERVICE');
    removed('Sub A()\n    Range("A1").Formula = "=inert|\' /c x\'!A0"\nEnd Sub', 'SCRIPT_EXTERNAL/DDE');
    removed('Sub A()\n    x = [CALL("inert","x","J")]\nEnd Sub', 'SCRIPT_EXTERNAL/NATIVE_CODE');
    removed('Sub A()\n    Application.OnKey "^q", "\'other.xlsm\'!B"\nEnd Sub', 'SCRIPT_EXTERNAL/OPEN_DOCUMENT');
  });

  it('removes text hidden from a reader: character codes, reversed and filled-in strings, split words, encoded data', () => {
    removed('Sub A()\n    s = Chr(112) & Chr(111) & Chr(119) & Chr(101) & Chr(114) & Chr(33)\nEnd Sub', 'SCRIPT_OBFUSCATION/CHAR_CODES');
    removed('Sub A()\n    s = StrReverse("exe.margorp-trieni")\nEnd Sub', 'SCRIPT_OBFUSCATION/DECODE', 'Strreverse');
    removed('Sub A()\n    s = Replace("iQnQeQrQt", "Q", "")\nEnd Sub', 'SCRIPT_OBFUSCATION/DECODE', 'Replace("...")');
    removed('Sub A()\n    For i = 1 To Len(s)\n        r = r & Chr(Asc(Mid(s, i, 1)) Xor 7)\n    Next\nEnd Sub', 'SCRIPT_OBFUSCATION/DECODE', 'Chr(Asc(...))');
    const split = removed('Sub A()\n    s = "pow" & "ersh" & "ell -w hidden"\nEnd Sub', 'SCRIPT_OBFUSCATION/CONCATENATION');
    expect(split.findings.find(f => f.detail === 'CONCATENATION')?.data?.word).to.equal('powershell');
    removed('Sub A()\n    u = "htt" & "ps:" & "//example.invalid/a"\nEnd Sub', 'SCRIPT_OBFUSCATION/CONCATENATION');
    // A payload built up one statement at a time, as encoded data once joined.
    const lines = Array.from({ length: 8 }, (_, i) => `    p = p & "${'QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo'.slice(0, 20)}${String(i).repeat(4)}"`).join('\n');
    removed(`Sub A()\n${lines}\nEnd Sub`, 'SCRIPT_OBFUSCATION/ENCODED_STRING');
    removed(`Sub A()\n    s = "${'QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo'.repeat(4)}"\nEnd Sub`, 'SCRIPT_OBFUSCATION/ENCODED_STRING');
    // Long text joined from many literals, and a JSON body built in pieces, hide nothing.
    kept(
      `Sub A()\n    m = "The first line of a long help text, " & "and its second line, " & "and a third." & Chr(13) & "" & Chr(13) & "And the end."\n    j = "{" & """name""" & ":" & "x" & "," & """size""" & ":" & n & "}"\nEnd Sub`,
    );
  });

  it('removes a module whose project refers to a library or project from outside the document', () => {
    const office: ScriptReference = { name: 'Office', kind: 'registered', libid: '*\\G{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}#2.0#0#C:\\inert\\MSO.DLL#Microsoft Office' };
    const normal: ScriptReference = { name: 'Normal', kind: 'project', libid: '*\\CNormal' };
    const forms: ScriptReference = { name: 'MSForms', kind: 'control', libid: '*\\G{0D452EE1-E08F-101A-852E-02608C4D0BB4}#2.0#0#C:\\inert\\FM20.DLL#Microsoft Forms 2.0' };
    kept('Sub A()\n    x = 1\nEnd Sub', { ...VBA, references: [office, normal, forms] });
    const xml: ScriptReference = { name: 'MSXML2', kind: 'registered', libid: '*\\G{F5078F18-C551-11D3-89B9-0000F81FE221}#6.0#0#C:\\inert\\msxml6.dll#Microsoft XML' };
    const other: ScriptReference = { name: 'InertTools', kind: 'project', libid: '*\\CC:\\inert\\tools.xlam' };
    const r = inspect('Sub A()\n    x = 1\nEnd Sub', { ...VBA, references: [office, xml, other] });
    expect(r.findings.filter(f => f.detail === 'REFERENCE').map(f => f.data?.api)).to.deep.equal(['MSXML2', 'InertTools']);
  });

  it('reports a module it cannot read, its size past the limit, and where each finding is', () => {
    expect(kinds(inspect('Sub A()\n    s = "never closed\nEnd Sub'))).to.deep.equal(['SCRIPT_SYNTAX/UNPARSEABLE']);
    expect(kinds(inspectScript('Sub A()\r\nEnd Sub', { context: VBA, limits: { scriptSize: 5 } }))).to.deep.equal(['SCRIPT_LIMIT/SIZE']);
    const r = inspect('Sub A()\n    x = 1\n    Shell "inert"\nEnd Sub');
    expect(r.findings.find(f => f.detail === 'PROCESS')?.location).to.equal('VBA/Module1, line 3');
  });

  it('reads comments, line continuations and strings as VBA does', () => {
    kept('Sub A()\n    \' Shell "inert" in a comment\n    Rem Kill "x" in a remark\n    s = "Shell and Kill in a string"\nEnd Sub');
    removed('Sub A()\n    x = Application. _\n        Run("Other", 1)\nEnd Sub', 'SCRIPT_DYNAMIC_CODE/EVAL');
    // A declaration in one procedure does not hide the library function in another.
    removed('Sub A()\n    Dim shell As Long\nEnd Sub\nSub B()\n    Shell "inert"\nEnd Sub', 'SCRIPT_EXTERNAL/PROCESS');
  });

  it('runs as the plugin office-defuse takes', async () => {
    const plugin = formScriptPlugin();
    expect(await plugin.process({ text: 'Sub A()\r\n    x = 1\r\nEnd Sub', ...VBA })).to.deep.include({ result: 'passed' });
    expect(await plugin.process({ text: 'Sub A()\r\n    Shell "inert"\r\nEnd Sub', ...VBA })).to.deep.include({ result: 'removed' });
  });
});
