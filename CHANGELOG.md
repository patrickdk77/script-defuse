# Changelog

## 0.3.0 - 2026-10-17

- The findings `formScriptPlugin` returns weigh what they add to the script's score: a finding that strips weighs what the plugin's `scoreWeights` or the table gives it, and one that only describes the script weighs 0. They carried the table's weight before, whatever the plugin's `scoreWeights` or `actionOverrides` said.

## 0.2.0 - 2026-10-16

- `inspectScript` reads a VBA module with `context.language: 'vba'`. A module stays when it calls nothing on a list of the ways a macro reaches outside its document: VBA's file, process, registry, DDE and environment functions, `Declare` and pointers, `CreateObject`, `GetObject` and `New` of a library's class, and the Office members that open other files and URLs, send mail, save elsewhere, print, or run code by name, later or in the VBA editor. A formula string that reaches outside counts too.
- `context.references` takes a VBA project's references. A type library outside the list in the README, or a project other than Word's Normal template, is SCRIPT_EXTERNAL/REFERENCE.
- New kinds for VBA: SCRIPT_FORM/DOCUMENT_MACRO, SCRIPT_EXTERNAL/FILE_SYSTEM, PROCESS, REGISTRY, DDE, COM_OBJECT, NATIVE_CODE, ENVIRONMENT and REFERENCE, and SCRIPT_DYNAMIC_CODE/LEGACY_MACRO.
- VBA obfuscation strips a module: `Chr` of printable characters, decoders that rebuild a string a character at a time, `StrReverse`, `Replace` of filler, and strings that spell a payload word only once their pieces are joined.
- `formScriptPlugin` takes the modules office-defuse 0.2.3 hands it.
- SCRIPT_SYNTAX/UNPARSEABLE says the script does not parse, where it said the script is not valid JavaScript.

## 0.1.0 - 2026-10-16

First release.

- `inspectScript` parses a script with acorn and calls it a form script when every call and property it uses formats, checks or calculates form fields: fields, the event, Acrobat's AForm helpers, `util` formatting, the `color` and `display` constants, message boxes and version checks, and the language itself. Anything else makes it unsafe.
- Findings name what an unsafe script reaches: web addresses, submits, mail, other documents, attached files, imports and exports, the network, menu commands, printing and saving. They name dynamic code, obfuscation, viewer APIs known from exploits and viewer APIs outside the allowlist, with the API and the line.
- Obfuscation strips a script: character codes, decoders, text written in a number base, text hidden among filler, strings joined from many tiny pieces, needless escapes, encoded and very long strings, arithmetic on hex constants, quoted names on viewer objects, and names computed at run time.
- `context.form: 'xfa'` reads a script against the XFA object model, and `context.language: 'formcalc'` reads FormCalc with a parser of its own and the same rules.
- SCRIPT_API/PASSWORD_PROMPT removes a prompt that asks for a password. script-defuse checks a bare assignment to a document property, such as `viewState = s`, as a write to the document.
- `formScriptPlugin` is a script plugin for pdf-defuse. It keeps form scripts, removes the rest, hands its findings to the report, and remembers the globals of the document scripts it kept for the field scripts that call them. It takes the language and form from the script pdf-defuse 0.2.4 hands it.
- `limits.scriptSize` and `limits.depth`, `actionOverrides`, `scoreWeights` and `scoreBands` work as in the other defuse packages.
