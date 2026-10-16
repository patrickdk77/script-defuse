# Changelog

## 0.1.0 - 2026-10-16

First release.

- `inspectScript` parses a script with acorn and calls it a form script when every call and property it uses formats, checks or calculates form fields: fields, the event, Acrobat's AForm helpers, `util` formatting, the `color` and `display` constants, message boxes and version checks, and the language itself. Anything else makes it unsafe.
- Findings name what an unsafe script reaches: web addresses, submits, mail, other documents, attached files, imports and exports, the network, menu commands, printing and saving. They name dynamic code, obfuscation, viewer APIs known from exploits and viewer APIs outside the allowlist, with the API and the line.
- Obfuscation strips a script: character codes, decoders, text written in a number base, text hidden among filler, strings joined from many tiny pieces, needless escapes, encoded and very long strings, arithmetic on hex constants, quoted names on viewer objects, and names computed at run time.
- `context.form: 'xfa'` reads a script against the XFA object model, and `context.language: 'formcalc'` reads FormCalc with a parser of its own and the same rules.
- SCRIPT_API/PASSWORD_PROMPT removes a prompt that asks for a password. script-defuse checks a bare assignment to a document property, such as `viewState = s`, as a write to the document.
- `formScriptPlugin` is a script plugin for pdf-defuse. It keeps form scripts, removes the rest, hands its findings to the report, and remembers the globals of the document scripts it kept for the field scripts that call them. It takes the language and form from the script pdf-defuse 0.2.4 hands it.
- `limits.scriptSize` and `limits.depth`, `actionOverrides`, `scoreWeights` and `scoreBands` work as in the other defuse packages.
