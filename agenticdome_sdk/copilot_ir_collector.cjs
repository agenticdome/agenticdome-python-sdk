"use strict";

const fs = require("fs");
const path = require("path");
const { createRequire } = require("module");

function readInput() {
  return new Promise((resolve) => {
    let value = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (chunk) => { value += chunk; });
    process.stdin.on("end", () => resolve(JSON.parse(value || "{}")));
  });
}

function dotted(ts, node) {
  if (!node) return "";
  if (ts.isIdentifier(node)) return node.text.toLowerCase();
  if (ts.isPropertyAccessExpression(node)) {
    const left = dotted(ts, node.expression);
    return `${left ? `${left}.` : ""}${node.name.text.toLowerCase()}`;
  }
  if (ts.isElementAccessExpression(node) && ts.isStringLiteral(node.argumentExpression)) {
    const left = dotted(ts, node.expression);
    return `${left ? `${left}.` : ""}${node.argumentExpression.text.toLowerCase()}`;
  }
  if (ts.isCallExpression(node)) return dotted(ts, node.expression);
  return "";
}

function relative(root, filename) {
  const value = path.relative(root, filename).split(path.sep).join("/");
  return value.startsWith("..") ? path.basename(filename) : value;
}

function safeCallHints(ts, node) {
  const hints = {};
  const first = node.arguments[0];
  if (!first || !ts.isObjectLiteralExpression(first)) return hints;
  for (const property of first.properties) {
    if (!ts.isPropertyAssignment(property)) continue;
    const key = property.name && property.name.getText().replace(/["']/g, "").toLowerCase();
    if (key === "direction" && ts.isStringLiteralLike(property.initializer)) {
      const direction = property.initializer.text.toLowerCase();
      if (["input", "inbound", "output", "outbound"].includes(direction)) hints.direction = direction;
    }
    if (key === "toolname" || key === "toolargs" || key === "tool_name" || key === "tool_args") hints.has_tool_binding = true;
  }
  return hints;
}

async function main() {
  const input = await readInput();
  const root = path.resolve(String(input.root || process.cwd()));
  let ts;
  try {
    ts = createRequire(path.join(root, "package.json"))("typescript");
  } catch (_) {
    process.stdout.write(JSON.stringify({ available: false, files_parsed: 0, parse_errors: 0, reason: "The workload does not provide the TypeScript compiler." }));
    return;
  }
  const functions = [];
  let filesParsed = 0;
  let parseErrors = 0;
  for (const filename of (Array.isArray(input.files) ? input.files : []).slice(0, 1000)) {
    let source;
    try { source = fs.readFileSync(filename, "utf8"); } catch (_) { parseErrors += 1; continue; }
    const kind = filename.endsWith(".tsx") ? ts.ScriptKind.TSX : filename.endsWith(".jsx") ? ts.ScriptKind.JSX : filename.endsWith(".js") ? ts.ScriptKind.JS : ts.ScriptKind.TS;
    const file = ts.createSourceFile(path.basename(filename), source, ts.ScriptTarget.Latest, true, kind);
    filesParsed += 1;
    const filePath = relative(root, filename);
    const moduleRecord = { symbol: "<module>", path: filePath, line: 1, hints: { entrypoint: true, parameters: [], decorators: [] }, events: [] };
    functions.push(moduleRecord);
    const stack = [moduleRecord];
    function line(node) { return file.getLineAndCharacterOfPosition(node.getStart(file, false)).line + 1; }
    function decorators(node) {
      const values = ts.canHaveDecorators && ts.canHaveDecorators(node) ? (ts.getDecorators(node) || []) : [];
      return values.map((item) => dotted(ts, item.expression)).slice(0, 50);
    }
    function visit(node) {
      let pushed = false;
      if (ts.isFunctionDeclaration(node) || ts.isMethodDeclaration(node) || ts.isArrowFunction(node) || ts.isFunctionExpression(node)) {
        let name = node.name && node.name.getText ? node.name.getText(file) : "anonymous";
        if (ts.isVariableDeclaration(node.parent) && node.parent.name) name = node.parent.name.getText(file);
        const parent = stack[stack.length - 1];
        const symbol = parent.symbol === "<module>" ? name : `${parent.symbol}.${name}`;
        const parameters = (node.parameters || []).map((item) => item.name.getText(file).toLowerCase()).slice(0, 100);
        const record = { symbol, path: filePath, line: line(node), hints: { parameters, decorators: decorators(node) }, events: [] };
        functions.push(record);
        stack.push(record);
        pushed = true;
      }
      const current = stack[stack.length - 1];
      if (ts.isCallExpression(node)) current.events.push({ event: "call", callee: dotted(ts, node.expression), line: line(node), flow_scope: [], hints: safeCallHints(ts, node) });
      else if (ts.isReturnStatement(node)) current.events.push({ event: "return", callee: "return", line: line(node), flow_scope: [] });
      else if (ts.isVariableDeclaration(node)) {
        const name = node.name && node.name.getText ? node.name.getText(file).toLowerCase() : "";
        if (["user_input", "userinput", "user_query", "userquery", "user_message", "usermessage"].includes(name)) current.events.push({ event: "assignment", assignment_role: "user_input", callee: "assignment", line: line(node), flow_scope: [] });
      }
      ts.forEachChild(node, visit);
      if (pushed) stack.pop();
    }
    ts.forEachChild(file, visit);
  }
  process.stdout.write(JSON.stringify({ available: true, typescript_version: String(ts.version || ""), files_parsed: filesParsed, parse_errors: parseErrors, functions }));
}

main().catch(() => {
  process.stdout.write(JSON.stringify({ available: false, files_parsed: 0, parse_errors: 1, reason: "TypeScript IR collection failed safely." }));
});
