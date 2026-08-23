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

function targetRefs(ts, node) {
  if (!node) return [];
  if (ts.isIdentifier(node) || ts.isPropertyAccessExpression(node)) {
    const value = dotted(ts, node);
    return value ? [value] : [];
  }
  if (ts.isArrayBindingPattern(node) || ts.isObjectBindingPattern(node)) {
    return node.elements.flatMap((item) => targetRefs(ts, item.name)).slice(0, 50);
  }
  return [];
}

function valueRefs(ts, node) {
  if (!node) return [];
  if (ts.isCallExpression(node)) {
    const value = dotted(ts, node.expression);
    const nested = node.arguments.flatMap((item) => valueRefs(ts, item));
    if (ts.isPropertyAccessExpression(node.expression)) nested.push(...valueRefs(ts, node.expression.expression));
    return [...new Set([...(value ? [`call:${value}`] : []), ...nested])].slice(0, 50);
  }
  if (ts.isIdentifier(node) || ts.isPropertyAccessExpression(node)) {
    const value = dotted(ts, node);
    return value ? [`ref:${value}`] : [];
  }
  if (ts.isAwaitExpression(node) || ts.isParenthesizedExpression(node)) return valueRefs(ts, node.expression);
  if (ts.isConditionalExpression(node)) return [...new Set([...valueRefs(ts, node.whenTrue), ...valueRefs(ts, node.whenFalse)])].slice(0, 50);
  if (ts.isArrayLiteralExpression(node)) return [...new Set(node.elements.flatMap((item) => valueRefs(ts, item)))].slice(0, 50);
  if (ts.isObjectLiteralExpression(node)) return [...new Set(node.properties.flatMap((item) => ts.isPropertyAssignment(item) ? valueRefs(ts, item.initializer) : []))].slice(0, 50);
  return [];
}

function directResultTargets(ts, node) {
  const parent = node && node.parent;
  if (parent && ts.isVariableDeclaration(parent) && parent.initializer === node) return targetRefs(ts, parent.name);
  if (parent && ts.isBinaryExpression(parent) && parent.operatorToken.kind === ts.SyntaxKind.EqualsToken && parent.right === node) return targetRefs(ts, parent.left);
  return [];
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
    const classStack = [];
    const flowStack = [];
    function line(node) { return file.getLineAndCharacterOfPosition(node.getStart(file, false)).line + 1; }
    function decorators(node) {
      const values = ts.canHaveDecorators && ts.canHaveDecorators(node) ? (ts.getDecorators(node) || []) : [];
      return values.map((item) => dotted(ts, item.expression)).slice(0, 50);
    }
    function visit(node) {
      let pushed = false;
      let pushedClass = false;
      if (ts.isClassDeclaration(node) || ts.isClassExpression(node)) {
        const className = node.name && node.name.getText ? node.name.getText(file) : "anonymous_class";
        classStack.push(className);
        pushedClass = true;
      }
      if (ts.isFunctionDeclaration(node) || ts.isMethodDeclaration(node) || ts.isArrowFunction(node) || ts.isFunctionExpression(node)) {
        let name = node.name && node.name.getText ? node.name.getText(file) : "anonymous";
        if (ts.isVariableDeclaration(node.parent) && node.parent.name) name = node.parent.name.getText(file);
        const parent = stack[stack.length - 1];
        const symbol = parent.symbol === "<module>"
          ? `${classStack.length ? `${classStack.join(".")}.` : ""}${name}`
          : `${parent.symbol}.${name}`;
        const parameters = (node.parameters || []).map((item) => item.name.getText(file).toLowerCase()).slice(0, 100);
        const record = { symbol, path: filePath, line: line(node), hints: { parameters, decorators: decorators(node) }, events: [] };
        functions.push(record);
        stack.push(record);
        pushed = true;
      }
      const current = stack[stack.length - 1];
      if (ts.isCallExpression(node)) current.events.push({ event: "call", callee: dotted(ts, node.expression), line: line(node), flow_scope: [...flowStack], hints: safeCallHints(ts, node), result_targets: directResultTargets(ts, node) });
      else if (ts.isReturnStatement(node)) current.events.push({ event: "return", callee: "return", line: line(node), flow_scope: [...flowStack], value_refs: valueRefs(ts, node.expression) });
      else if (ts.isThrowStatement(node)) current.events.push({ event: "raise", callee: "raise", line: line(node), flow_scope: [...flowStack] });
      else if (ts.isVariableDeclaration(node)) {
        const name = node.name && node.name.getText ? node.name.getText(file).toLowerCase() : "";
        const targets = targetRefs(ts, node.name);
        const role = ["user_input", "userinput", "user_query", "userquery", "user_message", "usermessage"].includes(name) ? "user_input" : "";
        current.events.push({ event: "assignment", assignment_role: role, callee: "assignment", line: line(node), flow_scope: [...flowStack], target_refs: targets, value_refs: valueRefs(ts, node.initializer) });
      }
      const visitArm = (marker, child) => {
        if (!child) return;
        flowStack.push(marker);
        visit(child);
        flowStack.pop();
      };
      const controlKind = ts.isTryStatement(node) ? "try"
        : ts.isIfStatement(node) ? "if"
          : ts.isForStatement(node) || ts.isForInStatement(node) || ts.isForOfStatement(node) ? "for"
            : ts.isWhileStatement(node) || ts.isDoStatement(node) ? "while"
              : ts.SyntaxKind[node.kind].toLowerCase();
      const marker = `${controlKind}@${line(node)}`;
      if (ts.isIfStatement(node)) {
        visit(node.expression);
        visitArm(`${marker}:body`, node.thenStatement);
        visitArm(`${marker}:else`, node.elseStatement);
      } else if (ts.isForStatement(node) || ts.isForInStatement(node) || ts.isForOfStatement(node) || ts.isWhileStatement(node) || ts.isDoStatement(node)) {
        ts.forEachChild(node, (child) => {
          if (child === node.statement) visitArm(`${marker}:body`, child);
          else visit(child);
        });
      } else if (ts.isTryStatement(node)) {
        visitArm(`${marker}:body`, node.tryBlock);
        if (node.catchClause) visitArm(`${marker}:except0`, node.catchClause);
        if (node.finallyBlock) visitArm(`${marker}:finally`, node.finallyBlock);
      } else {
        ts.forEachChild(node, visit);
      }
      if (pushed) stack.pop();
      if (pushedClass) classStack.pop();
    }
    ts.forEachChild(file, visit);
  }
  process.stdout.write(JSON.stringify({ available: true, typescript_version: String(ts.version || ""), files_parsed: filesParsed, parse_errors: parseErrors, functions }));
}

main().catch(() => {
  process.stdout.write(JSON.stringify({ available: false, files_parsed: 0, parse_errors: 1, reason: "TypeScript IR collection failed safely." }));
});
