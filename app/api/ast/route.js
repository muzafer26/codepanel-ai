import { exec } from "child_process";
import * as acorn from "acorn";

// Helper to execute a python script for AST compilation
async function parsePythonAST(code) {
  return new Promise((resolve) => {
    // Write python code snippet to parse via stdin
    const pythonScript = `
import ast
import json
import sys

def parse_code(code_content):
    try:
        tree = ast.parse(code_content)
        body = []
        for node in tree.body:
            node_line = getattr(node, 'lineno', 1)
            if isinstance(node, ast.Import):
                for name in node.names:
                    body.append({
                        "type": "ImportDeclaration",
                        "line": node_line,
                        "source": name.name,
                        "specifiers": [name.asname or name.name]
                    })
            elif isinstance(node, ast.ImportFrom):
                body.append({
                    "type": "ImportDeclaration",
                    "line": node_line,
                    "source": node.module or "",
                    "specifiers": [name.name for name in node.names]
                })
            elif isinstance(node, ast.FunctionDef):
                body.append({
                    "type": "FunctionDeclaration",
                    "line": node_line,
                    "id": node.name,
                    "params": [arg.arg for arg in node.args.args]
                })
            elif isinstance(node, ast.Assign):
                targets = []
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        targets.append(t.id)
                    elif isinstance(t, ast.Tuple) or isinstance(t, ast.List):
                        for el in t.elts:
                            if isinstance(el, ast.Name):
                                targets.append(el.id)
                
                # get a string representation of value
                val_snippet = "assign"
                try:
                    import ast as pyast
                    val_snippet = pyast.unparse(node.value)
                except Exception:
                    pass
                for t_id in targets:
                    body.append({
                        "type": "VariableDeclarator",
                        "line": node_line,
                        "id": t_id,
                        "init": val_snippet[:45]
                    })
            elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                call = node.value
                callee_name = "call"
                try:
                    import ast as pyast
                    callee_name = pyast.unparse(call.func)
                except Exception:
                    pass
                args = []
                for arg in call.args[:3]:
                    try:
                        import ast as pyast
                        args.append(pyast.unparse(arg))
                    except Exception:
                        pass
                body.append({
                    "type": "CallExpression",
                    "line": node_line,
                    "callee": callee_name,
                    "arguments": args
                })
            else:
                body.append({
                    "type": node.__class__.__name__,
                    "line": node_line,
                    "init": f"Python Node: {node.__class__.__name__}"
                })
        
        return {
            "type": "Program",
            "sourceType": "module",
            "body": body if len(body) > 0 else [{"type": "EmptyPythonProgram", "line": 1}]
        }
    except Exception as e:
        return {
            "type": "Program",
            "sourceType": "module",
            "body": [{"type": "ParsingError", "line": 1, "init": str(e)}]
        }

if __name__ == '__main__':
    code_in = sys.stdin.read()
    print(json.dumps(parse_code(code_in)))
`;

    const child = exec("python", (error, stdout, stderr) => {
      if (error) {
        console.error("Python parsing error:", stderr || error.message);
        resolve({
          type: "Program",
          sourceType: "module",
          body: [{ type: "PythonParsingError", line: 1, init: error.message }]
        });
      } else {
        try {
          resolve(JSON.parse(stdout));
        } catch (e) {
          resolve({
            type: "Program",
            sourceType: "module",
            body: [{ type: "JSONParseError", line: 1, init: "Invalid output from python process" }]
          });
        }
      }
    });

    child.stdin.write(code);
    child.stdin.end();
  });
}

function parseJS(code) {
  try {
    const parsed = acorn.parse(code, { ecmaVersion: 2022, sourceType: "module", locations: true });
    const body = [];

    parsed.body.forEach(node => {
      const line = node.loc ? node.loc.start.line : 1;
      
      if (node.type === "ImportDeclaration") {
        body.push({
          type: "ImportDeclaration",
          line,
          source: node.source.value,
          specifiers: node.specifiers.map(s => s.local?.name || "import")
        });
      } else if (node.type === "FunctionDeclaration") {
        body.push({
          type: "FunctionDeclaration",
          line,
          id: node.id ? node.id.name : "anonymous",
          params: node.params.map(p => p.name || p.left?.name || "param")
        });
      } else if (node.type === "VariableDeclaration") {
        node.declarations.forEach(decl => {
          const declLine = decl.loc ? decl.loc.start.line : line;
          let initSnippet = "assign";
          if (decl.init) {
            initSnippet = code.substring(decl.init.start, decl.init.end);
          }
          // extract left hand side variables
          const getLhsNames = (idNode) => {
            if (idNode.type === "Identifier") return [idNode.name];
            if (idNode.type === "ObjectPattern") {
              return idNode.properties.map(p => p.value?.name || p.key?.name).filter(Boolean);
            }
            if (idNode.type === "ArrayPattern") {
              return idNode.elements.map(el => el?.name).filter(Boolean);
            }
            return ["var"];
          };
          
          const names = getLhsNames(decl.id);
          names.forEach(name => {
            body.push({
              type: "VariableDeclarator",
              line: declLine,
              id: name,
              init: initSnippet.substring(0, 45)
            });
          });
        });
      } else if (node.type === "ExpressionStatement" && node.expression.type === "CallExpression") {
        const callee = code.substring(node.expression.callee.start, node.expression.callee.end);
        body.push({
          type: "CallExpression",
          line,
          callee,
          arguments: node.expression.arguments.map(arg => code.substring(arg.start, arg.end)).slice(0, 3)
        });
      } else {
        body.push({
          type: node.type,
          line,
          init: code.substring(node.start, node.end).substring(0, 45)
        });
      }
    });

    return {
      type: "Program",
      sourceType: "module",
      body: body.length > 0 ? body : [{ type: "EmptyJavaScriptProgram", line: 1 }]
    };
  } catch (e) {
    return {
      type: "Program",
      sourceType: "module",
      body: [{ type: "JavaScriptParsingError", line: 1, init: e.message }]
    };
  }
}

export async function POST(req) {
  try {
    const { code, language } = await req.json();
    if (!code) {
      return new Response(JSON.stringify({ error: "Missing code buffer" }), { status: 400 });
    }

    const lang = (language || "javascript").toLowerCase();
    let astResult;

    if (lang === "python") {
      astResult = await parsePythonAST(code);
    } else {
      astResult = parseJS(code);
    }

    return new Response(JSON.stringify(astResult), {
      headers: { "Content-Type": "application/json" }
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: err.message }), { status: 500 });
  }
}
