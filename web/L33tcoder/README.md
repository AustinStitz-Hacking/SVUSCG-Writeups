# L33tcoder

## Description

Six rounds of interviews and you still have to do this?

## Files

* [l33tcoder.zip](l33tcoder.zip)

## Writeup

This challenge provides a zip file with the source of the website so the best place to start is to extract it!

Overall, this is really more of a Python jail challenge than a web challenge. The command injection is quite literally intended, as the website executes Python code to solve fake "l33tcode" style challenges. However, where it tries to sanitize inputs, it ultimately fails.

The most important part of the source code is here in `/leetcode-validator/uscg_leetcode_validator/main.py`

```python
ALLOWED_NODES = {
    ast.Module, ast.FunctionDef, ast.arguments, ast.arg,
    ast.Assign, ast.AugAssign, ast.Return,
    ast.For, ast.While, ast.If, ast.Break, ast.Continue,
    ast.Expr,
    ast.Name, ast.Load, ast.Store,
    ast.Constant, ast.BinOp, ast.UnaryOp, ast.BoolOp, ast.Compare,
    ast.Subscript, ast.List, ast.Tuple,
    ast.Call,
    ast.Add, ast.Sub, ast.Mult, ast.Div, ast.FloorDiv, ast.Mod, ast.Pow,
    ast.And, ast.Or, ast.Not,
    ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE,
}
  
SAFE_FUNCTIONS = {"len", "range", "min", "max", "sum", "abs", "enumerate"}
  
def validate_code(path):
    with open(path, "r") as f:
        source = f.read()
  
    tree = ast.parse(source)
  
    # Must be a single top-level function
    if len(tree.body) != 1 or not isinstance(tree.body[0], ast.FunctionDef):
        raise ValueError("Submission must contain exactly one top-level function.")
  
    for node in ast.walk(tree):
        if type(node) not in ALLOWED_NODES:
            raise ValueError(f"Disallowed AST node: {type(node).__name__}")
  
        # Disallow all imports
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            raise ValueError("Imports are not allowed.")
  
        # Allow safe function calls only
        if isinstance(node, ast.Call):
            if not isinstance(node.func, ast.Name) or node.func.id not in SAFE_FUNCTIONS:
                raise ValueError(f"Function call to '{getattr(node.func, 'id', '?')}' is not allowed.")
```



Now, this seems to be good. It limits the types of Python nodes or constructs that can be used so you can't use imports and it limits function calls to a few select "safe" functions. However, how safe are they really?

While some programming languages will prevent you from overwriting system functions, Python is not one of them. There's nothing stopping you from renaming `len` as `__import__` and bypassing that check for import statements! Ultimately, this is where the solution to this challenge lies and we can craft a payload using assignments to these "safe" functions to execute arbitrary commands on the system and exfiltrate our flag.

![Payload](../../images/Pasted%20image%2020250616202340.png)

And looking at our webhook, we got our flag!

![Flag in webhook](../../images/Pasted%20image%2020250616202408.png)

And the flag is `SVUSCG{5eee1edb4ef47c856ba69697ec3d8ee2}`!
