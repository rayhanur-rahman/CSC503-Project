import ast
import socket
import re
import sys
import argparse
import os
import stat
import socket
import six
import subprocess
from pprint import pprint
from urllib.parse import urlparse


class Analyzer(ast.NodeVisitor):
    def __init__(self):
        self.imports = []
        self.vars = []
        self.strings = []
        self.subscripts = []
        self.calls = []
        self.attrs = []
        self.assign = []
        self.funcDef = []
        self.tryCatch = []
        self.JoinedStr = []
        self.BinOp = []

    def visit_Import(self, node):
        for alias in node.names:
            self.imports.append(alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        for alias in node.names:
            self.imports.append(alias.name)
        self.generic_visit(node)

    def visit_Name(self, node):
        self.vars.append(node)
        self.generic_visit(node)

    def visit_Str(self, node):
        self.strings.append(node)
        self.generic_visit(node)

    def visit_Subscript(self, node):
        self.subscripts.append(node)
        self.generic_visit(node)

    def visit_Call(self, node):
        self.calls.append(node)
        self.generic_visit(node)

    def visit_Attribute(self, node):
        self.attrs.append(node)
        self.generic_visit(node)

    def visit_Assign(self, node):
        self.assign.append(node)
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        self.funcDef.append(node)
        self.generic_visit(node)

    def visit_ExceptHandler(self, node):
        self.tryCatch.append(node)
        self.generic_visit(node)

    def visit_JoinedStr(self, node):
        self.JoinedStr.append(node)
        self.generic_visit(node)

    def visit_BinOp(self, node):
        self.BinOp.append(node)
        self.generic_visit(node)



def handleBinOp(node, ls, binopslist):
    
    if f'{node.lineno}@{node.col_offset}' not in binopslist:
        binopslist.append(f'{node.lineno}@{node.col_offset}')
    else:
        return

    if isinstance(node.right, ast.Str):
        ls.append(node.right.s)
    if isinstance(node.right, ast.Name):
        ls.append(':'+node.right.id+':')
    if isinstance(node.right, ast.JoinedStr):
        for element in reversed(node.right.values):
            if isinstance(element, ast.Str):
                ls.append(element.s)
            if isinstance(element, ast.FormattedValue):
                ls.append(':' + element.value.id + ':')
    if isinstance(node.right, ast.Call):
        if isinstance(node.right.func, ast.Attribute):
            if node.right.func.attr == 'format':
                if isinstance(node.right.func.value, ast.Str):
                    ls.append(node.right.func.value.s)

    if isinstance(node.left, ast.BinOp):
        handleBinOp(node.left, ls, binopslist)
    else:
        if isinstance(node.left, ast.Str):
            ls.append(node.left.s)
        if isinstance(node.left, ast.Name):
            ls.append(':'+node.left.id+':')
        if isinstance(node.left, ast.JoinedStr):
            for element in reversed(node.left.values):
                if isinstance(element, ast.Str):
                    ls.append(element.s)
                if isinstance(element, ast.FormattedValue):
                    if isinstance(element.value, ast.Name):
                        ls.append(':' + element.value.id + ':')
        if isinstance(node.left, ast.Call):
            if isinstance(node.left.func, ast.Attribute):
                if node.left.func.attr == 'format':
                    if isinstance(node.left.func.value, ast.Str):
                        ls.append(node.left.func.value.s)


def has_shell(node):
    keywords = node.keywords
    result = False
    for key in keywords:
        if key.arg == 'shell':
            val = key.value
            if isinstance(val, ast.Num):
                result = bool(val.n)
            elif isinstance(val, ast.List):
                result = bool(val.elts)
            elif isinstance(val, ast.Dict):
                result = bool(val.keys)
            elif isinstance(val, ast.Name) and val.id in ['False', 'None']:
                result = False
            elif not six.PY2 and isinstance(val, ast.NameConstant):
                result = val.value
            else:
                result = True
    return result


def detectSmell(input):
    dump = open('prolog-smell.csv', 'a')
    dump2 = open('prolog-fact.pl', 'a')
    try:
        with open(f'/home/rr/Workspace/CSC503-Project/gist-src/{input}', "r") as source:
            tree = ast.parse(source.read())
    except:
        print(f'failure parsing {input}')
        subprocess.call(
            f'rm /home/rr/Workspace/CSC503-Project/gist-src/{input}', shell=True)
        return 1

    analyzer = Analyzer()
    analyzer.visit(tree)

    SIMPLE_SQL_RE = re.compile(r'(select\s.*from\s|' 
    r'delete\s+from\s|'
    r'insert\s+into\s.*values\s|'
    r'update\s.*set\s)',
    re.IGNORECASE | re.DOTALL,
    )
    shellModules = {
            'subprocess': ['Popen', 'call', 'check_call', 'check_output', 'run'],
            'os': ['system', 'popen', 'popen2', 'popen3','popen4', 'execl','execle','execlp','execlpe','execv','execve','execvp','execvpe','spawnl','spawnle','spawnlp','spawnlpe','spawnv','spawnve','spawnvp','spawnvpe','startfile'],
            'popen2': ['poepn2', 'popen3', 'popen4'],
            'commands': ['getoutput', 'getstatusoutput']
        }

    sqlqueries = []
    hardcodedTmpDirectories = ['/tmp', '/var/tmp', '/dev/shm']
    hardcodedSecretWords = ['key', 'id', 'cert', 'root', 'passno', 'pass-no', 'pass_no', 'auth_token', 'authetication_token', 'auth-token', 'authentication-token', 'user', 'uname', 'username', 'user-name', 'user_name', 'owner-name', 'owner_name', 'owner', 'admin', 'login', 'pass', 'pwd', 'password', 'passwd', 'secret', 'uuid', 'crypt',
                            'certificate', 'userid', 'loginid', 'token', 'ssh_key', 'md5', 'rsa', 'ssl_content', 'ca_content', 'ssl-content', 'ca-content', 'ssh_key_content', 'ssh-key-content', 'ssh_key_public', 'ssh-key-public', 'ssh_key_private', 'ssh-key-private', 'ssh_key_public_content', 'ssh_key_private_content', 'ssh-key-public-content', 'ssh-key-private-content','token', 'secret', 'secrete']
    hardcodedPasswords = ['pass', 'pwd', 'password',
                          'passwd', 'passno', 'pass-no', 'pass_no','token', 'secret', 'secrete']

    hardcoded_pass_found = 0

    for var in analyzer.assign:
        for item in hardcodedPasswords:
            if isinstance(var.targets[0], ast.Name) and isinstance(var.value, ast.Str):
                if re.match(r'[_A-Za-z0-9-]*{text}\b'.format(text=str(item).lower()),
                            str(var.targets[0].id).lower().strip()):
                    if len(var.value.s) > 0:
                        hardcoded_pass_found += 1
                        print(input)
            if isinstance(var.targets[0], ast.Attribute) and isinstance(var.value, ast.Str):
                if re.match(r'[_A-Za-z0-9-]*{text}\b'.format(text=str(item).lower()),
                            str(var.targets[0].attr).lower().strip()):
                    if len(var.value.s) > 0:
                        hardcoded_pass_found += 1
                        print(input)
            if isinstance(var.targets[0], ast.Subscript) and isinstance(var.value, ast.Str):
                if isinstance(var.targets[0].slice.value, ast.Str):
                    if re.match(r'[_A-Za-z0-9-]*{text}\b'.format(text=str(item).lower()),
                                str(var.targets[0].slice.value.s).lower().strip()):
                        if len(var.value.s) > 0:
                            hardcoded_pass_found += 1
                            print(input)

    for var in analyzer.assign:
        for item in hardcodedSecretWords:
            if isinstance(var.targets[0], ast.Name) and isinstance(var.value, ast.Str):
                if re.match(r'[_A-Za-z0-9-]*{text}\b'.format(text=str(item).lower()),
                            str(var.targets[0].id).lower().strip()):
                    if len(var.value.s) > 0:
                        dump.write(
                            f'{input}, hardcoded secret, {var.lineno}\n')

                        dump2.write(f'statement({var.lineno}, language(python), file(path_{input[0:-3]}), funcName(null), funcArgs(0), funcArgNameInContext(null), funcArgValueInContext(null), funcAction(null), varNamePattern({item}), varValue(any), attrNamePattern(null), attrValue(null), dictKeyPattern(null), dictValue(null), isTryStatement(no), isExceptBlockSingleLine(null), passInExceptBlock(null), continueInExceptBlock(null), httpWritePerformedInStatement(no), hashFuncAppliedInSource(null), stringContains(null)).\n\n')

            if isinstance(var.targets[0], ast.Attribute) and isinstance(var.value, ast.Str):
                if re.match(r'[_A-Za-z0-9-]*{text}\b'.format(text=str(item).lower()),
                            str(var.targets[0].attr).lower().strip()):
                    if len(var.value.s) > 0:
                        dump.write(
                            f'{input}, hardcoded secret, {var.lineno}\n')


                        dump2.write(f'statement({var.lineno}, language(python), file(path_{input[0:-3]}), funcName(null), funcArgs(0), funcArgNameInContext(null), funcArgValueInContext(null), funcAction(null), varNamePattern(null), varValue(null), attrNamePattern({item}), attrValue(any), dictKeyPattern(null), dictValue(null), isTryStatement(no), isExceptBlockSingleLine(null), passInExceptBlock(null), continueInExceptBlock(null), httpWritePerformedInStatement(no), hashFuncAppliedInSource(null), stringContains(null)).\n\n')


            if isinstance(var.targets[0], ast.Subscript) and isinstance(var.value, ast.Str):
                if isinstance(var.targets[0].slice.value, ast.Str):
                    if re.match(r'[_A-Za-z0-9-]*{text}\b'.format(text=str(item).lower()),
                                str(var.targets[0].slice.value.s).lower().strip()):
                        if len(var.value.s) > 0:
                            dump.write(
                                f'{input}, hardcoded secret, {var.lineno}\n')
                            
                            dump2.write(f'statement({var.lineno}, language(python), file(path_{input[0:-3]}), funcName(null), funcArgs(0), funcArgNameInContext(null), funcArgValueInContext(null), funcAction(null), varNamePattern(null), varValue(null), attrNamePattern(null), attrValue(null), dictKeyPattern({item}), dictValue(any), isTryStatement(no), isExceptBlockSingleLine(null), passInExceptBlock(null), continueInExceptBlock(null), httpWritePerformedInStatement(no), hashFuncAppliedInSource(null), stringContains(null)).\n\n')

    for var in analyzer.assign:
        for item in hardcodedPasswords:
            if isinstance(var.targets[0], ast.Name) and isinstance(var.value, ast.Str):
                if re.match(r'[_A-Za-z0-9-]*{text}\b'.format(text=str(item).lower()), str(var.targets[0].id).lower().strip()):
                    if var.value.s == '':
                        dump.write(f'{input}, empty password, {var.lineno}\n')
                        dump2.write(f'statement({var.lineno}, language(python), file(path_{input[0:-3]}), funcName(null), funcArgs(0), funcArgNameInContext(null), funcArgValueInContext(null), funcAction(null), varNamePattern({item}), varValue(empty), attrNamePattern(null), attrValue(null), dictKeyPattern(null), dictValue(null), isTryStatement(no), isExceptBlockSingleLine(null), passInExceptBlock(null), continueInExceptBlock(null), httpWritePerformedInStatement(no), hashFuncAppliedInSource(null), stringContains(null)).\n\n')


            if isinstance(var.targets[0], ast.Attribute) and isinstance(var.value, ast.Str):
                if re.match(r'[_A-Za-z0-9-]*{text}\b'.format(text=str(item).lower()), str(var.targets[0].attr).lower().strip()):
                    if var.value.s == '':
                        dump.write(f'{input}, empty password, {var.lineno}\n')
                        dump2.write(f'statement({var.lineno}, language(python), file(path_{input[0:-3]}), funcName(null), funcArgs(0), funcArgNameInContext(null), funcArgValueInContext(null), funcAction(null), varNamePattern(null), varValue(null), attrNamePattern({item}), attrValue(empty), dictKeyPattern(null), dictValue(null), isTryStatement(no), isExceptBlockSingleLine(null), passInExceptBlock(null), continueInExceptBlock(null), httpWritePerformedInStatement(no), hashFuncAppliedInSource(null), stringContains(null)).\n\n')

            if isinstance(var.targets[0], ast.Subscript) and isinstance(var.value, ast.Str):
                if isinstance(var.targets[0].slice.value, ast.Str):
                    if re.match(r'[_A-Za-z0-9-]*{text}\b'.format(text=str(item).lower()), str(var.targets[0].slice.value.s).lower().strip()):
                        if var.value.s == '':
                            dump.write(
                                f'{input}, empty password, {var.lineno}\n')
                            dump2.write(f'statement({var.lineno}, language(python), file(path_{input[0:-3]}), funcName(null), funcArgs(0), funcArgNameInContext(null), funcArgValueInContext(null), funcAction(null), varNamePattern(null), varValue(null), attrNamePattern(null), attrValue(null), dictKeyPattern({item}), dictValue(empty), isTryStatement(no), isExceptBlockSingleLine(null), passInExceptBlock(null), continueInExceptBlock(null), httpWritePerformedInStatement(no), hashFuncAppliedInSource(null), stringContains(null)).\n\n')


    for var in analyzer.vars:
        if var.id == 'DEBUG' or var.id == 'DEBUG_PROPAGATE_EXCEPTIONS':
            if any(x.lineno == var.lineno and x.s == 'True' for x in analyzer.strings):
                dump.write(
                    f'{input}, DEBUG True in deployment, {var.lineno}\n')
                dump2.write(f'statement({var.lineno}, language(python), file(path_{input[0:-3]}), funcName(null), funcArgs(0), funcArgNameInContext(null), funcArgValueInContext(null), funcAction(null), varNamePattern({var.id.lower()}), varValue(yes), attrNamePattern(null), attrValue(null), dictKeyPattern(null), dictValue(null), isTryStatement(no), isExceptBlockSingleLine(null), passInExceptBlock(null), continueInExceptBlock(null), httpWritePerformedInStatement(no), hashFuncAppliedInSource(null), stringContains(null)).\n\n')


    for value in analyzer.strings:

        for item in hardcodedTmpDirectories:
            if item in value.s:
                dump.write(
                        f'{input}, use of tmp directory, {value.lineno}\n')
                
                dump2.write(f'statement({value.lineno}, language(python), file(path_{input[0:-3]}), funcName(null), funcArgs(0), funcArgNameInContext(null), funcArgValueInContext(null), funcAction(null), varNamePattern(null), varValue(null), attrNamePattern(null), attrValue(null), dictKeyPattern(null), dictValue(null), isTryStatement(no), isExceptBlockSingleLine(null), passInExceptBlock(null), continueInExceptBlock(null), httpWritePerformedInStatement(no), hashFuncAppliedInSource(null), stringContains(tmp)).\n\n')
                

        download = ['iso', 'tar', 'tar.gz', 'tar.bzip2', 'zip', 'rar', 'gzip', 'gzip2',
                    'deb', 'rpm', 'sh', 'run', 'bin', 'exe', 'zip', 'rar', '7zip', 'msi', 'bat']
        try:
            parsedUrl = urlparse(str(value.s))
        except:
            parsedUrl = ''
        if len(parsedUrl) > 1:
            if re.match(
                    r'^(http:\/\/www\.|https:\/\/www\.|http:\/\/|https:\/\/)?[a-z0-9]+([_\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?$',
                    str(value.s)):
                if ('http' in str(value.s).strip().lower() or 'www' in str(
                        value.s).strip().lower()) and 'https' not in str(value.s).strip().lower():
                    dump.write(
                        f'{input}, use of http without tls, {value.lineno}\n')
                    dump2.write(f'statement({value.lineno}, language(python), file(path_{input[0:-3]}), funcName(null), funcArgs(0), funcArgNameInContext(null), funcArgValueInContext(null), funcAction(null), varNamePattern(null), varValue(null), attrNamePattern(null), attrValue(null), dictKeyPattern(null), dictValue(null), isTryStatement(no), isExceptBlockSingleLine(null), passInExceptBlock(null), continueInExceptBlock(null), httpWritePerformedInStatement(no), hashFuncAppliedInSource(null), stringContains(http)).\n\n')

                for item in download:
                    if re.match(r'(http|https|www)[_\-a-zA-Z0-9:\/.]*{text}$'.format(text=item), str(value.s)):
                        if 'hashlib' not in analyzer.imports and 'pygpgme' not in analyzer.imports:
                            dump.write(f'{input}, no integrity check\n')
                            dump2.write(f'statement({value.lineno}, language(python), file(path_{input[0:-3]}), funcName(null), funcArgs(0), funcArgNameInContext(null), funcArgValueInContext(null), funcAction(null), varNamePattern(null), varValue(null), attrNamePattern(null), attrValue(null), dictKeyPattern(null), dictValue(null), isTryStatement(no), isExceptBlockSingleLine(null), passInExceptBlock(null), continueInExceptBlock(null), httpWritePerformedInStatement(yes), hashFuncAppliedInSource(no), stringContains(null)).\n\n')

            elif parsedUrl.scheme == 'http' or parsedUrl.scheme == 'https':
                if parsedUrl.scheme == 'http':
                    dump.write(
                        f'{input}, use of http without tls, {value.lineno}\n')
                    dump2.write(f'statement({value.lineno}, language(python), file(path_{input[0:-3]}), funcName(null), funcArgs(0), funcArgNameInContext(null), funcArgValueInContext(null), funcAction(null), varNamePattern(null), varValue(null), attrNamePattern(null), attrValue(null), dictKeyPattern(null), dictValue(null), isTryStatement(no), isExceptBlockSingleLine(null), passInExceptBlock(null), continueInExceptBlock(null), httpWritePerformedInStatement(no), hashFuncAppliedInSource(null), stringContains(http)).\n\n')
                for item in download:
                    if re.match(r'(http|https|www)[_\-a-zA-Z0-9:\/.]*{text}$'.format(text=item), str(value.s)):
                        if 'hashlib' not in analyzer.imports and 'pygpgme' not in analyzer.imports:
                            dump.write(
                                f'{input}, no integrity check, {value.lineno}\n')
                            dump2.write(f'statement({value.lineno}, language(python), file(path_{input[0:-3]}), funcName(null), funcArgs(0), funcArgNameInContext(null), funcArgValueInContext(null), funcAction(null), varNamePattern(null), varValue(null), attrNamePattern(null), attrValue(null), dictKeyPattern(null), dictValue(null), isTryStatement(no), isExceptBlockSingleLine(null), passInExceptBlock(null), continueInExceptBlock(null), httpWritePerformedInStatement(yes), hashFuncAppliedInSource(no), stringContains(null)).\n\n')

    for item in analyzer.subscripts:
        if isinstance(item.value, ast.Attribute):
            if item.value.attr == 'argv':
                dump.write(f'{input}, use of shell arguments, {item.lineno}\n')
                dump2.write(f'statement({item.lineno}, language(python), file(path_{input[0:-3]}), funcName(null), funcArgs(0), funcArgNameInContext(null), funcArgValueInContext(null), funcAction(null), varNamePattern(null), varValue(null), attrNamePattern(argv), attrValue(any), dictKeyPattern(null), dictValue(null), isTryStatement(no), isExceptBlockSingleLine(null), passInExceptBlock(null), continueInExceptBlock(null), httpWritePerformedInStatement(null), hashFuncAppliedInSource(null), stringContains(null)).\n\n')

    
    for item in analyzer.funcDef:
        argNames = []
        argValues = []

        if len(item.args.args) > 0 and len(item.args.defaults) > 0:
            for element in item.args.args:
                argNames.append(element.arg)
            for element in item.args.defaults:
                if isinstance(element, ast.Str):
                     argValues.append(element.s)

        if len(argNames) > len(argValues):
            diff = len(argNames) - len(argValues)
            for i in range(0, diff):
                argValues.insert(0, None)

        for i in range(0, len(argNames)):
            if (argNames[i] in hardcodedPasswords or argNames[i] in hardcodedSecretWords) and argValues != None:
                dump.write(f'{input}, hardcoded secret, {var.lineno}\n')
                dump2.write(f'statement({var.lineno}, language(python), file(path_{input[0:-3]}), funcName(null), funcArgs(0), funcArgNameInContext({argNames[i]}), funcArgValueInContext(any), funcAction(null), varNamePattern(null), varValue(null), attrNamePattern(null), attrValue(null), dictKeyPattern(null), dictValue(null), isTryStatement(no), isExceptBlockSingleLine(null), passInExceptBlock(null), continueInExceptBlock(null), httpWritePerformedInStatement(no), hashFuncAppliedInSource(null), stringContains(null)).\n\n')

    for item in analyzer.calls:

        if isinstance(item.func, ast.Attribute):
            if item.func.attr in shellModules['subprocess'] or item.func.attr in shellModules['os'] or item.func.attr in shellModules['commands'] or item.func.attr in shellModules['popen2'] :
                if has_shell(item) or not has_shell(item):
                    if len(item.args) > 0:
                        if isinstance(item.func.value, ast.Name):
                            if item.func.value.id == 'os' or item.func.value.id == 'subprocess' or item.func.value.id == 'commands' or item.func.value.id == 'popen2':
                                dump.write(f'{input}, shell injection, {item.lineno}\n')
                                dump2.write(f'statement({item.lineno}, language(python), file(path_{input[0:-3]}), funcName({item.func.attr}), funcArgs(any), funcArgNameInContext(shell), funcArgValueInContext(any), funcAction(null), varNamePattern(null), varValue(null), attrNamePattern(null), attrValue(null), dictKeyPattern(null), dictValue(null), isTryStatement(no), isExceptBlockSingleLine(null), passInExceptBlock(null), continueInExceptBlock(null), httpWritePerformedInStatement(null), hashFuncAppliedInSource(null), stringContains(null)).\n\n')
                                

        if isinstance(item.func, ast.Attribute):
            if has_shell(item):
                dump.write(f'{input}, shell injection, {item.lineno}\n')
                dump2.write(f'statement({item.lineno}, language(python), file(path_{input[0:-3]}), funcName(any), funcArgs(any), funcArgNameInContext(shell), funcArgValueInContext(any), funcAction(null), varNamePattern(null), varValue(null), attrNamePattern(null), attrValue(null), dictKeyPattern(null), dictValue(null), isTryStatement(no), isExceptBlockSingleLine(null), passInExceptBlock(null), continueInExceptBlock(null), httpWritePerformedInStatement(null), hashFuncAppliedInSource(null), stringContains(null)).\n\n')
        
        if isinstance(item.func, ast.Name):
            if item.func.id == 'exec':
                dump.write(f'{input}, exec used, {item.lineno}\n')
                dump2.write(f'statement({item.lineno}, language(python), file(path_{input[0:-3]}), funcName(exec), funcArgs(any), funcArgNameInContext(null), funcArgValueInContext(null), funcAction(null), varNamePattern(null), varValue(null), attrNamePattern(null), attrValue(null), dictKeyPattern(null), dictValue(null), isTryStatement(no), isExceptBlockSingleLine(null), passInExceptBlock(null), continueInExceptBlock(null), httpWritePerformedInStatement(null), hashFuncAppliedInSource(null), stringContains(null)).\n\n')

        if isinstance(item.func, ast.Attribute):
            if item.func.attr == 'format':
                if isinstance(item.func.value, ast.Str):
                    sql = item.func.value.s
                    sqlqueries.append({
                        'query': sql, 
                        'line': item.lineno
                    })

        if isinstance(item.func, ast.Attribute):
            if item.func.attr == 'get':
                if isinstance(item.func.value, ast.Name):
                    if item.func.value.id == 'requests':
                        x = 0
                        for element in item.keywords:
                            if element.arg == 'verify':
                                if isinstance(element.value, ast.NameConstant):
                                    if element.value.value == False:
                                        dump.write(f'{input}, no use of cert validation, {item.lineno}\n')
                                        dump2.write(f'statement({item.lineno}, language(python), file(path_{input[0:-3]}), funcName({item.func.attr}), funcArgs(any), funcArgNameInContext(verify), funcArgValueInContext(no), funcAction(null), varNamePattern(null), varValue(null), attrNamePattern(null), attrValue(null), dictKeyPattern(null), dictValue(null), isTryStatement(no), isExceptBlockSingleLine(null), passInExceptBlock(null), continueInExceptBlock(null), httpWritePerformedInStatement(null), hashFuncAppliedInSource(null), stringContains(null)).\n\n')


        if isinstance(item.func, ast.Attribute):
            if item.func.attr == 'run':
                if isinstance(item.func.value, ast.Name):
                    if item.func.value.id == 'app':
                        x = 0
                        for element in item.keywords:
                            if element.arg == 'debug':
                                if element.value.value == True:
                                    dump2.write(f'statement({item.lineno}, language(python), file(path_{input[0:-3]}), funcName({item.func.attr}), funcArgs(any), funcArgNameInContext({element.arg}), funcArgValueInContext(yes), funcAction(null), varNamePattern(null), varValue(null), attrNamePattern(null), attrValue(null), dictKeyPattern(null), dictValue(null), isTryStatement(no), isExceptBlockSingleLine(null), passInExceptBlock(null), continueInExceptBlock(null), httpWritePerformedInStatement(no), hashFuncAppliedInSource(null), stringContains(null)).\n\n')

        if len(item.keywords) > 0:
            for element in item.keywords:
                if isinstance(element, ast.keyword):
                    if element.arg != None:
                        if element.arg in hardcodedPasswords or element.arg in hardcodedSecretWords:
                            dump.write(f'{input}, hardcoded secret, {item.lineno}\n')
                            dump2.write(f'statement({item.lineno}, language(python), file(path_{input[0:-3]}), funcName(null), funcArgs(any), funcArgNameInContext(element.arg), funcArgValueInContext(any), funcAction(null), varNamePattern(null), varValue(null), attrNamePattern(null), attrValue(null), dictKeyPattern(null), dictValue(null), isTryStatement(no), isExceptBlockSingleLine(null), passInExceptBlock(null), continueInExceptBlock(null), httpWritePerformedInStatement(no), hashFuncAppliedInSource(null), stringContains(null)).\n\n')

        if isinstance(item.func, ast.Attribute):
            if item.func.attr == 'bind':
                if len(item.args) > 0:
                    if isinstance(item.args[0], ast.Tuple):
                        if isinstance(item.args[0].elts[0], ast.Str):
                            x = re.match(
                                '^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', item.args[0].elts[0].s)
                            if x != None:
                                dump.write(f'{input}, hardcoded ip address, {item.lineno}\n')
                                dump2.write(f'statement({item.lineno}, language(python), file(path_{input[0:-3]}), funcName({item.func.attr}), funcArgs(any), funcArgNameInContext(any), funcArgValueInContext(ip), funcAction(null), varNamePattern(null), varValue(null), attrNamePattern(null), attrValue(null), dictKeyPattern(null), dictValue(null), isTryStatement(no), isExceptBlockSingleLine(null), passInExceptBlock(null), continueInExceptBlock(null), httpWritePerformedInStatement(null), hashFuncAppliedInSource(null), stringContains(null)).\n\n')

        if isinstance(item.func, ast.Attribute):
            if item.func.attr != None:
                if item.func.attr == 'chmod':
                    if len(item.args) == 2:
                        if isinstance(item.args[1], ast.Num):
                            mode = item.args[1].n

                            if (mode is not None and isinstance(mode, int) and
                                    (mode & stat.S_IWOTH or mode & stat.S_IXGRP)):
                                dump.write(f'{input}, bad file permission, {item.lineno}\n')
                                if stat.S_IWOTH:
                                    dump2.write(f'statement({item.lineno}, language(python), file(path_{input[0:-3]}), funcName({item.func.attr}), funcArgs(2), funcArgNameInContext(null), funcArgValueInContext(null), funcAction(group-x), varNamePattern(null), varValue(null), attrNamePattern(null), attrValue(null), dictKeyPattern(null), dictValue(null), isTryStatement(no), isExceptBlockSingleLine(null), passInExceptBlock(null), continueInExceptBlock(null), httpWritePerformedInStatement(null), hashFuncAppliedInSource(null), stringContains(null)).\n\n')
                                if stat.S_IXGRP:
                                    dump2.write(f'statement({item.lineno}, language(python), file(path_{input[0:-3]}), funcName({item.func.attr}), funcArgs(2), funcArgNameInContext(null), funcArgValueInContext(null), funcAction(world-w), varNamePattern(null), varValue(null), attrNamePattern(null), attrValue(null), dictKeyPattern(null), dictValue(null), isTryStatement(no), isExceptBlockSingleLine(null), passInExceptBlock(null), continueInExceptBlock(null), httpWritePerformedInStatement(null), hashFuncAppliedInSource(null), stringContains(null)).\n\n')

        if isinstance(item.func, ast.Attribute):
            if item.func.attr == 'ArgumentParser' and item.func.value.id == 'argparse':
                dump.write(f'{input}, use of shell arguments, {item.lineno}\n')
                dump2.write(f'statement({item.lineno}, language(python), file(path_{input[0:-3]}), funcName({item.func.attr.lower()}), funcArgs(any), funcArgNameInContext(null), funcArgValueInContext(null), funcAction(null), varNamePattern(null), varValue(null), attrNamePattern(null), attrValue(null), dictKeyPattern(null), dictValue(null), isTryStatement(no), isExceptBlockSingleLine(null), passInExceptBlock(null), continueInExceptBlock(null), httpWritePerformedInStatement(null), hashFuncAppliedInSource(null), stringContains(null)).\n\n')

    
    for item in analyzer.tryCatch:

        if len(item.body) == 1:
            if isinstance(item.body[0], ast.Pass) or isinstance(item.body[0], ast.Continue):
                dump.write(f'{input}, ignoring except block, {item.lineno}\n')
                if isinstance(item.body[0], ast.Pass):
                    dump2.write(f'statement({item.lineno}, language(python), file(path_{input[0:-3]}), funcName(null), funcArgs(null), funcArgNameInContext(null), funcArgValueInContext(null), funcAction(null), varNamePattern(null), varValue(null), attrNamePattern(null), attrValue(null), dictKeyPattern(null), dictValue(null), isTryStatement(yes), isExceptBlockSingleLine(yes), passInExceptBlock(yes), continueInExceptBlock(null), httpWritePerformedInStatement(null), hashFuncAppliedInSource(null), stringContains(null)).\n\n')
                if isinstance(item.body[0], ast.Continue):
                    dump2.write(f'statement({item.lineno}, language(python), file(path_{input[0:-3]}), funcName(null), funcArgs(null), funcArgNameInContext(null), funcArgValueInContext(null), funcAction(null), varNamePattern(null), varValue(null), attrNamePattern(null), attrValue(null), dictKeyPattern(null), dictValue(null), isTryStatement(yes), isExceptBlockSingleLine(yes), passInExceptBlock(null), continueInExceptBlock(yes), httpWritePerformedInStatement(null), hashFuncAppliedInSource(null), stringContains(null)).\n\n')

    for item in analyzer.JoinedStr:
        ls = []
        for element in item.values:
            if isinstance(element, ast.Str):
                ls.append(element.s)
            if isinstance(element, ast.FormattedValue):
                if isinstance(element.value, ast.Name):
                    ls.append(':' + element.value.id + ':')
        sql = ''.join(ls)
        sqlqueries.append({
                        'query': sql, 
                        'line': item.lineno
                    })

    binopslist = []

    for item in analyzer.BinOp:
        if f'{item.lineno}@{item.col_offset}' in binopslist:
            continue

        ls = []
        handleBinOp(item, ls, binopslist)
        ls.reverse()
        sql = ''.join(ls)
        sqlqueries.append({
                        'query': sql, 
                        'line': item.lineno
                    })

    for item in sqlqueries:
        if SIMPLE_SQL_RE.search(item['query']) is not None:
            dump.write(f"{input}, sql injection, {item['line']}\n")
            dump2.write(f"statement({item['line']}, language(python), file(path_{input[0:-3]}), funcName(null), funcArgs(null), funcArgNameInContext(null), funcArgValueInContext(null), funcAction(null), varNamePattern(null), varValue(null), attrNamePattern(null), attrValue(null), dictKeyPattern(null), dictValue(null), isTryStatement(null), isExceptBlockSingleLine(null), passInExceptBlock(null), continueInExceptBlock(null), httpWritePerformedInStatement(null), hashFuncAppliedInSource(null), stringContains(parameterizedSql)).\n\n")
    
    dump.close()
    dump2.close()
    return hardcoded_pass_found


count = 0
for dirName, subdirList, fileList in os.walk('/home/rr/Workspace/CSC503-Project/gist-src'):
    for fileName in fileList:
        print(fileName)
        count = count + detectSmell(fileName)


print(count)
