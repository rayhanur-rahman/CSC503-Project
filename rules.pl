statement(10,
             language(python),
             file(ggg_hh_hh-jjjj-jjj-jjjjj),
             funcName(run),
             funcArgs(2),
             funcArgNameInContext(debug),
             funcArgValueInContext(yes),
             funcAction(root-x),
             varNamePattern(debug),
             varValue(yes),
             attrNamePattern(key),
             attrValue(any),
             dictKeyPattern(key),
             dictValue(any),
             isTryStatement(yes),
             isExceptBlockSingleLine(yes),
             passInExceptBlock(yes),
             continueInExceptBlock(no),
             httpWritePerformedInStatement(yes),
             hashFuncAppliedInSource(no),
             stringContains(http)
).


debugList([debug, debug_propagate_exception]).

hardcodedSecretIdentifierList([key, id, cert, root, passno, pass-no, pass_no, auth_token, authetication_token, auth-token, authentication-token, user, uname, username, user-name, user_name, owner-name, owner_name, owner, admin, login, pass, pwd, password, passwd, secret, uuid, crypt, certificate, userid, loginid, token, ssh_key, md5, rsa, ssl_content, ca_content, ssl-content, ca-content, ssh_key_content, ssh-key-content, ssh_key_public, ssh-key-public, ssh_key_private, ssh-key-private, ssh_key_public_content, ssh_key_private_content, ssh-key-private-content,token, secret, secrete, ssh-key-private-content]).

shellFunctionList([popen, call, check_call, check_output, run, system, popen, popen2, popen3,popen4, execl,execle,execlp,execlpe,execv,execve,execvp,execvpe,spawnl,spawnle,spawnlp,spawnlpe,spawnv,spawnve,spawnvp,spawnvpe,startfile, poepn2, popen3, popen4,getoutput, getstatusoutput]).


badFilePermission(Line, Lang, Path) :- statement(Line, language(Lang), file(Path), funcName(chmod), funcArgs(2),_, _, funcAction(group-x), _, _, _, _, _, _, _, _, _, _, _, _, _); statement(Line, language(Lang), file(Path), funcName(chmod), funcArgs(2),_, _, funcAction(world-w), _, _, _, _, _, _, _, _, _, _, _, _, _).

debugInDeployment(Line, Lang, Path) :- statement(Line, language(Lang), file(Path), _, _,_, _, _, varNamePattern(X), varValue(yes), _, _, _, _, _, _, _, _, _, _, _), debugList(L), member(X, L);
statement(Line, language(Lang), file(Path), funcName(run), _,funcArgNameInContext(X), funcArgValueInContext(yes), _, _,_, _, _, _, _, _, _, _, _, _, _, _), debugList(L), member(X, L).

hardcodedSecret(Line, Lang, Path) :- statement(Line, language(Lang), file(Path), _, _, _, _, _, varNamePattern(X), varValue(any), _, _, _, _, _, _, _, _, _, _, _), hardcodedSecretIdentifierList(L), member(X, L); 
statement(Line, language(Lang), file(Path), _, _, _, _, _, _, _, attrNamePattern(X), attrValue(any), _, _, _, _, _, _, _, _, _), hardcodedSecretIdentifierList(L), member(X, L);
statement(Line, language(Lang), file(Path), _, _, _, _, _, _, _, _, _, dictKeyPattern(X), dictValue(any), _, _, _, _, _, _, _), hardcodedSecretIdentifierList(L), member(X, L);
statement(Line, language(Lang), file(Path), _, _, funcArgNameInContext(X), funcArgValueInContext(any), _, _, _, _, _, _, _, _, _, _, _, _, _, _), hardcodedSecretIdentifierList(L), member(X, L).

emptyPassword(Line, Lang, Path) :- statement(Line, language(Lang), file(Path), _, _, _, _, _, varNamePattern(X), varValue(empty), _, _, _, _, _, _, _, _, _, _, _), hardcodedSecretIdentifierList(L), member(X, L); 
statement(Line, language(Lang), file(Path), _, _, _, _, _, _, _, attrNamePattern(X), attrValue(empty), _, _, _, _, _, _, _, _, _), hardcodedSecretIdentifierList(L), member(X, L);
statement(Line, language(Lang), file(Path), _, _, _, _, _, _, _, _, _, dictKeyPattern(X), dictValue(empty), _, _, _, _, _, _, _), hardcodedSecretIdentifierList(L), member(X, L).


execUsed(Line, Lang, Path) :-  statement(Line, language(Lang), file(Path), funcName(exec), _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _).

hardcodedBinding(Line, Lang, Path) :- statement(Line, language(Lang), file(Path), funcName(bind), _, _, funcArgValueInContext(ip), _, _, _, _, _, _, _, _, _, _, _, _, _, _); 
statement(Line, language(Lang), file(Path), _, _, _, _, _, varNamePattern(any), varValue(ip), _, _, _, _, _, _, _, _, _, _, _).



hardcodedTmpDirectory(Line, Lang, Path) :- statement(Line, language(Lang), file(Path), _, _, _, _, _, _, _, _, _, _, _, _, _, _, _ , _, _, stringContains(tmp)).

ignoreExceptBlock(Line, Lang, Path) :- statement(Line, language(Lang), file(Path), _, _, _, _, _, _, _, _, _, _, _, isTryStatement(yes), isExceptBlockSingleLine(yes), passInExceptBlock(yes),_, _, _, _) ; statement(Line, language(Lang), file(Path), _, _, _, _, _, _, _, _, _, _, _, isTryStatement(yes), isExceptBlockSingleLine(yes), _, continueInExceptBlock(yes), _, _, _).

noIntegrityCheck(Line, Lang, Path) :- statement(Line, language(Lang), file(Path), _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, httpWritePerformedInStatement(yes), hashFuncAppliedInSource(no) , _).

noCertificateValidation(Line, Lang, Path) :-  statement(Line, language(Lang), file(Path), funcName(get), _, funcArgNameInContext(verify), funcArgValueInContext(no), _, _, _, _, _, _, _, _, _, _, _, _, _, _).

useOfHttpWithoutTLS(Line, Lang, Path) :-  statement(Line, language(Lang), file(Path), _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, stringContains(http)).

sqlInjection(Line, Lang, Path) :- statement(Line, language(Lang), file(Path), _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, stringContains(parameterizedSql)).

shellInjection(Line, Lang, Path) :- statement(Line, language(Lang), file(Path), _, _, _, _, _, _, _, attrNamePattern(argv), attrValue(any), _, _, _, _, _, _, _, _, _);
statement(Line, language(Lang), file(Path), funcName(argumentParser), _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _);
statement(Line, language(Lang), file(Path), _, _, funcArgNameInContext(shell), _, _, _, _, _, _, _, _, _, _, _, _, _, _, _);
statement(Line, language(Lang), file(Path), funcName(X), _, funcArgNameInContext(shell), _, _, _, _, _, _, _, _, _, _, _, _, _, _, _), shellFunctionList(L), member(X,L). 

