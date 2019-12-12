

allSmellInAFile(Lang, Path, Count, Lines) :-
    atom_concat('path_', Path, P),
    findall(Y1, sqlInjection(Y1, Lang, P), L1),
    findall(Y2, shellInjection(Y2, Lang, P), L2),
    append(L1, L2, R1),
    findall(Y3, badFilePermission(Y3, Lang, P), L3),
    append(R1, L3, R2),
    findall(Y4, debugInDeployment(Y4, Lang, P), L4),
    append(R2, L4, R3),
    findall(Y5, hardcodedSecret(Y5, Lang, P), L5),
    append(R3, L5, R4),
    findall(Y6, emptyPassword(Y6, Lang, P), L6),
    append(R4, L6, R5),
    findall(Y7, execUsed(Y7, Lang, P), L7),
    append(R5, L7, R6),
    findall(Y8, noIntegrityCheck(Y8, Lang, P), L8),
    append(R6, L8, R7),
    findall(Y9, noCertificateValidation(Y9, Lang, P), L9),
    append(R7, L9, R8),
    findall(Y10, useOfHttpWithoutTLS(Y10, Lang, P), L10),
    append(R8, L10, R9),
    findall(Y11, ignoreExceptBlock(Y11, Lang, P), L11),
    append(R9, L11, R10),
    findall(Y12, hardcodedTmpDirectory(Y12, Lang, P), L12),
    append(R10, L12, Lines),
    length(Lines, S),
    Count is S.


smellInAFile(Lang, Path, SmellName, Count, Lines) :-
    SmellName = "shellInjection",
    atom_concat('path_', Path, P),
    findall(Y, shellInjection(Y, Lang, P), L),
    length(L, S),
    Count is S,
    copy_term(L, Lines).


smellInAFile(Lang, Path, SmellName, Count, Lines) :-
    SmellName = "sqlInjection",
    atom_concat('path_', Path, P),
    findall(Y, sqlInjection(Y, Lang, P), L),
    length(L, S),
    Count is S,
    copy_term(L, Lines).

smellInAFile(Lang, Path, SmellName, Count, Lines) :-
    SmellName = "badFilePermission",
    atom_concat('path_', Path, P),
    findall(Y, badFilePermission(Y, Lang, P), L),
    length(L, S),
    Count is S,
    copy_term(L, Lines).



smellInAFile(Lang, Path, SmellName, Count, Lines) :-
    SmellName = "debugInDeployment",
    atom_concat('path_', Path, P),
    findall(Y, debugInDeployment(Y, Lang, P), L),
    length(L, S),
    Count is S,
    copy_term(L, Lines).

smellInAFile(Lang, Path, SmellName, Count, Lines) :-
    SmellName = "hardcodedSecret",
    atom_concat('path_', Path, P),
    findall(Y, hardcodedSecret(Y, Lang, P), L),
    length(L, S),
    Count is S,
    copy_term(L, Lines).

smellInAFile(Lang, Path, SmellName, Count, Lines) :-
    SmellName = "emptyPassword",
    atom_concat('path_', Path, P),
    findall(Y, emptyPassword(Y, Lang, P), L),
    length(L, S),
    Count is S,
    copy_term(L, Lines).

smellInAFile(Lang, Path, SmellName, Count, Lines) :-
    SmellName = "execUsed",
    atom_concat('path_', Path, P),
    findall(Y, execUsed(Y, Lang, P), L),
    length(L, S),
    Count is S,
    copy_term(L, Lines).

smellInAFile(Lang, Path, SmellName, Count, Lines) :-
    SmellName = "noIntegrityCheck",
    atom_concat('path_', Path, P),
    findall(Y, noIntegrityCheck(Y, Lang, P), L),
    length(L, S),
    Count is S,
    copy_term(L, Lines).

smellInAFile(Lang, Path, SmellName, Count, Lines) :-
    SmellName = "noCertificateValidation",
    atom_concat('path_', Path, P),
    findall(Y, noCertificateValidation(Y, Lang, P), L),
    length(L, S),
    Count is S,
    copy_term(L, Lines).

smellInAFile(Lang, Path, SmellName, Count, Lines) :-
    SmellName = "useOfHttpWithoutTLS",
    atom_concat('path_', Path, P),
    findall(Y, useOfHttpWithoutTLS(Y, Lang, P), L),
    length(L, S),
    Count is S,
    copy_term(L, Lines).


smellInAFile(Lang, Path, SmellName, Count, Lines) :-
    SmellName = "ignoreExceptBlock",
    atom_concat('path_', Path, P),
    findall(Y, ignoreExceptBlock(Y, Lang, P), L),
    length(L, S),
    Count is S,
    copy_term(L, Lines).


smellInAFile(Lang, Path, SmellName, Count, Lines) :-
    SmellName = "hardcodedTmpDirectory",
    atom_concat('path_', Path, P),
    findall(Y, hardcodedTmpDirectory(Y, Lang, P), L),
    length(L, S),
    Count is S,
    copy_term(L, Lines).


smellInAllFile(Lang, SmellName, Count, Files) :-
    SmellName = "sqlInjection",
    findall(Y, sqlInjection(Y, Lang, P), L),
    length(L, S),
    Count is S,
    findall(X, sqlInjection(Z, Lang, X), F),
    copy_term(F, Files).

smellInAllFile(Lang, SmellName, Count, Files) :-
    SmellName = "shellInjection",
    findall(Y, shellInjection(Y, Lang, P), L),
    length(L, S),
    Count is S,
    findall(X, shellInjection(Z, Lang, X), F),
    copy_term(F, Files).
    
smellInAllFile(Lang, SmellName, Count, Files) :-
    SmellName = "badFilePermission",
    findall(Y, badFilePermission(Y, Lang, P), L),
    length(L, S),
    Count is S,
    findall(X, badFilePermission(Z, Lang, X), F),
    copy_term(F, Files).

smellInAllFile(Lang, SmellName, Count, Files) :-
    SmellName = "debugInDeployment",
    findall(Y, debugInDeployment(Y, Lang, P), L),
    length(L, S),
    Count is S,
    findall(X, debugInDeployment(Z, Lang, X), F),
    copy_term(F, Files).
    
smellInAllFile(Lang, SmellName, Count, Files) :-
    SmellName = "hardcodedSecret",
    findall(Y, hardcodedSecret(Y, Lang, P), L),
    length(L, S),
    Count is S,
    findall(X, hardcodedSecret(Z, Lang, X), F),
    copy_term(F, Files).

smellInAllFile(Lang, SmellName, Count, Files) :-
    SmellName = "emptyPassword",
    findall(Y, emptyPassword(Y, Lang, P), L),
    length(L, S),
    Count is S,
    findall(X, emptyPassword(Z, Lang, X), F),
    copy_term(F, Files).

smellInAllFile(Lang, SmellName, Count, Files) :-
    SmellName = "execUsed",
    findall(Y, execUsed(Y, Lang, P), L),
    length(L, S),
    Count is S,
    findall(X, execUsed(Z, Lang, X), F),
    copy_term(F, Files).

smellInAllFile(Lang, SmellName, Count, Files) :-
    SmellName = "noIntegrityCheck",
    findall(Y, noIntegrityCheck(Y, Lang, P), L),
    length(L, S),
    Count is S,
    findall(X, noIntegrityCheck(Z, Lang, X), F),
    copy_term(F, Files).

smellInAllFile(Lang, SmellName, Count, Files) :-
    SmellName = "noCertificateValidation",
    findall(Y, noCertificateValidation(Y, Lang, P), L),
    length(L, S),
    Count is S,
    findall(X, noCertificateValidation(Z, Lang, X), F),
    copy_term(F, Files).

smellInAllFile(Lang, SmellName, Count, Files) :-
    SmellName = "noCertificateValidation",
    findall(Y, noCertificateValidation(Y, Lang, P), L),
    length(L, S),
    Count is S,
    findall(X, noCertificateValidation(Z, Lang, X), F),
    copy_term(F, Files).


smellInAllFile(Lang, SmellName, Count, Files) :-
    SmellName = "useOfHttpWithoutTLS",
    findall(Y, useOfHttpWithoutTLS(Y, Lang, P), L),
    length(L, S),
    Count is S,
    findall(X, useOfHttpWithoutTLS(Z, Lang, X), F),
    copy_term(F, Files).


smellInAllFile(Lang, SmellName, Count, Files) :-
    SmellName = "ignoreExceptBlock",
    findall(Y, ignoreExceptBlock(Y, Lang, P), L),
    length(L, S),
    Count is S,
    findall(X, ignoreExceptBlock(Z, Lang, X), F),
    copy_term(F, Files).


smellInAllFile(Lang, SmellName, Count, Files) :-
    SmellName = "hardcodedTmpDirectory",
    findall(Y, hardcodedTmpDirectory(Y, Lang, P), L),
    length(L, S),
    Count is S,
    findall(X, hardcodedTmpDirectory(Z, Lang, X), F),
    copy_term(F, Files).
