# CSC503-Project

Steps:
- install ```pipenv``` by using ```pip``` or package manager like ```brew``` or ```apt```
- run ```pipenv install```
- in ```src/smellDetector.py```, edit line ```150, 155, 485```
- in ```src/AnsibleSmellDetector.py``` edit line ```268,269```
- in ```ymlPaths/github.txt```, edit all the file locations
- run both the ```src/AnsibleSmellDetector.py``` and ```src/smellDetector.py```
- outputs will be in ```./facts-ansible.pl``` and ```./facts-python.pl```
- append the rules in those files from ```./rules.pl```


#### Instructions on running Query

Supported Queries
- ```smellInAllFile(Lang, SmellName, Count, Files)```, this provides the occurence count of smell and corresponding file names for a specific smell and for all available files.
- ```smellInAFile(Lang, FileName, SmellName, Count, Lines)```, it computes the occurence count of security smell and corresponding line numbers for a specific smell and specific file.
- ```allSmellInAFile(Lang, FileName, Count, Lines)```, this provides the occurence count of all of the supported smells and corresponding line numbers for a specific file.


##### Python:
loading prolog files: swipl facts-python.pl query.pl 

Query examples:
- smellInAllFile(python, "hardcodedSecret", Count, Files).
- smellInAFile(python, d449e502f432278f772bd672ec785d7c, "hardcodedSecret", Count, Lines).
- allSmellInAFile(python, d449e502f432278f772bd672ec785d7c , Count, Lines).

##### Ansible: 
loading prolog files: swipl facts-ansible.pl query.pl

Query examples:
- smellInAllFile(ansible, "hardcodedSecret", Count, Files).
- allSmellInAFile(ansible, home_rr_Workspace_CSC503__Project_repo__openstack_openstack__tripleo__quickstart_playbooks_quickstart_, Count, Lines).


#### Supported Smells

- hardcodedSecret
- sqlInjection
- shellInjection
- badFilePermission
- debugInDeployment
- emptyPassword
- execUsed
- noIntegrityCheck
- noCertificateValidation
- useOfHttpWithoutTLS
- ignoreExceptBlock
- hardcodedTmpDirectory
- hardcodedBinding
