# CSC503-Project

## Introduction
This is the repo of the term project done in CSC503: Computational Applied Logic at Fall, 2019. This project does a language agnostic semantic analysis of security smell detection in Python and Ansible languages. This is an extension to the original work done in ```Share but Beware: Security Smell in Python Gist - R. Rahman, A. Rahman, L. Williams; International Conference on Software, Maintenance and Evolution, 2019``` and ```Security Smells in Infrastructure as Code Scripts, A. Rahman, R. Rahman, C. Parnin, L. Williams; Preprint - https://arxiv.org/abs/1907.07159```. 

## Steps(If you want to completely start from the scratch):
- install ```python3.7``` in your system
- install ```pipenv``` by using ```pip``` or package manager like ```brew``` or ```apt```
- in terminal, go to the project root directory
- run ```pipenv install```
- in ```ymlPaths/openstack.txt```, edit all the file locations. For example, if the absolute path of your project root is ```/home/jDoe/projects/CSC503-Project```, then first line should look like this: ```/home/jDoe/projects/CSC503-Project/repo-openstack/openstack@ansible-role-container-registry/handlers/main.yml```. Change all the other lines of file location in this manner.
- run both the ```src/AnsibleSmellDetector.py``` and ```src/smellDetector.py```
- outputs will be in ```./facts-ansible.pl``` and ```./facts-python.pl```
- append the rules in those files from ```./rules.pl```


## Instructions on running Query (If you only want to run prolog queries after downloading the repo)
Supported Queries
- ```smellInAllFile(Lang, SmellName, Count, Files)```, this provides the occurence count of smell and corresponding file names for a specific smell and for all available files.
- ```smellInAFile(Lang, FileName, SmellName, Count, Lines)```, it computes the occurence count of security smell and corresponding line numbers for a specific smell and specific file.
- ```allSmellInAFile(Lang, FileName, Count, Lines)```, this provides the occurence count of all of the supported smells and corresponding line numbers for a specific file.


### Python:
loading prolog files: swipl facts-python.pl query.pl 

Query examples:
- smellInAllFile(python, "hardcodedSecret", Count, Files).
- smellInAFile(python, d449e502f432278f772bd672ec785d7c, "hardcodedSecret", Count, Lines).
- allSmellInAFile(python, d449e502f432278f772bd672ec785d7c , Count, Lines).

### Ansible: 
loading prolog files: swipl facts-ansible.pl query.pl

Query examples:
- smellInAllFile(ansible, "hardcodedSecret", Count, Files).
- allSmellInAFile(ansible, home_rr_Workspace_CSC503__Project_repo__openstack_openstack__tripleo__quickstart_playbooks_quickstart_, Count, Lines).


### Supported Smells

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
