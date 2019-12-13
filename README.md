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

#### Instructions on Query

##### Python:
loading prolog files: swipl facts-python.pl query.pl 

Sample Query
- smellInAllFile(python, "hardcodedSecret", Count, Files).
- smellInAFile(python, d449e502f432278f772bd672ec785d7c, "hardcodedSecret", C, L).
- allSmellInAFile(python, d449e502f432278f772bd672ec785d7c , Count, Lines).

##### Ansible: 
loading prolog files: swipl facts-ansible.pl query.pl

Sample Query
- allSmellInAFile(ansible, home_rr_Workspace_CSC503__Project_repo__openstack_openstack__tripleo__quickstart_playbooks_quickstart_, C, L).
