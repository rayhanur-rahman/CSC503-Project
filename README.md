# CSC503-Project

This is the repo of the term project done in CSC503: Computational Applied Logic at Fall, 2019. This project does a language agnostic semantic analysis of security smell detection in Python and Ansible languages. This is an extension to the original work done in ```Share but Beware: Security Smell in Python Gist - R. Rahman, A. Rahman, L. Williams; International Conference on Software, Maintenance and Evolution, 2019``` and ```Security Smells in Infrastructure as Code Scripts, A. Rahman, R. Rahman, C. Parnin, L. Williams; Preprint - https://arxiv.org/abs/1907.07159```. 

Steps(If you want to completely start from the scratch):
- install ```python3.7``` in your system
- install ```pipenv``` by using ```pip``` or package manager like ```brew``` or ```apt```
- in terminal, go to the project root directory
- run ```pipenv install```
- in ```ymlPaths/openstack.txt```, edit all the file locations. For example, if the absolute path of your project root is ```/home/jDoe/projects/CSC503-Project```, then first line should look like this: ```/home/jDoe/projects/CSC503-Project/repo-openstack/openstack@ansible-role-container-registry/handlers/main.yml```. Change all the other lines of file location in this manner.
- run both the ```src/AnsibleSmellDetector.py``` and ```src/smellDetector.py```
- outputs will be in ```./facts-ansible.pl``` and ```./facts-python.pl```

Steps(If you cloned the repo, you'are just interested to run the prolog rules):
