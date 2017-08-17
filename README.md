# bucket-list-app-api

[![Build Status](https://travis-ci.org/mkiterian/viserys.svg?branch=tasks)](https://travis-ci.org/mkiterian/viserys)

# Bucketlist API
This repo contains a bucketlist API using flask. The API enables users to register, login and access bucketlist and bucketlist item resources. The user can create, update, delete and retrieve bucketlists and bucketlist items.


## Getting Started

### Prerequisites
- Install python 3.6 in your local environment
    - https://www.python.org/downloads/ 
- Install virtualenv and virtualenvwrapper
- Install postgres (PostgreSQL) 9.6.3
```
    pip install virtualenv
```
```
    pip install virtualenvwrapper
```

- Add these lines to your shell startup file. (Refer to http://virtualenvwrapper.readthedocs.io/en/latest/install.html for instructions specific to your OS)
    - export WORKON_HOME=$HOME/.virtualenvs
    - export PROJECT_HOME=$HOME/Devel
    - source /usr/local/bin/virtualenvwrapper.sh

- Create a virtual environment for the application by running
```
    workon bucket-venv
```
### Installing
- Create a directory for the app and cd into it
```
    mkdir bucketlist_api
    cd bucketlist_api
```
To clone the repo. In your terminal run the command:
```
    git clone https://github.com/mkiterian/bucket-list-app-api.git
```

- cd into bucket-list-app-api directory
- Run the command
```
pip install -r requirements.txt
```
This installs all the package dependencies in requirements.txt
Create a database named bcktlst in postgres
Run the commands
```
python manage.py db init migrate
python manage.py db init upgrade 
```
The api can then be run locally from terminal with the command
```
python run.py
```
## Running the tests

To run the tests create a test database named __db_for_api_tests__
In the terminal run the command:
```
coverage run --source=app -m py.test && coverage report
```
### Usage

[Documentation](http://docs.bucketlistapi9.apiary.io/)