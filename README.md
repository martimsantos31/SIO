# Grade: 18.6

# Structure:

# How to run the service:

## Requirements:
- Docker
- Docker-compose
- Python

## Steps:
- Inside the `src` directory run the `setup.sh`script which will create a virtual environment, install the dependencies and start the docker server
- Inside the `client` directory activate the virtual environment `activate ./.venv/bin/activate` and run the `test_p1.py` script to run the tests

## How to rerun the tests:
- Run the `clean.sh` script inside the client directory and inside the `repository/db`
- Make sure the files `organizations.json`, `sessions.json` and `files.json` are empty.

# Commands implemented:

- rep_add_role
- rep_assume_role
- rep_drop_role
- rep_list_roles
- rep_list_role_subjects
- rep_list_subject_roles
- rep_list_role_permissions
- rep_list_permission_roles
- rep_suspend_role
- rep_reactivate_role
- rep_add_permission
- rep_remove_permission
- rep_acl_doc
