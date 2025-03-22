#!/bin/sh

# Uncomment for execution debugging
#set -x

interpreter=$1
extension=$2
DELIVERY=2

if [ -z "$interpreter" ]; then
    int=\"
else
    int="\"$interpreter "
fi

is_command()
{
    if [ ! -z "$interpreter" ]; then
        [ -x $1 ]
        return $?
    else
        [ -s $1 ]
        return $?
    fi
}

test_exists()
{
    cmd=./$1
    shift
    set $cmd$extension

    echo -n "Cmd exists \""$*"\" "
    if is_command $1; then
        >&2 echo "OK"
        return 0
    else
        >&2 echo "FAIL"
        return 1
    fi
}

test_badargs()
{
    cmd=./$1
    shift
    set $cmd$extension $*

    >&2 echo -n "Bad args $int$*\" "
    if is_command $1; then
        $interpreter $* # > /dev/null 2>&1
        error=$?
        if [ $error -gt 0 ]; then
            >&2 echo "FAIL"
        else
            >&2 echo "OK"
        fi
    else
        >&2 echo "NA"
    fi
    >&2 echo "------------------------------------------------------------------------------------------------------------"
}

test_error()
{
    cmd=./$1
    shift
    set $cmd$extension $*

    >&2 echo -n "Rep error $int$*\" "
    if is_command $1; then
        $interpreter $* > /dev/null 2>&1
        error=$?
        if [ $error -lt 128 ]; then
            >&2 echo "FAIL"
        else
            >&2 echo "OK"
        fi
    else
        >&2 echo "NA"
    fi
    >&2 echo "------------------------------------------------------------------------------------------------------------"
}

test_ok()
{
    cmd=./$1
    shift
    set $cmd$extension $*

    >&2 echo -n "Good cmd $int$*\" "
    if is_command $1; then
        $interpreter $* # > /dev/null 2>&1
        error=$?
        if [ $error -ne 0 ]; then
            >&2 echo "FAIL"
        else
            >&2 echo "OK"
        fi
    else
        >&2 echo "NA"
    fi
    >&2 echo "------------------------------------------------------------------------------------------------------------"
}

test_exists_all()
{
    if [ $DELIVERY -ge 1 ]; then
        test_exists rep_subject_credentials
        test_exists rep_decrypt_file
        test_exists rep_create_org
        test_exists rep_list_orgs
        test_exists rep_create_session
        test_exists rep_get_file
        test_exists rep_list_docs
        test_exists rep_add_subject
        test_exists rep_add_doc
        test_exists rep_get_doc_metadata
        test_exists rep_get_doc_file
        test_exists rep_delete_doc
    fi
    if [ $DELIVERY -ge 2 ]; then
        test_exists rep_assume_role
        test_exists rep_drop_role
        test_exists rep_list_roles
        test_exists rep_list_subjects
        test_exists rep_list_role_subjects
        test_exists rep_list_subject_roles
        test_exists rep_list_role_permissions
        test_exists rep_list_permission_roles
        test_exists rep_suspend_subject
        test_exists rep_suspend_subject
        test_exists rep_activate_subject
        test_exists rep_add_role
        test_exists rep_suspend_role
        test_exists rep_reactivate_role
        test_exists rep_add_permission
        test_exists rep_remove_permission
        test_exists rep_add_permission
        test_exists rep_remove_permission
        test_exists rep_acl_doc
    fi
}

test_badargs_all()
{
    touch a_file
    touch a_session
    touch a_metadata
    touch a_pubkey
    touch a_credentials

    if [ $DELIVERY -ge 1 ]; then
        # rep_subject_credentials <password> <credentials file>
        test_badargs rep_subject_credentials
        test_badargs rep_subject_credentials passwd
        # rep_decrypt_file <encrypted file> <encryption metadata>
        test_badargs rep_decrypt_file
        test_badargs rep_decrypt_file file
        test_badargs rep_decrypt_file .file .metadata
        test_badargs rep_decrypt_file .file .metadata
        test_badargs rep_decrypt_file a_file .metadata
        test_badargs rep_decrypt_file a_file a_metadata
        # rep_create_org <organization> <username> <name> <email> <public key file>
        test_badargs rep_create_org
        test_badargs rep_create_org organization_a
        test_badargs rep_create_org organization_b username
        test_badargs rep_create_org organization_c username name
        test_badargs rep_create_org organization_d username name email
        test_badargs rep_create_org organization_e username name email .a_pubkey
        test_badargs rep_create_org organization_f username name email a_pubkey
        # rep_list_orgs
        # rep_create_session <organization> <username> <password> <credentials file> <session file>
        test_badargs rep_create_session
        test_badargs rep_create_session organization
        test_badargs rep_create_session organization username
        test_badargs rep_create_session organization username password
        test_badargs rep_create_session organization username password .credentials
        test_badargs rep_create_session organization username password .credentials .session
        test_badargs rep_create_session organization username password a_credentials .session
        test_badargs rep_create_session organization username password a_credentials a_session
        # rep_get_file <file handle> [file]
        test_badargs rep_get_file
        # rep_list_docs <session file> [-s username] [-d nt/ot/et date]
        test_badargs rep_list_docs
        test_badargs rep_list_docs .session
        test_badargs rep_list_docs a_session
        test_badargs rep_list_docs session -s
        test_badargs rep_list_docs session -d
        test_badargs rep_list_docs session -d nt
        test_badargs rep_list_docs session -d ot
        test_badargs rep_list_docs session -d et
        test_badargs rep_list_docs session -d date
        # rep_add_subject <session file> <username> <name> <email> <credentials file>
        test_badargs rep_add_subject
        test_badargs rep_add_subject session
        test_badargs rep_add_subject session username
        test_badargs rep_add_subject session username name
        test_badargs rep_add_subject session username name email
        test_badargs rep_add_subject .session username name email credentials
        test_badargs rep_add_subject a_session username name email .credentials
        test_badargs rep_add_subject a_session username name email a_credentials
        # rep_add_doc <session file> <document name> <file>
        test_badargs rep_add_doc
        test_badargs rep_add_doc session
        test_badargs rep_add_doc session document
        test_badargs rep_add_doc .session document file
        test_badargs rep_add_doc a_session document .file
        # rep_get_doc_metadata <session file> <document name>
        test_badargs rep_get_doc_metadata
        test_badargs rep_get_doc_metadata session
        test_badargs rep_get_doc_metadata .session document
        test_badargs rep_get_doc_metadata a_session document
        # rep_get_doc_file <session file> <document name> [file]
        test_badargs rep_get_doc_file
        test_badargs rep_get_doc_file session
        test_badargs rep_get_doc_file .session document
        test_badargs rep_get_doc_file a_session document
        # rep_delete_doc <session file> <document name>
        test_badargs rep_delete_doc_metadata
        test_badargs rep_delete_doc_metadata session
        test_badargs rep_delete_doc_metadata .session document
        test_badargs rep_delete_doc_metadata a_session document
    fi
    if [ $DELIVERY -ge 2 ]; then
        # rep_assume_role <session file> <role>
        test_badargs rep_assume_role
        test_badargs rep_assume_role session
        test_badargs rep_assume_role .session role
        test_badargs rep_assume_role a_session role
        # rep_drop_role <session file> <role>
        test_badargs rep_drop_role
        test_badargs rep_drop_role session
        test_badargs rep_drop_role .session role
        test_badargs rep_drop_role a_session role
        # rep_list_roles <session file> <role>
        test_badargs rep_list_roles
        test_badargs rep_list_roles session
        test_badargs rep_list_roles .session role
        test_badargs rep_list_roles a_session role
        # rep_list_subjects <session file> [username]
        test_badargs rep_list_subjects
        test_badargs rep_list_subjects .session
        test_badargs rep_list_subjects a_session
        # rep_list_role_subjects <session file> <role>
        test_badargs rep_list_role_subjects
        test_badargs rep_list_role_subjects session
        test_badargs rep_list_role_subjects .session role
        test_badargs rep_list_role_subjects a_session role
        # rep_list_subject_roles <session file> <username>
        test_badargs rep_list_subject_roles
        test_badargs rep_list_subject_roles session
        test_badargs rep_list_subject_roles .session username
        test_badargs rep_list_subject_roles a_session username
        # rep_list_role_permissions <session file> <role>
        test_badargs rep_list_role_permissions
        test_badargs rep_list_role_permissions session
        test_badargs rep_list_role_permissions .session role
        test_badargs rep_list_role_permissions a_session role
        # rep_list_permission_roles <session file> <permission>
        test_badargs rep_list_permission_roles
        test_badargs rep_list_permission_roles session
        test_badargs rep_list_permission_roles .session permission
        test_badargs rep_list_permission_roles a_session permission
        # rep_suspend_subject <session file> <username>
        test_badargs rep_suspend_subject
        test_badargs rep_suspend_subject session
        test_badargs rep_suspend_subject .session username
        test_badargs rep_suspend_subject a_session username
        # rep_activate_subject <session file> <username>
        test_badargs rep_activate_subject
        test_badargs rep_activate_subject session
        test_badargs rep_activate_subject .session username
        test_badargs rep_activate_subject a_session username
        # rep_add_role <session file> <role>
        test_badargs rep_add_role
        test_badargs rep_add_role session
        test_badargs rep_add_role .session role
        test_badargs rep_add_role a_session role
        # rep_suspend_role <session file> <role>
        test_badargs rep_suspend_role
        test_badargs rep_suspend_role session
        test_badargs rep_suspend_role .session role
        test_badargs rep_suspend_role a_session role
        # rep_reactivate_role <session file> <role>
        test_badargs rep_reactivate_role
        test_badargs rep_reactivate_role session
        test_badargs rep_reactivate_role .session role
        test_badargs rep_reactivate_role a_session role
        # rep_add_permission <session file> <role> <username>
        test_badargs rep_add_permission
        test_badargs rep_add_permission session
        test_badargs rep_add_permission session role
        test_badargs rep_add_permission .session role username
        test_badargs rep_add_permission a_session role username
        # rep_remove_permission <session file> <role> <username>
        test_badargs rep_remove_permission
        test_badargs rep_remove_permission session
        test_badargs rep_remove_permission session role
        test_badargs rep_remove_permission .session role user_perm
        test_badargs rep_remove_permission a_session role user_perm
        # rep_acl_doc <session file> <document name> [+/-] <role> <permission>
        test_badargs rep_acl_doc
        test_badargs rep_acl_doc session
        test_badargs rep_acl_doc session document
        test_badargs rep_acl_doc session document +
        test_badargs rep_acl_doc session document -
        test_badargs rep_acl_doc session document + role
        test_badargs rep_acl_doc .session document + role permission
        test_badargs rep_acl_doc a_session document + role permission
    fi
    rm a_file
    rm a_session
    rm a_metadata
    rm a_pubkey
    rm a_credentials
}

test_all() {
    #     test_exists rep_decrypt_file
    #     test_exists rep_get_file
    #     test_exists
    #     test_exists rep_add_subject
    #     test_exists rep_get_doc_metadata
    #     test_exists rep_get_doc_file
    #     test_exists rep_delete_doc


    # Download two books
    if [ ! -f pg84.txt ]; then
        wget https://www.gutenberg.org/cache/epub/84/pg84.txt
    fi
    if [ ! -f pg1513.txt ]; then
        wget https://www.gutenberg.org/cache/epub/1513/pg1513.txt
    fi


    if [ $DELIVERY -eq 1 ]; then

        # Create two users
        test_ok rep_subject_credentials olaadeus credentials1
        test_ok rep_subject_credentials adeusola credentials2
        test_ok rep_subject_credentials foobar credentials3

        credentials1=$(find . -name credentials1)
        credentials2=$(find . -name credentials2)
        credentials3=$(find . -name credentials3)

        # Extract the public keys
        # openssl rsa -in $credentials1 -passin pass:olaadeus -pubout -out pub1
        # openssl rsa -in $credentials2 -passin pass:adeusola -pubout -out pub2
        # openssl rsa -in $credentials3 -passin pass:foobar   -pubout -out pub3

        # Create two organizations
        test_ok rep_create_org org1 user1 name1 user1@org1.com credentials1
        test_ok rep_create_org org2 user2 name2 user2@org2.com credentials2

        # List repositories
        test_ok rep_list_orgs

        # Create two sessions
        test_ok rep_create_session org1 user1 olaadeus credentials1 session1
        test_ok rep_create_session org2 user2 adeusola credentials2 session2

        # Add two documents, one for each organization
        test_ok rep_add_doc session1 Frankenstein pg84.txt
        test_ok rep_add_doc session2 Romeo_and_Juliet pg1513.txt

        # List files
        test_ok rep_list_docs session1
        test_ok rep_list_docs session2

        # Get metadata
        test_ok rep_get_doc_metadata session1 Frankenstein > Frankenstein.metadata
        >&2 cat Frankenstein.metadata

        test_ok rep_get_doc_metadata session2 Romeo_and_Juliet > Romeo_and_Juliet.metadata
        >&2 cat Romeo_and_Juliet.metadata

        file1handle=$(cat Frankenstein.metadata |grep -e "file_handle" |cut -d '"' -f 4)

        >&2 echo "File1Handle: "$file1handle
        # Get files
        test_ok rep_get_file $file1handle Frankenstein1.enc

        test_ok rep_get_doc_file session2 Romeo_and_Juliet Romeo_and_Juliet2.enc

        file1enc=$(find . -name Frankenstein1.enc |head -n 1)
        file2enc=$(find . -name Romeo_and_Juliet2.enc |head -n 1)

        >&2 echo "Testing if file $file1enc is encrypted"
        if [ -f $file1enc ]; then
            >&2 echo "File Content is: " $(file $file1enc)

            if [ $(gzip < $file1enc |wc -c) -gt 400000 ]; then
                >&2 echo "File IS ENCRYPTED\nOK"
            else
                >&2 echo "File IS NOT ENCRYPTED\nFAIL"
            fi
        else
            >&2 echo "File Frankenstein1.enc not found\nFAIL"
        fi
        >&2 echo "------------------------------------------------------------------------------------------------------------"

        # Decrypt files
        if [ -f "$file1enc" ]; then
            test_ok rep_decrypt_file $file1enc Frankenstein.metadata > Frankenstein.txt
        else
            >&2 echo "rep_decrypt_file ERROR"
            >&2 echo "FAIL"
            >&2 echo "------------------------------------------------------------------------------------------------------------"
        fi

        if [ -f "$file1enc" ]; then
            >&2 echo "Testing if file < $file1enc > is decrypted"
            >&2 echo "File Content is: " $(file $file1enc)
            if [ $(md5sum $file1enc |cut -d ' ' -f 1) == "1e6d3c941fe4233efbbd5820de939460" ]; then
                >&2 echo "File IS THE ORIGINAL TEXT\nOK"
            else
                >&2 echo "File IS NOT THE ORIGINAL TEXT\nFAIL"
            fi
        else
            >&2 echo "File Frankenstein1.enc not found\nFAIL"
        fi
        >&2 echo "------------------------------------------------------------------------------------------------------------"


        # Add a user to an organization
        test_ok rep_add_subject session1 user3 name3 user3@org1 pub3

        test_ok rep_create_session org1 user3 foobar credentials3 session3

        # Get metadata
        test_ok rep_get_doc_metadata session3 Frankenstein |sed -e 's/.*cmd.*{/{/g' |grep -ve "^OK"  |grep -v '\----' > Frankenstein3.metadata

        # Get files
        test_ok rep_get_doc_file session3 Frankenstein Frankenstein3.enc

        file3enc=$(find . -name Frankenstein3.enc |head -n 1)

        # Decrypt files
        test_ok rep_decrypt_file $file3enc Frankenstein3.metadata

        # Delete a file
        test_ok rep_delete_doc session3 Frankenstein
        test_ok rep_delete_doc session2 Romeo_and_Juliet

        # Delete files
        test_ok rep_get_doc_metadata session1 Frankenstein
        if [ -f "$file1handle" ]; then
            test_ok rep_get_doc_file session1 $file1handle
        else
            >&2 echo "Good cmd: rep_get_doc_file NA Metadata not available"
            >&2 echo "FAIL"
            >&2 echo "------------------------------------------------------------------------------------------------------------"
        fi

        test_ok rep_get_doc_file session1 $file1handle

        # Suspend a user
        test_ok rep_suspend_subject session1 user3
        test_error rep_get_doc_metadata session3 Frankenstein

        # Activate a user
        test_ok rep_activate_subject session1 user3
        test_ok rep_get_doc_metadata session3 Frankenstein

    fi

    if [ $DELIVERY -eq 2 ]; then
        >&2 echo "Create two users"
        test_ok rep_subject_credentials olaadeus credentials1
        test_ok rep_subject_credentials adeusola credentials2

        credentials1=$(find . -name credentials1)
        credentials2=$(find . -name credentials2)

        # >&2 echo "Extract the public keys"
        # openssl rsa -in $credentials1 -passin pass:olaadeus -pubout -out pub1
        # openssl rsa -in $credentials2 -passin pass:adeusola -pubout -out pub2

        >&2 echo "Create one organization"
        test_ok rep_create_org org1 user1 name1 user1@org1.com credentials1

        >&2 echo "Create one session"
        test_ok rep_create_session org1 user1 olaadeus credentials1 session1

        >&2 echo "# List roles"
        test_ok rep_list_roles session1 manager

        >&2 echo "Add a user when should not be able to (because did not assume any role)"
        test_ok rep_add_subject session1 user2 name2 user2@org1.com credentials2

        >&2 echo "Assume the Manager role"
        test_ok rep_assume_role session1 manager

        >&2 echo "Add a user"
        test_ok rep_add_subject session1 user2 name2 user2@org1.com credentials2

        >&2 echo "Session with wrong credentials"
        test_ok rep_create_session org1 user2 blablabla credentials2 session2

        >&2 echo "Session with correct credentials"
        test_ok rep_create_session org1 user2 adeusola credentials2 session2

        >&2 echo "List subjects as owner"
        test_ok rep_list_subjects session1
        test_ok rep_list_subjects session1  user2

        >&2 echo "Suspend user2"
        test_ok rep_suspend_subject session1 user2

        >&2 echo "Activate user2"
        test_ok rep_activate_subject session1 user2

        >&2 echo "List subjects as user"
        test_ok rep_list_subjects session2

        >&2 echo  "Create two roles"
        test_ok rep_add_role session1 role1
        test_ok rep_add_role session1 role2

        >&2 echo "# List roles"
        test_ok rep_list_roles session1

        >&2 echo "Assume a role when not supposed to"
        test_ok rep_assume_role session2 role2

        >&2 echo "Add roles to a subject"
        test_ok rep_add_permission session1 role1 user2
        test_ok rep_add_permission session1 role2 user2

        >&2 echo " Suspends a role"
        test_ok rep_suspend_role session1 role2

        >&2 echo "Assume a role when not supposed to because it is suspended"
        test_ok rep_assume_role session2 role2

        >&2 echo "Reactivates a role"
        test_ok rep_reactivate_role session1 role2

        >&2 echo "Assume a role when supposed to"
        test_ok rep_assume_role session2 role2

        >&2 echo "List subjects of role"
        test_ok rep_list_role_subjects session1 manager
        test_ok rep_list_role_subjects session1 role1
        test_ok rep_list_role_subjects session1 role2

        >&2 echo "List roles of subject"
        test_ok rep_list_subject_roles session1 user2

        >&2 echo "Add Permission DOC_NEW to role1"
        test_ok rep_add_permission session1 role1 DOC_NEW
        test_ok rep_add_permission session1 role1 SUBJECT_UP
        test_ok rep_add_permission session1 role1 ROLE_ACL

        >&2 echo "Add document without permission"
        test_ok rep_add_doc session2 Frankenstein pg84.txt

        >&2 echo "Add document with permission"
        test_ok rep_assume_role session2 role1
        test_ok rep_add_doc session2 Romeo_and_Juliet pg1513.txt

        >&2 echo "Drop role1"
        test_ok rep_drop_role session2 role1

        >&2 echo "Remove user from role"
        test_ok rep_remove_permission session1 role1 user2

        >&2 echo "Give Read permission to role2"
        test_ok rep_acl_doc session1 Romeo_and_Juliet + role2 DOC_READ
        # test_ok rep_acl_doc session2 Romeo_and_Juliet + role2 DOC_READ


        >&2 echo "List permissions of role2"
        test_ok rep_list_role_permissions session1 role2

        >&2 echo "List roles of DOC_READ"
        test_ok rep_list_permission_roles session1 DOC_READ

        >&2 echo "Get file"
        test_ok rep_get_doc_file session2 Romeo_and_Juliet Romeo_and_Juliet.enc

        >&2 echo "Remove Read permission to role2"
        test_ok rep_acl_doc session1 Romeo_and_Juliet - role2 DOC_READ
        # test_ok rep_acl_doc session2 Romeo_and_Juliet - role2 DOC_READ

        >&2 echo "Get file without permission"
        test_ok rep_get_doc_file session2 Romeo_and_Juliet Romeo_and_Juliet.enc

        >&2 echo "Give Read permission to role2 again"
        test_ok rep_acl_doc session1 Romeo_and_Juliet + role2 DOC_READ
        # test_ok rep_acl_doc session2 Romeo_and_Juliet + role2 DOC_READ

        >&2 echo "Drop role2 from session2"
        test_ok rep_drop_role session2 role2

        >&2 echo "Get file without role in session"
        test_ok rep_get_doc_file session2 Romeo_and_Juliet Romeo_and_Juliet.enc
        test_ok rep_assume_role session2 role2

        >&2 echo "Remove role2 from user2"
        test_ok rep_remove_permission session1 role2 user2

        >&2 echo "Get file without role"
        test_ok rep_get_doc_file session2 Romeo_and_Juliet Romeo_and_Juliet.enc

        >&2 echo "Suspend role Manager"
        test_ok rep_suspend_role session1 manager

        >&2 echo "Remove user from Manager"
        test_ok rep_remove_permission session1 manager user1

    fi
}

# rep_subject_credentials <password> <credentials file>
# rep_decrypt_file <encrypted file> <encryption metadata>
# rep_create_org <organization> <username> <name> <email> <public key file>
# rep_list_orgs
# rep_create_session <organization> <username> <password> <credentials file> <session file>
# rep_get_file <file handle> [file]
# rep_assume_role <session file> <role>
# rep_drop_role <session file> <role>
# rep_list_roles <session file> <role>
# rep_list_subjects <session file> [username]
# rep_list_role_subjects <session file> <role>
# rep_list_subject_roles <session file> <username>
# rep_list_role_permissions <session file> <role>
# rep_list_permission_roles <session file> <permission>
# rep_list_docs <session file> [-s username] [-d nt/ot/et date]
# rep_add_subject <session file> <username> <name> <email> <credentials file>
# rep_suspend_subject <session file> <username>
# rep_activate_subject <session file> <username>
# rep_add_role <session file> <role>
# rep_suspend_role <session file> <role>
# rep_reactivate_role <session file> <role>
# rep_add_permission <session file> <role> <username>
# rep_remove_permission <session file> <role> <username>
# rep_add_permission <session file> <role> <permission>
# rep_remove_permission <session file> <role> <permission>
# rep_add_doc <session file> <document name> <file>
# rep_get_doc_metadata <session file> <document name>
# rep_get_doc_file <session file> <document name> [file]
# rep_delete_doc <session file> <document name>
# rep_acl_doc <session file> <document name> [+/-] <role> <permission>

# echo "Test the existence of all required commands ============================"
# test_exists_all
# echo "Test the validation of parameters of all required commands ============="
# test_badargs_all
>&2 echo "Test if all commands work ============="
test_all
