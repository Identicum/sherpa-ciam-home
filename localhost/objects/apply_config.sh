#!/bin/bash

terraform_init () {
    echo " "
    echo "Procesando terraform_init() en $1"
    cd $1
    terraform init
    cd ..
}

terraform_apply () {
    echo "Procesando terraform_apply($1)"
    cd $1

    echo "Elimina state si se regenero el ambiente sin hacer un destroy"
    rm -f ./terraform.tfstate.d/terraform.tfstate

    echo "Apply terraform config"
    terraform apply --auto-approve
    PROCESS_RESULT=$?
    if [ $PROCESS_RESULT != "0" ];
    then
        echo "Error en terraform apply($1, $2)"
        exit
    fi
    cd ..
}

cd ./objects

terraform_init master
terraform_apply master

terraform_init customers
terraform_apply customers

terraform_init employees
terraform_apply employees
