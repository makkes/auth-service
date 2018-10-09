#!groovy

properties([
        disableConcurrentBuilds()
])

node {
try {
    stage('checkout code') {
        checkout scm
    }

    stage('build') {
        sh '''#!/bin/bash
            cd auth
            docker build -t auth.services.makk.es:latest --build-arg VERSION="$(git log -n1 --format='%h %cd')" .
            '''
    }

    stage('deploy') {
        sh 'docker stop auth-service || true'
        sh 'docker rm auth-service || true'
        withCredentials([[$class: 'AmazonWebServicesCredentialsBinding', credentialsId: 'AUTH_AWS_KEYS']]) {
            sh "docker run --name auth-service  -d --restart=always --expose 4242 --network reverse-proxy -e AWS_ACCESS_KEY_ID=${env.AWS_ACCESS_KEY_ID} -e AWS_SECRET_ACCESS_KEY=${env.AWS_SECRET_ACCESS_KEY} -e LISTEN_HOST=0.0.0.0 -e LISTEN_PORT=4242 -e SERVE_PROTOCOL=https -e SERVE_HOST=auth.services.makk.es -e SERVE_PORT=443 auth.services.makk.es:latest"
        }
    }
    } catch (ex) {
        currentBuild.result = 'FAILURE'
        mail body: "Auth Service build failed: ${env.BUILD_URL}",
        to: "mail@makk.es",
        subject: "Auth Service build failed"
        throw ex
    }

}

