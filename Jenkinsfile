pipeline {
  agent {
    kubernetes {
      label 'cluster-api-provider-vsphere'
      defaultContainer 'jnlp'
      yaml """
apiVersion: v1
kind: Pod
metadata:
  labels:
    app: cluster-api-provider-vsphere
spec:
  containers:
  - name: builder-base
    image: jenkinsxio/builder-base:0.1.215
    tty: true
    securityContext:
      privileged: true
    command:
    - cat
    volumeMounts:
    - name: socket
      mountPath: /var/run/docker.sock
  - name: golang
    image: golang:1.12
    tty: true
    command:
    - cat
  - name: golangci
    image: golangci/golangci-lint:v1.16
    tty: true
    command:
    - cat
  volumes:
    - name: socket
      hostPath:
        path: /var/run/docker.sock
"""
    }
  }

  environment {
    ORG        = 'stackpointio-public'
    APP_NAME   = 'cluster-api-provider-vsphere'
    REPOSITORY = "$DOCKER_REGISTRY/$ORG/$APP_NAME"
    GO111MODULE = 'off'
    GOPATH = '/home/jenkins/go'
  }

  stages {

    stage('generate'){
      steps {
        container('golang') {
          dir('/home/jenkins/go/src/github.com/NetApp/cluster-api-provider-vsphere') {
            checkout scm
            sh('go generate ./pkg/... ./cmd/...')
          }
        }
      }
    }


  }
}
