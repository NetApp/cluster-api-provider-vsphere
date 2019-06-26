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
    ORG        = 'stackpoint-public'
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

    stage('manifests'){
      steps {
        container('golang') {
          dir('/home/jenkins/go/src/github.com/NetApp/cluster-api-provider-vsphere') {
            sh('go run vendor/sigs.k8s.io/controller-tools/cmd/controller-gen/main.go all')
          }
        }
      }
    }

    stage('build') {
      steps {
        container('builder-base') {
          script {
            image = docker.build("$ORG/$APP_NAME")
          }
        }
      }
    }

    stage('publish: dev') {
      when {
        branch 'PR-*'
      }
      environment {
        GIT_COMMIT_SHORT = sh(
                script: "printf \$(git rev-parse --short ${GIT_COMMIT})",
                returnStdout: true
        ).trim()
      }
      steps {
        container('builder-base') {
          script {
            docker.withRegistry("https://$DOCKER_REGISTRY", "gcr:$ORG") {
              image.push("netapp-dev-$GIT_COMMIT_SHORT")
            }
          }
        }
      }
    }

    stage('publish: netapp') {
      when {
        branch 'netapp'
      }
      environment {
        GIT_COMMIT_SHORT = sh(
                script: "printf \$(git rev-parse --short ${GIT_COMMIT})",
                returnStdout: true
        ).trim()
      }
      steps {
        container('builder-base') {
          script {
            docker.withRegistry("https://$DOCKER_REGISTRY", "gcr:$ORG") {
              image.push("netapp-$GIT_COMMIT_SHORT")
            }
          }
        }
      }
    }

  }
}
