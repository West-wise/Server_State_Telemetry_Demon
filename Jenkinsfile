pipeline {
    agent any
    options {
        disableConcurrentBuilds()
        timestamps()
    }
    parameters {
        string(name: 'GIT_SHA', defaultValue: '', description: 'GitHub Actions build commit SHA')
        string(name: 'DEPLOY_USER', defaultValue: 'ubuntu', description: 'SSH deployment account')
    }
    environment {
        GITHUB_REPOSITORY = 'West-wise/Server_State_Telemetry_Demon'
        SSH_CREDENTIALS_ID = 'sstd-deploy-ssh'
    }
    stages {
        stage('Validate') {
            steps {
                sh 'test -n "$GIT_SHA"'
            }
        }
        stage('Download artifact') {
            steps {
                withCredentials([string(credentialsId: 'github-actions-artifact-token', variable: 'GITHUB_TOKEN')]) {
                    sh '''#!/bin/bash
                    set -euo pipefail
                    artifact_name="sstd-aarch64-${GIT_SHA}"
                    artifact_url=$(curl --fail --silent --show-error \
                      -H "Authorization: Bearer ${GITHUB_TOKEN}" \
                      -H "Accept: application/vnd.github+json" \
                      "https://api.github.com/repos/${GITHUB_REPOSITORY}/actions/artifacts?name=${artifact_name}" | \
                      python3 -c 'import json, sys; artifacts = json.load(sys.stdin)["artifacts"]; print(artifacts[0]["archive_download_url"] if artifacts else "")')
                    test -n "$artifact_url"
                    rm -rf artifact && mkdir artifact
                    curl --fail --location --silent --show-error \
                      -H "Authorization: Bearer ${GITHUB_TOKEN}" \
                      -H "Accept: application/vnd.github+json" \
                      "$artifact_url" -o artifact.zip
                    unzip -q artifact.zip -d artifact
                    test -f artifact/SST_Demon
                    chmod 0755 artifact/SST_Demon
                    '''
                }
            }
        }
        stage('Deploy') {
            steps {
                sshagent(credentials: [env.SSH_CREDENTIALS_ID]) {
                    sh '''#!/bin/bash
                    set -euo pipefail
                    for host in 10.0.0.231 158.180.84.177 134.185.113.76; do
                      target="${DEPLOY_USER}@${host}"
                      remote_dir=$(ssh "$target" 'mktemp -d /tmp/sstd-deploy.XXXXXX')
                      scp artifact/SST_Demon deploy/sstd.service deploy/deploy.sh "$target:$remote_dir/"
                      ssh "$target" "sudo bash '$remote_dir/deploy.sh' '$remote_dir/SST_Demon' '$remote_dir/sstd.service'"
                      ssh "$target" "rm -rf '$remote_dir'"
                    done
                    '''
                }
            }
        }
    }
}
