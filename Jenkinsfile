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
        GITHUB_REPOSITORY = 'West-wise/Server_State_Telemetry'
        SSH_CREDENTIALS_ID = 'sstd-deploy-ssh'
    }
    stages {
        stage('Validate') {
            steps {
                sh 'test -n "$GIT_SHA"'
            }
        }
        stage('Download artifacts') {
            steps {
                withCredentials([string(credentialsId: 'github-actions-artifact-token', variable: 'GITHUB_TOKEN')]) {
                    sh '''#!/bin/bash
                    set -euo pipefail
                    rm -rf artifact
                    mkdir -p artifact/arm64 artifact/amd64

                    download_artifact() {
                      local artifact_name="$1"
                      local destination="$2"
                      local artifact_url

                      artifact_url=$(curl --fail --silent --show-error \
                        -H "Authorization: Bearer ${GITHUB_TOKEN}" \
                        -H "Accept: application/vnd.github+json" \
                        "https://api.github.com/repos/${GITHUB_REPOSITORY}/actions/artifacts?name=${artifact_name}" | \
                        python3 -c 'import json, sys; artifacts = json.load(sys.stdin)["artifacts"]; print(artifacts[0]["archive_download_url"] if artifacts else "")')
                      test -n "$artifact_url"
                      curl --fail --location --silent --show-error \
                        -H "Authorization: Bearer ${GITHUB_TOKEN}" \
                        -H "Accept: application/vnd.github+json" \
                        "$artifact_url" -o "${destination}.zip"
                      unzip -q "${destination}.zip" -d "$destination"
                      test -f "$destination/sstd"
                      chmod 0755 "$destination/sstd"
                    }

                    download_artifact "sstd-aarch64-${GIT_SHA}" artifact/arm64
                    download_artifact "sstd-amd64-${GIT_SHA}" artifact/amd64
                    '''
                }
            }
        }
        stage('Deploy ARM64 Canary') {
            steps {
                sshagent(credentials: [env.SSH_CREDENTIALS_ID]) {
                    sh '''#!/bin/bash
                    set -euo pipefail
                    target="${DEPLOY_USER}@10.0.0.231" # 134.185.115.16, same Jenkins host via private IP
                    remote_dir=$(ssh "$target" 'mktemp -d /tmp/sstd-deploy.XXXXXX')
                    trap 'ssh "$target" "rm -rf '\''$remote_dir'\''"' EXIT
                    scp artifact/arm64/sstd deploy/sstd.service deploy/deploy.sh "$target:$remote_dir/"
                    ssh "$target" "sudo bash '$remote_dir/deploy.sh' '$remote_dir/sstd' '$remote_dir/sstd.service'"
                    ssh "$target" "sudo systemctl is-active --quiet sstd.service"
                    '''
                }
            }
        }
        stage('Deploy ARM64 Second') {
            steps {
                sshagent(credentials: [env.SSH_CREDENTIALS_ID]) {
                    sh '''#!/bin/bash
                    set -euo pipefail
                    target="${DEPLOY_USER}@158.180.84.177"
                    remote_dir=$(ssh "$target" 'mktemp -d /tmp/sstd-deploy.XXXXXX')
                    trap 'ssh "$target" "rm -rf '\''$remote_dir'\''"' EXIT
                    scp artifact/arm64/sstd deploy/sstd.service deploy/deploy.sh "$target:$remote_dir/"
                    ssh "$target" "sudo bash '$remote_dir/deploy.sh' '$remote_dir/sstd' '$remote_dir/sstd.service'"
                    ssh "$target" "sudo systemctl is-active --quiet sstd.service"
                    '''
                }
            }
        }
        stage('Deploy AMD64') {
            steps {
                sshagent(credentials: [env.SSH_CREDENTIALS_ID]) {
                    sh '''#!/bin/bash
                    set -euo pipefail
                    target="${DEPLOY_USER}@134.185.113.76"
                    remote_dir=$(ssh "$target" 'mktemp -d /tmp/sstd-deploy.XXXXXX')
                    trap 'ssh "$target" "rm -rf '\''$remote_dir'\''"' EXIT
                    scp artifact/amd64/sstd deploy/sstd.service deploy/deploy.sh "$target:$remote_dir/"
                    ssh "$target" "sudo bash '$remote_dir/deploy.sh' '$remote_dir/sstd' '$remote_dir/sstd.service'"
                    ssh "$target" "sudo systemctl is-active --quiet sstd.service"
                    '''
                }
            }
        }
    }
}
