pipeline {
    agent any
    options {
        // 동시에 여러 배포가 실행되어 서버 상태가 꼬이는 것을 방지합니다.
        disableConcurrentBuilds()
        // 배포 대상 파일은 GitHub Release에서 받으므로 Jenkins workspace checkout을 사용하지 않습니다.
        skipDefaultCheckout(true)
        timestamps()
    }
    parameters {
        // GitHub Actions가 생성한 정식 Release 정보를 전달받습니다.
        string(name: 'RELEASE_TAG', defaultValue: '', description: 'GitHub Release tag')
        string(name: 'RELEASE_COMMIT', defaultValue: '', description: 'GitHub Release source commit SHA')
        string(name: 'DEPLOY_USER', defaultValue: 'ubuntu', description: 'SSH deployment account')
    }
    environment {
        GITHUB_REPOSITORY = 'West-wise/Server_State_Telemetry_Demon'
        SSH_CREDENTIALS_ID = 'sstd-deploy-ssh'
    }
    stages {
        // 필수 입력값이 전달되었는지 확인합니다.
        stage('Validate') {
            steps {
                sh 'test -n "$RELEASE_TAG" && test -n "$RELEASE_COMMIT"'
            }
        }
        // GitHub Release에서 플랫폼별 정식 패키지를 다운로드합니다.
        // Jenkins에서는 소스를 checkout하거나 다시 빌드하지 않습니다.
        stage('Download release') {
            steps {
                withCredentials([string(credentialsId: 'github-actions-artifact-token', variable: 'GITHUB_TOKEN')]) {
                    sh '''#!/bin/bash
                    set -euo pipefail
                    rm -rf release artifact
                    mkdir -p release artifact/arm64 artifact/amd64

                    # Release asset 이름이 정확히 일치하는 파일만 다운로드합니다.
                    download_asset() {
                      local asset_name="$1"
                      local destination="release/$asset_name"
                      local metadata_file
                      local asset_url

                      metadata_file=$(mktemp)
                      trap 'rm -f "$metadata_file"' RETURN

                      # 지정한 tag의 Release metadata를 조회합니다.
                      curl --fail --silent --show-error \
                        -H "Authorization: Bearer ${GITHUB_TOKEN}" \
                        -H "Accept: application/vnd.github+json" \
                        "https://api.github.com/repos/${GITHUB_REPOSITORY}/releases/tags/${RELEASE_TAG}" \
                        > "$metadata_file"

                      asset_url=$(python3 - "$metadata_file" "$asset_name" <<'PY'
import json
import sys

metadata_path, expected_name = sys.argv[1:]
with open(metadata_path, encoding="utf-8") as stream:
    payload = json.load(stream)

matches = [asset for asset in payload.get("assets", []) if asset.get("name") == expected_name]

if len(matches) != 1:
    raise SystemExit(f"expected exactly one release asset {expected_name!r}, found {len(matches)}")

print(matches[0]["browser_download_url"])
PY
                      )
                      test -n "$asset_url"
                      curl --fail --location --silent --show-error \
                        -H "Authorization: Bearer ${GITHUB_TOKEN}" \
                        -H "Accept: application/octet-stream" \
                        "$asset_url" -o "$destination"
                    }

                    download_asset "sstd-aarch64-${RELEASE_TAG}.tar.gz"
                    download_asset "sstd-amd64-${RELEASE_TAG}.tar.gz"
                    download_asset SHA256SUMS
                    download_asset release-manifest.json

                    # Release가 webhook에서 전달받은 commit으로 생성되었는지 확인합니다.
                    python3 - <<'PY'
import json
import os

with open("release/release-manifest.json", encoding="utf-8") as stream:
    manifest = json.load(stream)

if manifest.get("commit") != os.environ["RELEASE_COMMIT"]:
    raise SystemExit("release commit does not match RELEASE_COMMIT")
PY

                    # 패키지 무결성을 확인한 후 플랫폼별 디렉터리에 압축 해제합니다.
                    (cd release && sha256sum -c SHA256SUMS)
                    tar -xzf "release/sstd-aarch64-${RELEASE_TAG}.tar.gz" -C artifact/arm64
                    tar -xzf "release/sstd-amd64-${RELEASE_TAG}.tar.gz" -C artifact/amd64
                    test -x artifact/arm64/sstd
                    test -x artifact/amd64/sstd
                    '''
                }
            }
        }
        // ARM64 첫 번째 서버에 먼저 배포하여 canary로 동작을 확인합니다.
        stage('Deploy ARM64 Canary') {
            steps {
                sshagent(credentials: [env.SSH_CREDENTIALS_ID]) {
                    sh '''#!/bin/bash
                    set -euo pipefail
                    target="${DEPLOY_USER}@10.0.0.231" # 134.185.115.16, same Jenkins host via private IP
                    # 원격 임시 디렉터리에 실행 파일과 배포 스크립트를 전송합니다.
                    remote_dir=$(ssh "$target" 'mktemp -d /tmp/sstd-deploy.XXXXXX')
                    trap 'ssh "$target" "rm -rf '\''$remote_dir'\''"' EXIT
                    scp artifact/arm64/sstd deploy/sstd.service deploy/deploy.sh "$target:$remote_dir/"
                    ssh "$target" "sudo bash '$remote_dir/deploy.sh' '$remote_dir/sstd' '$remote_dir/sstd.service'"
                    # systemd 서비스가 정상적으로 실행되었는지 확인합니다.
                    ssh "$target" "sudo systemctl is-active --quiet sstd.service"
                    '''
                }
            }
        }
        // Canary가 성공한 뒤 두 번째 ARM64 서버에 배포합니다.
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
        // AMD64 서버에 AMD64용 artifact를 배포합니다.
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
