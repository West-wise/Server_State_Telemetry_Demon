# SSTD 수동 릴리즈

## 검증과 발행

- `.github/workflows/ci.yml`은 `main` 대상 PR과 `main` push에서 빌드·테스트를 수행한다.
  CI artifact는 검증용이며 정식 Release가 아니다.
- `.github/workflows/release.yml`은 사람이 Actions에서 수동 실행한다.
  PR, 브랜치 push, 태그 push만으로 정식 Release를 생성하지 않는다.
- 실행 브랜치는 `main`이어야 한다. 다른 브랜치나 태그에서는 첫 단계가 실패하고
  패키징·발행·배포로 진행하지 않는다.

## 발행 절차

1. 원하는 변경을 PR로 검증한 뒤 사람이 `main`에 병합한다.
2. 발행할 버전을 `CMakeLists.txt`의 `project(SSTD VERSION ...)`에 반영한다.
   버전 변경도 PR로 검증·병합한다. 작은 수정마다 버전을 올릴 필요는 없다.
3. GitHub **Actions → Release SSTD → Run workflow**에서 `main`을 선택한다.
4. `deploy`는 기본값 OFF다. 이번 발행 직후 운영 배포까지 실행할 경우에만 선택한다.
5. 실행 결과와 Release의 패키지, `SHA256SUMS`, `release-manifest.json`을 확인한다.

버전 `2.0.1`은 태그 `v2.0.1`로 발행된다. 동일 태그 또는 Release가 이미 있으면 실패한다.
테스트와 amd64/aarch64 패키징에 성공해야 발행한다. 소스, Release 태그와 manifest는
수동 실행 시점의 커밋 SHA를 사용하므로, 실행 도중 `main`이 이동해도 같은 커밋을 가리킨다.
동시 Release 실행은 직렬화하며 진행 중인 실행을 새 실행으로 취소하지 않는다.

## 배포와 실패 복구

`deploy`를 선택하면 발행 성공 후 기존 Jenkins job에 `RELEASE_TAG`와 `RELEASE_COMMIT`을
전달한다. 선택하지 않으면 Jenkins를 호출하지 않으며 Jenkins 인증정보도 필요하지 않다.
나중에 배포하려면 사람이 Jenkins에서 발행된 태그와 manifest의 commit을 지정해 실행한다.

Release 생성 후 Jenkins 호출이 실패하더라도 생성된 Release는 남아 있다.
같은 버전을 다시 발행하지 말고 기존 Release와 Jenkins 실행 여부를 확인한 뒤 배포를 재개한다.
검증 실패를 우회하거나 기존 태그·Release를 삭제해 재발행하지 않는다.

기존 `deploy/deploy.sh`는 서비스 재시작 실패 시 이전 바이너리 복원을 시도한다.
이는 전체 설정·서비스 파일의 롤백을 보장하지 않으므로 운영자가 결과를 확인한다.
이 workflow 변경을 되돌릴 때는 `main` push 자동 발행과 Jenkins 자동 호출이 다시 활성화될 수
있다는 점을 검토한다.
