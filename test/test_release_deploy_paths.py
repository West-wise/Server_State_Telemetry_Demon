"""Run on Linux: python3 test/test_release_deploy_paths.py [release-package-directory]."""
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
PACKAGE_DIR = Path(sys.argv.pop(1)).resolve() if len(sys.argv) > 1 else None

# All SSH/SCP calls stay in this shell: no network, credentials, or remote commands.
MOCKS = r'''
ssh() {
  printf 'ssh %s\n' "$*" >> "$MOCK_CALLS"
  if [[ "$2" == mktemp* ]]; then
    printf '/tmp/sstd-deploy.mock\n'
  fi
}
scp() {
  local source
  for source in "${@:1:$#-1}"; do
    if [[ ! -f "$source" ]]; then
      printf 'scp: stat local "%s": No such file or directory\n' "$source" >&2
      return 255
    fi
  done
  printf 'scp %s\n' "$*" >> "$MOCK_CALLS"
}
'''


class ReleaseDeployPathsTest(unittest.TestCase):
    def test_deploy_from_clean_workspace(self):
        stages = re.findall(
            r"stage\('(Deploy [^']+)'\).*?sh '''(.*?)'''",
            (ROOT / 'Jenkinsfile').read_text(encoding='utf-8'), re.DOTALL,
        )
        self.assertEqual(len(stages), 3)
        for name, script in stages:
            with self.subTest(stage=name), tempfile.TemporaryDirectory(prefix='sstd-deploy-test-') as temp:
                workspace = Path(temp)
                for arch, folder in [('aarch64', 'arm64'), ('amd64', 'amd64')]:
                    artifact = workspace / 'artifact' / folder
                    artifact.mkdir(parents=True)
                    if PACKAGE_DIR:
                        packages = list(PACKAGE_DIR.glob(f'sstd-{arch}-*.tar.gz'))
                        self.assertEqual(len(packages), 1)
                        with tarfile.open(packages[0]) as package:
                            members = {m.name.removeprefix('./'): m for m in package.getmembers()}
                            for filename in ['sstd', 'sstd.service', 'deploy.sh']:
                                with package.extractfile(members[filename]) as source:
                                    (artifact / filename).write_bytes(source.read())
                    else:
                        # Same three-file layout as the Release packaging step.
                        (artifact / 'sstd').write_bytes(b'test binary, never executed')
                        for filename in ['sstd.service', 'deploy.sh']:
                            shutil.copyfile(ROOT / 'deploy' / filename, artifact / filename)
                self.assertFalse((workspace / 'deploy').exists())
                calls = workspace / 'calls.log'
                result = subprocess.run(
                    ['bash', '--noprofile', '--norc', '-eu', '-c', MOCKS + script],
                    cwd=workspace, env=dict(os.environ, DEPLOY_USER='test-user', MOCK_CALLS=str(calls)),
                    capture_output=True, text=True, timeout=10,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                recorded = calls.read_text()
                self.assertEqual(recorded.count('scp '), 1)
                self.assertEqual(recorded.count('sudo bash '), 1)
                self.assertEqual(recorded.count('sudo systemctl is-active --quiet sstd.service'), 1)


if __name__ == '__main__':
    unittest.main()
