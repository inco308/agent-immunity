"""使用合成制品和 GitHub 元数据离线验证开发者预览包。"""

import hashlib
import io
import json
from pathlib import Path
import stat
import unittest
from unittest.mock import call, patch
import warnings
import zipfile

from scripts import fetch_verified_dist as download
from scripts import preview_archive
from scripts.preview_archive import verify_archive
from tests.support import temporary_directory


VERSION = "0.3.0a1"
WHEEL = f"agent_immunity-{VERSION}-py3-none-any.whl"
SOURCE = f"agent_immunity-{VERSION}.tar.gz"
PACKAGES = {WHEEL: b"synthetic wheel bytes\n", SOURCE: b"synthetic source bytes\n"}
SHA = "8da20f996839700a30a8d9a77613991ed865f5ca"
RUN_ID = 1357911
REPO_ID = 246810


def digest(data):
    return hashlib.sha256(data).hexdigest()


def sums(packages):
    return "".join(f"{digest(data)}  {name}\n" for name, data in packages.items()).encode("utf-8")


def entries():
    return [*PACKAGES.items(), ("SHA256SUMS", sums(PACKAGES))]


def archive_bytes(members):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        # 部分负例刻意构造重复中央目录项。
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", message="Duplicate name:", category=UserWarning)
            for name, data in members:
                archive.writestr(name, data)
    return output.getvalue()


def workflow_run(repo_id=REPO_ID):
    repository = {"id": repo_id, "full_name": "inco308/agent-immunity"}
    return {
        "id": RUN_ID, "run_attempt": 1, "repository": repository, "head_repository": repository.copy(),
        "event": "push", "head_branch": "main", "path": ".github/workflows/ci.yml",
        "status": "completed", "conclusion": "success", "head_sha": SHA,
    }


def release_artifact(repo_id=REPO_ID):
    return {
        "id": 97531, "name": "agent-immunity-dist", "expired": False,
        "digest": "sha256:" + "9a" * 32, "size_in_bytes": 900,
        "workflow_run": {"id": RUN_ID, "repository_id": repo_id, "head_repository_id": repo_id,
                         "head_branch": "main", "head_sha": SHA},
    }


class RunOriginTests(unittest.TestCase):
    def test_exact_successful_main_push_is_accepted(self):
        download.verify_run(workflow_run(), SHA, RUN_ID, REPO_ID)

    def test_wrong_repository_workflow_source_commit_or_result_is_rejected(self):
        changes = (
            ("id", RUN_ID + 1), ("run_attempt", 2), ("run_attempt", None), ("run_attempt", True),
            ("repository", {"id": REPO_ID + 1, "full_name": "inco308/agent-immunity"}),
            ("repository", {"id": REPO_ID, "full_name": "elsewhere/agent-immunity"}),
            ("head_repository", {"id": REPO_ID + 1, "full_name": "fork/agent-immunity"}),
            ("head_repository", None),
            ("event", "pull_request"), ("event", "pull_request_target"),
            ("head_branch", "feature/preview"), ("path", ".github/workflows/other.yml"),
            ("head_sha", "7" * 40), ("status", "in_progress"), ("conclusion", "failure"),
        )
        for field, value in changes:
            run = workflow_run()
            run[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                download.verify_run(run, SHA, RUN_ID, REPO_ID)


class ArtifactMetadataTests(unittest.TestCase):
    def select(self, artifacts):
        payload = {"total_count": len(artifacts), "artifacts": artifacts}
        return download.select_artifact(payload, RUN_ID, SHA, REPO_ID)

    def test_unique_named_artifact_survives_unrelated_entries(self):
        artifact = release_artifact()
        unrelated = {**artifact, "id": artifact["id"] + 1, "name": "test-log"}
        selected = self.select([unrelated, artifact])
        self.assertEqual(selected, artifact)

    def test_exact_maximum_download_size_is_accepted(self):
        artifact = {**release_artifact(), "size_in_bytes": 32 * 1024 * 1024}
        self.assertEqual(self.select([artifact]), artifact)

    def test_same_named_file_must_have_the_exact_run_repository_branch_and_commit(self):
        changes = (
            ("id", RUN_ID + 1), ("repository_id", REPO_ID + 1),
            ("head_repository_id", REPO_ID + 1), ("head_branch", "test-run"),
            ("head_sha", "e" * 40),
        )
        for field, value in changes:
            artifact = release_artifact()
            artifact["workflow_run"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.select([artifact])
        artifact = release_artifact()
        del artifact["workflow_run"]
        with self.assertRaises(ValueError):
            self.select([artifact])

    def test_missing_or_ambiguous_named_artifact_is_rejected(self):
        artifact = release_artifact()
        for label, items in (
            ("empty", []),
            ("wrong_name", [{**artifact, "name": "another-product-dist"}]),
            ("duplicate", [artifact, {**artifact, "id": artifact["id"] + 1}]),
        ):
            with self.subTest(label=label), self.assertRaises(ValueError):
                self.select(items)
        incomplete = {"total_count": 2, "artifacts": [artifact]}
        with self.assertRaises(ValueError):
            download.select_artifact(incomplete, RUN_ID, SHA, REPO_ID)

    def test_expired_unbounded_or_unverifiable_download_is_rejected(self):
        changes = (
            ("expired", True), ("expired", None), ("digest", None), ("digest", "sha256:" + "a" * 63),
            ("digest", "sha256:" + "x" * 64), ("digest", "sha1:" + "f" * 40),
            ("size_in_bytes", 0), ("size_in_bytes", -1), ("size_in_bytes", True),
            ("size_in_bytes", 32 * 1024 * 1024 + 1),
        )
        for field, value in changes:
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                self.select([{**release_artifact(), field: value}])


class OfflineDownloadTests(unittest.TestCase):
    def setUp(self):
        temp = temporary_directory()
        self.addCleanup(temp.cleanup)
        self.output = Path(temp.name) / "release"
        self.raw = archive_bytes(entries())
        self.item = release_artifact(download.REPOSITORY_ID)
        self.item.update(size_in_bytes=len(self.raw), digest="sha256:" + digest(self.raw))

    def fetch(self):
        # 模拟远端三份响应。ZIP 哈希、成员内容与最终查验记录都走正式下载程序。
        responses = [json.dumps(workflow_run(download.REPOSITORY_ID)).encode(),
                     json.dumps({"total_count": 1, "artifacts": [self.item]}).encode(), self.raw]
        with patch.object(download, "_api_bytes", side_effect=responses) as self.read_api:
            return download.fetch_verified(RUN_ID, SHA, self.output)

    def test_receipt_links_the_selected_commit_outer_zip_and_inner_packages(self):
        reported = self.fetch()
        base = "repos/inco308/agent-immunity/actions"
        self.assertEqual(self.read_api.call_args_list, [
            call(f"{base}/runs/{RUN_ID}", 1024 * 1024),
            call(f"{base}/runs/{RUN_ID}/artifacts?name=agent-immunity-dist&per_page=100", 1024 * 1024),
            call(f"{base}/artifacts/{self.item['id']}/zip", self.item["size_in_bytes"]),
        ])
        dest = self.output / "verified"
        self.assertEqual({p.name for p in dest.iterdir()}, {*PACKAGES, "SHA256SUMS", "receipt.json"})
        self.assertEqual((dest / "SHA256SUMS").read_bytes(), sums(PACKAGES))
        for name, data in PACKAGES.items():
            self.assertEqual((dest / name).read_bytes(), data)
        receipt = json.loads((dest / "receipt.json").read_text(encoding="utf-8"))
        self.assertEqual(receipt, reported)
        self.assertEqual((receipt["run_id"], receipt["commit"], receipt["artifact_id"]),
                         (RUN_ID, SHA, self.item["id"]))
        self.assertEqual(receipt["archive_digest"], "sha256:" + digest(self.raw))
        self.assertEqual(receipt["files"], {name: digest((dest / name).read_bytes()) for name in PACKAGES})

    def test_valid_inner_manifest_cannot_override_wrong_outer_hash_or_length(self):
        original = self.item
        for mismatched in ({"digest": "sha256:" + "0" * 64}, {"size_in_bytes": len(self.raw) + 1}):
            with self.subTest(field=next(iter(mismatched))):
                self.item = {**original, **mismatched}
                with self.assertRaises(ValueError):
                    self.fetch()
                self.assertFalse(self.output.exists())

    def test_confirmed_outer_zip_with_bad_inner_manifest_leaves_no_output(self):
        wrong = sums({**PACKAGES, WHEEL: b"other synthetic wheel"})
        self.raw = archive_bytes([*PACKAGES.items(), ("SHA256SUMS", wrong)])
        self.item.update(size_in_bytes=len(self.raw), digest="sha256:" + digest(self.raw))
        with self.assertRaises(ValueError):
            self.fetch()
        self.assertEqual(self.read_api.call_count, 3)
        self.assertFalse(self.output.exists())

    def test_second_download_preserves_existing_output(self):
        self.output.mkdir()
        sentinel = self.output / "prior-receipt.json"
        sentinel.write_bytes(b"release evidence from previous run\n")
        with self.assertRaises(FileExistsError):
            self.fetch()
        self.read_api.assert_not_called()
        self.assertEqual(list(self.output.iterdir()), [sentinel])
        self.assertEqual(sentinel.read_bytes(), b"release evidence from previous run\n")


class PreviewArchiveTests(unittest.TestCase):
    def setUp(self):
        temp = temporary_directory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.archive = self.root / "download.zip"
        self.staging = self.root / "staging"
        self.staging.mkdir()

    def verify(self, members):
        self.archive.write_bytes(archive_bytes(members))
        # 每项负例独立开始，避免前一例的临时文件导致预期外的“通过”。
        case = len(list(self.staging.iterdir()))
        target = self.staging / str(case)
        target.mkdir()
        return verify_archive(self.archive, target), target

    def test_two_packages_have_matching_bytes_hashes_and_version(self):
        report, dest = self.verify(entries())
        self.assertEqual(report["version"], VERSION)
        self.assertEqual(report["files"], {name: digest(data) for name, data in PACKAGES.items()})
        self.assertEqual({p.name for p in dest.iterdir()}, {WHEEL, SOURCE, "SHA256SUMS"})
        self.assertEqual((dest / "SHA256SUMS").read_bytes(), sums(PACKAGES))
        for name, data in PACKAGES.items():
            self.assertEqual((dest / name).read_bytes(), data)

    def test_traversal_directory_and_unexpected_members_are_rejected(self):
        absolute = self.root / "absolute-output.txt"
        for name in (f"../{WHEEL}", "..\\" + WHEEL, str(absolute), "folder/", f"folder/{WHEEL}", "extra.py"):
            # 维持三个成员和内外一致的清单，从而独立检验外层路径约束。
            renamed = {name: PACKAGES[WHEEL], SOURCE: PACKAGES[SOURCE]}
            with self.subTest(member=name), self.assertRaises(ValueError):
                self.verify([*renamed.items(), ("SHA256SUMS", sums(renamed))])
        with self.assertRaises(ValueError):
            self.verify([*entries(), ("extra.py", b"unexpected fourth member")])
        self.assertFalse((self.staging / WHEEL).exists())
        self.assertFalse(absolute.exists())

    def test_incomplete_zip_is_a_validation_error(self):
        self.archive.write_bytes(archive_bytes(entries())[:-22])
        with self.assertRaises(ValueError):
            verify_archive(self.archive, self.staging)

    def test_unsupported_compression_is_rejected_despite_valid_package_hashes(self):
        unsupported = zipfile.ZipInfo(WHEEL)
        unsupported.compress_type = zipfile.ZIP_BZIP2
        with self.assertRaises(ValueError):
            self.verify([(unsupported, PACKAGES[WHEEL]), (SOURCE, PACKAGES[SOURCE]), ("SHA256SUMS", sums(PACKAGES))])

    def test_uncompressed_member_and_total_limits_have_independent_boundaries(self):
        # 用小额度核验恰好达标、单件超一字节和总量超一字节，避免生成大归档。
        packages = {WHEEL: b"wheel" * 200, SOURCE: b"source" * 220}
        members = [*packages.items(), ("SHA256SUMS", sums(packages))]
        biggest = max(len(data) for _, data in members)
        combined = sum(len(data) for _, data in members)
        with patch.object(preview_archive, "MEMBER_LIMIT", biggest), patch.object(preview_archive, "TOTAL_LIMIT", combined):
            report, _ = self.verify(members)
            self.assertEqual(report["files"], {name: digest(data) for name, data in packages.items()})
        for name, limit in (("MEMBER_LIMIT", biggest - 1), ("TOTAL_LIMIT", combined - 1)):
            with self.subTest(limit=name), patch.object(preview_archive, name, limit), self.assertRaises(ValueError):
                self.verify(members)

    def test_duplicate_exact_and_case_insensitive_members_are_rejected(self):
        for name in (WHEEL, WHEEL.upper()):
            with self.subTest(member=name), self.assertRaises(ValueError):
                self.verify([(WHEEL, PACKAGES[WHEEL]), (name, PACKAGES[WHEEL]), ("SHA256SUMS", sums(PACKAGES))])

    def test_symlink_disguised_as_a_valid_package_name_is_rejected(self):
        link = zipfile.ZipInfo(WHEEL)
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        payload = {WHEEL: b"../outside.txt", SOURCE: PACKAGES[SOURCE]}
        with self.assertRaises(ValueError):
            self.verify([(link, payload[WHEEL]), (SOURCE, payload[SOURCE]), ("SHA256SUMS", sums(payload))])

    def test_digest_verification_and_package_completeness_are_independent(self):
        other_source = SOURCE.replace(VERSION, "0.4.0a1")
        mixed_versions = {WHEEL: PACKAGES[WHEEL], other_source: PACKAGES[SOURCE]}
        samples = {
            "tampered_wheel": [(WHEEL, PACKAGES[WHEEL] + b"x"), (SOURCE, PACKAGES[SOURCE]), ("SHA256SUMS", sums(PACKAGES))],
            "tampered_source": [(WHEEL, PACKAGES[WHEEL]), (SOURCE, b"changed source"), ("SHA256SUMS", sums(PACKAGES))],
            "wheel_only": [(WHEEL, PACKAGES[WHEEL]), ("SHA256SUMS", sums({WHEEL: PACKAGES[WHEEL]}))],
            "source_only": [(SOURCE, PACKAGES[SOURCE]), ("SHA256SUMS", sums({SOURCE: PACKAGES[SOURCE]}))],
            "no_manifest": list(PACKAGES.items()),
            "missing_hash": [*PACKAGES.items(), ("SHA256SUMS", sums({WHEEL: PACKAGES[WHEEL]}))],
            "repeated_hash": [*PACKAGES.items(), ("SHA256SUMS", sums({WHEEL: PACKAGES[WHEEL]}) * 2)],
            "different_versions": [*mixed_versions.items(), ("SHA256SUMS", sums(mixed_versions))],
        }
        for label, members in samples.items():
            with self.subTest(label=label), self.assertRaises(ValueError):
                self.verify(members)


if __name__ == "__main__":
    unittest.main()
