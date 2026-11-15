"""核对部署证据判据与容器清理归属。真实部署验收由 Linux Docker 执行。"""
import json
import unittest
from unittest.mock import patch

from deploy.container import verify_deployment as verify


class ContainerVerificationTests(unittest.TestCase):
    def test_inspect_rejects_partial_hardening_and_unexpected_mounts(self):
        mounts = [{"Type": "bind", "Destination": path, "RW": writable} for path, writable in (
            (verify.CONTAINER_INPUT, False), (verify.CONTAINER_OUTPUT, True))]
        defaults = [False, True, "none", ["ALL"], None, ["no-new-privileges"],
                    verify.MEMORY, verify.NANO_CPUS, verify.PIDS, mounts, "65532:65532", True]
        for position, value in (
            (0, True), (1, False), (2, "bridge"), (3, []), (4, ["NET_RAW"]), (5, []),
            (6, 0), (7, 0), (8, 0), (9, [*mounts, {"Type": "bind", "Destination": "/extra", "RW": False}]),
            (9, [dict(mounts[0], RW=True), mounts[1]]), (10, "0:0"), (11, False),
        ):
            with self.subTest(field=position, value=value):
                values = list(defaults)
                values[position] = value
                output = "\n".join(json.dumps(item) for item in values)
                with patch.object(verify, "docker", return_value=output), self.assertRaises(verify.VerificationError):
                    verify.inspect_settings("own-container", 65532, 65532)

    def test_cleanup_never_removes_a_different_container(self):
        original, unexpected = "1" * 64, "2" * 64
        for listing in [unexpected, original + "\n" + unexpected]:
            with self.subTest(listing=listing), patch.object(verify, "docker", return_value=listing) as command:
                with self.assertRaises(verify.VerificationError):
                    verify.cleanup_owned("this-run", original)
                self.assertEqual(command.call_count, 1)
                args = command.call_args.args[0]
                self.assertEqual(args[:2], ["container", "ls"])
                self.assertIn("label=" + verify.OWNER_LABEL + "=this-run", args)

    def test_cleanup_recovers_own_id_after_create_client_timeout(self):
        cid = "a" * 64
        with patch.object(verify, "docker", side_effect=[cid, cid, ""]) as command:
            verify.cleanup_owned("this-run", None)
            self.assertEqual(command.call_args_list[1].args[0], ["container", "rm", "-f", cid])
            self.assertEqual(command.call_args_list[2], command.call_args_list[0])


if __name__ == "__main__":
    unittest.main()
