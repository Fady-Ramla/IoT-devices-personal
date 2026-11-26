import logging
import unittest
from types import SimpleNamespace

from ryu.lib import hub

from topology_monitor import TopologyMonitor


class FakeBarrierRequest:
    def __init__(self, datapath):
        self.datapath = datapath
        self.xid = None


class FakeParser:
    def OFPBarrierRequest(self, datapath):
        return FakeBarrierRequest(datapath)


class FakeDatapath:
    def __init__(self, monitor, behavior="success"):
        self.id = 1
        self.monitor = monitor
        self.behavior = behavior
        self.ofproto_parser = FakeParser()
        self.next_xid = 0
        self.sent_messages = []

    def set_xid(self, message):
        self.next_xid += 1
        message.xid = self.next_xid
        return self.next_xid

    def _send_error(self, xid):
        msg = SimpleNamespace(
            datapath=self,
            xid=xid,
            type=1,
            code=2,
            data=b"simulated OpenFlow error",
        )
        self.monitor.security_openflow_error_handler(
            SimpleNamespace(msg=msg)
        )

    def _send_barrier_reply(self, xid):
        msg = SimpleNamespace(datapath=self, xid=xid)
        self.monitor.security_barrier_reply_handler(
            SimpleNamespace(msg=msg)
        )

    def send_msg(self, message):
        self.sent_messages.append(message)

        if isinstance(message, FakeBarrierRequest):
            if self.behavior == "success":
                self._send_barrier_reply(message.xid)

            elif self.behavior == "flow_error":
                flow_message = self.sent_messages[0]
                self._send_error(flow_message.xid)
                self._send_barrier_reply(message.xid)

            elif self.behavior == "barrier_error":
                self._send_error(message.xid)

            elif self.behavior == "disconnect":
                self.monitor._fail_security_transactions_for_datapath(
                    self
                )

            elif self.behavior == "timeout":
                pass

            return True

        if self.behavior == "send_failed":
            return False

        return True


class SecurityOpenFlowTests(unittest.TestCase):
    def setUp(self):
        self.monitor = TopologyMonitor.__new__(TopologyMonitor)
        self.monitor.logger = logging.getLogger(
            "test.security.openflow"
        )
        self.monitor._security_pending_lock = hub.Semaphore(1)
        self.monitor._security_xid_transactions = {}
        self.monitor._security_openflow_timeout = 0.01

    def run_batch(self, behavior):
        datapath = FakeDatapath(self.monitor, behavior)
        result = self.monitor._send_security_flow_batch(
            datapath, [SimpleNamespace(xid=None)]
        )
        return result

    def assert_no_pending_transactions(self):
        self.assertEqual(
            self.monitor._security_xid_transactions, {}
        )

    def test_barrier_reply_confirms_batch(self):
        result = self.run_batch("success")

        self.assertTrue(result["success"])
        self.assertEqual(result["status"], "confirmed")
        self.assertTrue(result["barrier_received"])
        self.assertEqual(result["openflow_errors"], [])
        self.assert_no_pending_transactions()

    def test_flow_mod_error_fails_batch(self):
        result = self.run_batch("flow_error")

        self.assertFalse(result["success"])
        self.assertEqual(result["status"], "openflow_error")
        self.assertEqual(len(result["openflow_errors"]), 1)
        self.assertTrue(result["barrier_received"])
        self.assert_no_pending_transactions()

    def test_barrier_error_fails_without_waiting_for_timeout(self):
        result = self.run_batch("barrier_error")

        self.assertFalse(result["success"])
        self.assertEqual(result["status"], "openflow_error")
        self.assertTrue(result["barrier_error_received"])
        self.assertFalse(result["barrier_received"])
        self.assert_no_pending_transactions()

    def test_send_failure_is_reported(self):
        result = self.run_batch("send_failed")

        self.assertFalse(result["success"])
        self.assertEqual(result["status"], "send_failed")
        self.assert_no_pending_transactions()

    def test_disconnect_wakes_pending_operation(self):
        result = self.run_batch("disconnect")

        self.assertFalse(result["success"])
        self.assertEqual(result["status"], "disconnected")
        self.assert_no_pending_transactions()

    def test_missing_barrier_reply_times_out(self):
        result = self.run_batch("timeout")

        self.assertFalse(result["success"])
        self.assertEqual(result["status"], "timeout")
        self.assertFalse(result["barrier_received"])
        self.assert_no_pending_transactions()

    def test_empty_batch_is_rejected(self):
        datapath = FakeDatapath(self.monitor)
        result = self.monitor._send_security_flow_batch(
            datapath, []
        )

        self.assertFalse(result["success"])
        self.assertEqual(result["status"], "empty_batch")
        self.assertEqual(datapath.sent_messages, [])
        self.assert_no_pending_transactions()


if __name__ == "__main__":
    unittest.main()
