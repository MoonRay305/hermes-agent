"""Tests for dispatch_in_gateway and Linear bridge gating in kanban watchers.

- Non-dispatch gateways (dispatch_in_gateway=false) exit before opening any DB.
- HERMES_KANBAN_DISPATCH_IN_GATEWAY env var disables without loading config.
- Dispatch-owning gateways (dispatch_in_gateway=true) proceed past the gate.
- The embedded Linear bridge only runs from the dispatch-owning watcher and is
  best-effort: bridge failure must not break the normal dispatcher tick.
"""

import asyncio
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from gateway.config import Platform
from gateway.run import GatewayRunner


def _make_runner(with_adapter=False):
    runner = GatewayRunner.__new__(GatewayRunner)
    runner._running = True
    runner.adapters = {Platform.TELEGRAM: MagicMock()} if with_adapter else {}
    runner._kanban_sub_fail_counts = {}
    runner._kanban_dispatcher_lock_handle = None
    return runner


def _fake_config(dispatch_in_gateway):
    return {"kanban": {"dispatch_in_gateway": dispatch_in_gateway}}


def test_notifier_watcher_skips_when_dispatch_disabled():
    """dispatch_in_gateway=false returns before opening any board DB."""
    runner = _make_runner()
    with patch("hermes_cli.config.load_config", return_value=_fake_config(False)):
        with patch("hermes_cli.kanban_db.connect") as mock_connect:
            asyncio.run(runner._kanban_notifier_watcher())
    mock_connect.assert_not_called()


def test_notifier_watcher_env_override_disables(monkeypatch):
    """HERMES_KANBAN_DISPATCH_IN_GATEWAY=false skips config load entirely."""
    runner = _make_runner()
    monkeypatch.setenv("HERMES_KANBAN_DISPATCH_IN_GATEWAY", "false")
    with patch("hermes_cli.config.load_config") as mock_load_config:
        with patch("hermes_cli.kanban_db.connect") as mock_connect:
            asyncio.run(runner._kanban_notifier_watcher())
    mock_load_config.assert_not_called()
    mock_connect.assert_not_called()


def test_notifier_watcher_runs_when_dispatch_enabled():
    """dispatch_in_gateway=true proceeds past the gate to the board fan-out."""
    runner = _make_runner(with_adapter=True)
    past_gate = []
    sleep_calls = []

    async def fake_sleep(delay):
        sleep_calls.append(delay)
        # Stop after the initial delay + first per-interval sleep so the loop
        # body runs exactly once.
        if len(sleep_calls) >= 2:
            runner._running = False

    async def fake_to_thread(fn, *args, **kwargs):
        return fn(*args, **kwargs)

    import hermes_cli.kanban_db as _kb

    with patch("hermes_cli.config.load_config", return_value=_fake_config(True)):
        with patch.object(
            _kb,
            "list_boards",
            side_effect=lambda *a, **kw: past_gate.append(True) or [],
        ):
            with patch("asyncio.sleep", side_effect=fake_sleep):
                with patch("asyncio.to_thread", side_effect=fake_to_thread):
                    asyncio.run(runner._kanban_notifier_watcher())

    assert past_gate, "list_boards should be called when dispatch_in_gateway=true"


def _dispatcher_config(*, linear_enabled):
    return {
        "kanban": {
            "dispatch_in_gateway": True,
            "dispatch_interval_seconds": 1,
            "auto_decompose": False,
            "linear_bridge": {
                "enabled": linear_enabled,
                "dry_run": True,
                "poll_interval_seconds": 0,
            },
        }
    }


def _dispatch_result():
    return SimpleNamespace(
        spawned=[],
        reclaimed=0,
        crashed=[],
        timed_out=[],
        promoted=0,
        auto_blocked=[],
        skipped_unroutable=[],
    )


def test_dispatcher_watcher_does_not_poll_linear_when_bridge_disabled(monkeypatch):
    """The dispatcher loop must not contact Linear when kanban.linear_bridge.enabled=false."""
    runner = _make_runner()
    sleep_calls = []

    async def fake_sleep(delay):
        sleep_calls.append(delay)
        if len(sleep_calls) >= 2:
            runner._running = False

    async def fake_to_thread(fn, *args, **kwargs):
        return fn(*args, **kwargs)

    import hermes_cli.kanban_db as _kb

    with patch("hermes_cli.config.load_config", return_value=_dispatcher_config(linear_enabled=False)):
        with patch("gateway.kanban_watchers._acquire_singleton_lock", return_value=(None, "unavailable")):
            with patch.object(_kb, "list_boards", return_value=[]):
                with patch.object(_kb, "write_dispatcher_heartbeat"):
                    with patch.object(_kb, "reap_worker_zombies", return_value=[]):
                        with patch("gateway.linear_bridge.run_bridge_tick") as mock_linear_tick:
                            with patch("asyncio.sleep", side_effect=fake_sleep):
                                with patch("asyncio.to_thread", side_effect=fake_to_thread):
                                    asyncio.run(runner._kanban_dispatcher_watcher())

    mock_linear_tick.assert_not_called()


def test_dispatcher_watcher_live_disable_flip_stops_next_tick(monkeypatch):
    """A true -> false config flip stops bridge polling without a restart."""
    runner = _make_runner()
    sleep_calls = []
    config_reads = 0

    def changing_config():
        nonlocal config_reads
        config_reads += 1
        return _dispatcher_config(linear_enabled=(config_reads == 1))

    async def fake_sleep(delay):
        sleep_calls.append(delay)
        if len(sleep_calls) >= 2:
            runner._running = False

    async def fake_to_thread(fn, *args, **kwargs):
        return fn(*args, **kwargs)

    import hermes_cli.kanban_db as _kb

    with patch("hermes_cli.config.load_config", side_effect=changing_config):
        with patch(
            "gateway.kanban_watchers._acquire_singleton_lock",
            return_value=(None, "unavailable"),
        ):
            with patch.object(_kb, "list_boards", return_value=[]):
                with patch.object(_kb, "write_dispatcher_heartbeat"):
                    with patch.object(_kb, "reap_worker_zombies", return_value=[]):
                        with patch(
                            "gateway.linear_bridge.run_bridge_tick"
                        ) as mock_linear_tick:
                            with patch("asyncio.sleep", side_effect=fake_sleep):
                                with patch(
                                    "asyncio.to_thread", side_effect=fake_to_thread
                                ):
                                    asyncio.run(runner._kanban_dispatcher_watcher())

    assert config_reads >= 2
    mock_linear_tick.assert_not_called()


def test_dispatcher_tick_runs_linear_bridge_best_effort_before_dispatch(tmp_path):
    """A lock-owning dispatcher tick polls Linear before normal dispatch.

    That ordering lets newly bridged Kanban cards dispatch in the same tick;
    bridge failure is still caught so dispatch remains unaffected.
    """
    runner = _make_runner()
    calls = []
    sleep_calls = []

    async def fake_sleep(delay):
        sleep_calls.append(delay)
        if len(sleep_calls) >= 2:
            runner._running = False

    async def fake_to_thread(fn, *args, **kwargs):
        return fn(*args, **kwargs)

    class DummyConn:
        def close(self):
            pass

    def fake_dispatch_once(*args, **kwargs):
        calls.append("dispatch")
        return _dispatch_result()

    def fake_linear_tick(cfg):
        calls.append("linear")
        assert cfg["enabled"] is True
        raise RuntimeError("linear outage")

    import hermes_cli.kanban_db as _kb

    with patch("hermes_cli.config.load_config", return_value=_dispatcher_config(linear_enabled=True)):
        with patch("gateway.kanban_watchers._acquire_singleton_lock", return_value=(None, "unavailable")):
            with patch.object(_kb, "kanban_db_path", return_value=tmp_path / "kanban.db"):
                with patch.object(_kb, "list_boards", return_value=[{"slug": "default"}]):
                    with patch.object(_kb, "connect", return_value=DummyConn()):
                        with patch.object(_kb, "dispatch_once", side_effect=fake_dispatch_once):
                            with patch.object(_kb, "has_spawnable_ready", return_value=False):
                                with patch.object(_kb, "has_spawnable_review", return_value=False):
                                    with patch.object(_kb, "write_dispatcher_heartbeat"):
                                        with patch.object(_kb, "reap_worker_zombies", return_value=[]):
                                            with patch("gateway.linear_bridge.run_bridge_tick", side_effect=fake_linear_tick):
                                                with patch("asyncio.sleep", side_effect=fake_sleep):
                                                    with patch("asyncio.to_thread", side_effect=fake_to_thread):
                                                        asyncio.run(runner._kanban_dispatcher_watcher())

    assert calls == ["linear", "dispatch"]
