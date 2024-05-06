# Copyright 2018-2021 The Matrix.org Foundation C.I.C.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# ruff: noqa: ARG001 ARG002

import hashlib
import ipaddress
import logging
import os
import os.path
import sqlite3
from collections import deque
from collections.abc import Awaitable, Callable
from typing import (
    Any,
    TypeVar,
    cast,
)
from unittest.mock import Mock

import twisted
from incremental import Version
from synapse.config.database import DatabaseConnectionConfig
from synapse.config.homeserver import HomeServerConfig
from synapse.events.presence_router import load_legacy_presence_router
from synapse.handlers.auth import load_legacy_password_auth_providers
from synapse.module_api.callbacks.spamchecker_callbacks import load_legacy_spam_checkers
from synapse.module_api.callbacks.third_party_event_rules_callbacks import (
    load_legacy_third_party_event_rules,
)
from synapse.server import HomeServer
from synapse.storage import DataStore
from synapse.storage.database import LoggingDatabaseConnection
from synapse.storage.engines import create_engine
from synapse.storage.prepare_database import prepare_database
from synapse.types import ISynapseReactor
from synapse.util import Clock
from twisted.internet import address, tcp, threads, udp
from twisted.internet.defer import Deferred
from twisted.internet.interfaces import (
    IReactorPluggableNameResolver,
    IReactorTime,
)
from twisted.internet.testing import MemoryReactorClock
from twisted.python import threadpool
from twisted.python.failure import Failure
from typing_extensions import ParamSpec
from zope.interface import implementer

from tests.utils import (
    SQLITE_PERSIST_DB,
    default_config,
)

logger = logging.getLogger(__name__)

R = TypeVar("R")
P = ParamSpec("P")

# A pre-prepared SQLite DB that is used as a template when creating new SQLite
# DB each test run. This dramatically speeds up test set up when using SQLite.
PREPPED_SQLITE_DB_CONN: LoggingDatabaseConnection | None = None


# ISynapseReactor implies IReactorPluggableNameResolver, but explicitly
# marking this as an implementer of the latter seems to keep mypy-zope happier.
@implementer(IReactorPluggableNameResolver, ISynapseReactor)
class ThreadedMemoryReactorClock(MemoryReactorClock):
    """
    A MemoryReactorClock that supports callFromThread.
    """

    def __init__(self) -> None:
        self.threadpool = ThreadPool(self)

        self._tcp_callbacks: dict[tuple[str, int], Callable] = {}
        self._udp: list[udp.Port] = []
        self._thread_callbacks: deque[Callable[..., R]] = deque()

        # In order for the TLS protocol tests to work, modify _get_default_clock
        # on newer Twisted versions to use the test reactor's clock.
        #
        # This is *super* dirty since it is never undone and relies on the next
        # test to overwrite it.
        if twisted.version > Version("Twisted", 23, 8, 0):
            from twisted.protocols import tls

            tls._get_default_clock = lambda: self

        super().__init__()

    def callFromThread(
        self, callable_: Callable[..., Any], *args: object, **kwargs: object
    ) -> None:
        """
        Make the callback fire in the next reactor iteration.
        """

        def cb():
            return callable_(*args, **kwargs)

        # it's not safe to call callLater() here, so we append the callback to a
        # separate queue.
        self._thread_callbacks.append(cb)

    def getThreadPool(self) -> "threadpool.ThreadPool":
        # Cast to match super-class.
        return cast(threadpool.ThreadPool, self.threadpool)

    def advance(self, amount: float) -> None:
        # first advance our reactor's time, and run any "callLater" callbacks that
        # makes ready
        super().advance(amount)

        # now run any "callFromThread" callbacks
        while True:
            try:
                callback = self._thread_callbacks.popleft()
            except IndexError:
                break
            callback()

            # check for more "callLater" callbacks added by the thread callback
            # This isn't required in a regular reactor, but it ends up meaning that
            # our database queries can complete in a single call to `advance` [1] which
            # simplifies tests.
            #
            # [1]: we replace the threadpool backing the db connection pool with a
            # mock ThreadPool which doesn't really use threads; but we still use
            # reactor.callFromThread to feed results back from the db functions to the
            # main thread.
            super().advance(0)


def validate_connector(connector: tcp.Connector, expected_ip: str) -> None:
    """Try to validate the obtained connector as it would happen when
    synapse is running and the conection will be established.

    This method will raise a useful exception when necessary, else it will
    just do nothing.

    This is in order to help catch quirks related to reactor.connectTCP,
    since when called directly, the connector's destination will be of type
    IPv4Address, with the hostname as the literal host that was given (which
    could be an IPv6-only host or an IPv6 literal).

    But when called from reactor.connectTCP *through* e.g. an Endpoint, the
    connector's destination will contain the specific IP address with the
    correct network stack class.

    Note that testing code paths that use connectTCP directly should not be
    affected by this check, unless they specifically add a test with a
    matching reactor.lookups[HOSTNAME] = "IPv6Literal", where reactor is of
    type ThreadedMemoryReactorClock.
    For an example of implementing such tests, see test/handlers/send_email.py.
    """
    destination = connector.getDestination()

    # We use address.IPv{4,6}Address to check what the reactor thinks it is
    # is sending but check for validity with ipaddress.IPv{4,6}Address
    # because they fail with IPs on the wrong network stack.
    cls_mapping = {
        address.IPv4Address: ipaddress.IPv4Address,
        address.IPv6Address: ipaddress.IPv6Address,
    }

    cls = cls_mapping.get(destination.__class__)

    if cls is not None:
        try:
            cls(expected_ip)
        except Exception as exc:  # noqa: BLE001
            msg = f"Invalid IP type and resolution for {destination}. Expected {expected_ip} to be {cls.__name__}"
            raise ValueError(msg) from exc
    else:
        msg = f"Unknown address type {destination.__class__.__name__} for {destination}"
        raise ValueError(msg)


class ThreadPool:
    """
    Threadless thread pool.

    See twisted.python.threadpool.ThreadPool
    """

    def __init__(self, reactor: IReactorTime):
        self._reactor = reactor

    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass

    def callInThreadWithCallback(
        self,
        onResult: Callable[[bool, Failure | R], None],
        function: Callable[P, R],
        *args: P.args,
        **kwargs: P.kwargs,
    ) -> "Deferred[None]":
        def _(res: Any) -> None:
            if isinstance(res, Failure):
                onResult(False, res)
            else:
                onResult(True, res)

        d: "Deferred[None]" = Deferred()
        d.addCallback(lambda _: function(*args, **kwargs))
        d.addBoth(_)
        self._reactor.callLater(0, d.callback, True)
        return d


def _make_test_homeserver_synchronous(server: HomeServer) -> None:
    """
    Make the given test homeserver's database interactions synchronous.
    """

    clock = server.get_clock()

    for database in server.get_datastores().databases:
        pool = database._db_pool

        def wrap_pool(pool):
            def runWithConnection(
                func: Callable[..., R], *args: Any, **kwargs: Any
            ) -> Awaitable[R]:
                return threads.deferToThreadPool(
                    pool._reactor,
                    pool.threadpool,
                    pool._runWithConnection,
                    func,
                    *args,
                    **kwargs,
                )

            def runInteraction(
                desc: str, func: Callable[..., R], *args: Any, **kwargs: Any
            ) -> Awaitable[R]:
                return threads.deferToThreadPool(
                    pool._reactor,
                    pool.threadpool,
                    pool._runInteraction,
                    desc,
                    func,
                    *args,
                    **kwargs,
                )

            pool.runWithConnection = runWithConnection  # type: ignore[method-assign]
            pool.runInteraction = runInteraction  # type: ignore[assignment]
            # Replace the thread pool with a threadless 'thread' pool
            pool.threadpool = ThreadPool(clock._reactor)
            pool.running = True

        wrap_pool(pool)

    # We've just changed the Databases to run DB transactions on the same
    # thread, so we need to disable the dedicated thread behaviour.
    server.get_datastores().main.USE_DEDICATED_DB_THREADS_FOR_EVENT_FETCHING = False


def get_clock() -> tuple[ThreadedMemoryReactorClock, Clock]:
    clock = ThreadedMemoryReactorClock()
    hs_clock = Clock(clock)
    return clock, hs_clock


class TestHomeServer(HomeServer):
    DATASTORE_CLASS = DataStore  # type: ignore[assignment]


def setup_test_homeserver(
    name: str = "test",
    config: HomeServerConfig | None = None,
    reactor: type[ISynapseReactor] | None = None,
    homeserver_to_use: type[HomeServer] = TestHomeServer,
    **kwargs: Any,
) -> HomeServer:
    """
    Setup a homeserver suitable for running tests against.  Keyword arguments
    are passed to the Homeserver constructor.

    If no datastore is supplied, one is created and given to the homeserver.

    Calling this method directly is deprecated: you should instead derive from
    HomeserverTestCase.
    """
    if reactor is None:
        from twisted.internet import reactor as _reactor

        reactor = cast(ISynapseReactor, _reactor)

    if config is None:
        config = default_config(name, parse=True)

    config.caches.resize_all_caches()

    if SQLITE_PERSIST_DB:
        # The current working directory is in _trial_temp, so this gets created within that directory.
        test_db_location = os.path.abspath("test.db")
        logger.debug("Will persist db to %s", test_db_location)
        # Ensure each test gets a clean database.
        try:
            os.remove(test_db_location)
        except FileNotFoundError:
            pass
        else:
            logger.debug("Removed existing DB at %s", test_db_location)
    else:
        test_db_location = ":memory:"

    database_config = {
        "name": "sqlite3",
        "args": {"database": test_db_location, "cp_min": 1, "cp_max": 1},
    }

    # Check if we have set up a DB that we can use as a template.
    global PREPPED_SQLITE_DB_CONN
    if PREPPED_SQLITE_DB_CONN is None:
        temp_engine = create_engine(database_config)
        PREPPED_SQLITE_DB_CONN = LoggingDatabaseConnection(
            sqlite3.connect(":memory:"), temp_engine, "PREPPED_CONN"
        )

        database = DatabaseConnectionConfig("master", database_config)
        config.database.databases = [database]
        prepare_database(PREPPED_SQLITE_DB_CONN, create_engine(database_config), config)

    database_config["_TEST_PREPPED_CONN"] = PREPPED_SQLITE_DB_CONN

    if "db_txn_limit" in kwargs:
        database_config["txn_limit"] = kwargs["db_txn_limit"]

    database = DatabaseConnectionConfig("master", database_config)
    config.database.databases = [database]

    create_engine(database.config)

    hs = homeserver_to_use(
        name,
        config=config,
        version_string="Synapse/tests",
        reactor=reactor,
    )

    # Install @cache_in_self attributes
    for key, val in kwargs.items():
        setattr(hs, "_" + key, val)

    # Mock TLS
    hs.tls_server_context_factory = Mock()

    hs.setup()

    # bcrypt is far too slow to be doing in unit tests
    # Need to let the HS build an auth handler and then mess with it
    # because AuthHandler's constructor requires the HS, so we can't make one
    # beforehand and pass it in to the HS's constructor (chicken / egg)
    async def _hash(p: str) -> str:
        return hashlib.md5(p.encode("utf8")).hexdigest()

    hs.get_auth_handler().hash = _hash  # type: ignore[assignment]

    async def validate_hash(p: str, h: str) -> bool:
        return hashlib.md5(p.encode("utf8")).hexdigest() == h

    hs.get_auth_handler().validate_hash = validate_hash  # type: ignore[assignment]

    # Make the threadpool and database transactions synchronous for testing.
    _make_test_homeserver_synchronous(hs)

    # Load any configured modules into the homeserver
    module_api = hs.get_module_api()
    for module, module_config in hs.config.modules.loaded_modules:
        hs.mockmod = module(module_config, module_api)
        logger.debug("Loaded module %s %r", module, module_config)

    load_legacy_spam_checkers(hs)
    load_legacy_third_party_event_rules(hs)
    load_legacy_presence_router(hs)
    load_legacy_password_auth_providers(hs)

    return hs
