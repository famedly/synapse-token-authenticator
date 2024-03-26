# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2018 New Vector
# Copyright 2019 Matrix.org Federation C.I.C
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

import functools
import gc
import json
import logging
import time
from collections.abc import Awaitable, Callable, Iterable
from typing import (
    Any,
    ClassVar,
    Concatenate,
    TypeVar,
)
from unittest.mock import Mock

from synapse import events
from synapse.config._base import Config, RootConfig
from synapse.config.homeserver import HomeServerConfig
from synapse.http.server import JsonResource, OptionsResource
from synapse.http.site import SynapseRequest, SynapseSite
from synapse.logging.context import (
    SENTINEL_CONTEXT,
    LoggingContext,
    current_context,
    set_current_context,
)
from synapse.rest import RegisterServletsFunc
from synapse.server import HomeServer
from synapse.types import JsonDict, Requester, UserID, create_requester
from synapse.util import Clock
from synapse.util.httpresourcetree import create_resource_tree
from twisted.internet.defer import Deferred, ensureDeferred
from twisted.internet.testing import MemoryReactor, MemoryReactorClock
from twisted.python.threadpool import ThreadPool
from twisted.trial import unittest
from twisted.web.resource import Resource
from twisted.web.server import Request
from typing_extensions import ParamSpec

from tests.rest import RestHelper
from tests.server import (
    CustomHeaderType,
    FakeChannel,
    ThreadedMemoryReactorClock,
    get_clock,
    make_request,
    setup_test_homeserver,
)
from tests.test_utils import setup_awaitable_errors
from tests.test_utils.logging_setup import setup_logging
from tests.utils import checked_cast, default_config

setup_logging()

TV = TypeVar("TV")

P = ParamSpec("P")
R = TypeVar("R")
S = TypeVar("S")


def around(target: TV) -> Callable[[Callable[Concatenate[S, P], R]], None]:
    """A CLOS-style 'around' modifier, which wraps the original method of the
    given instance with another piece of code.

    @around(self)
    def method_name(orig, *args, **kwargs):
        return orig(*args, **kwargs)
    """

    def _around(code: Callable[Concatenate[S, P], R]) -> None:
        name = code.__name__
        orig = getattr(target, name)

        def new(*args: P.args, **kwargs: P.kwargs) -> R:
            return code(orig, *args, **kwargs)

        setattr(target, name, new)

    return _around


_TConfig = TypeVar("_TConfig", Config, RootConfig)


def deepcopy_config(config: _TConfig) -> _TConfig:
    new_config: _TConfig

    if isinstance(config, RootConfig):
        new_config = config.__class__(config.config_files)  # type: ignore[arg-type]
    else:
        new_config = config.__class__(config.root)

    for attr_name in config.__dict__:
        if attr_name.startswith("__") or attr_name == "root":
            continue
        attr = getattr(config, attr_name)
        new_attr = deepcopy_config(attr) if isinstance(attr, Config) else attr

        setattr(new_config, attr_name, new_attr)

    return new_config


@functools.lru_cache(maxsize=8)
def _parse_config_dict(config: str) -> RootConfig:
    config_obj = HomeServerConfig()
    config_obj.parse_config_dict(json.loads(config), "", "")
    return config_obj


def make_homeserver_config_obj(config: dict[str, Any]) -> RootConfig:
    """Creates a :class:`HomeServerConfig` instance with the given configuration dict.

    This is equivalent to::

        config_obj = HomeServerConfig()
        config_obj.parse_config_dict(config, "", "")

    but it keeps a cache of `HomeServerConfig` instances and deepcopies them as needed,
    to avoid validating the whole configuration every time.
    """
    config_obj = _parse_config_dict(json.dumps(config, sort_keys=True))
    return deepcopy_config(config_obj)


class TestCase(unittest.TestCase):
    """A subclass of twisted.trial's TestCase which looks for 'loglevel'
    attributes on both itself and its individual test methods, to override the
    root logger's logging level while that test (case|method) runs."""

    def __init__(self, methodName: str):
        super().__init__(methodName)

        method = getattr(self, methodName)

        level = getattr(method, "loglevel", getattr(self, "loglevel", None))

        @around(self)
        def setUp(orig: Callable[[], R]) -> R:
            # if we're not starting in the sentinel logcontext, then to be honest
            # all future bets are off.
            if current_context():
                self.fail(
                    f"Test starting with non-sentinel logging context {current_context()}"
                )

            # Disable GC for duration of test. See below for why.
            gc.disable()

            old_level = logging.getLogger().level
            if level is not None and old_level != level:

                @around(self)
                def tearDown(orig: Callable[[], R]) -> R:
                    ret = orig()
                    logging.getLogger().setLevel(old_level)
                    return ret

                logging.getLogger().setLevel(level)

            # Trial messes with the warnings configuration, thus this has to be
            # done in the context of an individual TestCase.
            self.addCleanup(setup_awaitable_errors())

            return orig()

        # We want to force a GC to workaround problems with deferreds leaking
        # logcontexts when they are GCed (see the logcontext docs).
        #
        # The easiest way to do this would be to do a full GC after each test
        # run, but that is very expensive. Instead, we disable GC (above) for
        # the duration of the test and only run a gen-0 GC, which is a lot
        # quicker. This doesn't clean up everything, since the TestCase
        # instance still holds references to objects created during the test,
        # such as HomeServers, so we do a full GC every so often.

        @around(self)
        def tearDown(orig: Callable[[], R]) -> R:
            ret = orig()
            gc.collect(0)
            # Run a full GC every 50 gen-0 GCs.
            gen0_stats = gc.get_stats()[0]
            gen0_collections = gen0_stats["collections"]
            if gen0_collections % 50 == 0:
                gc.collect()
            gc.enable()
            set_current_context(SENTINEL_CONTEXT)

            return ret


class HomeserverTestCase(TestCase):
    """
    A base TestCase that reduces boilerplate for HomeServer-using test cases.

    Defines a setUp method which creates a mock reactor, and instantiates a homeserver
    running on that reactor.

    There are various hooks for modifying the way that the homeserver is instantiated:

    * override make_homeserver, for example by making it pass different parameters into
      setup_test_homeserver.

    * override default_config, to return a modified configuration dictionary for use
      by setup_test_homeserver.

    * On a per-test basis, you can use the @override_config decorator to give a
      dictionary containing additional configuration settings to be added to the basic
      config dict.

    Attributes:
        servlets: List of servlet registration function.
        user_id (str): The user ID to assume if auth is hijacked.
        hijack_auth: Whether to hijack auth to return the user specified
           in user_id.
    """

    hijack_auth: ClassVar[bool] = True
    needs_threadpool: ClassVar[bool] = False
    servlets: ClassVar[list[RegisterServletsFunc]] = []

    def __init__(self, methodName: str):
        super().__init__(methodName)

        # see if we have any additional config for this test
        method = getattr(self, methodName)
        self._extra_config = getattr(method, "_extra_config", None)

    def setUp(self) -> None:
        """
        Set up the TestCase by calling the homeserver constructor, optionally
        hijacking the authentication system to return a fixed user, and then
        calling the prepare function.
        """
        self.reactor, self.clock = get_clock()
        self._hs_args = {"clock": self.clock, "reactor": self.reactor}
        self.hs = self.make_homeserver(self.reactor, self.clock)

        # Honour the `use_frozen_dicts` config option. We have to do this
        # manually because this is taken care of in the app `start` code, which
        # we don't run. Plus we want to reset it on tearDown.
        events.USE_FROZEN_DICTS = self.hs.config.server.use_frozen_dicts

        if self.hs is None:
            msg = "No homeserver returned from make_homeserver."
            raise TypeError(msg)

        if not isinstance(self.hs, HomeServer):
            msg = f"A homeserver wasn't returned, but {self.hs!r}"
            raise TypeError(msg)

        # create the root resource, and a site to wrap it.
        self.resource = self.create_test_resource()
        self.site = SynapseSite(
            logger_name="synapse.access.http.fake",
            site_tag=self.hs.config.server.server_name,
            config=self.hs.config.server.listeners[0],
            resource=self.resource,
            server_version_string="1",
            max_request_body_size=4096,
            reactor=self.reactor,
            hs=self.hs,
        )

        self.helper = RestHelper(
            self.hs,
            checked_cast(MemoryReactorClock, self.hs.get_reactor()),
            self.site,
            getattr(self, "user_id", None),
        )

        if hasattr(self, "user_id") and self.hijack_auth:
            assert self.helper.auth_user_id is not None
            token = "some_fake_token"

            # We need a valid token ID to satisfy foreign key constraints.
            token_id = self.get_success(
                self.hs.get_datastores().main.add_access_token_to_user(
                    self.helper.auth_user_id,
                    token,
                    None,
                    None,
                )
            )

            # This has to be a function and not just a Mock, because
            # `self.helper.auth_user_id` is temporarily reassigned in some tests
            async def get_requester(*args: Any, **kwargs: Any) -> Requester:
                assert self.helper.auth_user_id is not None
                return create_requester(
                    user_id=UserID.from_string(self.helper.auth_user_id),
                    access_token_id=token_id,
                )

            # Type ignore: mypy doesn't like us assigning to methods.
            self.hs.get_auth().get_user_by_req = get_requester  # type: ignore[method-assign]
            self.hs.get_auth().get_user_by_access_token = get_requester  # type: ignore[method-assign]
            self.hs.get_auth().get_access_token_from_request = Mock(return_value=token)  # type: ignore[method-assign]

        if self.needs_threadpool:
            self.reactor.threadpool = ThreadPool()  # type: ignore[assignment]
            self.addCleanup(self.reactor.threadpool.stop)
            self.reactor.threadpool.start()

        if hasattr(self, "prepare"):
            self.prepare(self.reactor, self.clock, self.hs)

    def tearDown(self) -> None:
        # Reset to not use frozen dicts.
        events.USE_FROZEN_DICTS = False

    def wait_on_thread(self, deferred: Deferred, timeout: int = 10) -> None:
        """
        Wait until a Deferred is done, where it's waiting on a real thread.
        """
        start_time = time.time()

        while not deferred.called:
            if start_time + timeout < time.time():
                msg = "Timed out waiting for threadpool"
                raise ValueError(msg)
            self.reactor.advance(0.01)
            time.sleep(0.01)

    def wait_for_background_updates(self) -> None:
        """Block until all background database updates have completed."""
        store = self.hs.get_datastores().main
        while not self.get_success(
            store.db_pool.updates.has_completed_background_updates()
        ):
            self.get_success(
                store.db_pool.updates.do_next_background_update(False), by=0.1
            )

    def make_homeserver(
        self, reactor: ThreadedMemoryReactorClock, clock: Clock
    ) -> HomeServer:
        """
        Make and return a homeserver.

        Args:
            reactor: A Twisted Reactor, or something that pretends to be one.
            clock: The Clock, associated with the reactor.

        Returns:
            A homeserver suitable for testing.

        Function to be overridden in subclasses.
        """
        return self.setup_test_homeserver()

    def create_test_resource(self) -> Resource:
        """
        Create a the root resource for the test server.

        The default calls `self.create_resource_dict` and builds the resultant dict
        into a tree.
        """
        root_resource = OptionsResource()
        create_resource_tree(self.create_resource_dict(), root_resource)
        return root_resource

    def create_resource_dict(self) -> dict[str, Resource]:
        """Create a resource tree for the test server

        A resource tree is a mapping from path to twisted.web.resource.

        The default implementation creates a JsonResource and calls each function in
        `servlets` to register servlets against it.
        """
        servlet_resource = JsonResource(self.hs)
        for servlet in self.servlets:
            servlet(self.hs, servlet_resource)
        resources: dict[str, Resource] = {
            "/_matrix/client": servlet_resource,
            "/_synapse/admin": servlet_resource,
        }
        resources.update(self.hs._module_web_resources)
        return resources

    def default_config(self) -> JsonDict:
        """
        Get a default HomeServer config dict.
        """
        config = default_config("test")

        # apply any additional config which was specified via the override_config
        # decorator.
        if self._extra_config is not None:
            config.update(self._extra_config)

        return config

    def prepare(
        self, reactor: MemoryReactor, clock: Clock, homeserver: HomeServer
    ) -> None:
        """
        Prepare for the test.  This involves things like mocking out parts of
        the homeserver, or building test data common across the whole test
        suite.

        Args:
            reactor: A Twisted Reactor, or something that pretends to be one.
            clock: The Clock, associated with the reactor.
            homeserver: The HomeServer to test against.

        Function to optionally be overridden in subclasses.
        """

    def make_request(
        self,
        method: bytes | str,
        path: bytes | str,
        content: bytes | str | JsonDict = b"",
        access_token: str | None = None,
        request: type[Request] = SynapseRequest,
        shorthand: bool = True,
        federation_auth_origin: bytes | None = None,
        content_is_form: bool = False,
        await_result: bool = True,
        custom_headers: Iterable[CustomHeaderType] | None = None,
        client_ip: str = "127.0.0.1",
    ) -> FakeChannel:
        """
        Create a SynapseRequest at the path using the method and containing the
        given content.

        Args:
            method: The HTTP request method ("verb").
            path: The HTTP path, suitably URL encoded (e.g. escaped UTF-8 & spaces
                and such). content (bytes or dict): The body of the request.
                JSON-encoded, if a dict.
            shorthand: Whether to try and be helpful and prefix the given URL
            with the usual REST API path, if it doesn't contain it.
            federation_auth_origin: if set to not-None, we will add a fake
                Authorization header pretenting to be the given server name.
            content_is_form: Whether the content is URL encoded form data. Adds the
                'Content-Type': 'application/x-www-form-urlencoded' header.

            await_result: whether to wait for the request to complete rendering. If
                 true (the default), will pump the test reactor until the the renderer
                 tells the channel the request is finished.

            custom_headers: (name, value) pairs to add as request headers

            client_ip: The IP to use as the requesting IP. Useful for testing
                ratelimiting.

        Returns:
            The FakeChannel object which stores the result of the request.
        """
        return make_request(
            self.reactor,
            self.site,
            method,
            path,
            content,
            access_token,
            request,
            shorthand,
            federation_auth_origin,
            content_is_form,
            await_result,
            custom_headers,
            client_ip,
        )

    def setup_test_homeserver(
        self, name: str | None = None, **kwargs: Any
    ) -> HomeServer:
        """
        Set up the test homeserver, meant to be called by the overridable
        make_homeserver. It automatically passes through the test class's
        clock & reactor.

        Args:
            See tests.utils.setup_test_homeserver.

        Returns:
            synapse.server.HomeServer
        """
        kwargs = dict(kwargs)
        kwargs.update(self._hs_args)
        config = self.default_config() if "config" not in kwargs else kwargs["config"]

        # The server name can be specified using either the `name` argument or a config
        # override. The `name` argument takes precedence over any config overrides.
        if name is not None:
            config["server_name"] = name

        # Parse the config from a config dict into a HomeServerConfig
        config_obj = make_homeserver_config_obj(config)
        kwargs["config"] = config_obj

        # The server name in the config is now `name`, if provided, or the `server_name`
        # from a config override, or the default of "test". Whichever it is, we
        # construct a homeserver with a matching name.
        kwargs["name"] = config_obj.server.server_name

        async def run_bg_updates() -> None:
            with LoggingContext("run_bg_updates"):
                self.get_success(stor.db_pool.updates.run_background_updates(False))

        hs = setup_test_homeserver(**kwargs)
        stor = hs.get_datastores().main

        # Run the database background updates, when running against "master".
        if hs.__class__.__name__ == "TestHomeServer":
            self.get_success(run_bg_updates())

        return hs

    def pump(self, by: float = 0.0) -> None:
        """
        Pump the reactor enough that Deferreds will fire.
        """
        self.reactor.pump([by] * 100)

    def get_success(self, d: Awaitable[TV], by: float = 0.0) -> TV:
        deferred: Deferred[TV] = ensureDeferred(d)  # type: ignore[arg-type]
        self.pump(by=by)
        return self.successResultOf(deferred)


def override_config(extra_config: JsonDict) -> Callable[[TV], TV]:
    """A decorator which can be applied to test functions to give additional HS config

    For use

    For example:

        class MyTestCase(HomeserverTestCase):
            @override_config({"enable_registration": False, ...})
            def test_foo(self):
                ...

    Args:
        extra_config: Additional config settings to be merged into the default
            config dict before instantiating the test homeserver.
    """

    def decorator(func: TV) -> TV:
        # This attribute is being defined.
        func._extra_config = extra_config  # type: ignore[attr-defined]
        return func

    return decorator
