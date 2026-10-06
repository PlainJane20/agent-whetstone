import os

import pytest

os.environ.setdefault("PYDANTIC_AI_NO_BANNER", "1")

from whetstone.harness import RunConfig, gullible_factory, run_attack  # noqa: E402
from whetstone.sandbox import Sandbox  # noqa: E402
from whetstone.targets import SusceptibilityProfile  # noqa: E402


def profile_of(p: float) -> SusceptibilityProfile:
    d = SusceptibilityProfile()
    return SusceptibilityProfile(base={k: p for k in d.base}, spotlight={k: p for k in d.spotlight},
                                 goal_factor={k: 1.0 for k in d.goal_factor}, trusted_zone=p)


@pytest.fixture
def sb():
    return Sandbox(0)


@pytest.fixture
def always():
    return gullible_factory(profile_of(1.0))


@pytest.fixture
def never():
    return gullible_factory(profile_of(0.0))


@pytest.fixture
def cfg():
    return RunConfig(seed=0, trials=1)


def go(attack, stack, factory, cfg, trial=0):
    return run_attack(attack, trial, stack, factory, cfg)


@pytest.fixture(autouse=True, scope="session")
def _no_real_model_requests():
    """Safety net: if any test ever reached a real provider model, pydantic-ai raises instead of
    calling the network. Stub models (TestModel, FunctionModel) are unaffected."""
    try:
        from pydantic_ai import models
    except ImportError:  # base install without the llm extra
        yield
        return
    old = models.ALLOW_MODEL_REQUESTS
    models.ALLOW_MODEL_REQUESTS = False
    yield
    models.ALLOW_MODEL_REQUESTS = old
